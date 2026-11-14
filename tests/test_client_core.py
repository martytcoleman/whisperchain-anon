"""the real client talking to a real server over http on localhost."""
import os
import threading

import pytest
from werkzeug.serving import make_server

from client import core
from client.cli import safe
from client.keys import KeyChanged
from server.db import connect
from server.manage import promote_admin
from tests.conftest import PASSWORD


@pytest.fixture
def server(app):
    srv = make_server("127.0.0.1", 0, app, threaded=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


@pytest.fixture
def people(server, app, tmp_path, monkeypatch, user_private_key):
    """admin + alice (sender) + bob (recipient) + mod, all logged in, round 1 open."""
    # making 3072-bit keys is slow, so every test user shares one
    monkeypatch.setattr(core, "generate_user_key", lambda: user_private_key)
    home = str(tmp_path / "clients")

    def new(name):
        c = core.Client(server, home, name)
        c.register(PASSWORD)
        return c

    admin = new("admin")
    conn = connect(app.config["DB_PATH"])
    promote_admin(conn, app.config["AUDIT_KEY"], "admin")
    conn.close()
    admin.login(PASSWORD)
    admin.start_round()

    out = {"admin": admin, "home": home, "server": server}
    for name, roles in (("alice", ["sender"]), ("bob", ["recipient"]), ("mod", ["moderator"])):
        c = new(name)
        admin.approve(next(u["id"] for u in admin.users() if u["username"] == name), roles)
        out[name] = c
    for name in ("alice", "bob", "mod"):
        out[name].login(PASSWORD)
    return out


def test_whole_flow(people):
    alice, bob, mod = people["alice"], people["bob"], people["mod"]
    assert alice.token_status() == "token ready"        # picked up at login
    alice.send("bob", "your code reviews are great")
    assert alice.token_status() == "token already used this round"

    [msg] = bob.inbox()
    assert msg["text"] == "your code reviews are great"

    bob.flag(msg["id"], "testing the flag flow")
    [f] = mod.flag_queue()
    assert f["plaintext"] == "your code reviews are great"
    mod.freeze(f["token_id"], "test")
    assert bob.inbox() == []


def test_login_picks_up_a_token_and_saves_it_privately(people):
    path = os.path.join(people["home"], "alice", "token.json")
    assert oct(os.stat(path).st_mode & 0o777) == "0o600"
    assert oct(os.stat(os.path.join(people["home"], "alice")).st_mode & 0o777) == "0o700"


def test_send_does_not_carry_the_login(people, monkeypatch):
    # catch the actual request the client makes for /messages
    seen = {}
    real_post = core.requests.post

    def spy(url, **kwargs):
        seen.update(url=url, headers=kwargs.get("headers", {}))
        return real_post(url, **kwargs)

    monkeypatch.setattr(core.requests, "post", spy)
    people["alice"].send("bob", "hi")
    assert seen["url"].endswith("/messages")
    assert "Authorization" not in seen["headers"]


def test_cant_send_twice_in_a_round(people):
    people["alice"].send("bob", "one")
    with pytest.raises(ValueError, match="already sent"):
        people["alice"].send("bob", "two")


def test_new_round_needs_a_new_login_for_a_token(people):
    people["admin"].start_round()
    with pytest.raises(ValueError, match="no token for this round"):
        people["alice"].send("bob", "hi")
    people["alice"].login(PASSWORD)
    people["alice"].send("bob", "hi")


def test_swapped_key_is_refused(people, app):
    alice = people["alice"]
    alice.send("bob", "first message pins bob's key")
    people["admin"].start_round()
    alice.login(PASSWORD)

    # a malicious admin swaps bob's key for a different one
    from client.keys import generate_user_key, public_pem
    conn = connect(app.config["DB_PATH"])
    conn.execute("UPDATE users SET public_key = ? WHERE username = 'bob'",
                 (public_pem(generate_user_key()),))
    conn.close()
    with pytest.raises(KeyChanged):
        alice.send("bob", "this should not go out")


def test_wrong_password_and_missing_key(people, server, tmp_path):
    with pytest.raises(core.ApiError):
        core.Client(server, people["home"], "bob").login("wrong password!")
    with pytest.raises(ValueError, match="no key"):
        core.Client(server, str(tmp_path / "elsewhere"), "bob").login(PASSWORD)


def test_flag_needs_a_message_you_have(people):
    with pytest.raises(ValueError):
        people["bob"].flag(12345, "nope")


def test_moderator_saves_the_audit_head(people):
    mod = people["mod"]
    first = mod.verify_audit()
    assert first["ok"] and not first["checked_saved_head"]
    second = mod.verify_audit()
    assert second["ok"] and second["checked_saved_head"]


def test_server_permissions_still_apply(people):
    # the client hides commands, but even if you call them the server says no
    with pytest.raises(core.ApiError) as e:
        people["alice"].flag_queue()
    assert e.value.status == 403


def test_key_change_flow(people, monkeypatch):
    bob, admin, alice = people["bob"], people["admin"], people["alice"]
    alice.send("bob", "sent to the old key")

    from client import keys
    monkeypatch.setattr(core, "generate_user_key", keys.generate_user_key)   # a really new key
    bob.request_new_key(PASSWORD)
    admin.approve_key(next(u["id"] for u in admin.users() if u["username"] == "bob"))
    # old message still opens: the old key is kept alongside the new one
    assert bob.inbox()[0]["text"] == "sent to the old key"

    # alice notices bob's key changed and won't send until she accepts it
    admin.start_round()
    alice.login(PASSWORD)
    with pytest.raises(KeyChanged):
        alice.send("bob", "to the new key")
    alice.trust_new_key("bob")
    alice.send("bob", "to the new key")
    assert [m["text"] for m in bob.inbox()] == ["sent to the old key", "to the new key"]

    # and both keys survive logging in again from scratch
    fresh = core.Client(people["server"], people["home"], "bob")
    fresh.login(PASSWORD)
    assert len(fresh.inbox()) == 2


def test_safe_strips_terminal_escapes():
    assert safe("hi\x1b[2Jthere") == "hi?[2Jthere"
    assert safe("line one\nline two") == "line one\nline two"
