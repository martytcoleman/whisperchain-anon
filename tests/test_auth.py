"""registration, login, sessions, and the deny-by-default rule."""
import time

import pytest

from server import auth
from tests.conftest import PASSWORD, auth_header


def test_new_accounts_are_pending_and_cant_log_in(client, users):
    users.register("alice")
    r = client.post("/login", json={"username": "alice", "password": PASSWORD})
    assert r.status_code == 401 and "pending" in r.json["error"]


def test_register_rejects_bad_input(client, public_key_pem):
    cases = [
        {"username": "A!", "password": PASSWORD, "public_key": public_key_pem},
        {"username": "bob", "password": "short", "public_key": public_key_pem},
        {"username": "bob", "password": PASSWORD, "public_key": "not a key"},
    ]
    for body in cases:
        assert client.post("/register", json=body).status_code == 400


def test_small_rsa_key_rejected(client):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    small = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
    pem = small.public_bytes(serialization.Encoding.PEM,
                             serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    r = client.post("/register", json={"username": "bob", "password": PASSWORD, "public_key": pem})
    assert r.status_code == 400 and "3072" in r.json["error"]


def test_duplicate_username(client, users):
    users.register("alice")
    r = client.post("/register", json={"username": "alice", "password": PASSWORD,
                                       "public_key": users.pem})
    assert r.status_code == 409


def test_wrong_password_and_unknown_user_look_the_same(client, users):
    users.make("alice", ["recipient"])
    a = client.post("/login", json={"username": "alice", "password": "wrong password!"})
    b = client.post("/login", json={"username": "nobody", "password": "wrong password!"})
    assert a.status_code == b.status_code == 401
    assert a.json == b.json


def test_lockout_after_repeated_failures(client, users, db):
    users.make("alice", ["recipient"])
    for _ in range(auth.MAX_FAILED_LOGINS):
        client.post("/login", json={"username": "alice", "password": "wrong password!"})
    # even the right password is refused while locked
    r = client.post("/login", json={"username": "alice", "password": PASSWORD})
    assert r.status_code == 401 and "too many" in r.json["error"]
    actions = [row["action"] for row in db.execute("SELECT action FROM audit_log")]
    assert "account_locked" in actions


def test_passwords_and_sessions_not_stored_in_plain_text(client, users, db, app):
    _, session = users.make("alice", ["recipient"])
    # read the raw db file plus its write-ahead log, which holds recent writes
    raw_db = b""
    for path in (app.config["DB_PATH"], app.config["DB_PATH"] + "-wal"):
        try:
            with open(path, "rb") as f:
                raw_db += f.read()
        except FileNotFoundError:
            pass
    assert PASSWORD.encode() not in raw_db
    assert session.encode() not in raw_db


def test_expired_session_rejected(client, users, db):
    _, session = users.make("alice", ["recipient"])
    db.execute("UPDATE sessions SET expires_at = ?", (time.time() - 1,))
    assert client.get("/me", headers=auth_header(session)).status_code == 401


def test_logout_kills_session(client, users):
    _, session = users.make("alice", ["recipient"])
    client.post("/logout", headers=auth_header(session))
    assert client.get("/me", headers=auth_header(session)).status_code == 401


def test_me_shows_roles_and_permissions(client, users):
    _, session = users.make("alice", ["sender", "recipient"])
    me = client.get("/me", headers=auth_header(session)).json
    assert me["roles"] == ["recipient", "sender"]
    assert "token:request" in me["permissions"] and "user:approve" not in me["permissions"]


def test_every_route_has_an_access_rule(app):
    # complete mediation: no route is allowed to exist without a check on it
    for endpoint, view in app.view_functions.items():
        assert hasattr(view, "access_rule"), f"{endpoint} has no access rule"


def test_route_without_rule_is_blocked(app, client):
    @app.get("/oops")
    def oops():
        return {"secret": True}
    r = client.get("/oops")
    assert r.status_code == 403 and "secret" not in r.get_data(as_text=True)


def test_typo_in_permission_fails_at_startup():
    from server.rbac import require_permission
    with pytest.raises(ValueError):
        require_permission("inbox:raed")
