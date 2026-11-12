"""flagging, the moderator queue, freezing, alerts, and the audit endpoints."""
import json
import os

from client import crypto
from common import blind_rsa
from common.envelope import b64e, token_id
from server import rounds
from tests.conftest import auth_header
from tests.test_messages import build, inbox, world  # noqa: F401  (world is a fixture)
from tests.test_tokens import request_token

REASON = "this is harassment"


def send(client, token, recipient_id, pem, text="you're the worst"):
    r = client.post("/messages", json=build(client, token, recipient_id, pem, text))
    assert r.status_code == 201, r.json


def key_for(msg, private_key):
    """what bob's client does: decrypt locally, keep the aes key for flagging."""
    _, message_key = crypto.decrypt_message(private_key, msg["envelope"])
    return b64e(message_key)


def flag(client, session, msg_id, key, reason=REASON):
    return client.post(f"/inbox/{msg_id}/flag", json={"key": key, "reason": reason},
                       headers=auth_header(session))


def queue(client, session, status="open"):
    r = client.get(f"/moderation/flags?status={status}", headers=auth_header(session))
    assert r.status_code == 200, r.json
    return r.json["flags"]


def alerts_for(client, session, rule):
    r = client.get("/alerts", headers=auth_header(session))
    return [a for a in r.json["alerts"] if a["rule"] == rule]


def flagged_world(client, world, users, public_key_pem, user_private_key):
    """alice sends bob something nasty, bob flags it, a moderator exists."""
    send(client, world["token"], world["bob_id"], public_key_pem)
    [msg] = inbox(client, world["bob"])
    assert flag(client, world["bob"], msg["id"], key_for(msg, user_private_key)).status_code == 201
    _, mod = users.make("mod", ["moderator"])
    return msg, mod


# --- flagging ---

def test_flag_shows_up_in_queue_without_the_recipient(client, world, users, public_key_pem,
                                                      user_private_key):
    _, mod = flagged_world(client, world, users, public_key_pem, user_private_key)
    [f] = queue(client, mod)
    assert f["plaintext"] == "you're the worst" and f["reason"] == REASON
    assert f["token_id"] == token_id(world["token"]["public_key"])
    # nothing about who received it
    assert "bob" not in json.dumps(f) and "recipient_id" not in f and "message_id" not in f


def test_flag_with_wrong_key_is_rejected(client, world, public_key_pem):
    send(client, world["token"], world["bob_id"], public_key_pem)
    [msg] = inbox(client, world["bob"])
    r = flag(client, world["bob"], msg["id"], b64e(os.urandom(32)))
    assert r.status_code == 400 and "commitment" in r.json["error"]


def test_flag_with_key_from_another_message_is_rejected(client, world, users, public_key_pem,
                                                        user_private_key):
    # bob gets two messages and tries to use the first one's real key on the
    # second, i.e. pin the first message's text on the second token
    _, carol = users.make("carol", ["sender"])
    _, carol_token = request_token(client, carol)
    send(client, world["token"], world["bob_id"], public_key_pem, "nasty")
    send(client, carol_token, world["bob_id"], public_key_pem, "nice")
    first, second = inbox(client, world["bob"])
    r = flag(client, world["bob"], second["id"], key_for(first, user_private_key))
    assert r.status_code == 400


def test_cant_flag_someone_elses_message(client, world, users, public_key_pem, user_private_key):
    _, dave = users.make("dave", ["recipient"])
    send(client, world["token"], world["bob_id"], public_key_pem)
    [msg] = inbox(client, world["bob"])
    # even with the right key
    assert flag(client, dave, msg["id"], key_for(msg, user_private_key)).status_code == 403
    assert flag(client, dave, 9999, key_for(msg, user_private_key)).status_code == 404


def test_cant_flag_twice(client, world, users, public_key_pem, user_private_key):
    msg, _ = flagged_world(client, world, users, public_key_pem, user_private_key)
    assert flag(client, world["bob"], msg["id"], key_for(msg, user_private_key)).status_code == 409


def test_flag_needs_reason(client, world, public_key_pem, user_private_key):
    send(client, world["token"], world["bob_id"], public_key_pem)
    [msg] = inbox(client, world["bob"])
    assert flag(client, world["bob"], msg["id"], key_for(msg, user_private_key), "").status_code == 400


def test_only_recipients_can_flag(client, world, public_key_pem, user_private_key):
    send(client, world["token"], world["bob_id"], public_key_pem)
    [msg] = inbox(client, world["bob"])
    for session in (world["alice"], world["admin"]):
        assert flag(client, session, msg["id"], key_for(msg, user_private_key)).status_code == 403


def test_only_moderators_see_the_queue(client, world):
    for session in (world["alice"], world["bob"], world["admin"]):
        assert client.get("/moderation/flags", headers=auth_header(session)).status_code == 403


# --- freezing ---

def freeze(client, mod, tid, reason="abuse"):
    return client.post(f"/moderation/tokens/{tid}/freeze", json={"reason": reason},
                       headers=auth_header(mod))


def unfreeze(client, mod, tid, reason="my mistake"):
    return client.post(f"/moderation/tokens/{tid}/unfreeze", json={"reason": reason},
                       headers=auth_header(mod))


def test_freeze_withdraws_message_and_blocks_token(client, world, users, public_key_pem,
                                                   user_private_key, db):
    _, mod = flagged_world(client, world, users, public_key_pem, user_private_key)
    tid = token_id(world["token"]["public_key"])
    r = freeze(client, mod, tid)
    assert r.status_code == 200 and r.json["withdrawn"] == 1

    assert inbox(client, world["bob"]) == []                       # gone from the inbox
    assert queue(client, mod) == [] and queue(client, mod, "frozen")[0]["frozen"]

    # trying to use it again gets refused and raises an alert
    again = build(client, world["token"], world["bob_id"], public_key_pem, "again")
    assert client.post("/messages", json=again).status_code == 403
    assert len(alerts_for(client, mod, "frozen_token_used")) == 1

    row = db.execute("SELECT * FROM audit_log WHERE action = 'token_frozen'").fetchone()
    assert row["role"] == "moderator" and row["actor_id"] is not None   # moderators are accountable


def test_unfreeze_puts_everything_back(client, world, users, public_key_pem, user_private_key):
    _, mod = flagged_world(client, world, users, public_key_pem, user_private_key)
    tid = token_id(world["token"]["public_key"])
    freeze(client, mod, tid)
    r = unfreeze(client, mod, tid)
    assert r.status_code == 200 and r.json["restored"] == 1
    assert len(inbox(client, world["bob"])) == 1
    assert queue(client, mod)[0]["frozen"] is False
    assert unfreeze(client, mod, tid).status_code == 404               # not frozen anymore


def test_freeze_checks(client, world, users, public_key_pem, user_private_key):
    _, mod = flagged_world(client, world, users, public_key_pem, user_private_key)
    tid = token_id(world["token"]["public_key"])
    assert freeze(client, mod, tid, reason="").status_code == 400      # need a reason
    assert freeze(client, mod, "nothex").status_code == 400
    assert freeze(client, mod, "a" * 64).status_code == 404            # never sent anything
    assert freeze(client, mod, tid).status_code == 200
    assert freeze(client, mod, tid).status_code == 409                 # already frozen


def test_only_moderators_can_freeze(client, world, public_key_pem):
    send(client, world["token"], world["bob_id"], public_key_pem)
    tid = token_id(world["token"]["public_key"])
    for session in (world["admin"], world["bob"], world["alice"]):
        assert freeze(client, session, tid).status_code == 403


def test_dismiss(client, world, users, public_key_pem, user_private_key, db):
    _, mod = flagged_world(client, world, users, public_key_pem, user_private_key)
    [f] = queue(client, mod)
    url = f"/moderation/flags/{f['id']}/dismiss"
    assert client.post(url, headers=auth_header(world["admin"])).status_code == 403
    assert client.post(url, headers=auth_header(mod)).status_code == 200
    assert client.post(url, headers=auth_header(mod)).status_code == 409
    assert queue(client, mod) == [] and len(queue(client, mod, "dismissed")) == 1
    assert len(inbox(client, world["bob"])) == 1                       # dismissing doesn't withdraw
    row = db.execute("SELECT * FROM audit_log WHERE action = 'flag_dismissed'").fetchone()
    assert row["actor_id"] is not None


# --- alerts ---

def test_flag_threshold_alert_fires_once_and_never_freezes(client, world, users, public_key_pem,
                                                           user_private_key, db):
    client.post("/admin/policy", json={"name": "flag_threshold", "value": 2},
                headers=auth_header(world["admin"]))
    tokens = [world["token"]]
    for name in ("carol", "erin"):
        _, s = users.make(name, ["sender"])
        tokens.append(request_token(client, s)[1])
    for t in tokens:
        send(client, t, world["bob_id"], public_key_pem)
    for msg in inbox(client, world["bob"]):
        flag(client, world["bob"], msg["id"], key_for(msg, user_private_key))

    _, mod = users.make("mod", ["moderator"])
    [alert] = alerts_for(client, mod, "flag_threshold")                 # 3 flags, still one alert
    assert json.loads(alert["detail"])["flags"] == 2
    # alert only. a person has to decide to freeze
    assert db.execute("SELECT COUNT(*) FROM frozen_tokens").fetchone()[0] == 0


def test_invalid_token_alert(client, world, users, public_key_pem):
    body = build(client, world["token"], world["bob_id"], public_key_pem)
    body["token"]["signature"] = hex(world["token"]["signature"] + 1)
    for _ in range(6):
        assert client.post("/messages", json=body).status_code == 403
    _, mod = users.make("mod", ["moderator"])
    [alert] = alerts_for(client, mod, "invalid_tokens")
    assert json.loads(alert["detail"])["attempts"] == 5


def test_lockout_alert(client, users):
    users.make("bob", ["recipient"])
    for _ in range(5):
        client.post("/login", json={"username": "bob", "password": "wrong password"})
    _, mod = users.make("mod", ["moderator"])
    assert len(alerts_for(client, mod, "account_locked")) == 1


def test_minted_token_raises_alert(client, world, users, public_key_pem, db):
    # pretend the round's signing key leaked and someone made their own token
    # without ever asking the server
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    current = rounds.current_round(db)
    n, d = rounds.private_numbers(current)
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes_raw()
    sig = pow(blind_rsa.fdh(blind_rsa.token_message(current["epoch"], pub), n), d, n)
    minted = {"epoch": current["epoch"], "public_key": pub, "signature": sig, "private_key": key}

    send(client, world["token"], world["bob_id"], public_key_pem)   # the one real token
    send(client, minted, world["bob_id"], public_key_pem)           # accepted, it verifies...
    _, mod = users.make("mod", ["moderator"])
    [alert] = alerts_for(client, mod, "unissued_tokens")            # ...but it gets noticed
    assert json.loads(alert["detail"]) == {"epoch": current["epoch"], "issued": 1, "used": 2}


def test_alert_times_are_rounded(client, world, users, public_key_pem, db):
    tid = token_id(world["token"]["public_key"])
    db.execute("INSERT INTO frozen_tokens VALUES (?, 'now', 'test')", (tid,))
    client.post("/messages", json=build(client, world["token"], world["bob_id"], public_key_pem))
    for row in db.execute("SELECT ts FROM audit_log WHERE action IN "
                          "('frozen_token_used', 'alert_raised')"):
        assert row["ts"].endswith(":00:00Z")
    assert db.execute("SELECT created_at FROM alerts").fetchone()[0].endswith(":00:00Z")


def test_who_can_see_alerts(client, world):
    assert client.get("/alerts", headers=auth_header(world["admin"])).status_code == 200
    for session in (world["alice"], world["bob"]):
        assert client.get("/alerts", headers=auth_header(session)).status_code == 403


# --- audit endpoints ---

def test_audit_read_and_verify(client, world, users):
    _, mod = users.make("mod", ["moderator"])
    r = client.get("/audit", headers=auth_header(mod))
    assert r.status_code == 200 and r.json["entries"]
    saved_head = r.json["head"]

    client.post("/admin/rounds", headers=auth_header(world["admin"]))    # more log entries
    v = client.get(f"/audit/verify?head={saved_head}", headers=auth_header(mod)).json
    assert v["ok"] and v["head"] != saved_head
    bad = client.get(f"/audit/verify?head={'f' * 64}", headers=auth_header(mod)).json
    assert not bad["ok"]

    for session in (world["alice"], world["bob"]):
        assert client.get("/audit", headers=auth_header(session)).status_code == 403
