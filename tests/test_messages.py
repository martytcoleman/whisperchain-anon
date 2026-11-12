"""sending and receiving through the real server, plus every way of cheating
we could think of."""
import json
import threading

import pytest

from client import crypto
from common.envelope import b64e, token_id
from tests.conftest import auth_header
from tests.test_tokens import request_token, start_round

TEXT = "thanks for staying late to help with the lab"


@pytest.fixture
def world(client, users):
    """a started round, alice (sender) with a fresh token, and bob (recipient)."""
    admin = users.admin()
    start_round(client, admin)
    _, alice = users.make("alice", ["sender"])
    bob_id, bob = users.make("bob", ["recipient"])
    _, token = request_token(client, alice)
    return {"admin": admin, "alice": alice, "bob": bob, "bob_id": bob_id, "token": token}


def build(client, token, recipient_id, pem, text=TEXT):
    """what the client does to send: encrypt for the recipient, sign with the token key."""
    rnd = client.get("/round").json
    envelope = crypto.encrypt_message(text, pem, recipient_id, rnd["round_id"], token["epoch"])
    return {
        "envelope": envelope,
        "token": {"epoch": token["epoch"], "public_key": b64e(token["public_key"]),
                  "signature": hex(token["signature"])},
        "signature": crypto.sign_envelope(token["private_key"], envelope),
    }


def inbox(client, session):
    r = client.get("/inbox", headers=auth_header(session))
    assert r.status_code == 200
    return r.json["messages"]


def test_end_to_end(client, world, public_key_pem, user_private_key):
    body = build(client, world["token"], world["bob_id"], public_key_pem)
    assert client.post("/messages", json=body).status_code == 201
    [msg] = inbox(client, world["bob"])
    text, _ = crypto.decrypt_message(user_private_key, msg["envelope"])
    assert text == TEXT


def test_one_message_per_token_per_round(client, world, public_key_pem):
    assert client.post("/messages", json=build(client, world["token"], world["bob_id"],
                                               public_key_pem)).status_code == 201
    again = build(client, world["token"], world["bob_id"], public_key_pem, "second one")
    assert client.post("/messages", json=again).status_code == 409


def test_replaying_the_exact_same_request(client, world, public_key_pem):
    body = build(client, world["token"], world["bob_id"], public_key_pem)
    assert client.post("/messages", json=body).status_code == 201
    assert client.post("/messages", json=body).status_code == 409
    assert len(inbox(client, world["bob"])) == 1


def test_forged_token_rejected(client, world, public_key_pem, db):
    body = build(client, world["token"], world["bob_id"], public_key_pem)
    body["token"]["signature"] = hex(world["token"]["signature"] + 1)
    assert client.post("/messages", json=body).status_code == 403
    assert db.execute("SELECT COUNT(*) FROM audit_log WHERE action = 'invalid_token'").fetchone()[0] == 1


def test_made_up_token_rejected(client, world, public_key_pem):
    # a real token key pair, but the server never signed it
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    fake_key = Ed25519PrivateKey.generate()
    fake = {**world["token"], "private_key": fake_key,
            "public_key": fake_key.public_key().public_bytes_raw()}
    assert client.post("/messages", json=build(client, fake, world["bob_id"],
                                               public_key_pem)).status_code == 403


def test_token_from_last_round_rejected(client, world, public_key_pem):
    start_round(client, world["admin"])
    body = build(client, world["token"], world["bob_id"], public_key_pem)
    assert client.post("/messages", json=body).status_code == 403


def test_tampered_envelope_rejected(client, world, public_key_pem):
    body = build(client, world["token"], world["bob_id"], public_key_pem)
    body["envelope"]["ciphertext"] = body["envelope"]["ciphertext"][:-4] + "AAAA"
    assert client.post("/messages", json=body).status_code == 403


def test_someone_elses_token_signature_rejected(client, world, users, public_key_pem):
    # carol takes alice's envelope signature and tries to pair it with her own token
    _, carol = users.make("carol", ["sender"])
    _, carol_token = request_token(client, carol)
    body = build(client, world["token"], world["bob_id"], public_key_pem)
    body["token"] = {"epoch": carol_token["epoch"], "public_key": b64e(carol_token["public_key"]),
                     "signature": hex(carol_token["signature"])}
    assert client.post("/messages", json=body).status_code == 403


def test_must_be_sent_to_a_real_recipient(client, world, users, public_key_pem):
    mod_id, _ = users.make("mod", ["moderator"])
    for target in (mod_id, 9999):
        body = build(client, world["token"], target, public_key_pem)
        assert client.post("/messages", json=body).status_code == 400


def test_sending_with_a_login_attached_is_refused(client, world, public_key_pem):
    body = build(client, world["token"], world["bob_id"], public_key_pem)
    r = client.post("/messages", json=body, headers=auth_header(world["alice"]))
    assert r.status_code == 400 and "identify you" in r.json["error"]


def test_frozen_token_rejected(client, world, public_key_pem, db):
    db.execute("INSERT INTO frozen_tokens VALUES (?, 'now', 'test')",
               (token_id(world["token"]["public_key"]),))
    body = build(client, world["token"], world["bob_id"], public_key_pem)
    assert client.post("/messages", json=body).status_code == 403


def test_bad_shapes_rejected(client, world, public_key_pem):
    good = build(client, world["token"], world["bob_id"], public_key_pem)
    broken = [
        {},
        {**good, "envelope": {**good["envelope"], "extra": 1}},
        {**good, "envelope": {**good["envelope"], "round": "1"}},
        {**good, "envelope": {**good["envelope"], "ciphertext": "A" * 9000}},
        {**good, "token": {"epoch": 1}},
        {**good, "signature": 5},
    ]
    for body in broken:
        assert client.post("/messages", json=body).status_code == 400


def test_concurrent_sends_with_one_token(app, world, public_key_pem):
    client = app.test_client()
    bodies = [build(client, world["token"], world["bob_id"], public_key_pem, f"msg {i}")
              for i in range(20)]
    results = []

    def attempt(body):
        results.append(app.test_client().post("/messages", json=body).status_code)

    threads = [threading.Thread(target=attempt, args=(b,)) for b in bodies]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count(201) == 1 and results.count(409) == 19


def test_only_recipients_can_read_an_inbox(client, world):
    for session in (world["alice"], world["admin"]):
        assert client.get("/inbox", headers=auth_header(session)).status_code == 403


def test_you_only_see_your_own_messages(client, world, users, public_key_pem):
    dave_id, dave = users.make("dave", ["recipient"])
    client.post("/messages", json=build(client, world["token"], world["bob_id"], public_key_pem))
    assert len(inbox(client, world["bob"])) == 1
    assert inbox(client, dave) == []


def test_nothing_identifying_is_stored(client, world, public_key_pem, db, app):
    client.post("/messages", json=build(client, world["token"], world["bob_id"], public_key_pem))
    raw_db = b""
    for path in (app.config["DB_PATH"], app.config["DB_PATH"] + "-wal"):
        try:
            with open(path, "rb") as f:
                raw_db += f.read()
        except FileNotFoundError:
            pass
    assert TEXT.encode() not in raw_db                     # no plaintext anywhere

    columns = [c["name"] for c in db.execute("PRAGMA table_info(messages)")]
    assert not any("sender" in c or "ip" == c or "time" in c for c in columns)

    sent = db.execute("SELECT * FROM audit_log WHERE action = 'message_sent'").fetchone()
    assert sent["actor_id"] is None and "alice" not in sent["details"]
    assert sent["ts"].endswith(":00:00Z")


def test_delivery_is_logged(client, world, public_key_pem, db):
    client.post("/messages", json=build(client, world["token"], world["bob_id"], public_key_pem))
    inbox(client, world["bob"])
    row = db.execute("SELECT * FROM audit_log WHERE action = 'message_delivered'").fetchone()
    assert row["role"] == "recipient" and json.loads(row["details"])["count"] == 1


def test_directory(client, world):
    assert client.get("/directory").status_code == 401
    names = [r["username"] for r in client.get("/directory", headers=auth_header(world["alice"])).json["recipients"]]
    assert names == ["bob"]   # only people with the recipient role


def test_key_change_needs_admin_approval(client, world, db):
    from client.keys import generate_user_key, public_pem
    new_pem = public_pem(generate_user_key())
    r = client.post("/me/key", json={"public_key": new_pem}, headers=auth_header(world["bob"]))
    assert r.status_code == 200
    # nothing changed yet
    listed = client.get("/directory", headers=auth_header(world["alice"])).json["recipients"][0]
    assert listed["public_key"] != new_pem

    assert client.post(f"/admin/users/{world['bob_id']}/key/approve",
                       headers=auth_header(world["bob"])).status_code == 403
    assert client.post(f"/admin/users/{world['bob_id']}/key/approve",
                       headers=auth_header(world["admin"])).status_code == 200
    listed = client.get("/directory", headers=auth_header(world["alice"])).json["recipients"][0]
    assert listed["public_key"] == new_pem
    assert db.execute("SELECT COUNT(*) FROM audit_log WHERE action = 'key_approved'").fetchone()[0] == 1
