"""token issuance through the real server, including attempts to cheat."""
import threading

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from common import blind_rsa
from tests.conftest import auth_header


def start_round(client, admin):
    r = client.post("/admin/rounds", headers=auth_header(admin))
    assert r.status_code == 200, r.json
    return r.json


def request_token(client, session):
    """does what the real client will do: make a token key, blind it, get it
    signed, unblind it. returns (http response, token dict or None)."""
    rnd = client.get("/round").json
    n, e = int(rnd["n"], 16), rnd["e"]
    token_key = Ed25519PrivateKey.generate()
    pub = token_key.public_key().public_bytes_raw()
    msg = blind_rsa.token_message(rnd["epoch"], pub)
    blinded, r = blind_rsa.blind(msg, n, e)

    resp = client.post("/tokens", json={"epoch": rnd["epoch"], "blinded": hex(blinded)},
                       headers=auth_header(session))
    if resp.status_code != 200:
        return resp, None
    sig = blind_rsa.unblind(int(resp.json["blind_signature"], 16), r, n)
    return resp, {"epoch": rnd["epoch"], "public_key": pub, "signature": sig, "n": n, "e": e,
                  "blinded": blinded, "private_key": token_key}


def token_is_valid(token):
    msg = blind_rsa.token_message(token["epoch"], token["public_key"])
    return blind_rsa.verify(msg, token["signature"], token["n"], token["e"])


def test_sender_gets_a_valid_token(client, users):
    start_round(client, users.admin())
    _, alice = users.make("alice", ["sender"])
    resp, token = request_token(client, alice)
    assert resp.status_code == 200 and token_is_valid(token)


def test_only_one_token_per_round(client, users):
    start_round(client, users.admin())
    _, alice = users.make("alice", ["sender"])
    request_token(client, alice)
    resp, _ = request_token(client, alice)
    assert resp.status_code == 409


def test_non_senders_cant_get_tokens(client, users):
    start_round(client, users.admin())
    for role in ("recipient", "moderator", "admin"):
        session = users.admin() if role == "admin" else users.make(f"u_{role}", [role])[1]
        resp, _ = request_token(client, session)
        assert resp.status_code == 403, role


def test_no_round_yet(client, users):
    _, alice = users.make("alice", ["sender"])
    assert client.get("/round").status_code == 404
    r = client.post("/tokens", json={"epoch": 1, "blinded": "ff"}, headers=auth_header(alice))
    assert r.status_code == 409


def test_wrong_epoch_rejected(client, users):
    start_round(client, users.admin())
    _, alice = users.make("alice", ["sender"])
    r = client.post("/tokens", json={"epoch": 99, "blinded": "ff"}, headers=auth_header(alice))
    assert r.status_code == 409


def test_garbage_doesnt_use_up_your_token(client, users):
    start_round(client, users.admin())
    _, alice = users.make("alice", ["sender"])
    n = int(client.get("/round").json["n"], 16)
    for bad in ("not hex", "0", hex(n)):
        r = client.post("/tokens", json={"epoch": 1, "blinded": bad}, headers=auth_header(alice))
        assert r.status_code == 400
    resp, _ = request_token(client, alice)
    assert resp.status_code == 200   # still gets the real one


def test_new_round_new_key_and_old_tokens_stop_working(client, users):
    admin = users.admin()
    start_round(client, admin)
    _, alice = users.make("alice", ["sender"])
    _, old_token = request_token(client, alice)

    start_round(client, admin)
    resp, new_token = request_token(client, alice)   # allowed again in the new round
    assert resp.status_code == 200
    assert new_token["n"] != old_token["n"]           # fresh signing key
    # the old token doesn't verify under the new round's key or epoch
    msg = blind_rsa.token_message(new_token["epoch"], old_token["public_key"])
    assert not blind_rsa.verify(msg, old_token["signature"], new_token["n"], new_token["e"])


def test_old_private_keys_are_wiped(client, users, db):
    admin = users.admin()
    start_round(client, admin)
    start_round(client, admin)
    rows = db.execute("SELECT id, private_key_pem FROM rounds ORDER BY id").fetchall()
    assert rows[0]["private_key_pem"] is None and rows[1]["private_key_pem"] is not None


def test_longer_token_lifetime(client, users, db):
    # token_validity_rounds = 2: rounds 1 and 2 share a key, round 3 gets a new one
    admin = users.admin()
    client.post("/admin/policy", json={"name": "token_validity_rounds", "value": 2},
                headers=auth_header(admin))
    _, alice = users.make("alice", ["sender"])

    start_round(client, admin)
    assert request_token(client, alice)[0].status_code == 200
    r2 = start_round(client, admin)
    assert r2["epoch"] == 1
    assert request_token(client, alice)[0].status_code == 409   # still the same epoch
    r3 = start_round(client, admin)
    assert r3["epoch"] == 3
    assert request_token(client, alice)[0].status_code == 200


def test_issuance_records_are_deleted_when_epoch_ends(client, users, db):
    admin = users.admin()
    start_round(client, admin)
    _, alice = users.make("alice", ["sender"])
    request_token(client, alice)
    assert db.execute("SELECT COUNT(*) FROM issuance").fetchone()[0] == 1
    start_round(client, admin)
    assert db.execute("SELECT COUNT(*) FROM issuance").fetchone()[0] == 0


def test_server_keeps_nothing_that_links_a_token_to_a_user(client, users, db, app):
    start_round(client, users.admin())
    _, alice = users.make("alice", ["sender"])
    _, token = request_token(client, alice)

    raw_db = b""
    for path in (app.config["DB_PATH"], app.config["DB_PATH"] + "-wal"):
        try:
            with open(path, "rb") as f:
                raw_db += f.read()
        except FileNotFoundError:
            pass
    # neither the blinded value nor anything about the real token is stored
    assert hex(token["blinded"])[2:].encode() not in raw_db
    assert token["public_key"] not in raw_db
    assert hex(token["signature"])[2:].encode() not in raw_db

    entry = db.execute("SELECT * FROM audit_log WHERE action = 'token_issued'").fetchone()
    assert entry["actor_id"] is None and "alice" not in entry["details"]
    assert entry["ts"].endswith(":00:00Z")


def test_concurrent_requests_only_get_one_token(app, users):
    users.client.post("/admin/rounds", headers=auth_header(users.admin()))
    _, alice = users.make("alice", ["sender"])
    results = []

    def attempt():
        resp, _ = request_token(app.test_client(), alice)
        results.append(resp.status_code)

    threads = [threading.Thread(target=attempt) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count(200) == 1 and results.count(409) == 19


def test_policy_checks(client, users):
    admin = users.admin()
    _, mod = users.make("mod", ["moderator"])
    assert client.post("/admin/policy", json={"name": "flag_threshold", "value": 5},
                       headers=auth_header(mod)).status_code == 403
    for bad in [{"name": "nope", "value": 1}, {"name": "flag_threshold", "value": 0},
                {"name": "flag_threshold", "value": "3"}]:
        assert client.post("/admin/policy", json=bad, headers=auth_header(admin)).status_code == 400
    assert client.post("/admin/policy", json={"name": "flag_threshold", "value": 5},
                       headers=auth_header(admin)).status_code == 200
    assert client.get("/admin/policy", headers=auth_header(admin)).json["flag_threshold"] == 5
