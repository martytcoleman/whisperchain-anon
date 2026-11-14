"""runs a short scripted scenario against a fresh server and prints the audit log.

    python -m scripts.audit_demo

this is what docs/audit_log_sample.md was made from. it uses a throwaway
data folder, so it doesn't touch your real data/ or client_data/.

at the end it plays an attacker with direct access to the database file
(but not the audit key) and shows verify catching two kinds of tampering.
"""
import json
import logging
import shutil
import sqlite3
import tempfile
import threading

from werkzeug.serving import make_server

from client.core import ApiError, Client
from server import audit
from server.app import create_app
from server.db import connect
from server.manage import promote_admin

PASSWORD = "correct horse battery"


def step(text):
    print(f"  - {text}")


def run_scenario(app, url, home):
    def user(name):
        c = Client(url, home, name)
        c.register(PASSWORD)
        return c

    print("scenario:")
    admin = user("admin")
    conn = connect(app.config["DB_PATH"])
    promote_admin(conn, app.config["AUDIT_KEY"], "admin")
    conn.close()
    admin.login(PASSWORD)
    step("admin bootstrapped from the server command line, logs in")

    people = {n: user(n) for n in ("alice", "carol", "bob", "mod")}
    ids = {u["username"]: u["id"] for u in admin.users()}
    for name, roles in (("alice", ["sender"]), ("carol", ["sender"]),
                        ("bob", ["recipient"]), ("mod", ["moderator"])):
        admin.approve(ids[name], roles)
    step("alice, carol, bob, mod register; admin approves them")

    try:
        admin.set_roles(ids["mod"], ["moderator", "admin"])
    except ApiError:
        step("admin tries to make mod an admin too: refused (separation of duties)")

    admin.start_round()
    step("admin starts round 1")

    alice, carol, bob, mod = (people[n] for n in ("alice", "carol", "bob", "mod"))
    for p in people.values():
        p.login(PASSWORD)
    step("everyone logs in; alice and carol pick up their tokens")

    alice.send("bob", "thanks for explaining recursion so patiently")
    carol.send("bob", "nobody wants you in this class")
    step("alice and carol each send bob a message")

    try:
        alice.audit()
    except ApiError:
        step("alice tries to read the audit log: refused")

    # a forged token: alice's token file with the server's signature changed
    path = f"{home}/alice/token.json"
    real = open(path).read()
    forged = json.loads(real)
    forged["signature"] = hex(int(forged["signature"], 16) + 1)
    forged["used_rounds"] = []
    with open(path, "w") as f:
        json.dump(forged, f)
    try:
        alice.send("bob", "sent with a forged token")
    except ApiError:
        step("someone sends with a forged token signature: refused")
    with open(path, "w") as f:
        f.write(real)

    messages = bob.inbox()
    step("bob reads his inbox (2 messages)")
    nasty = next(m for m in messages if "nobody" in m["text"])
    bob.flag(nasty["id"], "this is harassment, not a compliment")
    step("bob flags carol's message")

    [flag] = mod.flag_queue()
    mod.freeze(flag["token_id"], "harassment, confirmed")
    step("mod freezes the token behind the flagged message")

    carol_token = json.load(open(f"{home}/carol/token.json"))
    carol_token["used_rounds"] = []   # pretend she's trying again
    with open(f"{home}/carol/token.json", "w") as f:
        json.dump(carol_token, f)
    try:
        carol.send("bob", "you can't stop me")
    except ApiError:
        step("carol tries to use her frozen token again: refused, alert raised")

    for _ in range(5):
        try:
            Client(url, home, "alice").login("not the password")
        except ApiError:
            pass
    step("someone guesses alice's password 5 times: account locked, alert raised")

    mod.verify_audit()
    step("mod verifies the log and saves the head hash on their machine")

    admin.start_round()
    step("admin starts round 2 (new signing key, issuance records wiped)")


def print_log(db_path):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    print()
    print(f"{'#':>3}  {'time (utc)':<20}  {'action':<20}  {'role':<10}  {'actor':<5}  details")
    print("-" * 110)
    for r in conn.execute("SELECT * FROM audit_log ORDER BY id"):
        print(f"{r['id']:>3}  {r['ts']:<20}  {r['action']:<20}  {r['role'] or '-':<10}  "
              f"{r['actor_id'] or '-':<5}  {r['details']}")
    last = conn.execute("SELECT id, prev_hash, entry_hash, signature FROM audit_log "
                        "ORDER BY id DESC LIMIT 1").fetchone()
    print()
    print(f"last entry (#{last['id']}) in full:")
    print(f"  prev_hash  {last['prev_hash']}")
    print(f"  entry_hash {last['entry_hash']}")
    print(f"  signature  {last['signature']}")
    conn.close()


def tamper_demo(db_path, public_key, workdir):
    print()
    print("verify on the real log:")
    conn = connect(db_path)
    print("  ", audit.verify(conn, public_key))
    conn.close()

    # attacker 1: edits an entry in place. the triggers block UPDATE, so they
    # drop the trigger first (they have the db file, so they can)
    copy1 = f"{workdir}/tampered1.db"
    shutil.copy(db_path, copy1)
    conn = sqlite3.connect(copy1)
    conn.execute("DROP TRIGGER audit_log_no_update")
    row = conn.execute("SELECT id FROM audit_log WHERE action = 'token_frozen'").fetchone()
    conn.execute("UPDATE audit_log SET details = ? WHERE id = ?",
                 (json.dumps({"reason": "routine", "token": "0" * 64, "withdrawn": 0}), row[0]))
    conn.commit()
    conn.close()
    print()
    print(f"attacker edits entry #{row[0]} (token_frozen) to hide which token was frozen:")
    conn = connect(copy1)
    print("  ", audit.verify(conn, public_key))
    conn.close()

    # attacker 2: same edit, but also recomputes that entry's hash and every
    # hash after it so the chain links up again. they don't have the audit
    # key, so they can't make new signatures
    copy2 = f"{workdir}/tampered2.db"
    shutil.copy(copy1, copy2)
    conn = sqlite3.connect(copy2)
    conn.row_factory = sqlite3.Row
    prev = conn.execute("SELECT entry_hash FROM audit_log WHERE id = ?", (row[0] - 1,)).fetchone()[0]
    for r in conn.execute("SELECT * FROM audit_log WHERE id >= ? ORDER BY id", (row[0],)).fetchall():
        h = audit._hash_entry(prev, r["ts"], r["action"], r["role"], r["actor_id"],
                              json.loads(r["details"]))
        conn.execute("UPDATE audit_log SET prev_hash = ?, entry_hash = ? WHERE id = ?",
                     (prev, h, r["id"]))
        prev = h
    conn.commit()
    conn.close()
    print()
    print("attacker also recomputes every hash from that entry on, so the chain links up:")
    conn = connect(copy2)
    print("  ", audit.verify(conn, public_key))
    conn.close()


def main():
    logging.disable(logging.CRITICAL)   # hide the web server's request lines
    workdir = tempfile.mkdtemp(prefix="whisperchain-demo-")
    try:
        app = create_app(f"{workdir}/data")
        server = make_server("127.0.0.1", 0, app, threaded=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        run_scenario(app, f"http://127.0.0.1:{server.server_port}", f"{workdir}/clients")
        server.shutdown()
        print_log(app.config["DB_PATH"])
        tamper_demo(app.config["DB_PATH"], app.config["AUDIT_KEY"].public_key(), workdir)
    finally:
        shutil.rmtree(workdir)


if __name__ == "__main__":
    main()
