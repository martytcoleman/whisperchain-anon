"""attack the audit log the way someone with direct db access would, and make
sure verify() catches each trick."""
import json

import pytest

from server import audit
from server.db import connect, init_db


@pytest.fixture
def setup(tmp_path):
    conn = connect(str(tmp_path / "test.db"))
    init_db(conn)
    key = audit.load_or_create_key(str(tmp_path / "audit_key.pem"))
    for i in range(5):
        audit.log(conn, key, "role_assigned", role="admin", actor_id=1, target=i)
    return conn, key, key.public_key()


def drop_triggers(conn):
    # an attacker with the db file can just remove the triggers, so the
    # tests below assume they're gone and rely on the hashes + signatures
    conn.execute("DROP TRIGGER audit_log_no_update")
    conn.execute("DROP TRIGGER audit_log_no_delete")


def test_clean_log_verifies(setup):
    conn, _, pub = setup
    assert audit.verify(conn, pub) == (True, "ok")


def test_entries_are_chained(setup):
    conn, _, _ = setup
    rows = conn.execute("SELECT prev_hash, entry_hash FROM audit_log ORDER BY id").fetchall()
    assert rows[0]["prev_hash"] == audit.GENESIS_HASH
    for before, after in zip(rows, rows[1:]):
        assert after["prev_hash"] == before["entry_hash"]


def test_edited_entry_is_caught(setup):
    conn, _, pub = setup
    drop_triggers(conn)
    conn.execute("UPDATE audit_log SET details = ? WHERE id = 3", (json.dumps({"target": 999}),))
    ok, msg = audit.verify(conn, pub)
    assert not ok and msg.startswith("entry 3")


def test_deleted_entry_is_caught(setup):
    conn, _, pub = setup
    drop_triggers(conn)
    conn.execute("DELETE FROM audit_log WHERE id = 2")
    ok, msg = audit.verify(conn, pub)
    assert not ok and "chain broken" in msg


def test_rehashed_without_key_is_caught(setup):
    # the smarter attacker edits an entry AND recomputes its hash, but
    # doesn't have the audit key so can't produce a valid signature
    conn, _, pub = setup
    drop_triggers(conn)
    row = conn.execute("SELECT * FROM audit_log WHERE id = 5").fetchone()
    fake_details = {"target": 999}
    fake_hash = audit._hash_entry(row["prev_hash"], row["ts"], row["action"],
                                  row["role"], row["actor_id"], fake_details)
    conn.execute("UPDATE audit_log SET details = ?, entry_hash = ? WHERE id = 5",
                 (json.dumps(fake_details), fake_hash))
    ok, msg = audit.verify(conn, pub)
    assert not ok and "bad signature" in msg


def test_truncation_caught_with_saved_head(setup):
    # chopping off the newest entries leaves a valid-looking shorter chain.
    # only a head hash saved somewhere else catches that
    conn, _, pub = setup
    saved_head = audit.get_head(conn)
    drop_triggers(conn)
    conn.execute("DELETE FROM audit_log WHERE id >= 4")
    assert audit.verify(conn, pub)[0]                      # looks fine on its own
    ok, msg = audit.verify(conn, pub, expected_head=saved_head)
    assert not ok and "saved head" in msg


def test_sender_events_have_coarse_time(setup):
    conn, key, _ = setup
    audit.log(conn, key, "message_sent", role="sender", round=1)
    ts = conn.execute("SELECT ts FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()["ts"]
    assert ts.endswith(":00:00Z")


def test_key_file_is_reused(tmp_path):
    path = str(tmp_path / "k.pem")
    a = audit.load_or_create_key(path)
    b = audit.load_or_create_key(path)
    assert a.public_key().public_bytes_raw() == b.public_key().public_bytes_raw()
