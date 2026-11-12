"""making sure the db itself enforces the rules the design depends on."""
import sqlite3

import pytest

from server.db import connect, init_db, transaction


@pytest.fixture
def conn(tmp_path):
    c = connect(str(tmp_path / "test.db"))
    init_db(c)
    return c


def add_log_entry(conn):
    conn.execute(
        "INSERT INTO audit_log (ts, action, role, details, prev_hash, entry_hash, signature) "
        "VALUES ('t', 'test', NULL, '{}', '0', 'h', 's')")


def test_audit_log_rejects_update(conn):
    add_log_entry(conn)
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        conn.execute("UPDATE audit_log SET action = 'edited'")


def test_audit_log_rejects_delete(conn):
    add_log_entry(conn)
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        conn.execute("DELETE FROM audit_log")


def test_one_token_per_user_per_round(conn):
    conn.execute("INSERT INTO issuance VALUES (1, 1)")
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("INSERT INTO issuance VALUES (1, 1)")
    conn.execute("INSERT INTO issuance VALUES (1, 2)")  # next round is fine though


def test_token_can_only_be_spent_once_per_round(conn):
    conn.execute("INSERT INTO spent_tokens VALUES ('abc', 1)")
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("INSERT INTO spent_tokens VALUES ('abc', 1)")


def test_invalid_role_rejected(conn):
    conn.execute("INSERT INTO users (username, password_hash, public_key) VALUES ('a', 'x', 'k')")
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("INSERT INTO user_roles VALUES (1, 'superuser')")


def test_transaction_rolls_back_on_error(conn):
    with pytest.raises(sqlite3.IntegrityError):
        with transaction(conn):
            conn.execute("INSERT INTO issuance VALUES (5, 5)")
            conn.execute("INSERT INTO issuance VALUES (5, 5)")  # this one blows up
    # and the first insert got undone too
    assert conn.execute("SELECT COUNT(*) FROM issuance").fetchone()[0] == 0
