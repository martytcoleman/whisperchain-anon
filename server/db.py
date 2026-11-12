"""database schema + connection helpers.

the quotas (one token per sender per round, one message per token per round)
are enforced by unique / primary key constraints in here instead of
"check then insert" code. that way two requests hitting at the same time
can't both sneak through.
"""
import sqlite3
from contextlib import contextmanager

SCHEMA = """
-- accounts. you register with a public key and stay 'pending' until an
-- admin approves you
CREATE TABLE IF NOT EXISTS users (
    id                 INTEGER PRIMARY KEY,
    username           TEXT NOT NULL UNIQUE,
    password_hash      TEXT NOT NULL,
    public_key         TEXT NOT NULL,          -- pem, rsa-3072 encryption key
    pending_public_key TEXT,                   -- new key waiting on admin approval
    status             TEXT NOT NULL DEFAULT 'pending'
                       CHECK (status IN ('pending', 'active', 'rejected')),
    failed_logins      INTEGER NOT NULL DEFAULT 0,
    locked_until       REAL NOT NULL DEFAULT 0
);

-- people can have more than one role so roles get their own table
CREATE TABLE IF NOT EXISTS user_roles (
    user_id INTEGER NOT NULL REFERENCES users(id),
    role    TEXT NOT NULL CHECK (role IN ('sender', 'recipient', 'moderator', 'admin')),
    PRIMARY KEY (user_id, role)
);

-- login sessions. we only keep a hash of the session id, so if someone
-- steals the db they don't get working sessions out of it
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id),
    expires_at REAL NOT NULL
);

-- rounds are grouped into epochs. every epoch gets its own rsa key for
-- blind signing tokens, and a token is only good during the epoch it was
-- signed in. with the default policy (token_validity_rounds = 1) every round
-- is its own epoch, so every round gets a fresh key and fresh tokens.
-- only the current round row keeps the private key, older rows get it wiped
CREATE TABLE IF NOT EXISTS rounds (
    id              INTEGER PRIMARY KEY,
    started_at      TEXT NOT NULL,
    epoch           INTEGER NOT NULL,          -- id of the round that started this epoch
    public_key_pem  TEXT NOT NULL,
    private_key_pem TEXT,                      -- null except on the current round
    is_current      INTEGER NOT NULL DEFAULT 0
);

-- settings the admin can change (alert threshold, token lifetime)
CREATE TABLE IF NOT EXISTS policy (
    name  TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- this is the only place a real user gets tied to anything token related.
-- it's only here to enforce one token per sender per epoch, and it gets
-- cleared as soon as the epoch ends. no timestamp and no rowid on purpose,
-- so you can't line the row order up with the audit log
CREATE TABLE IF NOT EXISTS issuance (
    user_id INTEGER NOT NULL,
    epoch   INTEGER NOT NULL,
    PRIMARY KEY (user_id, epoch)
) WITHOUT ROWID;

-- a token gets one message per round. with the default lifetime of one
-- round that just means one message per token
CREATE TABLE IF NOT EXISTS spent_tokens (
    token_id TEXT NOT NULL,                    -- sha-256 of the token's public key
    round_id INTEGER NOT NULL,
    PRIMARY KEY (token_id, round_id)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS frozen_tokens (
    token_id  TEXT PRIMARY KEY,
    frozen_at TEXT NOT NULL,
    reason    TEXT NOT NULL
);

-- stored messages. notice what's not here: no sender id, no ip, no send
-- time. the only readable stuff is routing info (recipient, round) and
-- public crypto material, the actual content is ciphertext
CREATE TABLE IF NOT EXISTS messages (
    id           INTEGER PRIMARY KEY,
    recipient_id INTEGER NOT NULL REFERENCES users(id),
    round_id     INTEGER NOT NULL,
    token_id     TEXT NOT NULL,
    envelope     TEXT NOT NULL,                -- json: ciphertext, nonce, wrapped key, commitment
    token        TEXT NOT NULL,                -- json: token public key + blind signature
    signature    TEXT NOT NULL,                -- token key's signature over the envelope
    withdrawn    INTEGER NOT NULL DEFAULT 0    -- set if the token that sent it gets frozen
);

-- flagged messages. the plaintext only ends up here because the recipient
-- chose to reveal it, and only after the server checked it against the
-- sender's commitment
CREATE TABLE IF NOT EXISTS flags (
    id         INTEGER PRIMARY KEY,
    message_id INTEGER NOT NULL UNIQUE REFERENCES messages(id),
    round_id   INTEGER NOT NULL,
    token_id   TEXT NOT NULL,
    plaintext  TEXT NOT NULL,
    reason     TEXT NOT NULL,
    status     TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'resolved'))
);

CREATE TABLE IF NOT EXISTS alerts (
    id         INTEGER PRIMARY KEY,
    created_at TEXT NOT NULL,
    rule       TEXT NOT NULL,
    detail     TEXT NOT NULL
);

-- append-only audit log. each entry has the previous entry's hash (hash
-- chain) plus a server signature
CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY,
    ts         TEXT NOT NULL,
    action     TEXT NOT NULL,
    role       TEXT,
    actor_id   INTEGER,                        -- only filled in for admin/moderator actions
    details    TEXT NOT NULL,                  -- json
    prev_hash  TEXT NOT NULL,
    entry_hash TEXT NOT NULL,
    signature  TEXT NOT NULL
);

-- the db itself won't let anyone edit or delete log entries
CREATE TRIGGER IF NOT EXISTS audit_log_no_update
BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;

CREATE TRIGGER IF NOT EXISTS audit_log_no_delete
BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;
"""

DEFAULT_POLICY = {
    "flag_threshold": "3",          # flags in a round before an alert goes off
    "token_validity_rounds": "1",   # 1 = fresh unlinkable token every round
}


def connect(path):
    # isolation_level=None turns off python's automatic transactions so we
    # control exactly where they start and end (see transaction() below)
    conn = sqlite3.connect(path, timeout=10, isolation_level=None,
                           check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_db(conn):
    conn.executescript(SCHEMA)
    for name, value in DEFAULT_POLICY.items():
        conn.execute("INSERT OR IGNORE INTO policy (name, value) VALUES (?, ?)",
                     (name, value))


@contextmanager
def transaction(conn):
    """run a bunch of statements as one all-or-nothing transaction.

    BEGIN IMMEDIATE grabs the write lock right away, so two requests can't
    both read something like "token not spent yet" before either one writes.
    """
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise


def get_policy(conn, name):
    row = conn.execute("SELECT value FROM policy WHERE name = ?", (name,)).fetchone()
    return int(row["value"])
