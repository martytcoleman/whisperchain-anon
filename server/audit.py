"""the audit log: append-only, hash-chained, and signed.

three layers, each catching something the others don't:
  1. the db triggers (in db.py) refuse UPDATE/DELETE, so normal code and
     casual poking can't edit history
  2. each entry includes the hash of the one before it (a hash chain), so
     changing, deleting, or reordering an old entry breaks every hash after it
  3. each entry's hash is signed with the server's audit key, so someone who
     edits the db directly can't just recompute the hashes to cover it up
     (they'd need the key too)

what this can't do: someone with the db AND the audit key could rewrite the
whole thing and re-sign it. that's why get_head() exists, so a copy of the
latest hash can be kept somewhere off the server and checked later.
"""
import base64
import hashlib
import json
import os
from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from server.db import transaction

GENESIS_HASH = "0" * 64   # the "previous hash" for the very first entry

# events that come from anonymous senders (or alerts they cause). their
# timestamps get rounded down to the hour so the log can't be used to line up
# "alice was online at 10:01" with "a message was sent at 10:01"
COARSE_TIME_ACTIONS = {"token_issued", "message_sent", "invalid_token",
                       "frozen_token_used", "alert_raised"}


def load_or_create_key(path):
    """the audit signing key lives in its own file, separate from the db."""
    if os.path.exists(path):
        with open(path, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(serialization.Encoding.PEM,
                            serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    # create the file readable by the owner only
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
    return key


def _timestamp(action):
    now = datetime.now(timezone.utc)
    if action in COARSE_TIME_ACTIONS:
        now = now.replace(minute=0, second=0, microsecond=0)
    return now.strftime("%Y-%m-%dT%H:%M:%SZ")


def _hash_entry(prev_hash, ts, action, role, actor_id, details):
    # sort_keys + no spaces gives the exact same bytes every time for the same
    # data, which matters because we're hashing it
    body = json.dumps(
        {"ts": ts, "action": action, "role": role, "actor_id": actor_id, "details": details},
        sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((prev_hash + body).encode()).hexdigest()


def log(conn, key, action, role=None, actor_id=None, **details):
    """add one entry to the log.

    role is the role involved (e.g. "sender"). actor_id should only be passed
    for admin and moderator actions, never for anything a sender does.
    """
    # reading the last hash and inserting the new entry has to happen inside
    # one transaction, otherwise two requests could both chain off the same
    # previous entry. if the caller already opened one, just use theirs
    if conn.in_transaction:
        _append(conn, key, action, role, actor_id, details)
    else:
        with transaction(conn):
            _append(conn, key, action, role, actor_id, details)


def _append(conn, key, action, role, actor_id, details):
    ts = _timestamp(action)
    prev_hash = get_head(conn)
    entry_hash = _hash_entry(prev_hash, ts, action, role, actor_id, details)
    signature = base64.b64encode(key.sign(entry_hash.encode())).decode()
    conn.execute(
        "INSERT INTO audit_log (ts, action, role, actor_id, details, prev_hash, entry_hash, signature) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (ts, action, role, actor_id, json.dumps(details, sort_keys=True),
         prev_hash, entry_hash, signature))


def get_head(conn):
    """hash of the newest entry. save this somewhere off the server now and then."""
    row = conn.execute("SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
    return row["entry_hash"] if row else GENESIS_HASH


def verify(conn, public_key, expected_head=None):
    """walk the whole log and check every link and signature.

    returns (True, "ok") or (False, "what went wrong and at which entry").
    if expected_head is given (a hash saved earlier), also make sure that
    entry is still in the log, which catches someone chopping entries off
    the end or rewriting everything with the key.
    """
    prev_hash = GENESIS_HASH
    seen_hashes = set()
    for row in conn.execute("SELECT * FROM audit_log ORDER BY id"):
        if row["prev_hash"] != prev_hash:
            return False, f"entry {row['id']}: chain broken (an entry before it was changed, removed, or reordered)"

        details = json.loads(row["details"])
        recomputed = _hash_entry(prev_hash, row["ts"], row["action"], row["role"],
                                 row["actor_id"], details)
        if recomputed != row["entry_hash"]:
            return False, f"entry {row['id']}: contents don't match its hash (entry was edited)"

        try:
            public_key.verify(base64.b64decode(row["signature"]), row["entry_hash"].encode())
        except Exception:
            return False, f"entry {row['id']}: bad signature (hash was recomputed without the audit key)"

        seen_hashes.add(row["entry_hash"])
        prev_hash = row["entry_hash"]

    if expected_head is not None and expected_head not in seen_hashes:
        return False, "the saved head hash isn't in the log anymore (entries were cut off or the log was rewritten)"
    return True, "ok"
