"""rounds, epochs, and the blind signing key.

a round is one messaging period (one message per sender per round).
an epoch is a run of rounds that share a signing key, so a token stays good
for the whole epoch. how many rounds per epoch is the token_validity_rounds
policy. the default is 1, meaning each round is its own epoch and nobody's
tokens can be linked from one round to the next.
"""
from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from server.db import get_policy

KEY_BITS = 3072


def current_round(conn):
    return conn.execute("SELECT * FROM rounds WHERE is_current = 1").fetchone()


def public_numbers(round_row):
    """(n, e) for the round's signing key. this part is public."""
    key = serialization.load_pem_public_key(round_row["public_key_pem"].encode())
    nums = key.public_numbers()
    return nums.n, nums.e


def private_numbers(round_row):
    """(n, d) for the round's signing key. only the current round still has it."""
    key = serialization.load_pem_private_key(round_row["private_key_pem"].encode(), password=None)
    nums = key.private_numbers()
    return nums.public_numbers.n, nums.d


def start_round(conn):
    """start the next round. call this inside a transaction.

    if the current epoch still has rounds left, the new round keeps the same
    key. otherwise a brand new key is made, and the issuance table is wiped
    since the only thing it was for (one token per sender per epoch) is over.
    returns the new round row.
    """
    old = current_round(conn)
    new_id = old["id"] + 1 if old else 1
    rounds_per_epoch = get_policy(conn, "token_validity_rounds")

    if old and new_id - old["epoch"] < rounds_per_epoch:
        epoch = old["epoch"]
        public_pem, private_pem = old["public_key_pem"], old["private_key_pem"]
    else:
        epoch = new_id
        key = rsa.generate_private_key(public_exponent=65537, key_size=KEY_BITS)
        private_pem = key.private_bytes(serialization.Encoding.PEM,
                                        serialization.PrivateFormat.PKCS8,
                                        serialization.NoEncryption()).decode()
        public_pem = key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        # throw away who-got-a-token info for the epoch that just ended
        conn.execute("DELETE FROM issuance")

    # the old round loses its private key, only the current round holds one
    conn.execute("UPDATE rounds SET is_current = 0, private_key_pem = NULL WHERE is_current = 1")
    conn.execute(
        "INSERT INTO rounds (id, started_at, epoch, public_key_pem, private_key_pem, is_current) "
        "VALUES (?, ?, ?, ?, ?, 1)",
        (new_id, datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
         epoch, public_pem, private_pem))
    return current_round(conn)
