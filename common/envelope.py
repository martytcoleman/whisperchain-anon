"""the message envelope: the thing that gets encrypted, signed, stored and flagged.

both sides need these helpers. the client builds and signs envelopes, the
server checks signatures and (when something's flagged) checks the revealed
key against the commitment.
"""
import base64
import hashlib
import hmac
import json

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ENVELOPE_FIELDS = ("version", "epoch", "round", "recipient_id",
                   "nonce", "ciphertext", "wrapped_key", "commitment")
MAX_MESSAGE_CHARS = 1000


def b64e(b):
    return base64.b64encode(b).decode()


def b64d(s):
    return base64.b64decode(s, validate=True)


def canonical(envelope):
    """exact bytes to sign. same data always gives the same bytes, otherwise a
    signature made on one machine wouldn't verify on another."""
    return json.dumps({k: envelope[k] for k in ENVELOPE_FIELDS},
                      sort_keys=True, separators=(",", ":")).encode()


def token_id(token_public_bytes):
    """short name for a token, used in the db and the log. it's a hash of the
    token's public key, so it says nothing about who owns the token."""
    return hashlib.sha256(token_public_bytes).hexdigest()


def commitment(message_key):
    return hashlib.sha256(message_key).hexdigest()


def verify_signature(envelope, token_public_bytes, signature_b64):
    try:
        Ed25519PublicKey.from_public_bytes(token_public_bytes).verify(
            b64d(signature_b64), canonical(envelope))
        return True
    except (InvalidSignature, ValueError):
        return False


def open_with_key(envelope, message_key):
    """decrypt an envelope given its aes key. raises ValueError if anything's off.

    the recipient uses this after unwrapping the key with their rsa key. the
    server uses it when a recipient flags a message and hands over the key:
    if the key doesn't match the sender's commitment, or the ciphertext
    doesn't decrypt with it, the flag is fake.
    """
    if not hmac.compare_digest(commitment(message_key), envelope["commitment"]):
        raise ValueError("key doesn't match the sender's commitment")
    try:
        plaintext = AESGCM(message_key).decrypt(
            b64d(envelope["nonce"]), b64d(envelope["ciphertext"]), None)
    except InvalidTag:
        # gcm checks an authentication tag, so any change to the ciphertext
        # (or the wrong key) ends up here instead of giving garbage text
        raise ValueError("ciphertext was tampered with or the key is wrong")
    return plaintext.decode()
