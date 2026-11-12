"""helpers for users' rsa public keys. shared by the server and the client."""
import hashlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

MIN_KEY_BITS = 3072


def load_rsa_public_key(pem):
    """parse a pem public key and make sure it's rsa and big enough. raises ValueError if not."""
    try:
        key = serialization.load_pem_public_key(pem.encode())
    except (ValueError, TypeError):
        raise ValueError("not a valid PEM public key")
    if not isinstance(key, RSAPublicKey):
        raise ValueError("public key must be RSA")
    if key.key_size < MIN_KEY_BITS:
        raise ValueError(f"RSA key must be at least {MIN_KEY_BITS} bits")
    return key


def fingerprint(pem):
    """short-ish hash of a public key that two people can read out and compare.

    this is what key pinning checks: if someone's fingerprint ever changes,
    the client refuses to send to them until the user looks into it.
    """
    der = load_rsa_public_key(pem).public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    h = hashlib.sha256(der).hexdigest()
    return ":".join(h[i:i + 4] for i in range(0, len(h), 4))
