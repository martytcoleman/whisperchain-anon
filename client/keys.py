"""the user's own keys, and pinning other people's keys.

the private key is created here on the user's machine and never sent
anywhere. only the public half goes to the server.
"""
import json
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from common.pubkey import fingerprint


def generate_user_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)


def public_pem(private_key):
    return private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def save_private_key(private_key, path, password):
    # encrypted with the user's password, so a copied key file is useless on
    # its own. BestAvailableEncryption lets the library pick a strong kdf + cipher
    pem = private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(password.encode()))
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)


def load_private_key(path, password):
    """raises ValueError if the password is wrong."""
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=password.encode())


class KeyChanged(Exception):
    pass


class KeyPins:
    """remembers the fingerprint of every recipient we've sent to (trust on first use).

    the server hands out public keys, so a malicious server or admin could
    swap bob's key for their own and read what people send him. pinning means
    that only works if they do it before the first time you ever message bob.
    after that, a changed key gets refused until the user checks it out.
    """

    def __init__(self, path):
        self.path = path
        self.pins = {}
        if os.path.exists(path):
            with open(path) as f:
                self.pins = json.load(f)

    def check(self, username, public_key_pem):
        """returns "new" the first time (and pins it), "ok" if it matches, raises KeyChanged if not."""
        fp = fingerprint(public_key_pem)
        pinned = self.pins.get(username)
        if pinned is None:
            self.pins[username] = fp
            self._save()
            return "new"
        if pinned != fp:
            raise KeyChanged(
                f"{username}'s key changed!\n  pinned: {pinned}\n  now:    {fp}\n"
                "check with them in person before trusting the new key")
        return "ok"

    def accept_new_key(self, username, public_key_pem):
        """the user checked with the person and the new key is legit."""
        self.pins[username] = fingerprint(public_key_pem)
        self._save()

    def _save(self):
        with open(self.path, "w") as f:
            json.dump(self.pins, f, indent=2)
