"""encrypting a compliment for someone, and decrypting your own messages.

this is "hybrid" encryption, which is how basically everything (tls, pgp,
signal) does it:
  - the message itself is encrypted with a random one-time aes key. aes is
    fast and has no size limit
  - that aes key is then encrypted with the recipient's rsa public key. rsa
    can only encrypt small things, but an aes key is only 32 bytes
only the recipient's private key can unwrap the aes key, so only they can read it.
"""
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from common.envelope import (MAX_MESSAGE_CHARS, b64d, b64e, canonical, commitment,
                             open_with_key)
from common.pubkey import load_rsa_public_key

# oaep is the safe way to use rsa for encryption. it adds randomness, so
# encrypting the same thing twice gives different results, and it blocks the
# classic attacks on "textbook" rsa
OAEP = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(), label=None)


def encrypt_message(plaintext, recipient_public_pem, recipient_id, round_id, epoch):
    if not plaintext.strip():
        raise ValueError("message is empty")
    if len(plaintext) > MAX_MESSAGE_CHARS:
        raise ValueError(f"message is over {MAX_MESSAGE_CHARS} characters")

    message_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)   # gcm needs a unique nonce per key, and every key here is new anyway
    ciphertext = AESGCM(message_key).encrypt(nonce, plaintext.encode(), None)
    wrapped_key = load_rsa_public_key(recipient_public_pem).encrypt(message_key, OAEP)

    return {
        "version": 1,
        "epoch": epoch,
        "round": round_id,
        "recipient_id": recipient_id,
        "nonce": b64e(nonce),
        "ciphertext": b64e(ciphertext),
        "wrapped_key": b64e(wrapped_key),
        # a hash of the aes key, locked in by the signature. if the recipient
        # flags this later, they have to hand over a key that matches it
        "commitment": commitment(message_key),
    }


def sign_envelope(token_private_key, envelope):
    """sign with the token's ed25519 key. ties this exact message to this token."""
    return b64e(token_private_key.sign(canonical(envelope)))


def decrypt_message(private_key, envelope):
    """returns (plaintext, message_key). keep the key around in case you want to flag it."""
    try:
        message_key = private_key.decrypt(b64d(envelope["wrapped_key"]), OAEP)
    except ValueError:
        raise ValueError("couldn't unwrap the message key (not encrypted for you?)")
    return open_with_key(envelope, message_key), message_key
