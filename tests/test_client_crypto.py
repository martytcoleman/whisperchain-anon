"""client-side encryption, signing, key storage and pinning."""
import copy
import os

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from client import crypto, keys
from common import envelope as env


@pytest.fixture(scope="module")
def bob_key():
    return keys.generate_user_key()


@pytest.fixture(scope="module")
def eve_key():
    return keys.generate_user_key()


@pytest.fixture
def sealed(bob_key):
    return crypto.encrypt_message("you explained recursion really well today",
                                  keys.public_pem(bob_key), recipient_id=2, round_id=1, epoch=1)


def test_round_trip(bob_key, sealed):
    text, k = crypto.decrypt_message(bob_key, sealed)
    assert text == "you explained recursion really well today"
    assert env.commitment(k) == sealed["commitment"]


def test_nothing_readable_in_the_envelope(sealed):
    assert b"recursion" not in str(sealed).encode()


def test_same_message_encrypts_differently_each_time(bob_key):
    pem = keys.public_pem(bob_key)
    a = crypto.encrypt_message("hi", pem, 2, 1, 1)
    b = crypto.encrypt_message("hi", pem, 2, 1, 1)
    assert a["ciphertext"] != b["ciphertext"] and a["wrapped_key"] != b["wrapped_key"]


def test_someone_else_cant_decrypt(eve_key, sealed):
    with pytest.raises(ValueError):
        crypto.decrypt_message(eve_key, sealed)


def test_flipped_byte_in_ciphertext_is_caught(bob_key, sealed):
    raw = bytearray(env.b64d(sealed["ciphertext"]))
    raw[0] ^= 1
    tampered = {**sealed, "ciphertext": env.b64e(bytes(raw))}
    with pytest.raises(ValueError, match="tampered"):
        crypto.decrypt_message(bob_key, tampered)


def test_signature_covers_every_field(sealed):
    token_key = Ed25519PrivateKey.generate()
    pub = token_key.public_key().public_bytes_raw()
    sig = crypto.sign_envelope(token_key, sealed)
    assert env.verify_signature(sealed, pub, sig)
    for field in env.ENVELOPE_FIELDS:
        changed = copy.deepcopy(sealed)
        changed[field] = 999 if isinstance(changed[field], int) else changed[field] + "x"
        assert not env.verify_signature(changed, pub, sig), field


def test_signature_from_another_token_rejected(sealed):
    sig = crypto.sign_envelope(Ed25519PrivateKey.generate(), sealed)
    other = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    assert not env.verify_signature(sealed, other, sig)


def test_fake_flag_with_wrong_key_is_caught(sealed):
    # a recipient trying to frame a token by "revealing" some other key
    with pytest.raises(ValueError, match="commitment"):
        env.open_with_key(sealed, AESGCM.generate_key(bit_length=256))


def test_fake_flag_with_made_up_ciphertext_is_caught(bob_key, sealed):
    # recipient keeps the real key but swaps in their own nasty ciphertext.
    # the commitment matches but the signature over the envelope won't, and
    # the real ciphertext stays what the sender sent
    _, k = crypto.decrypt_message(bob_key, sealed)
    nonce = os.urandom(12)
    forged = {**sealed, "nonce": env.b64e(nonce),
              "ciphertext": env.b64e(AESGCM(k).encrypt(nonce, b"something awful", None))}
    token_key = Ed25519PrivateKey.generate()
    sig = crypto.sign_envelope(token_key, sealed)
    assert not env.verify_signature(forged, token_key.public_key().public_bytes_raw(), sig)


def test_message_limits(bob_key):
    pem = keys.public_pem(bob_key)
    with pytest.raises(ValueError):
        crypto.encrypt_message("   ", pem, 2, 1, 1)
    with pytest.raises(ValueError):
        crypto.encrypt_message("x" * (env.MAX_MESSAGE_CHARS + 1), pem, 2, 1, 1)


def test_private_key_file_is_encrypted(tmp_path, bob_key):
    path = tmp_path / "key.pem"
    keys.save_private_key(bob_key, str(path), "my password 123")
    data = path.read_bytes()
    assert b"ENCRYPTED PRIVATE KEY" in data
    assert oct(path.stat().st_mode)[-3:] == "600"
    loaded = keys.load_private_key(str(path), "my password 123")
    assert keys.public_pem(loaded) == keys.public_pem(bob_key)
    with pytest.raises(ValueError):
        keys.load_private_key(str(path), "wrong password")


def test_key_pinning(tmp_path, bob_key, eve_key):
    pins = keys.KeyPins(str(tmp_path / "pins.json"))
    assert pins.check("bob", keys.public_pem(bob_key)) == "new"
    assert pins.check("bob", keys.public_pem(bob_key)) == "ok"
    # server swaps bob's key for eve's
    with pytest.raises(keys.KeyChanged):
        pins.check("bob", keys.public_pem(eve_key))
    # pins survive restarting the client
    again = keys.KeyPins(str(tmp_path / "pins.json"))
    with pytest.raises(keys.KeyChanged):
        again.check("bob", keys.public_pem(eve_key))
