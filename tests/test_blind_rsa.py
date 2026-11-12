"""the blind signature math on its own, no server involved."""
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from common import blind_rsa


@pytest.fixture(scope="module")
def key():
    k = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    nums = k.private_numbers()
    return nums.public_numbers.n, nums.public_numbers.e, nums.d


def test_toy_example_from_the_explanation():
    # tiny textbook numbers so it can be checked by hand: p=61, q=53
    n, e, d = 3233, 17, 2753
    m, r = 42, 7
    blinded = (m * pow(r, e, n)) % n
    assert blinded == 2508
    signed = pow(blinded, d, n)
    assert signed == 2057
    s = (signed * pow(r, -1, n)) % n
    assert s == 3065 == pow(m, d, n)   # same as if the server had signed 42 directly
    assert pow(s, e, n) == m           # and it verifies


def test_full_round_trip(key):
    n, e, d = key
    msg = blind_rsa.token_message(1, b"some token public key bytes")
    blinded, r = blind_rsa.blind(msg, n, e)
    sig = blind_rsa.unblind(blind_rsa.sign_blinded(blinded, n, d), r, n)
    assert blind_rsa.verify(msg, sig, n, e)


def test_signature_doesnt_work_for_other_messages(key):
    n, e, d = key
    msg = blind_rsa.token_message(1, b"token a")
    blinded, r = blind_rsa.blind(msg, n, e)
    sig = blind_rsa.unblind(blind_rsa.sign_blinded(blinded, n, d), r, n)
    assert not blind_rsa.verify(blind_rsa.token_message(1, b"token b"), sig, n, e)
    assert not blind_rsa.verify(blind_rsa.token_message(2, b"token a"), sig, n, e)  # other round
    assert not blind_rsa.verify(msg, sig + 1, n, e)
    assert not blind_rsa.verify(msg, 0, n, e)


def test_same_token_blinds_differently_every_time(key):
    n, e, _ = key
    msg = blind_rsa.token_message(1, b"token")
    assert blind_rsa.blind(msg, n, e)[0] != blind_rsa.blind(msg, n, e)[0]


def test_server_cant_tell_which_request_a_token_came_from(key):
    """this is the unlinkability argument as a test.

    two senders get tokens. later one token gets spent. even the server, with
    its private key d, can find a blinding factor that would connect that
    token to EITHER request. both stories fit the data perfectly, so the data
    says nothing about which one is true.
    """
    n, e, d = key
    msg_a = blind_rsa.token_message(1, b"alice's token")
    msg_b = blind_rsa.token_message(1, b"bob's token")
    blinded_a, _ = blind_rsa.blind(msg_a, n, e)
    blinded_b, _ = blind_rsa.blind(msg_b, n, e)

    spent = msg_a   # alice spends hers, server tries to work out whose it is
    m = blind_rsa.fdh(spent, n)
    for blinded_seen in (blinded_a, blinded_b):
        # r = (blinded / m)^d is a valid blinding factor linking this token to this request
        r = pow((blinded_seen * pow(m, -1, n)) % n, d, n)
        assert (m * pow(r, e, n)) % n == blinded_seen


def test_server_refuses_out_of_range_values(key):
    n, _, d = key
    for bad in (0, 1, n, n + 5):
        with pytest.raises(ValueError):
            blind_rsa.sign_blinded(bad, n, d)


def test_fdh_uses_the_full_range(key):
    n, _, _ = key
    # a plain sha-256 would always be under 2^256. fdh outputs should be way bigger
    assert all(blind_rsa.fdh(bytes([i]), n).bit_length() > 3000 for i in range(20))
