"""chaum-style blind rsa signatures, used for the anonymous tokens.

the idea in one line: the sender hides their token behind a random number r,
the server signs the hidden version, and the sender strips r back off and is
left with a normal signature on a token the server never actually saw.

    sender:  blinded = m * r^e mod n        (r is random, kept secret)
    server:  s'      = blinded^d mod n      (= m^d * r mod n)
    sender:  s       = s' * r^-1 mod n      (= m^d mod n, a normal rsa signature on m)
    anyone:  check s^e mod n == m

the cryptography library doesn't have blind signatures, so this is the one
bit of crypto written by hand. it's just modular arithmetic with python's
built-in pow(). everything else (key generation, randomness, hashing) still
comes from the standard libraries.
"""
import hashlib
import math
import secrets

TOKEN_PREFIX = b"whisperchain-token-v1|"


def token_message(round_id, token_public_bytes):
    """what actually gets signed: the round number + the token's ed25519 public key.

    putting the round in here means a token signed in round 3 can't be passed
    off as a round 4 token.
    """
    return TOKEN_PREFIX + str(round_id).encode() + b"|" + token_public_bytes


def fdh(message, n):
    """full-domain hash: turn a message into a number spread over all of 0..n-1.

    plain sha-256 is only 256 bits but n is 3072 bits, so we chain sha-256
    with a counter until we have enough bytes (plus a little extra so the
    final "mod n" doesn't favor small numbers).

    why bother: raw rsa is multiplicative, sig(a) * sig(b) = sig(a*b). if we
    signed small or structured numbers someone could combine signatures they
    already have into new ones. hashing over the whole range makes that useless.
    """
    size = (n.bit_length() + 7) // 8 + 16
    out = b""
    counter = 0
    while len(out) < size:
        out += hashlib.sha256(counter.to_bytes(4, "big") + message).digest()
        counter += 1
    return int.from_bytes(out[:size], "big") % n


def blind(message, n, e):
    """sender side. returns (blinded, r). keep r secret, you need it to unblind."""
    m = fdh(message, n)
    while True:
        r = secrets.randbelow(n - 2) + 2
        # r has to have an inverse mod n or we couldn't unblind later.
        # for a real rsa modulus this basically always passes first try
        if math.gcd(r, n) == 1:
            break
    return (m * pow(r, e, n)) % n, r


def sign_blinded(blinded, n, d):
    """server side. signs whatever number it's given, without seeing what's under it.

    because of that, the key used here must only ever be used for this.
    """
    if not 1 < blinded < n:
        raise ValueError("blinded value out of range")
    return pow(blinded, d, n)


def unblind(blind_signature, r, n):
    """sender side. strip the r back off: (m^d * r) * r^-1 = m^d."""
    return (blind_signature * pow(r, -1, n)) % n


def verify(message, signature, n, e):
    """anyone with the public key. true if signature is a valid signature on message."""
    if not 0 < signature < n:
        return False
    return pow(signature, e, n) == fdh(message, n)
