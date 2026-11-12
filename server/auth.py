"""passwords, login lockout, and sessions.

nothing in here knows about flask. it just takes a db connection, which makes
it easy to test and easy to read on its own.
"""
import base64
import hashlib
import hmac
import secrets
import time

SESSION_LIFETIME = 8 * 60 * 60      # 8 hours
MAX_FAILED_LOGINS = 5
LOCKOUT_SECONDS = 5 * 60

# scrypt is deliberately slow and memory hungry, so if the db gets stolen,
# guessing passwords offline is expensive. n=2^14, r=8, p=1 is the usual
# interactive-login setting
_SCRYPT = dict(n=2 ** 14, r=8, p=1, dklen=32)


def _b64(b):
    return base64.b64encode(b).decode()


def hash_password(password):
    # a random salt per user means two people with the same password still get
    # different hashes, and precomputed tables are useless
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, **_SCRYPT)
    return f"scrypt${_b64(salt)}${_b64(digest)}"


def check_password(password, stored):
    _, salt, digest = stored.split("$")
    attempt = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt), **_SCRYPT)
    # compare_digest takes the same time no matter where the bytes differ,
    # so response timing doesn't leak how close a guess was
    return hmac.compare_digest(attempt, base64.b64decode(digest))


# used when the username doesn't exist, so "wrong username" takes as long as
# "wrong password" and you can't use timing to find out who has an account
_DUMMY_HASH = hash_password("not-a-real-password")


class LoginFailed(Exception):
    def __init__(self, message, locked=False):
        super().__init__(message)
        self.locked = locked   # true if this attempt is the one that locked the account


def check_login(conn, username, password):
    """returns the user row if the login is good, otherwise raises LoginFailed.

    the same vague message is used for a wrong username and a wrong password
    so the error doesn't tell an attacker which one they got right.
    """
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if user is None:
        check_password(password, _DUMMY_HASH)
        raise LoginFailed("invalid username or password")

    now = time.time()
    if user["locked_until"] > now:
        raise LoginFailed("too many failed logins, try again in a few minutes")

    if not check_password(password, user["password_hash"]):
        # "+ 1" happens inside the db so two wrong guesses at the same time
        # both get counted
        conn.execute("UPDATE users SET failed_logins = failed_logins + 1 WHERE id = ?", (user["id"],))
        failed = conn.execute("SELECT failed_logins FROM users WHERE id = ?",
                              (user["id"],)).fetchone()[0]
        if failed >= MAX_FAILED_LOGINS:
            conn.execute("UPDATE users SET failed_logins = 0, locked_until = ? WHERE id = ?",
                         (now + LOCKOUT_SECONDS, user["id"]))
            raise LoginFailed("too many failed logins, try again in a few minutes", locked=True)
        raise LoginFailed("invalid username or password")

    conn.execute("UPDATE users SET failed_logins = 0 WHERE id = ?", (user["id"],))

    # only check this after the password, so you can't probe whether some
    # username is pending without knowing its password
    if user["status"] != "active":
        raise LoginFailed(f"account is {user['status']}")
    return user


def _hash_token(raw):
    return hashlib.sha256(raw.encode()).hexdigest()


def create_session(conn, user_id):
    # the client gets the raw token, the db only gets its hash. same idea as
    # passwords: a stolen db doesn't give you anything you can log in with
    raw = secrets.token_urlsafe(32)
    conn.execute("INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
                 (_hash_token(raw), user_id, time.time() + SESSION_LIFETIME))
    return raw


def user_for_session(conn, raw):
    """look up who a session token belongs to. returns None if it's invalid,
    expired, or the account isn't active anymore.

    roles are read fresh from the db on every request instead of being stored
    in the session, so if an admin takes a role away it's gone immediately.
    """
    row = conn.execute(
        "SELECT u.id, u.username, u.status FROM sessions s JOIN users u ON u.id = s.user_id "
        "WHERE s.token_hash = ? AND s.expires_at > ?",
        (_hash_token(raw), time.time())).fetchone()
    if row is None or row["status"] != "active":
        return None
    roles = [r["role"] for r in conn.execute(
        "SELECT role FROM user_roles WHERE user_id = ? ORDER BY role", (row["id"],))]
    return {"id": row["id"], "username": row["username"], "roles": roles}


def end_session(conn, raw):
    conn.execute("DELETE FROM sessions WHERE token_hash = ?", (_hash_token(raw),))
