"""register, log in, log out, and "who am i"."""
import re
import sqlite3

from flask import Blueprint, g, request

from common.pubkey import fingerprint, load_rsa_public_key
from server import alerts, auth
from server.context import db, error, log
from server.db import transaction
from server.rbac import permissions_for, public, require_login

bp = Blueprint("auth", __name__)

USERNAME_RE = re.compile(r"^[a-z0-9_]{3,32}$")
MIN_PASSWORD_LENGTH = 10


@bp.post("/register")
@public
def register():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip().lower()
    password = str(data.get("password", ""))
    public_key = str(data.get("public_key", ""))

    if not USERNAME_RE.match(username):
        return error(400, "username must be 3-32 characters: lowercase letters, digits, underscore")
    if len(password) < MIN_PASSWORD_LENGTH:
        return error(400, f"password must be at least {MIN_PASSWORD_LENGTH} characters")
    try:
        load_rsa_public_key(public_key)
    except ValueError as e:
        return error(400, str(e))

    # new accounts start out 'pending' with no roles. an admin has to approve
    # them and decide what roles they get
    try:
        with transaction(db()):
            cur = db().execute(
                "INSERT INTO users (username, password_hash, public_key) VALUES (?, ?, ?)",
                (username, auth.hash_password(password), public_key))
            log("user_registered", target=username, key_fingerprint=fingerprint(public_key))
    except sqlite3.IntegrityError:
        return error(409, "username already taken")
    return {"id": cur.lastrowid, "status": "pending"}, 201


@bp.post("/login")
@public
def login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip().lower()
    password = str(data.get("password", ""))
    try:
        user = auth.check_login(db(), username, password)
    except auth.LoginFailed as e:
        if e.locked:
            log("account_locked", target=username)
            alerts.raise_alert("account_locked", target=username)
        return error(401, str(e))
    token = auth.create_session(db(), user["id"])
    return {"session": token, "user": auth.user_for_session(db(), token)}


@bp.post("/logout")
@require_login
def logout():
    auth.end_session(db(), request.headers["Authorization"][len("Bearer "):])
    return {"ok": True}


@bp.get("/me")
@require_login
def me():
    # the client uses this to decide which pages/commands to show. that's just
    # for convenience, the server still checks every request on its own
    return {**g.user, "permissions": sorted(permissions_for(g.user["roles"]))}


@bp.post("/me/key")
@require_login
def request_key_change():
    # a new key doesn't take effect until an admin approves it. that way a
    # stolen session alone can't quietly swap your key for the attacker's
    public_key = str((request.get_json(silent=True) or {}).get("public_key", ""))
    try:
        load_rsa_public_key(public_key)
    except ValueError as e:
        return error(400, str(e))
    with transaction(db()):
        db().execute("UPDATE users SET pending_public_key = ? WHERE id = ?",
                     (public_key, g.user["id"]))
        log("key_change_requested", target=g.user["id"], key_fingerprint=fingerprint(public_key))
    return {"status": "pending admin approval", "fingerprint": fingerprint(public_key)}
