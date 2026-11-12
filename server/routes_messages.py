"""the key directory, anonymous sending, and the recipient inbox."""
import json
import sqlite3

from flask import Blueprint, g, request

from common import blind_rsa
from common.envelope import ENVELOPE_FIELDS, b64d, token_id, verify_signature
from common.pubkey import fingerprint
from server import rounds
from server.context import db, error, log
from server.db import transaction
from server.rbac import public, require_permission

bp = Blueprint("messages", __name__)

MAX_CIPHERTEXT_B64 = 8000   # a 1000 character message is way under this


@bp.get("/directory")
@require_permission("directory:read")
def directory():
    # everyone who can receive messages, with their public keys. the client
    # pins these fingerprints so a swapped key gets noticed
    rows = db().execute(
        "SELECT u.id, u.username, u.public_key FROM users u "
        "JOIN user_roles r ON r.user_id = u.id "
        "WHERE u.status = 'active' AND r.role = 'recipient' ORDER BY u.username").fetchall()
    return {"recipients": [{"id": r["id"], "username": r["username"], "public_key": r["public_key"],
                            "fingerprint": fingerprint(r["public_key"])} for r in rows]}


def _shape_problem(envelope, token, signature):
    """basic sanity checks on the request body before doing any crypto."""
    if not isinstance(envelope, dict) or set(envelope) != set(ENVELOPE_FIELDS):
        return "envelope has the wrong fields"
    for field in ("epoch", "round", "recipient_id", "version"):
        if not isinstance(envelope[field], int) or isinstance(envelope[field], bool):
            return f"envelope.{field} must be a number"
    for field in ("nonce", "ciphertext", "wrapped_key", "commitment"):
        if not isinstance(envelope[field], str):
            return f"envelope.{field} must be a string"
    if envelope["version"] != 1:
        return "unsupported envelope version"
    if len(envelope["ciphertext"]) > MAX_CIPHERTEXT_B64:
        return "message too long"
    if not isinstance(token, dict) or not isinstance(token.get("epoch"), int) \
            or not isinstance(token.get("public_key"), str) or not isinstance(token.get("signature"), str):
        return "token has the wrong fields"
    if not isinstance(signature, str):
        return "signature must be a string"
    return None


@bp.post("/messages")
@public   # on purpose: the token is what authorizes this, not a login
def send_message():
    # a login here would tie the message to a person and undo the whole point
    # of the blind token, so refuse instead of silently ignoring it
    if "Authorization" in request.headers or request.cookies:
        return error(400, "don't attach a login to an anonymous message, it would identify you")

    data = request.get_json(silent=True) or {}
    envelope, token, signature = data.get("envelope"), data.get("token"), data.get("signature")
    problem = _shape_problem(envelope, token, signature)
    if problem:
        return error(400, problem)
    try:
        token_public = b64d(token["public_key"])
        token_signature = int(token["signature"], 16)
    except ValueError:
        return error(400, "token is badly encoded")
    if len(token_public) != 32:
        return error(400, "token public key must be 32 bytes")
    tid = token_id(token_public)

    with transaction(db()):
        current = rounds.current_round(db())
        if current is None:
            return error(409, "no round has been started yet")

        # 1. is this a real token, signed by the server for the current epoch?
        n, e = rounds.public_numbers(current)
        message = blind_rsa.token_message(token["epoch"], token_public)
        if token["epoch"] != current["epoch"] or not blind_rsa.verify(message, token_signature, n, e):
            log("invalid_token", role="anonymous", reason="token signature invalid or expired")
            return error(403, "invalid or expired token")

        # 2. was this exact envelope signed by that token's key?
        if not verify_signature(envelope, token_public, signature):
            log("invalid_token", role="anonymous", reason="message signature invalid")
            return error(403, "message signature doesn't match the token")

        # 3. is it for this round, and to someone who can actually receive?
        if envelope["round"] != current["id"] or envelope["epoch"] != token["epoch"]:
            return error(400, "envelope is for a different round")
        recipient = db().execute(
            "SELECT u.id FROM users u JOIN user_roles r ON r.user_id = u.id "
            "WHERE u.id = ? AND u.status = 'active' AND r.role = 'recipient'",
            (envelope["recipient_id"],)).fetchone()
        if recipient is None:
            return error(400, "no such recipient")

        # 4. has a moderator frozen this token?
        if db().execute("SELECT 1 FROM frozen_tokens WHERE token_id = ?", (tid,)).fetchone():
            log("frozen_token_used", role="anonymous", token=tid)
            return error(403, "this token has been frozen")

        # 5. one message per token per round. the primary key on spent_tokens
        # is what actually enforces this, so two requests racing each other
        # can't both get through
        try:
            db().execute("INSERT INTO spent_tokens (token_id, round_id) VALUES (?, ?)",
                         (tid, current["id"]))
        except sqlite3.IntegrityError:
            return error(409, "this token already sent its message this round")

        # no sender anything in here, just the recipient (needed to deliver it)
        # and the encrypted envelope
        db().execute(
            "INSERT INTO messages (recipient_id, round_id, token_id, envelope, token, signature) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (recipient["id"], current["id"], tid, json.dumps(envelope),
             json.dumps(token), signature))
        log("message_sent", role="sender", round=current["id"], token=tid)
    return {"ok": True}, 201


@bp.get("/inbox")
@require_permission("inbox:read")
def inbox():
    # only ever your own messages. the WHERE clause is the object-level check:
    # being a recipient doesn't let you read other recipients' mail
    rows = db().execute(
        "SELECT id, round_id, envelope, token, signature FROM messages "
        "WHERE recipient_id = ? AND withdrawn = 0 ORDER BY id", (g.user["id"],)).fetchall()
    if rows:
        log("message_delivered", role="recipient", count=len(rows))
    return {"messages": [{
        "id": r["id"],
        "round": r["round_id"],
        "envelope": json.loads(r["envelope"]),
        "token_public_key": json.loads(r["token"])["public_key"],
        "signature": r["signature"],
    } for r in rows]}
