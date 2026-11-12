"""the moderator dashboard: flag queue, freezing tokens, alerts, audit log.

moderators see what recipients chose to reveal, and nothing else. the flag
queue has the plaintext, the reason, the round and the token id, but never
who received the message, and nobody anywhere knows who sent it.
"""
import re
import sqlite3
from datetime import datetime, timezone

from flask import Blueprint, current_app, g, request

from server import audit
from server.context import db, error, log
from server.db import transaction
from server.rbac import require_permission

bp = Blueprint("moderation", __name__)

FLAG_STATUSES = ("open", "dismissed", "frozen")
TOKEN_ID_RE = re.compile(r"^[0-9a-f]{64}$")   # sha-256 hex
MAX_REASON = 500


def _reason():
    reason = str((request.get_json(silent=True) or {}).get("reason", "")).strip()
    return reason if 1 <= len(reason) <= MAX_REASON else None


@bp.get("/moderation/flags")
@require_permission("moderation:read")
def flag_queue():
    status = request.args.get("status", "open")
    if status not in FLAG_STATUSES:
        return error(400, f"status must be one of {', '.join(FLAG_STATUSES)}")
    rows = db().execute(
        "SELECT f.id, f.round_id, f.token_id, f.plaintext, f.reason, f.status, "
        "EXISTS (SELECT 1 FROM frozen_tokens t WHERE t.token_id = f.token_id) AS frozen "
        "FROM flags f WHERE f.status = ? ORDER BY f.id", (status,)).fetchall()
    # no recipient and no message id in here on purpose
    return {"flags": [{"id": r["id"], "round": r["round_id"], "token_id": r["token_id"],
                       "plaintext": r["plaintext"], "reason": r["reason"],
                       "status": r["status"], "frozen": bool(r["frozen"])} for r in rows]}


@bp.post("/moderation/flags/<int:flag_id>/dismiss")
@require_permission("flag:resolve")
def dismiss_flag(flag_id):
    # "i looked at it and it's fine"
    with transaction(db()):
        flag = db().execute("SELECT status, token_id FROM flags WHERE id = ?", (flag_id,)).fetchone()
        if flag is None:
            return error(404, "no such flag")
        if flag["status"] != "open":
            return error(409, f"flag is already {flag['status']}")
        db().execute("UPDATE flags SET status = 'dismissed' WHERE id = ?", (flag_id,))
        log("flag_dismissed", role="moderator", actor_id=g.user["id"],
            flag=flag_id, token=flag["token_id"])
    return {"id": flag_id, "status": "dismissed"}


@bp.post("/moderation/tokens/<token_id>/freeze")
@require_permission("token:freeze")
def freeze_token(token_id):
    reason = _reason()
    if reason is None:
        return error(400, f"give a reason (1-{MAX_REASON} characters)")
    if not TOKEN_ID_RE.match(token_id):
        return error(400, "token id must be 64 hex characters")

    # all of this happens together or not at all: block the token, pull its
    # message(s) out of the inbox, and mark its open flags as handled
    with transaction(db()):
        if not db().execute("SELECT 1 FROM messages WHERE token_id = ?", (token_id,)).fetchone():
            return error(404, "no message was sent with that token")
        try:
            db().execute("INSERT INTO frozen_tokens (token_id, frozen_at, reason) VALUES (?, ?, ?)",
                         (token_id, datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), reason))
        except sqlite3.IntegrityError:
            return error(409, "token is already frozen")
        withdrawn = db().execute("UPDATE messages SET withdrawn = 1 WHERE token_id = ?",
                                 (token_id,)).rowcount
        db().execute("UPDATE flags SET status = 'frozen' WHERE token_id = ? AND status = 'open'",
                     (token_id,))
        log("token_frozen", role="moderator", actor_id=g.user["id"],
            token=token_id, reason=reason, withdrawn=withdrawn)
    return {"token_id": token_id, "frozen": True, "withdrawn": withdrawn}


@bp.post("/moderation/tokens/<token_id>/unfreeze")
@require_permission("token:freeze")
def unfreeze_token(token_id):
    # the exact opposite of freeze, for when a freeze was a mistake: unblock
    # the token, put its message(s) back, and reopen its flags
    reason = _reason()
    if reason is None:
        return error(400, f"give a reason (1-{MAX_REASON} characters)")
    with transaction(db()):
        if db().execute("DELETE FROM frozen_tokens WHERE token_id = ?", (token_id,)).rowcount == 0:
            return error(404, "that token isn't frozen")
        restored = db().execute("UPDATE messages SET withdrawn = 0 WHERE token_id = ?",
                                (token_id,)).rowcount
        db().execute("UPDATE flags SET status = 'open' WHERE token_id = ? AND status = 'frozen'",
                     (token_id,))
        log("token_unfrozen", role="moderator", actor_id=g.user["id"],
            token=token_id, reason=reason, restored=restored)
    return {"token_id": token_id, "frozen": False, "restored": restored}


@bp.get("/alerts")
@require_permission("alerts:read")
def list_alerts():
    rows = db().execute("SELECT * FROM alerts ORDER BY id DESC").fetchall()
    return {"alerts": [{"id": r["id"], "time": r["created_at"], "rule": r["rule"],
                        "detail": r["detail"]} for r in rows]}


@bp.get("/audit")
@require_permission("audit:read")
def read_audit():
    try:
        limit = min(int(request.args.get("limit", 100)), 1000)
    except ValueError:
        return error(400, "limit must be a number")
    rows = db().execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return {"head": audit.get_head(db()),
            "entries": [{k: r[k] for k in ("id", "ts", "action", "role", "actor_id",
                                           "details", "entry_hash")} for r in rows]}


@bp.get("/audit/verify")
@require_permission("audit:read")
def verify_audit():
    # pass ?head=<a hash you saved earlier> to also check nothing got cut
    # off or rewritten since then. this is a convenience: a server that's
    # lying could lie here too. the real check is running verify-log yourself
    # on a copy of the db, with the head hash you saved
    ok, message = audit.verify(db(), current_app.config["AUDIT_KEY"].public_key(),
                               expected_head=request.args.get("head"))
    return {"ok": ok, "message": message, "head": audit.get_head(db())}
