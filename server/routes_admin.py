"""admin endpoints: approving people and managing their roles.

note what's NOT in here: nothing that returns messages, flagged content, or
anything about who sent what. admins only manage accounts and settings.
"""
from flask import Blueprint, g, request

from common.pubkey import fingerprint
from server import rounds
from server.context import db, error, log
from server.db import DEFAULT_POLICY, transaction
from server.rbac import check_role_change, require_permission

bp = Blueprint("admin", __name__, url_prefix="/admin")


def _roles_from_request():
    roles = (request.get_json(silent=True) or {}).get("roles")
    if not isinstance(roles, list) or not roles or not all(isinstance(r, str) for r in roles):
        return None
    return sorted(set(roles))


def _set_roles(user_id, roles):
    db().execute("DELETE FROM user_roles WHERE user_id = ?", (user_id,))
    for role in roles:
        db().execute("INSERT INTO user_roles (user_id, role) VALUES (?, ?)", (user_id, role))


def _refuse_role_change(user_id, roles, problem):
    # an admin trying to break separation of duties is exactly the kind of
    # thing the log is for, so the refusal gets logged with who tried it
    log("role_change_refused", role="admin", actor_id=g.user["id"],
        target=user_id, roles=roles, reason=problem)
    return error(400, problem)


@bp.get("/users")
@require_permission("user:approve")
def list_users():
    users = []
    for row in db().execute("SELECT * FROM users ORDER BY id"):
        roles = [r["role"] for r in db().execute(
            "SELECT role FROM user_roles WHERE user_id = ? ORDER BY role", (row["id"],))]
        users.append({
            "id": row["id"],
            "username": row["username"],
            "status": row["status"],
            "roles": roles,
            "key_fingerprint": fingerprint(row["public_key"]),
            "has_pending_key": row["pending_public_key"] is not None,
        })
    return {"users": users}


@bp.post("/users/<int:user_id>/approve")
@require_permission("user:approve")
def approve_user(user_id):
    roles = _roles_from_request()
    if roles is None:
        return error(400, "give the user at least one role")
    problem = check_role_change(g.user["id"], user_id, roles)
    if problem:
        return _refuse_role_change(user_id, roles, problem)

    with transaction(db()):
        user = db().execute("SELECT status FROM users WHERE id = ?", (user_id,)).fetchone()
        if user is None:
            return error(404, "no such user")
        if user["status"] != "pending":
            return error(409, f"user is already {user['status']}")
        db().execute("UPDATE users SET status = 'active' WHERE id = ?", (user_id,))
        _set_roles(user_id, roles)
        log("user_approved", role="admin", actor_id=g.user["id"], target=user_id, roles=roles)
    return {"id": user_id, "status": "active", "roles": roles}


@bp.post("/users/<int:user_id>/reject")
@require_permission("user:approve")
def reject_user(user_id):
    with transaction(db()):
        user = db().execute("SELECT status FROM users WHERE id = ?", (user_id,)).fetchone()
        if user is None:
            return error(404, "no such user")
        if user["status"] != "pending":
            return error(409, f"user is already {user['status']}")
        db().execute("UPDATE users SET status = 'rejected' WHERE id = ?", (user_id,))
        log("user_rejected", role="admin", actor_id=g.user["id"], target=user_id)
    return {"id": user_id, "status": "rejected"}


@bp.post("/users/<int:user_id>/roles")
@require_permission("role:assign")
def set_roles(user_id):
    roles = _roles_from_request()
    if roles is None:
        return error(400, "give the user at least one role")
    problem = check_role_change(g.user["id"], user_id, roles)
    if problem:
        return _refuse_role_change(user_id, roles, problem)

    with transaction(db()):
        user = db().execute("SELECT status FROM users WHERE id = ?", (user_id,)).fetchone()
        if user is None:
            return error(404, "no such user")
        if user["status"] != "active":
            return error(409, "can only change roles of active users")
        _set_roles(user_id, roles)
        log("role_assigned", role="admin", actor_id=g.user["id"], target=user_id, roles=roles)
    return {"id": user_id, "roles": roles}


@bp.post("/users/<int:user_id>/key/approve")
@require_permission("key:approve")
def approve_key(user_id):
    with transaction(db()):
        user = db().execute("SELECT pending_public_key FROM users WHERE id = ?", (user_id,)).fetchone()
        if user is None:
            return error(404, "no such user")
        if user["pending_public_key"] is None:
            return error(409, "no key change waiting for this user")
        db().execute("UPDATE users SET public_key = pending_public_key, pending_public_key = NULL "
                     "WHERE id = ?", (user_id,))
        # the fingerprint goes in the signed log, so a sneaky key swap by an
        # admin leaves a permanent record
        log("key_approved", role="admin", actor_id=g.user["id"], target=user_id,
            key_fingerprint=fingerprint(user["pending_public_key"]))
    return {"id": user_id, "key_fingerprint": fingerprint(user["pending_public_key"])}


@bp.post("/rounds")
@require_permission("round:manage")
def start_round():
    with transaction(db()):
        new = rounds.start_round(db())
        log("round_started", role="admin", actor_id=g.user["id"],
            round=new["id"], epoch=new["epoch"], new_key=new["epoch"] == new["id"])
    return {"round_id": new["id"], "epoch": new["epoch"]}


@bp.get("/policy")
@require_permission("policy:set")
def get_policy():
    return {row["name"]: int(row["value"]) for row in db().execute("SELECT * FROM policy")}


@bp.post("/policy")
@require_permission("policy:set")
def set_policy():
    data = request.get_json(silent=True) or {}
    name, value = data.get("name"), data.get("value")
    # only settings that already exist, and only whole numbers >= 1
    if name not in DEFAULT_POLICY:
        return error(400, f"unknown policy, options are: {', '.join(DEFAULT_POLICY)}")
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        return error(400, "value must be a whole number, at least 1")
    with transaction(db()):
        db().execute("UPDATE policy SET value = ? WHERE name = ?", (str(value), name))
        log("policy_changed", role="admin", actor_id=g.user["id"], name=name, value=value)
    return {name: value}
