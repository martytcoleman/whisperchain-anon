"""role-based access control policy.

ROLE_PERMISSIONS is the one place that says who can do what. it's basically
the role-permission matrix from docs/rbac_and_threat_model.md written in python.

sending a message isn't in here on purpose. if the server checked "is this
user a sender?" when a message comes in, it would know who sent it. so
sending is authorized by the anonymous token instead (a capability), and
rbac just controls who's allowed to get a token in the first place. only
senders have "token:request".
"""

from functools import wraps

from flask import g, request

from server import auth
from server.context import db, error, log

ROLES = ("sender", "recipient", "moderator", "admin")

ROLE_PERMISSIONS = {
    "sender": {
        "directory:read",
        "token:request",
    },
    "recipient": {
        "directory:read",
        "inbox:read",
        "flag:create",
    },
    "moderator": {
        "directory:read",
        "moderation:read",
        "flag:resolve",
        "token:freeze",
        "audit:read",
        "alerts:read",
    },
    "admin": {
        "directory:read",
        "user:approve",
        "role:assign",
        "key:approve",
        "round:manage",
        "policy:set",
        "audit:read",
        "alerts:read",
    },
}

# separation of duties: nobody gets both of these.
# admins control accounts and keys, moderators see flagged content and can
# punish tokens. if one person had both they could make fake accounts, flag
# someone's messages with them, then freeze the token themselves without
# anyone else being involved
MUTUALLY_EXCLUSIVE = [{"admin", "moderator"}]


def permissions_for(roles):
    perms = set()
    for role in roles:
        perms |= ROLE_PERMISSIONS.get(role, set())
    return perms


def has_permission(roles, permission):
    # unknown roles get nothing and unknown permissions are never granted,
    # so anything not listed above is denied by default
    return permission in permissions_for(roles)


def check_role_change(actor_id, target_id, new_roles):
    """returns an error message if the role change isn't allowed, otherwise None."""
    if actor_id == target_id:
        return "you cannot change your own roles"
    unknown = set(new_roles) - set(ROLES)
    if unknown:
        return f"unknown role(s): {', '.join(sorted(unknown))}"
    for group in MUTUALLY_EXCLUSIVE:
        if group <= set(new_roles):
            return "separation of duties: " + " and ".join(sorted(group)) + " cannot be combined"
    return None


# ---- the decorators that go on every endpoint ----
#
# every flask route has to have exactly one of these:
#   @public                    anyone, no login (register, login, sending a message)
#   @require_login             any logged-in active user
#   @require_permission("x")   logged in AND one of your roles grants x
#
# app.py refuses to serve any route that doesn't have one, so forgetting to
# add a check means the route is blocked instead of wide open.

def public(view):
    view.access_rule = "public"
    return view


def _session_user():
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return None
    return auth.user_for_session(db(), header[len("Bearer "):])


def require_login(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        user = _session_user()
        if user is None:
            return error(401, "login required")
        g.user = user
        return view(*args, **kwargs)
    wrapper.access_rule = "login"
    return wrapper


ALL_PERMISSIONS = set().union(*ROLE_PERMISSIONS.values())


def require_permission(permission):
    # catch typos like "inbox:raed" when the server starts, not in production
    if permission not in ALL_PERMISSIONS:
        raise ValueError(f"unknown permission: {permission}")

    # wrapper replaces the real route function, so these checks run first on
    # every request and the route only runs if they pass
    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            # roles come fresh from the db each request (auth.user_for_session),
            # so a role change takes effect right away
            user = _session_user()
            if user is None:
                return error(401, "login required")   # 401 = don't know who you are
            if not has_permission(user["roles"], permission):   # 403 = know you, not allowed
                # log the role, not the person. it's still useful for spotting
                # someone poking at endpoints they shouldn't
                log("access_denied", role=",".join(user["roles"]) or "none",
                    permission=permission)
                return error(403, f"requires {permission}")
            g.user = user
            return view(*args, **kwargs)
        wrapper.access_rule = permission
        return wrapper
    return decorator
