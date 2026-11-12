"""role-based access control policy.

ROLE_PERMISSIONS is the one place that says who can do what. it's basically
the role-permission matrix from docs/design.md (section 3) written in python.

sending a message isn't in here on purpose. if the server checked "is this
user a sender?" when a message comes in, it would know who sent it. so
sending is authorized by the anonymous token instead (a capability), and
rbac just controls who's allowed to get a token in the first place. only
senders have "token:request".
"""

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
