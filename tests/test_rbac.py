"""the role-permission matrix from docs/rbac_and_threat_model.md, typed out by
hand and checked against the code. if someone changes ROLE_PERMISSIONS without
updating the matrix doc (or the other way around) this fails."""
import pytest

from server.rbac import ROLES, check_role_change, has_permission

# permission -> roles allowed to do it (copied from the matrix in the doc)
EXPECTED = {
    "user:approve":    {"admin"},
    "role:assign":     {"admin"},
    "key:approve":     {"admin"},
    "directory:read":  {"sender", "recipient", "moderator", "admin"},
    "round:manage":    {"admin"},
    "policy:set":      {"admin"},
    "token:request":   {"sender"},
    "inbox:read":      {"recipient"},
    "flag:create":     {"recipient"},
    "moderation:read": {"moderator"},
    "flag:resolve":    {"moderator"},
    "token:freeze":    {"moderator"},
    "audit:read":      {"moderator", "admin"},
    "alerts:read":     {"moderator", "admin"},
}


@pytest.mark.parametrize("permission", EXPECTED)
@pytest.mark.parametrize("role", ROLES)
def test_matrix(role, permission):
    assert has_permission([role], permission) == (role in EXPECTED[permission])


def test_unknown_permission_is_denied():
    assert not has_permission(list(ROLES), "messages:read_all")


def test_unknown_role_grants_nothing():
    assert not has_permission(["superuser"], "user:approve")


def test_no_role_can_read_messages_or_sender_identity():
    # there's no permission for this at all, on purpose
    for role in ROLES:
        assert not has_permission([role], "message:read")
        assert not has_permission([role], "sender:identify")


def test_admin_and_moderator_cannot_be_combined():
    assert "separation of duties" in check_role_change(1, 2, ["admin", "moderator"])


def test_cannot_change_own_roles():
    assert check_role_change(1, 1, ["recipient"]) is not None


def test_normal_assignment_is_allowed():
    assert check_role_change(1, 2, ["sender", "recipient"]) is None
