"""admin endpoints, and making sure nobody else can use them."""
from tests.conftest import auth_header


def test_admin_approves_with_roles(client, users):
    admin = users.admin()
    alice = users.register("alice")
    r = client.post(f"/admin/users/{alice}/approve", json={"roles": ["sender", "recipient"]},
                    headers=auth_header(admin))
    assert r.status_code == 200 and r.json["roles"] == ["recipient", "sender"]


def test_approve_needs_a_role(client, users):
    admin = users.admin()
    alice = users.register("alice")
    r = client.post(f"/admin/users/{alice}/approve", json={"roles": []},
                    headers=auth_header(admin))
    assert r.status_code == 400


def test_reject(client, users):
    admin = users.admin()
    alice = users.register("alice")
    assert client.post(f"/admin/users/{alice}/reject", headers=auth_header(admin)).status_code == 200
    r = client.post("/login", json={"username": "alice", "password": "correct horse battery"})
    assert r.status_code == 401 and "rejected" in r.json["error"]


def test_separation_of_duties_on_approve_and_role_change(client, users):
    admin = users.admin()
    alice = users.register("alice")
    r = client.post(f"/admin/users/{alice}/approve", json={"roles": ["admin", "moderator"]},
                    headers=auth_header(admin))
    assert r.status_code == 400 and "separation of duties" in r.json["error"]

    bob, _ = users.make("bob", ["moderator"])
    r = client.post(f"/admin/users/{bob}/roles", json={"roles": ["moderator", "admin"]},
                    headers=auth_header(admin))
    assert r.status_code == 400


def test_admin_cant_change_own_roles(client, users, db):
    admin = users.admin()
    admin_id = db.execute("SELECT id FROM users WHERE username = 'admin'").fetchone()["id"]
    r = client.post(f"/admin/users/{admin_id}/roles", json={"roles": ["admin", "sender"]},
                    headers=auth_header(admin))
    assert r.status_code == 400


def test_unknown_role_rejected(client, users):
    admin = users.admin()
    alice = users.register("alice")
    r = client.post(f"/admin/users/{alice}/approve", json={"roles": ["superuser"]},
                    headers=auth_header(admin))
    assert r.status_code == 400


def test_non_admins_get_403_and_its_logged(client, users, db):
    users.register("target")
    for role in ("sender", "recipient", "moderator"):
        _, session = users.make(f"user_{role}", [role])
        for method, path in [("get", "/admin/users"),
                             ("post", "/admin/users/1/approve"),
                             ("post", "/admin/users/1/reject"),
                             ("post", "/admin/users/1/roles")]:
            r = getattr(client, method)(path, json={"roles": ["admin"]}, headers=auth_header(session))
            assert r.status_code == 403, (role, path)
    denied = db.execute("SELECT COUNT(*) FROM audit_log WHERE action = 'access_denied'").fetchone()[0]
    assert denied == 12


def test_no_login_gets_401(client):
    assert client.get("/admin/users").status_code == 401


def test_role_removal_takes_effect_immediately(client, users):
    admin = users.admin()
    alice, session = users.make("alice", ["sender", "recipient"])
    assert "token:request" in client.get("/me", headers=auth_header(session)).json["permissions"]
    client.post(f"/admin/users/{alice}/roles", json={"roles": ["recipient"]},
                headers=auth_header(admin))
    # same session, but the sender role is already gone
    assert "token:request" not in client.get("/me", headers=auth_header(session)).json["permissions"]


def test_admin_actions_are_logged_with_the_admin(client, users, db):
    users.make("alice", ["recipient"])
    row = db.execute("SELECT * FROM audit_log WHERE action = 'user_approved'").fetchone()
    assert row["role"] == "admin" and row["actor_id"] is not None
