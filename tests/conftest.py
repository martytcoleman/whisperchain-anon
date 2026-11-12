"""shared test setup: a fresh server per test plus helpers for making users."""
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from server.app import create_app
from server.db import connect
from server.manage import promote_admin

PASSWORD = "correct horse battery"


@pytest.fixture(scope="session")
def public_key_pem():
    # making a 3072-bit key takes a moment, so all test users share one
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    return key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


@pytest.fixture
def app(tmp_path):
    return create_app(str(tmp_path))


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def db(app):
    conn = connect(app.config["DB_PATH"])
    yield conn
    conn.close()


def auth_header(session):
    return {"Authorization": f"Bearer {session}"}


class Users:
    """makes approved users with whatever roles a test needs."""

    def __init__(self, app, client, public_key_pem):
        self.app, self.client, self.pem = app, client, public_key_pem
        self.admin_session = None

    def register(self, username):
        r = self.client.post("/register", json={
            "username": username, "password": PASSWORD, "public_key": self.pem})
        assert r.status_code == 201, r.json
        return r.json["id"]

    def login(self, username):
        r = self.client.post("/login", json={"username": username, "password": PASSWORD})
        assert r.status_code == 200, r.json
        return r.json["session"]

    def admin(self):
        if self.admin_session is None:
            self.register("admin")
            conn = connect(self.app.config["DB_PATH"])
            promote_admin(conn, self.app.config["AUDIT_KEY"], "admin")
            conn.close()
            self.admin_session = self.login("admin")
        return self.admin_session

    def make(self, username, roles):
        """register + admin approval, returns (user_id, session)."""
        admin = self.admin()
        user_id = self.register(username)
        r = self.client.post(f"/admin/users/{user_id}/approve",
                             json={"roles": roles}, headers=auth_header(admin))
        assert r.status_code == 200, r.json
        return user_id, self.login(username)


@pytest.fixture
def users(app, client, public_key_pem):
    return Users(app, client, public_key_pem)
