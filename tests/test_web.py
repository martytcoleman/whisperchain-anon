"""the local web ui: xss, csrf, host checks, headers, and that it really works."""
import glob
import os

import pytest

from client.web import create_web_app
from tests.conftest import PASSWORD
from tests.test_client_core import people, server  # noqa: F401  (fixtures)

PORT = 8000
BASE = f"http://127.0.0.1:{PORT}"
XSS = '<script>alert("hi")</script><img src=x onerror=alert(1)>'


@pytest.fixture
def web(people):
    app = create_web_app(people["server"], people["home"], PORT)
    app.config["TESTING"] = True

    def browser(username=None):
        """a browser tab, logged in as username if given."""
        b = app.test_client()
        b.get("/login", base_url=BASE)
        if username:
            r = b.post("/login", base_url=BASE, data={
                "username": username, "password": PASSWORD, "csrf": csrf(b)})
            assert r.status_code == 302, r.data
        return b
    return browser


def csrf(browser):
    with browser.session_transaction(base_url=BASE) as s:
        return s["csrf"]


def post(browser, path, **data):
    return browser.post(path, base_url=BASE, data={**data, "csrf": csrf(browser)},
                        follow_redirects=True)


def page(browser, path):
    r = browser.get(path, base_url=BASE, follow_redirects=True)
    return r.status_code, r.get_data(as_text=True)


def test_send_and_read_through_the_web(web, people):
    alice = web("alice")
    r = post(alice, "/send", recipient="bob", message="nice talk today")
    assert "sent anonymously" in r.get_data(as_text=True)
    _, body = page(web("bob"), "/inbox")
    assert "nice talk today" in body


def test_message_text_is_escaped_in_inbox_and_moderation(web, people):
    people["alice"].send("bob", XSS)
    bob = web("bob")
    _, body = page(bob, "/inbox")
    assert "<script>" not in body and "<img src=x" not in body
    assert "&lt;script&gt;" in body

    msg_id = people["bob"].inbox()[0]["id"]
    post(bob, f"/inbox/{msg_id}/flag", reason=XSS, confirm="yes")
    _, body = page(web("mod"), "/moderation")
    assert "<script>" not in body and "<img src=x" not in body
    assert body.count("&lt;script&gt;") == 2          # the message and the reason


def test_post_without_csrf_token_is_refused(web, people):
    alice = web("alice")
    r = alice.post("/send", base_url=BASE, data={"recipient": "bob", "message": "forged"})
    assert r.status_code == 403
    r = alice.post("/send", base_url=BASE, data={"recipient": "bob", "message": "forged",
                                                 "csrf": "guess"})
    assert r.status_code == 403
    assert people["bob"].inbox() == []                 # nothing got sent


def test_login_form_needs_csrf_too(web):
    b = web()
    r = b.post("/login", base_url=BASE, data={"username": "alice", "password": PASSWORD})
    assert r.status_code == 403


def test_foreign_host_is_refused(web):
    # dns rebinding: an attacker's domain pointed at 127.0.0.1
    b = web()
    assert b.get("/login", base_url=f"http://evil.example:{PORT}").status_code == 403
    assert b.get("/login", base_url="http://127.0.0.1:9999").status_code == 403


def test_security_headers(people):
    r = create_web_app(people["server"], people["home"], PORT).test_client().get("/login", base_url=BASE)
    csp = r.headers["Content-Security-Policy"]
    assert "default-src 'none'" in csp and "script-src" not in csp   # no scripts allowed at all
    assert "frame-ancestors 'none'" in csp
    assert r.headers["Cache-Control"] == "no-store"
    cookie = r.headers["Set-Cookie"]
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie


def test_templates_never_turn_off_escaping():
    folder = os.path.join(os.path.dirname(__file__), "..", "client", "templates")
    for path in glob.glob(os.path.join(folder, "*.html")):
        text = open(path).read()
        assert "|safe" not in text.replace(" ", "") and "autoescape false" not in text, path
        assert "<script" not in text, path


def test_menu_hides_pages_but_server_still_decides(web):
    alice = web("alice")
    _, body = page(alice, "/")
    assert "Send" in body and "Inbox" not in body and "Moderation" not in body
    # going to the page anyway: the real server refuses
    _, body = page(alice, "/inbox")
    assert "requires inbox:read" in body
    _, body = page(alice, "/admin")
    assert "requires user:approve" in body


def test_flag_needs_confirmation(web, people):
    people["alice"].send("bob", "hello")
    bob = web("bob")
    msg_id = people["bob"].inbox()[0]["id"]
    r = post(bob, f"/inbox/{msg_id}/flag", reason="test")
    assert "tick the box" in r.get_data(as_text=True)
    assert people["mod"].flag_queue() == []


def test_not_logged_in_goes_to_login(web):
    r = web().get("/inbox", base_url=BASE)
    assert r.status_code == 302 and r.headers["Location"].endswith("/login")


def test_wrong_password(web):
    b = web()
    r = b.post("/login", base_url=BASE, data={"username": "alice", "password": "nope nope nope",
                                              "csrf": csrf(b)})
    assert r.status_code == 401


def test_logout(web):
    alice = web("alice")
    post(alice, "/logout")
    r = alice.get("/", base_url=BASE)
    assert r.status_code == 302


def test_admin_and_moderator_pages(web, people):
    _, body = page(web("admin"), "/admin")
    assert "alice" in body and "Start a new round" in body
    people["alice"].send("bob", "something")
    people["bob"].flag(people["bob"].inbox()[0]["id"], "bad")
    mod = web("mod")
    token_id = people["mod"].flag_queue()[0]["token_id"]
    r = post(mod, "/moderation/freeze", token_id=token_id, reason="abuse")
    assert "1 message(s) withdrawn" in r.get_data(as_text=True)
    r = post(mod, "/audit/verify")
    assert "log OK" in r.get_data(as_text=True)


def test_actions_go_back_to_their_own_page(web, people):
    # the browser sends no Referer (we turn it off), so each action has to
    # name the page it returns to instead of bouncing you to home
    admin = web("admin")
    r = admin.post("/admin/round", base_url=BASE, data={"csrf": csrf(admin)})
    assert r.status_code == 302 and r.headers["Location"].endswith("/admin")
    mod = web("mod")
    r = mod.post("/moderation/flags/999/dismiss", base_url=BASE, data={"csrf": csrf(mod)})
    assert r.headers["Location"].endswith("/moderation")
