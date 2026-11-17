"""the local web ui: a small website that runs on your own machine.

    python -m client.web [--port 8000] [--server http://127.0.0.1:5000]

then open http://127.0.0.1:8000. it's the same client as the cli (it calls
client/core.py), just with pages instead of a prompt. your keys still never
leave your machine: this runs locally, and the real server only ever gets
ciphertext.

because it's a website, other websites you visit could try to attack it
(threat T15/T16). the defenses are all in here:
  - only listens on 127.0.0.1, and checks the Host header so a site can't
    reach it by pointing its own domain at 127.0.0.1 (dns rebinding)
  - every form has a csrf token, so another site can't submit forms here
    through your browser
  - no javascript at all, and a content-security-policy that blocks any, so
    even if some message text slipped through as html it couldn't run
  - jinja escapes everything it puts in a page (we never use |safe)
"""
import argparse
import secrets
from functools import wraps

from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for

from client.core import ApiError, Client
from client.keys import KeyChanged

ROLES = ("sender", "recipient", "moderator", "admin")

# token status from client/core.py, said the way a person would say it
TOKEN_TEXT = {
    "token ready": "You can send one message this round.",
    "token already used this round": "You've sent your message for this round. "
                                     "You can send again when a new round starts.",
    "no token for this round": "You don't have a token for this round yet.",
    "no round open yet": "No round is open yet, so nobody can send right now.",
}

# what refresh_token() did when you logged in (or clicked "get my token")
PICKUP_TEXT = {
    "new token": "Picked up your anonymous token for this round.",
    "have token": "You already have your token for this round.",
    "no round open yet": "No round is open yet, so there's no token to pick up.",
}

SECURITY_HEADERS = {
    # no scripts, no plugins, no framing, forms only post back to us
    "Content-Security-Policy": ("default-src 'none'; style-src 'self'; form-action 'self'; "
                                "frame-ancestors 'none'; base-uri 'none'"),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    # pages have decrypted messages on them, don't keep them in the browser cache
    "Cache-Control": "no-store",
}


def create_web_app(server_url, home_dir, port):
    app = Flask(__name__)
    # a new secret every time it starts, so old cookies just stop working
    app.secret_key = secrets.token_bytes(32)
    app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict")
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
    clients = {}   # browser session id -> logged-in Client. memory only

    @app.before_request
    def checks():
        if request.host not in allowed_hosts:
            abort(403)
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(32)
        if request.method == "POST":
            if not secrets.compare_digest(request.form.get("csrf", ""), session["csrf"]):
                abort(403)
        g.client = clients.get(session.get("sid"))

    @app.after_request
    def add_headers(response):
        response.headers.update(SECURITY_HEADERS)
        return response

    @app.context_processor
    def template_helpers():
        c = g.get("client")
        return {"csrf": session.get("csrf"), "me": c,
                "can": lambda permission: c is not None and permission in c.permissions}

    @app.errorhandler(403)
    def forbidden(_e):
        return render_template("error.html", message="forbidden"), 403

    def login_required(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            if g.client is None:
                return redirect(url_for("login"))
            return view(*args, **kwargs)
        return wrapper

    def attempt(action, success=None):
        """run a client call and turn errors into a message on the page.
        returns the result, or None if it failed."""
        try:
            result = action()
        except (ApiError, KeyChanged, ValueError) as e:
            flash(str(e), "error")
            return None
        if success:
            flash(success(result) if callable(success) else success, "ok")
        return result

    def back(page):
        # go back to the page the action came from. we can't use the browser's
        # Referer header for this because we tell it not to send one
        # (Referrer-Policy: no-referrer), so each action names its page
        return redirect(url_for(page))

    # --- account ---

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            c = Client(server_url, home_dir, request.form.get("username", "").strip().lower())
            try:
                token_status = c.login(request.form.get("password", ""))
            except (ApiError, ValueError) as e:
                flash(str(e), "error")
                return render_template("login.html"), 401
            sid = secrets.token_urlsafe(32)
            clients[sid] = c
            session.clear()   # new session id and csrf token after logging in
            session["sid"], session["csrf"] = sid, secrets.token_urlsafe(32)
            if token_status:
                flash(PICKUP_TEXT.get(token_status, token_status), "ok")
            return redirect(url_for("home"))
        return render_template("login.html")

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            password = request.form.get("password", "")
            if password != request.form.get("password2", ""):
                flash("passwords don't match", "error")
            else:
                c = Client(server_url, home_dir, request.form.get("username", "").strip().lower())
                fp = attempt(lambda: c.register(password),
                             "registered. an admin has to approve you before you can log in.")
                if fp:
                    return render_template("registered.html", fingerprint=fp)
        return render_template("register.html")

    @app.post("/logout")
    @login_required
    def logout():
        try:
            g.client.logout()
        except ApiError:
            pass
        clients.pop(session.get("sid"), None)
        session.clear()
        return redirect(url_for("login"))

    @app.get("/")
    @login_required
    def home():
        # a short "what can i do" list. no inbox count here on purpose:
        # counting means fetching the inbox, and every fetch is logged as a
        # delivery, so just opening the home page would spam the audit log
        c = g.client
        token = c.token_status() if "token:request" in c.permissions else None
        open_flags = pending_users = None
        try:
            if "moderation:read" in c.permissions:
                open_flags = len(c.flag_queue("open"))
            if "user:approve" in c.permissions:
                pending_users = sum(u["status"] == "pending" for u in c.users())
        except ApiError:
            pass
        return render_template("home.html", token=token, token_text=TOKEN_TEXT.get(token),
                               open_flags=open_flags, pending_users=pending_users)

    @app.get("/account")
    @login_required
    def account():
        return render_template("account.html", directory=g.client.directory())

    @app.post("/account/new-key")
    @login_required
    def new_key():
        attempt(lambda: g.client.request_new_key(request.form.get("password", "")),
                lambda fp: f"new key waiting for admin approval, fingerprint {fp}")
        return back("account")

    @app.post("/trust")
    @login_required
    def trust():
        username = request.form.get("username", "")
        attempt(lambda: g.client.trust_new_key(username),
                lambda fp: f"now trusting {username}'s key {fp}")
        return back("send")

    # --- sender ---

    @app.route("/send", methods=["GET", "POST"])
    @login_required
    def send():
        changed_key = None
        if request.method == "POST":
            username = request.form.get("recipient", "")
            try:
                g.client.send(username, request.form.get("message", ""))
                flash("sent anonymously.", "ok")
                return redirect(url_for("send"))
            except KeyChanged as e:
                changed_key = {"username": username, "detail": str(e)}
            except (ApiError, ValueError) as e:
                flash(str(e), "error")
        token = g.client.token_status()
        return render_template("send.html", recipients=g.client.directory(), token=token,
                               token_text=TOKEN_TEXT.get(token, token), changed_key=changed_key)

    @app.post("/token")
    @login_required
    def token():
        attempt(g.client.refresh_token, lambda status: PICKUP_TEXT.get(status, status))
        return back("send")

    # --- recipient ---

    @app.get("/inbox")
    @login_required
    def inbox():
        # no role check here on purpose: the link is hidden for non-recipients,
        # and if they come here anyway the server says no
        messages = attempt(g.client.inbox)
        return render_template("inbox.html", messages=messages or [])

    @app.post("/inbox/<int:message_id>/flag")
    @login_required
    def flag(message_id):
        if request.form.get("confirm", "") != "yes":
            flash("tick the box to confirm you want to reveal this message to moderators", "error")
        else:
            attempt(lambda: g.client.flag(message_id, request.form.get("reason", "")), "flagged.")
        return redirect(url_for("inbox"))

    # --- moderator ---

    @app.get("/moderation")
    @login_required
    def moderation():
        status = request.args.get("status", "open")
        flags = attempt(lambda: g.client.flag_queue(status))
        alerts = attempt(g.client.alerts)
        return render_template("moderation.html", flags=flags or [], alerts=alerts or [],
                               status=status)

    @app.post("/moderation/flags/<int:flag_id>/dismiss")
    @login_required
    def dismiss(flag_id):
        attempt(lambda: g.client.dismiss(flag_id), "flag dismissed")
        return back("moderation")

    @app.post("/moderation/freeze")
    @login_required
    def freeze():
        attempt(lambda: g.client.freeze(request.form.get("token_id", ""), request.form.get("reason", "")),
                lambda r: f"token frozen, {r['withdrawn']} message(s) withdrawn")
        return back("moderation")

    @app.post("/moderation/unfreeze")
    @login_required
    def unfreeze():
        attempt(lambda: g.client.unfreeze(request.form.get("token_id", ""), request.form.get("reason", "")),
                lambda r: f"token unfrozen, {r['restored']} message(s) restored")
        return back("moderation")

    @app.get("/audit")
    @login_required
    def audit():
        entries = attempt(lambda: g.client.audit(100))
        return render_template("audit.html", entries=entries or [])

    @app.post("/audit/verify")
    @login_required
    def verify():
        result = attempt(g.client.verify_audit)
        if result:
            extra = " (and the head you saved last time is still there)" if result["checked_saved_head"] else ""
            flash(("log OK" + extra) if result["ok"] else "PROBLEM: " + result["message"],
                  "ok" if result["ok"] else "error")
        return redirect(url_for("audit"))

    # --- admin ---

    @app.get("/admin")
    @login_required
    def admin():
        users = attempt(g.client.users)
        policy = attempt(g.client.policy)
        return render_template("admin.html", users=users or [], policy=policy or {}, roles=ROLES)

    @app.post("/admin/users/<int:user_id>/approve")
    @login_required
    def approve(user_id):
        attempt(lambda: g.client.approve(user_id, request.form.getlist("roles")), "user approved")
        return back("admin")

    @app.post("/admin/users/<int:user_id>/reject")
    @login_required
    def reject(user_id):
        attempt(lambda: g.client.reject(user_id), "user rejected")
        return back("admin")

    @app.post("/admin/users/<int:user_id>/roles")
    @login_required
    def roles(user_id):
        attempt(lambda: g.client.set_roles(user_id, request.form.getlist("roles")), "roles updated")
        return back("admin")

    @app.post("/admin/users/<int:user_id>/approve-key")
    @login_required
    def approve_key(user_id):
        attempt(lambda: g.client.approve_key(user_id), "key approved")
        return back("admin")

    @app.post("/admin/round")
    @login_required
    def new_round():
        attempt(g.client.start_round, lambda r: f"round {r['round_id']} started")
        return back("admin")

    @app.post("/admin/policy")
    @login_required
    def policy():
        def change():
            return g.client.set_policy(request.form.get("name", ""), int(request.form.get("value", "")))
        attempt(change, "policy updated")
        return back("admin")

    return app


def main():
    parser = argparse.ArgumentParser(prog="python -m client.web")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--server", default="http://127.0.0.1:5000")
    parser.add_argument("--home", default="client_data", help="where your keys are kept")
    args = parser.parse_args()
    print(f"open http://127.0.0.1:{args.port}")
    # 127.0.0.1 only: nothing else on the network can reach this
    create_web_app(args.server, args.home, args.port).run(host="127.0.0.1", port=args.port)


if __name__ == "__main__":
    main()
