"""builds the flask app and plugs everything together."""
import os

from flask import Flask, current_app, request

from server import audit, routes_admin, routes_auth, routes_sender
from server.context import close_db, error
from server.db import connect, init_db

MAX_REQUEST_BYTES = 64 * 1024   # nothing legit is bigger than this, so big requests get cut off


def create_app(data_dir):
    os.makedirs(data_dir, exist_ok=True)
    # no static_folder: the server only speaks json and serves no files or pages
    app = Flask(__name__, static_folder=None)
    app.config["DB_PATH"] = os.path.join(data_dir, "whisperchain.db")
    app.config["AUDIT_KEY"] = audit.load_or_create_key(os.path.join(data_dir, "audit_key.pem"))
    app.config["MAX_CONTENT_LENGTH"] = MAX_REQUEST_BYTES

    conn = connect(app.config["DB_PATH"])
    init_db(conn)
    conn.close()

    app.register_blueprint(routes_auth.bp)
    app.register_blueprint(routes_admin.bp)
    app.register_blueprint(routes_sender.bp)
    app.teardown_appcontext(close_db)

    @app.before_request
    def deny_routes_without_a_rule():
        # deny by default: if someone adds a route and forgets @public,
        # @require_login or @require_permission, it gets blocked here
        view = current_app.view_functions.get(request.endpoint)
        if view is not None and not hasattr(view, "access_rule"):
            return error(403, "this endpoint has no access rule")

    # always answer in json, even for errors flask generates itself
    @app.errorhandler(404)
    def not_found(_e):
        return error(404, "not found")

    @app.errorhandler(405)
    def wrong_method(_e):
        return error(405, "method not allowed")

    @app.errorhandler(413)
    def too_big(_e):
        return error(413, "request too large")

    return app
