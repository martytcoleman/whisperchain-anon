"""little helpers every route uses. kept separate so the route files stay short."""
from flask import current_app, g, jsonify

from server import audit
from server.db import connect


def db():
    # every request gets its own db connection. sharing one connection
    # between requests would mix their transactions together
    if "db" not in g:
        g.db = connect(current_app.config["DB_PATH"])
    return g.db


def close_db(_exc=None):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def log(action, role=None, actor_id=None, **details):
    audit.log(db(), current_app.config["AUDIT_KEY"], action, role, actor_id, **details)


def error(status, message):
    return jsonify(error=message), status
