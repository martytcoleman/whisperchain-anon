"""server-side admin commands, run on the server machine itself.

the very first admin can't be approved by an admin because there isn't one
yet. so they register like anyone else and then whoever runs the server
promotes them from the command line. needing shell access to the server is
the trust anchor here.

    python -m server.manage promote-admin <username> [--data-dir data]
    python -m server.manage verify-log [--data-dir data]
"""
import argparse
import os

from server import audit
from server.db import connect, init_db, transaction


def promote_admin(conn, audit_key, username):
    with transaction(conn):
        user = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if user is None:
            raise SystemExit(f"no user called {username!r}, register first")
        conn.execute("UPDATE users SET status = 'active' WHERE id = ?", (user["id"],))
        conn.execute("DELETE FROM user_roles WHERE user_id = ?", (user["id"],))
        conn.execute("INSERT INTO user_roles (user_id, role) VALUES (?, 'admin')", (user["id"],))
        audit.log(conn, audit_key, "admin_bootstrapped", role="operator", target=user["id"])


def main():
    parser = argparse.ArgumentParser(prog="python -m server.manage")
    parser.add_argument("--data-dir", default="data")
    sub = parser.add_subparsers(dest="command", required=True)
    promote = sub.add_parser("promote-admin")
    promote.add_argument("username")
    sub.add_parser("verify-log")
    args = parser.parse_args()

    conn = connect(os.path.join(args.data_dir, "whisperchain.db"))
    init_db(conn)
    key = audit.load_or_create_key(os.path.join(args.data_dir, "audit_key.pem"))

    if args.command == "promote-admin":
        promote_admin(conn, key, args.username)
        print(f"{args.username} is now an admin")
    elif args.command == "verify-log":
        ok, message = audit.verify(conn, key.public_key())
        print(("OK: " if ok else "PROBLEM: ") + message)
        print("current head:", audit.get_head(conn))


if __name__ == "__main__":
    main()
