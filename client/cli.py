"""the terminal client: an interactive shell over client/core.py.

    python -m client.cli --user alice --register    (once, makes your keys)
    python -m client.cli --user alice               (log in, get a whisper> prompt)

you type your password once. your private key and session only live in
memory while the shell is open and are gone when you quit.

`help` only lists commands your roles can use. that's just to keep things
tidy, the server checks every request on its own, so typing a hidden
command just gets you a 403.
"""
import argparse
import cmd
import getpass
import json

from client.core import ApiError, Client
from client.keys import KeyChanged


def safe(text):
    """strip control characters before printing anything from someone else.

    a message could contain terminal escape codes that clear the screen or
    fake output. it's the terminal version of xss (threat T15)."""
    return "".join(c if c.isprintable() or c == "\n" else "?" for c in str(text))


def needs(permission):
    """marks which permission a command is for, so help can hide the rest."""
    def mark(fn):
        fn.permission = permission
        return fn
    return mark


def parse_roles(text):
    return [r.strip() for r in text.split(",") if r.strip()]


class Shell(cmd.Cmd):
    prompt = "whisper> "

    def __init__(self, client):
        super().__init__()
        self.c = client

    # --- shell plumbing ---

    def get_names(self):
        # cmd uses this for help and tab completion
        names = []
        for name in dir(self.__class__):
            if name == "do_EOF":
                continue   # that's just ctrl-d, not a real command
            fn = getattr(self, "do_" + name[3:], None) if name.startswith("do_") else None
            if fn is None or getattr(fn, "permission", None) in (None, *self.c.permissions):
                names.append(name)
        return names

    def onecmd(self, line):
        try:
            return super().onecmd(line)
        except ApiError as e:
            print(f"error ({e.status}): {safe(e)}")
        except KeyChanged as e:
            print(safe(e))
            print("if you've checked with them, run: trust <username>")
        except ValueError as e:
            print(f"error: {safe(e)}")

    def emptyline(self):
        pass   # default would repeat the last command, which is a bad idea for "send"

    def default(self, line):
        print(f"unknown command: {safe(line.split()[0])} (try 'help')")

    # --- everyone ---

    def do_whoami(self, _arg):
        """show your username, roles, and permissions"""
        print(f"{self.c.user['username']} (id {self.c.user['id']})")
        print("roles:", ", ".join(self.c.user["roles"]))
        print("permissions:", ", ".join(sorted(self.c.permissions)))

    def do_directory(self, _arg):
        """list recipients and their key fingerprints"""
        for r in self.c.directory():
            print(f"  {safe(r['username']):<16} {r['fingerprint']}")

    def do_trust(self, arg):
        """trust <username>: accept a recipient's changed key (check with them in person first!)"""
        fp = self.c.trust_new_key(arg.strip())
        print(f"now trusting {safe(arg.strip())}'s key {fp}")

    def do_new_key(self, _arg):
        """make a new key pair. it's only used once an admin approves it"""
        password = getpass.getpass("password (to encrypt the new key): ")
        print("pending admin approval, new fingerprint:", self.c.request_new_key(password))

    def do_quit(self, _arg):
        """log out and exit"""
        self.c.logout()
        print("logged out")
        return True

    do_EOF = do_quit   # ctrl-d

    # --- sender ---

    @needs("token:request")
    def do_token(self, _arg):
        """show this round's token status (and pick one up if you don't have it)"""
        status = self.c.token_status()
        if status == "no token for this round":
            print(self.c.refresh_token())
            print("tip: wait a while before sending, so getting the token and "
                  "sending don't happen right next to each other")
        else:
            print(status)

    @needs("token:request")
    def do_send(self, arg):
        """send <username>: send an anonymous compliment"""
        username = arg.strip()
        if not username:
            print("usage: send <username>")
            return
        status = self.c.token_status()
        if status != "token ready":   # say so before making them type the message
            print(status)
            return
        text = input("message: ")
        self.c.send(username, text)
        print("sent anonymously.")

    # --- recipient ---

    @needs("inbox:read")
    def do_inbox(self, _arg):
        """show and decrypt your messages"""
        messages = self.c.inbox()
        if not messages:
            print("no messages")
        for m in messages:
            body = safe(m["text"]) if m["text"] is not None else f"[can't decrypt: {m['error']}]"
            print(f"[{m['id']}] round {m['round']}: {body}")

    @needs("flag:create")
    def do_flag(self, arg):
        """flag <message id>: report a message to the moderators"""
        try:
            message_id = int(arg)
        except ValueError:
            print("usage: flag <message id>")
            return
        print("flagging shows this message's text to the moderators. they won't see who you are.")
        if input("continue? [y/N] ").strip().lower() != "y":
            print("cancelled")
            return
        self.c.flag(message_id, input("reason: "))
        print("flagged.")

    # --- moderator ---

    @needs("moderation:read")
    def do_flags(self, arg):
        """flags [open|dismissed|frozen]: the flag queue (default: open)"""
        flags = self.c.flag_queue(arg.strip() or "open")
        if not flags:
            print("nothing here")
        for f in flags:
            print(f"[{f['id']}] round {f['round']}  token {f['token_id']}"
                  f"{'  (frozen)' if f['frozen'] else ''}")
            print(f"    message: {safe(f['plaintext'])}")
            print(f"    reason:  {safe(f['reason'])}")

    @needs("flag:resolve")
    def do_dismiss(self, arg):
        """dismiss <flag id>: mark a flag as reviewed, no action needed"""
        self.c.dismiss(int(arg))
        print("dismissed")

    @needs("token:freeze")
    def do_freeze(self, arg):
        """freeze <token id>: block a token and withdraw its message"""
        result = self.c.freeze(arg.strip(), input("reason: "))
        print(f"frozen, {result['withdrawn']} message(s) withdrawn")

    @needs("token:freeze")
    def do_unfreeze(self, arg):
        """unfreeze <token id>: undo a freeze and restore its message"""
        result = self.c.unfreeze(arg.strip(), input("reason: "))
        print(f"unfrozen, {result['restored']} message(s) restored")

    @needs("alerts:read")
    def do_alerts(self, _arg):
        """show alerts"""
        alerts = self.c.alerts()
        if not alerts:
            print("no alerts")
        for a in alerts:
            print(f"{a['time']}  {a['rule']:<18} {safe(a['detail'])}")

    @needs("audit:read")
    def do_audit(self, arg):
        """audit [n]: show the last n log entries (default 20)"""
        for e in reversed(self.c.audit(int(arg) if arg.strip() else 20)):
            who = f" by user {e['actor_id']}" if e["actor_id"] else ""
            print(f"#{e['id']} {e['ts']}  {e['action']:<20} [{e['role'] or '-'}]{who}  {safe(e['details'])}")

    @needs("audit:read")
    def do_verify(self, _arg):
        """check the audit log's hash chain and signatures"""
        r = self.c.verify_audit()
        print(("OK: " if r["ok"] else "PROBLEM: ") + r["message"])
        if r["checked_saved_head"]:
            print("also checked: the head you saved last time is still in the log")
        print("head saved:", r["head"])

    # --- admin ---

    @needs("user:approve")
    def do_users(self, _arg):
        """list all users"""
        for u in self.c.users():
            extra = "  (key change waiting)" if u["has_pending_key"] else ""
            print(f"  {u['id']:>3}  {safe(u['username']):<16} {u['status']:<9} "
                  f"{','.join(u['roles']) or '-':<22} {u['key_fingerprint'][:19]}...{extra}")

    @needs("user:approve")
    def do_approve(self, arg):
        """approve <user id> <role,role>: approve a registration"""
        user_id, roles = arg.split(maxsplit=1)
        print(json.dumps(self.c.approve(int(user_id), parse_roles(roles))))

    @needs("user:approve")
    def do_reject(self, arg):
        """reject <user id>: reject a registration"""
        print(json.dumps(self.c.reject(int(arg))))

    @needs("role:assign")
    def do_roles(self, arg):
        """roles <user id> <role,role>: replace a user's roles"""
        user_id, roles = arg.split(maxsplit=1)
        print(json.dumps(self.c.set_roles(int(user_id), parse_roles(roles))))

    @needs("key:approve")
    def do_approve_key(self, arg):
        """approve_key <user id>: switch a user to the new key they asked for"""
        print("new fingerprint:", self.c.approve_key(int(arg))["key_fingerprint"])

    @needs("round:manage")
    def do_new_round(self, _arg):
        """start a new round (new tokens for everyone)"""
        r = self.c.start_round()
        print(f"round {r['round_id']} started (epoch {r['epoch']})")

    @needs("policy:set")
    def do_policy(self, arg):
        """policy [name value]: show or change a setting"""
        if arg.strip():
            name, value = arg.split()
            self.c.set_policy(name, int(value))
        for name, value in self.c.policy().items():
            print(f"  {name} = {value}")


def main():
    parser = argparse.ArgumentParser(prog="python -m client.cli")
    parser.add_argument("--user", required=True)
    parser.add_argument("--register", action="store_true", help="make keys and register")
    parser.add_argument("--server", default="http://127.0.0.1:5000")
    parser.add_argument("--home", default="client_data", help="where your keys are kept")
    args = parser.parse_args()
    client = Client(args.server, args.home, args.user.strip().lower())

    try:
        if args.register:
            password = getpass.getpass("choose a password (10+ characters): ")
            if getpass.getpass("again: ") != password:
                raise SystemExit("passwords don't match")
            print("making your key pair (a few seconds)...")
            fp = client.register(password)
            print(f"registered. your key fingerprint is {fp}")
            print("an admin has to approve you before you can log in.")
            return

        token_status = client.login(getpass.getpass("password: "))
    except (ApiError, ValueError) as e:
        raise SystemExit(f"error: {e}")

    print(f"logged in as {client.user['username']} ({', '.join(client.user['roles'])})")
    if token_status:
        print(f"token: {token_status}")
    print("type 'help' for commands")
    Shell(client).cmdloop()


if __name__ == "__main__":
    main()
