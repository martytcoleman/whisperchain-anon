"""everything the client does, with no printing or input in here.

the cli and the web ui are both thin layers over this, so all the
security-relevant client stuff (making keys, blinding tokens, encrypting,
pinning, sending anonymously) only exists once.

what's kept on disk, in <home>/<username>/ (folder readable only by you):
  keys/1.pem, 2.pem ...  your private keys, encrypted with your password.
                         newest is used, older ones stay so old messages
                         still decrypt after a key change
  pins.json              fingerprints of recipients you've sent to
  token.json             this round's anonymous token
  audit_head.txt         (moderators) the last audit head hash you saw
"""
import json
import os

import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from client import crypto
from client.keys import (KeyPins, generate_user_key, load_private_key, public_pem,
                         save_private_key)
from common import blind_rsa
from common.envelope import b64d, b64e
from common.pubkey import fingerprint

TIMEOUT = 30


class ApiError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


class Client:
    def __init__(self, server_url, home_root, username):
        self.server = server_url.rstrip("/")
        self.username = username
        self.home = os.path.join(home_root, username)
        self.http = requests.Session()   # logged-in requests only
        self.user = None                 # filled in by login()
        self.permissions = set()
        self._private_keys = []          # unlocked keys, newest first, memory only
        self._message_keys = {}          # message id -> aes key, for flagging
        self.pins = None

    # --- plumbing ---

    def _path(self, *parts):
        return os.path.join(self.home, *parts)

    def _call(self, method, path, **kwargs):
        r = self.http.request(method, self.server + path, timeout=TIMEOUT, **kwargs)
        return _handle(r)

    def _write_private(self, path, data):
        # readable by you only, same idea as the key files
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(data)

    # --- account ---

    def register(self, password):
        """make a key pair here, send only the public half."""
        if os.path.exists(self._path("keys")):
            raise ValueError(f"there's already a key for {self.username} on this machine")
        key = generate_user_key()
        _handle(requests.post(self.server + "/register", timeout=TIMEOUT, json={
            "username": self.username, "password": password, "public_key": public_pem(key)}))
        # only save once the server said yes, so a taken username doesn't
        # leave a stray key behind
        os.makedirs(self.home, mode=0o700, exist_ok=True)
        os.makedirs(self._path("keys"), mode=0o700)
        save_private_key(key, self._path("keys", "1.pem"), password)
        return fingerprint(public_pem(key))

    def login(self, password):
        data = self._call("POST", "/login", json={"username": self.username, "password": password})
        self.http.headers["Authorization"] = f"Bearer {data['session']}"
        self.user = data["user"]
        self.permissions = set(self._call("GET", "/me")["permissions"])
        self._unlock_keys(password)
        self.pins = KeyPins(self._path("pins.json"))
        # senders get this round's token now, while logged in, so that later
        # sending (logged out) happens at a different time. if both happened
        # back to back the server could match them up by timing
        return self.refresh_token() if "token:request" in self.permissions else None

    def _unlock_keys(self, password):
        folder = self._path("keys")
        if not os.path.isdir(folder):
            raise ValueError(f"no key for {self.username} on this machine (register from this machine)")
        names = sorted(os.listdir(folder), key=lambda n: int(n.split(".")[0]), reverse=True)
        self._private_keys = [load_private_key(os.path.join(folder, n), password) for n in names]

    def logout(self):
        if self.user:
            self._call("POST", "/logout")
        self.http.headers.pop("Authorization", None)
        self.user, self.permissions, self._private_keys = None, set(), []
        self._message_keys.clear()

    def request_new_key(self, password):
        """make a new key pair. the server only switches to it once an admin approves."""
        folder = self._path("keys")
        number = max(int(n.split(".")[0]) for n in os.listdir(folder)) + 1
        key = generate_user_key()
        result = self._call("POST", "/me/key", json={"public_key": public_pem(key)})
        save_private_key(key, os.path.join(folder, f"{number}.pem"), password)
        self._private_keys.insert(0, key)
        return result["fingerprint"]

    def directory(self):
        return self._call("GET", "/directory")["recipients"]

    # --- sender ---

    def _load_token(self):
        try:
            with open(self._path("token.json")) as f:
                return json.load(f)
        except FileNotFoundError:
            return None

    def refresh_token(self):
        """get this epoch's token if we don't have it yet. returns a status string."""
        r = requests.get(self.server + "/round", timeout=TIMEOUT)
        if r.status_code == 404:
            return "no round open yet"
        rnd = _handle(r)
        saved = self._load_token()
        if saved and saved["epoch"] == rnd["epoch"]:
            return "have token"

        n, e = int(rnd["n"], 16), rnd["e"]
        # the token is a throwaway key pair just for this epoch, nothing to do
        # with my account key. its private half never leaves this machine
        token_key = Ed25519PrivateKey.generate()
        token_public = token_key.public_key().public_bytes_raw()
        # blind it with a random r so the server signs it without seeing it
        blinded, r_blind = blind_rsa.blind(blind_rsa.token_message(rnd["epoch"], token_public), n, e)
        # this request IS logged in (server checks the sender role and one per
        # epoch). that's fine, all it ever sees is the blinded number
        try:
            data = self._call("POST", "/tokens", json={"epoch": rnd["epoch"], "blinded": hex(blinded)})
        except ApiError as err:
            if err.status == 409:
                return str(err)   # e.g. already got one this epoch
            raise
        # divide r back out: now it's a normal rsa signature on the real token,
        # which the server has never seen
        signature = blind_rsa.unblind(int(data["blind_signature"], 16), r_blind, n)
        # check it before trusting it. a bad signature here means the server
        # misbehaved, and the token would just be rejected later anyway
        if not blind_rsa.verify(blind_rsa.token_message(rnd["epoch"], token_public), signature, n, e):
            raise ValueError("server returned a bad token signature")
        self._write_private(self._path("token.json"), json.dumps({
            "epoch": rnd["epoch"],
            "private_key": b64e(token_key.private_bytes_raw()),
            "public_key": b64e(token_public),
            "signature": hex(signature),
            "used_rounds": [],
        }))
        return "new token"

    def token_status(self):
        saved, rnd = self._load_token(), requests.get(self.server + "/round", timeout=TIMEOUT)
        if rnd.status_code == 404:
            return "no round open yet"
        rnd = _handle(rnd)
        if not saved or saved["epoch"] != rnd["epoch"]:
            return "no token for this round"
        if rnd["round_id"] in saved["used_rounds"]:
            return "token already used this round"
        return "token ready"

    def send(self, recipient_username, text):
        recipient = next((r for r in self.directory() if r["username"] == recipient_username), None)
        if recipient is None:
            raise ValueError(f"{recipient_username} isn't a recipient")
        # raises KeyChanged if the server is handing out a different key than last time
        self.pins.check(recipient_username, recipient["public_key"])

        rnd = _handle(requests.get(self.server + "/round", timeout=TIMEOUT))
        token = self._load_token()
        if not token or token["epoch"] != rnd["epoch"]:
            raise ValueError("no token for this round. tokens are picked up when you log in, "
                             "so log in again and send a bit later")
        if rnd["round_id"] in token["used_rounds"]:
            raise ValueError("you already sent your message this round")

        # hybrid encryption (client/crypto.py): fresh aes key for the text, that
        # key wrapped with the recipient's rsa key, plus a commitment (hash of
        # the aes key) so a flag can be checked later
        envelope = crypto.encrypt_message(text, recipient["public_key"], recipient["id"],
                                          rnd["round_id"], rnd["epoch"])
        # sign the whole envelope with the token's private key. proves the token
        # holder wrote exactly this, so a copied token can't send anything else
        token_key = Ed25519PrivateKey.from_private_bytes(b64d(token["private_key"]))
        body = {
            "envelope": envelope,
            "token": {"epoch": token["epoch"], "public_key": token["public_key"],
                      "signature": token["signature"]},
            "signature": crypto.sign_envelope(token_key, envelope),
        }
        # the anonymous part: plain requests.post, NOT self.http. so no login
        # header, no cookies, and a brand new connection instead of reusing
        # the logged-in one
        r = requests.post(self.server + "/messages", json=body, timeout=TIMEOUT,
                          headers={"Connection": "close"})
        if r.status_code in (201, 409):   # 409 = already spent, remember that too
            token["used_rounds"].append(rnd["round_id"])
            self._write_private(self._path("token.json"), json.dumps(token))
        _handle(r)

    def trust_new_key(self, username):
        """after checking with them in person that their key really changed."""
        recipient = next((r for r in self.directory() if r["username"] == username), None)
        if recipient is None:
            raise ValueError(f"{username} isn't a recipient")
        self.pins.accept_new_key(username, recipient["public_key"])
        return recipient["fingerprint"]

    # --- recipient ---

    def inbox(self):
        """fetch and decrypt your messages. decryption happens here, never on the server."""
        out = []
        for m in self._call("GET", "/inbox")["messages"]:
            text, problem = None, None
            for key in self._private_keys:   # newest key first
                try:
                    text, message_key = crypto.decrypt_message(key, m["envelope"])
                    self._message_keys[m["id"]] = message_key
                    break
                except ValueError as e:
                    problem = str(e)
            out.append({"id": m["id"], "round": m["round"], "text": text,
                        "error": None if text is not None else problem})
        return out

    def flag(self, message_id, reason):
        """hands the server this one message's key so moderators can read it."""
        if message_id not in self._message_keys:
            self.inbox()
        if message_id not in self._message_keys:
            raise ValueError("no message with that id in your inbox")
        self._call("POST", f"/inbox/{message_id}/flag",
                   json={"key": b64e(self._message_keys[message_id]), "reason": reason})

    # --- moderator ---

    def flag_queue(self, status="open"):
        return self._call("GET", "/moderation/flags", params={"status": status})["flags"]

    def dismiss(self, flag_id):
        return self._call("POST", f"/moderation/flags/{flag_id}/dismiss")

    def freeze(self, token_id, reason):
        return self._call("POST", f"/moderation/tokens/{token_id}/freeze", json={"reason": reason})

    def unfreeze(self, token_id, reason):
        return self._call("POST", f"/moderation/tokens/{token_id}/unfreeze", json={"reason": reason})

    def alerts(self):
        return self._call("GET", "/alerts")["alerts"]

    def audit(self, limit=50):
        return self._call("GET", "/audit", params={"limit": limit})["entries"]

    def verify_audit(self):
        """check the log, and that the head we saved last time is still in it.
        saving the head on our side is what catches the server rewriting history."""
        path = self._path("audit_head.txt")
        saved = open(path).read().strip() if os.path.exists(path) else None
        params = {"head": saved} if saved else {}
        result = self._call("GET", "/audit/verify", params=params)
        if result["ok"]:
            self._write_private(path, result["head"])
        result["checked_saved_head"] = saved is not None
        return result

    # --- admin ---

    def users(self):
        return self._call("GET", "/admin/users")["users"]

    def approve(self, user_id, roles):
        return self._call("POST", f"/admin/users/{user_id}/approve", json={"roles": roles})

    def reject(self, user_id):
        return self._call("POST", f"/admin/users/{user_id}/reject")

    def set_roles(self, user_id, roles):
        return self._call("POST", f"/admin/users/{user_id}/roles", json={"roles": roles})

    def approve_key(self, user_id):
        return self._call("POST", f"/admin/users/{user_id}/key/approve")

    def start_round(self):
        return self._call("POST", "/admin/rounds")

    def policy(self):
        return self._call("GET", "/admin/policy")

    def set_policy(self, name, value):
        return self._call("POST", "/admin/policy", json={"name": name, "value": value})


def _handle(r):
    """turn a response into its json, or an ApiError with the server's message."""
    try:
        data = r.json()
    except ValueError:
        data = {}
    if r.status_code >= 400:
        raise ApiError(r.status_code, data.get("error", f"server said {r.status_code}"))
    return data
