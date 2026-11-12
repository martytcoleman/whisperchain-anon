"""getting an anonymous token.

this is the one sender step where the server DOES know who you are, because
it has to check you're a sender and haven't had a token yet this epoch. but
all it sees is a blinded number, so it can't recognize the token later when
it's used to send a message.
"""
import sqlite3

from flask import Blueprint, g, request

from common import blind_rsa
from server import rounds
from server.context import db, error, log
from server.db import transaction
from server.rbac import public, require_permission

bp = Blueprint("sender", __name__)


@bp.get("/round")
@public
def get_round():
    # the current round and its public signing key. clients need (n, e) to
    # blind their token, and it's public info anyway
    current = rounds.current_round(db())
    if current is None:
        return error(404, "no round has been started yet")
    n, e = rounds.public_numbers(current)
    return {"round_id": current["id"], "epoch": current["epoch"], "n": hex(n), "e": e}


@bp.post("/tokens")
@require_permission("token:request")
def issue_token():
    data = request.get_json(silent=True) or {}
    try:
        blinded = int(str(data.get("blinded", "")), 16)
    except ValueError:
        return error(400, "blinded must be a hex number")

    with transaction(db()):
        current = rounds.current_round(db())
        if current is None:
            return error(409, "no round has been started yet")
        # the client says which epoch it blinded for. if a new epoch started in
        # between, its token would be useless, so tell it to fetch the new key
        if data.get("epoch") != current["epoch"]:
            return error(409, "epoch has changed, fetch /round again")

        n, d = rounds.private_numbers(current)
        if not 1 < blinded < n:
            return error(400, "blinded value out of range")

        # record "this user got their token for this epoch" BEFORE signing.
        # the primary key makes a second request fail right here, even if two
        # requests arrive at the same moment
        try:
            db().execute("INSERT INTO issuance (user_id, epoch) VALUES (?, ?)",
                         (g.user["id"], current["epoch"]))
        except sqlite3.IntegrityError:
            return error(409, "you already have a token for this epoch")

        blind_signature = blind_rsa.sign_blinded(blinded, n, d)
        # no user id in the log, just that a sender got a token
        log("token_issued", role="sender", epoch=current["epoch"])
    return {"blind_signature": hex(blind_signature)}
