"""alert rules.

an alert just tells moderators "something looks off, go look". alerts never
freeze anything on their own. a pile of fake flags shouldn't be able to
punish someone automatically (threat T10), so a person always decides.

every alert goes two places: the alerts table (what the dashboard shows) and
the audit log (so an alert can't quietly disappear later).
"""
import json
from datetime import datetime, timezone

from server.context import db, log
from server.db import get_policy, transaction

INVALID_TOKEN_LIMIT = 5   # bad tokens in one round before we alert


def raise_alert(rule, **detail):
    # rounded to the hour like other sender-side events. some alerts are
    # caused by an anonymous sender, and an exact time could help tie them
    # back to a person
    now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    if db().in_transaction:
        _save(now, rule, detail)
    else:
        with transaction(db()):
            _save(now, rule, detail)


def _save(now, rule, detail):
    db().execute("INSERT INTO alerts (created_at, rule, detail) VALUES (?, ?, ?)",
                 (now.strftime("%Y-%m-%dT%H:%M:%SZ"), rule, json.dumps(detail, sort_keys=True)))
    log("alert_raised", rule=rule, **detail)


def _raised_before(rule, **match):
    """has this alert already gone off for this round/epoch? keeps us from
    raising the same alert again on every flag after the line is crossed."""
    for row in db().execute("SELECT detail FROM alerts WHERE rule = ?", (rule,)):
        detail = json.loads(row["detail"])
        if all(detail.get(k) == v for k, v in match.items()):
            return True
    return False


def check_flag_threshold(round_id):
    # too many flags in one round. with fresh tokens every round each token
    # only sends one message, so counting per round makes more sense than
    # counting per token
    flags = db().execute("SELECT COUNT(*) FROM flags WHERE round_id = ?",
                         (round_id,)).fetchone()[0]
    if flags >= get_policy(db(), "flag_threshold") and not _raised_before("flag_threshold", round=round_id):
        raise_alert("flag_threshold", round=round_id, flags=flags)


def check_invalid_tokens(round_id):
    # someone keeps trying forged or expired tokens. could be an attack, could
    # be a broken client, either way a moderator should know
    attempts = db().execute(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'invalid_token' "
        "AND json_extract(details, '$.round') = ?", (round_id,)).fetchone()[0]
    if attempts >= INVALID_TOKEN_LIMIT and not _raised_before("invalid_tokens", round=round_id):
        raise_alert("invalid_tokens", round=round_id, attempts=attempts)


def check_unissued_tokens(epoch):
    # threat T4: if the signing key leaks, someone can make valid tokens
    # without asking the server. those tokens still verify, but the server
    # never handed them out, so more different tokens end up being used than
    # were issued. this can't stop that, but it does notice it
    used = db().execute(
        "SELECT COUNT(DISTINCT m.token_id) FROM messages m JOIN rounds r ON r.id = m.round_id "
        "WHERE r.epoch = ?", (epoch,)).fetchone()[0]
    issued = db().execute("SELECT COUNT(*) FROM issuance WHERE epoch = ?", (epoch,)).fetchone()[0]
    if used > issued and not _raised_before("unissued_tokens", epoch=epoch):
        raise_alert("unissued_tokens", epoch=epoch, used=used, issued=issued)
