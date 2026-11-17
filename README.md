# WhisperChain+

In this project, the goal was to build an anonymous compliment platform for an educational environment, in which students, TAs, and faculty may send and receive anonymous compliments. We set out to build four distinct roles into the system: Sender, Recipient, Moderator, and Admin.

- Confidentiality: the messages senders send should only be readable by the recipient and not the server itself or an admin.
- Anonymity: no one (server included) should be able to tell who sent a message

In order to accomplish these goals, I had to engage with an important tradeoff we learned in class: the tradeoff between accountability and anonymity, as we had to figure out a way to properly respond/react to abuse from someone we cannot identify. In short, the way we addressed this was by designing the system such that accountability is linked to the anonymous token and not the person behind that token.

Documents:

- `docs/report.md`: my written security design report for final submission
- `docs/rbac_and_threat_model.md`: role-permission matrix and threat model
- `docs/audit_log_sample.md`: sample audit log output with analysis

## Requirements

- Python 3.13
- macOS or Linux

## Setup

```bash
git clone https://github.com/martytcoleman/whisperchain-anon.git
cd whisperchain-anon
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Run the tests to check everything works:

```bash
pytest
```

## Running it

You need two terminals, each with the virtual environment activated (`source .venv/bin/activate`).

**Terminal 1: the server**

```bash
python -m server
```

It listens on `127.0.0.1:5000` and keeps its database and audit signing key in `data/`.

**Terminal 2: the web UI**

```bash
python -m client.web
```

Open http://127.0.0.1:8000. The web UI runs on your machine and talks to the server. Private
keys are created and kept on the client side in `client_data/<username>/` and never sent to the
server.

There is also a terminal client with the same features:

```bash
python -m client.cli --user alice --register   # once: makes your keys and registers
python -m client.cli --user alice              # log in and get a whisper> prompt
```

Type `help` at the prompt to see the commands available to your roles.

## First-time setup

1. In the web UI, register four accounts: `admin`, `alice`, `bob`, `mod` (passwords need at
   least 10 characters).
2. There is no admin yet to approve anyone, so promote the first one from the server machine:

   ```bash
   python -m server.manage promote-admin admin
   ```

3. Log in as `admin`, open **Admin**, and approve the others: `alice` as sender, `bob` as
   recipient, `mod` as moderator.
4. Click **Start a new round**. Senders can only get a token once a round is open.

## Demo walkthrough

To be logged in as two people at once, use a normal window and a private window.

1. **Send.** Log in as `alice` (her token for the round is picked up at login). Open **Send**,
   choose `bob`, and send a message.
2. **Receive.** Log in as `bob` and open **Inbox**. The message is decrypted in the client.
3. **One per round.** Try sending a second message as `alice`. It's refused until the admin
   starts a new round and she logs in again.
4. **Flag.** As `bob`, open **Flag this message**, give a reason, tick the confirmation, and flag it.
5. **Moderate.** Log in as `mod` and open **Moderation**. The flagged text, reason, and token id
   are shown, but not who sent or received it. Click **Freeze token**. The message disappears from
   bob's inbox. **Unfreeze token** puts it back.
6. **Audit.** As `mod` or `admin`, open **Audit log** and click **Verify chain and signatures**.

Things worth trying:

- Send a message containing `<script>alert(1)</script>`. It shows up as plain text.
- As `alice`, go to http://127.0.0.1:8000/inbox directly. The menu hides the page, and the server
  refuses the request anyway.
- Try to give `admin` the moderator role as well. It's refused (separation of duties).

## Checking the audit log

On the server machine:

```bash
python -m server.manage verify-log
```

This recomputes the hash chain, checks every signature, and prints the current head hash.

## Starting over

Stop both programs and delete the data:

```bash
rm -rf data client_data
```

## Project layout

```
server/                 the server (JSON API only, no pages)
  app.py                builds the Flask app, deny-by-default check, error handlers
  db.py                 schema, constraints, transactions
  rbac.py               role-permission policy and the decorators that enforce it
  auth.py               password hashing, lockout, sessions
  audit.py              append-only, hash-chained, signed audit log
  rounds.py             rounds, epochs, and the token signing keys
  alerts.py             alert rules
  routes_auth.py        register, login, logout, key change requests
  routes_admin.py       approvals, roles, keys, rounds, policy
  routes_sender.py      blind-signed token issuance
  routes_messages.py    directory, anonymous sending, inbox, flagging
  routes_moderation.py  flag queue, freeze/unfreeze, alerts, audit
  manage.py             promote-admin and verify-log commands
common/                 code used by both sides
  blind_rsa.py          blind RSA signatures (full-domain hash)
  envelope.py           message envelope, signatures, commitment check
  pubkey.py             key loading and fingerprints
client/
  core.py               all client logic (keys, tokens, encryption, pinning)
  cli.py                terminal client
  web.py                local web UI
  keys.py, crypto.py    key storage, pinning, hybrid encryption
  templates/, static/   web UI pages and stylesheet
tests/                  pytest suite
docs/                   report, design document, tables, audit log sample
```
