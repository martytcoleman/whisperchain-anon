# WhisperChain+ Design Document

Milestone 1: System Design and Threat Model

## 1. System Overview

WhisperChain+ lets people in a learning community (students, TAs, faculty) send each other
anonymous compliments. The two properties I care about most pull in opposite directions.
Senders have to be anonymous, and message contents have to stay private. But the system
also needs enough accountability to deal with abuse. Most of the design below is about
balancing those two goals without leaning on any single party being trustworthy.

I tried to keep the number of security mechanisms small and make each one count. Every
mechanism in the design exists because the spec requires it or because it addresses a
specific threat in Section 5:

| Mechanism | What it's for |
|---|---|
| RBAC policy table checked on every request | Role enforcement for all identified actions |
| Blind-signed anonymous tokens | Unlinkable tokens, one per sender per round, anonymous sending |
| Hybrid end-to-end encryption (RSA-OAEP + AES-GCM) | Message confidentiality, including at rest |
| Key commitment with verifiable flag reveal | Lets moderators trust flagged content; prevents framing |
| Append-only, hash-chained, signed audit log | Accountability and tamper evidence |
| Database uniqueness constraints | One message per round, even under concurrent requests |
| Flag-threshold alerts and token freezing | Abuse response |

### 1.1 How it works

A user registers with a username, a password, and a public key that their client generates
locally. The account starts out pending. An Admin approves it and assigns a role. From
then on the user logs in normally.

At the start of each round, a Sender asks the server for a token. The client makes a fresh
key pair for the token, blinds it, and sends the blinded value to the server. The server
checks that the user is a Sender and hasn't already received a token this round, then signs
it. The client unblinds the signature and ends up with a valid signed token. The server
never saw that token in unblinded form, so it has no way of recognizing it later.

To send a compliment, the client looks up the recipient's public key, encrypts the
message, signs it with the token's key, and submits it without logging in. The only
thing that authorizes the request is the token. The server checks that the token's
signature is valid for the current round, that the token hasn't been used, and that it
hasn't been frozen. If those checks pass, it stores the ciphertext.

Recipients download their inbox and decrypt it on their own machine. If a message is
abusive, the recipient can flag it, which means revealing the message key to the server.
The server confirms the key actually matches what the sender committed to, and only then
puts the decrypted message in the moderator queue. Moderators review flagged messages and
can freeze the token that sent one. Every significant action goes into an append-only,
signed audit log that never records who sent what.

### 1.2 Architecture

```
  User's machine                                          Server
  +-------------------------------------------+          +------------------------------------+
  |  Browser --> local web UI (127.0.0.1)     |          |  Flask + SQLite, JSON API only     |
  |  Terminal --> CLI                         |  login   |                                    |
  |            \      /                       | -------> |  - accounts, roles, RBAC checks    |
  |       client core library (Python)        |          |  - blind-signs tokens              |
  |   - generates and holds private keys      |  send    |  - stores ciphertext only          |
  |   - blinds / unblinds tokens              | -------> |  - moderation queue and alerts     |
  |   - encrypts / decrypts messages          | (token,  |  - signed, hash-chained audit log  |
  |   - pins recipients' key fingerprints     | no login)|  - serves no web pages             |
  +-------------------------------------------+          +------------------------------------+
```

There are two interfaces, a terminal CLI and a simple web UI, and both sit on top of the
same client library. All of the cryptography lives in that one library, so there's only
one implementation to get right.

The web UI runs on the user's own machine instead of being served by the server. That
might seem like an odd choice, but it matters. Whoever serves the UI code effectively
controls the private keys. If the server shipped the JavaScript that handles your keys,
a compromised server could quietly ship a version that steals them, and end-to-end
encryption would be meaningless. Running the UI locally keeps keys inside the user's trust
boundary. It also means the server has no HTML at all, so it isn't exposed to cross-site
scripting.

### 1.3 What I trust

Two rules shape the system. First, secrets stay on the client: the server only ever sees
public keys and ciphertext. Second, sending is anonymous: messages are submitted with a
token instead of a login.

| Component | Trusted for | Not trusted for |
|---|---|---|
| User's device (CLI and local web UI) | Holding their private keys, encrypting and decrypting | If it's compromised, that user's messages are exposed, and there isn't much the system can do about that |
| Server | Availability, and enforcing the rules (RBAC, quotas, freezes) | Message confidentiality or sender anonymity. Those are protected cryptographically, so they hold even if the server is curious or malicious. |
| Admin | Approving users, roles, keys, and policy | Reading messages or identifying senders. The Admin account is a high-value target (see T1 through T4). |
| Moderator | Judging flagged content | Seeing unflagged content or anyone's identity |
| Public key directory | Distributing keys, only to the extent users verify fingerprints | Being honest by default (see T3) |
| Other websites in the user's browser | Nothing | Must not be able to drive the local UI (T16) |
| Message text | Nothing; it's written by an anonymous, possibly malicious sender | Must never be rendered as HTML (T15) |

### 1.4 Rounds, tokens, and the freezing problem

A **round** is a messaging period (say, a week) that the Admin starts. A **token** is an
Ed25519 public key that the server has blind-signed with that round's signing key. Each
Sender gets one token per round, and each token can send one message.

The spec asks for two things that don't fit together cleanly:

- Tokens are anonymous and unlinkable, one per round, and each Sender gets one message per round.
- Moderators can freeze tokens to block future abuse from anonymous sources.

Blocking someone's future messages means recognizing their future messages, and
recognizing them means they're linkable to the earlier ones. So I can't have full
round-to-round unlinkability and freezes that follow the sender into later rounds at the
same time. This is a real tradeoff between privacy and accountability, not an
implementation detail. I considered three options:

| Option | Privacy | Accountability | Complexity |
|---|---|---|---|
| A. Fresh token every round | Strongest. Nothing connects one round to the next, even for the server. | A freeze revokes the token immediately and withdraws its message, but the sender gets a new, unrecognizable token next round. Damage is capped at one message per round. | Lowest |
| B. Token valid for N rounds | Weaker. The server can tell that the same pseudonym sent messages across N rounds, though not who it is. | A freeze blocks the rest of the N rounds, and counting flags per token becomes meaningful. | Same code with a different setting |
| C. Escrowed identity (cut-and-choose or group signatures) | Unlinkable until an abuse threshold is hit | Full | High, and easy to get subtly wrong |

I'm going with **Option A as the default**, because it matches the spec's anonymity
requirement exactly. In this mode, freezing a token means a few concrete things:

- the token is revoked immediately
- any further attempt to use it is rejected and raises an alert
- the message it sent is withdrawn from the recipient's inbox

Repeat abuse is still bounded, because nobody can get more than one token per round.

The token lifetime is also an Admin policy setting, `token_validity_rounds`, defaulting to
1. Raising it switches to Option B. That costs one integer in the code and lets me show the
tradeoff in action. I don't claim that Option B gives the same anonymity as Option A; it
deliberately gives some up in exchange for longer-lasting freezes. Option C would satisfy
both goals, but it brings in a lot more cryptography than I can implement
and verify with confidence in a project of this size, so I left it out.

---

## 2. Roles

One account can hold multiple roles. Most users will be Recipients, and some will also be
Senders. I enforce one separation-of-duties rule: the same account can never be both an
Admin and a Moderator, and Admins can't change their own roles.

**Sender.** Can request one anonymous token per round and send one encrypted message per
round. Sending happens without logging in, so the server can't tell which Sender sent a
given message.

**Recipient.** Receives messages addressed to them, decrypts them locally, and can flag
abusive messages in their own inbox. Flagging is a deliberate choice to reveal that one
message to the moderators.

**Moderator.** Reviews the flagged message queue. For each flagged message they see the
plaintext, the reason, the round, and the token id. They don't see the recipient's
identity, any unflagged message, or anything about who the sender is. Moderators can
freeze and unfreeze tokens and can review the audit log and alerts.

**Admin.** Approves registrations, assigns and revokes roles, approves public keys, starts
rounds (which rotates the token signing key), and sets policy like the alert threshold and
token lifetime. Admins see meta-events only. There is no endpoint that gives an Admin
message content or sender information, and since messages are end-to-end encrypted, an
Admin couldn't read them even with direct database access.

---

## 3. Role-Permission Matrix

"Anon" means an unauthenticated request. Each permission name below corresponds directly
to an entry in the server's policy table (`server/rbac.py`), and every row is covered by a
test. Denied requests return 403 and are recorded in the audit log as `access_denied`.

| Permission | Action | Sender | Recipient | Moderator | Admin | Anon |
|---|---|:-:|:-:|:-:|:-:|:-:|
| (none) | Register (starts pending, includes public key) | - | - | - | - | Yes |
| (none) | Log in / log out | Yes | Yes | Yes | Yes | - |
| `user:approve` | Approve or reject a registration and assign the initial role | No | No | No | Yes | No |
| `role:assign` | Grant or revoke roles (separation of duties is checked) | No | No | No | Yes | No |
| `key:approve` | Approve or replace a user's public key | No | No | No | Yes | No |
| `directory:read` | Look up a recipient's public key | Yes | Yes | Yes | Yes | No |
| `round:manage` | Start a new round and its signing key | No | No | No | Yes | No |
| `policy:set` | Change the alert threshold or token lifetime | No | No | No | Yes | No |
| `token:request` | Get a blind-signed token (one per round) | Yes | No | No | No | No |
| (token) | Send a message, which requires a valid, unused, unfrozen token | via token | No | No | No | With token only |
| `inbox:read` | Fetch your own inbox (ciphertext) | No | Yes | No | No | No |
| (client-side) | Decrypt a message; the server has no keys to do this | No | Own only | No | No | No |
| `flag:create` | Flag a message in your own inbox | No | Yes | No | No | No |
| `moderation:read` | View the flagged queue and alerts (moderator dashboard) | No | No | Yes | No | No |
| `token:freeze` | Freeze or unfreeze a token | No | No | Yes | No | No |
| `audit:read` | Read and verify the audit log | No | No | Yes | Yes | No |
| `alerts:read` | View alerts | No | No | Yes | Yes | No |
| (none) | View any unflagged message | No | Own only | No | No | No |
| (none) | Learn who sent a message | No | No | No | No | No |

The last row is a property of the design rather than a rule I enforce. No endpoint exposes
sender identity, and the server never stores it in the first place.

---

## 4. Access Control Plan

I use a hybrid model: **role-based access control** for everything a logged-in user does,
and **capabilities** for the one action that has to stay anonymous.

### 4.1 RBAC for identified actions

The policy lives in one place, a dictionary called `ROLE_PERMISSIONS` in `server/rbac.py`
that maps each role to its set of permissions. It's the code version of the matrix in
Section 3, kept short enough to audit by reading it.

Every endpoint is wrapped in a `@require_permission("...")` decorator, which checks, in
order:

1. the session is valid
2. the account is active
3. at least one of the user's roles grants the permission

If any check fails, the request is denied. An endpoint with no declared permission is also
denied, so the default is fail-safe. Authorization runs server-side on every request, and
decisions aren't cached. The UI hides pages a user's roles don't allow, but that's a
convenience only; the server is the only thing actually enforcing access.

Some checks depend on the specific object, not just the role. A Recipient can only read
and flag messages where `recipient_id` is their own user id, which stops someone from
just changing a message id in a request to get at another user's data.

Separation of duties is checked whenever roles are assigned: Admin and Moderator are
mutually exclusive, and nobody can modify their own roles. And there is no "admin
override" anywhere. No endpoint returns message content to an Admin, and even if one were
added by mistake, the content is end-to-end encrypted.

### 4.2 Capabilities for anonymous sending

Sending can't go through RBAC. If the server checked "is this user a Sender?" at send
time, it would learn who sent the message. So RBAC controls who can get a token
(`token:request` is granted only to Senders), and the token itself acts as a capability:
holding a valid one is what authorizes the send. The send endpoint doesn't accept a
session at all, and the client deliberately leaves off cookies and auth headers on that
request.

| Request type | Model | What's checked |
|---|---|---|
| Logged-in actions | RBAC | session, then user, then roles, then permission, then object ownership |
| Sending a message | Capability | blind signature valid under the round key, token unused, token not frozen, message signature valid |

### 4.3 Concurrency

Quotas are enforced with database UNIQUE constraints inside a single transaction. I
never check a quota first and insert afterward, because two concurrent requests could both
pass the check before either one inserts.

- **Token issuance:** the server inserts `(user_id, round)` into the issuance table before it signs anything. A second concurrent request fails on the constraint.
- **Sending:** the token's public key goes into `spent_tokens` in the same transaction that stores the message, so one token yields exactly one message.
- **Freezes:** the freeze check and the spend happen together inside a `BEGIN IMMEDIATE` transaction.

---

## 5. Threat Model

**Assets:**
- message contents
- sender anonymity
- metadata (who receives how much, and when)
- audit log integrity
- fair quotas
- service availability

**Adversaries:**
- a curious or malicious server operator or Admin
- a malicious Sender (spam, harassment)
- a malicious Recipient (false flags)
- a curious Moderator
- an outside attacker who steals the database
- a network observer

**High-value targets:**
- the round signing key, since anyone holding it can mint tokens
- the audit signing key, since anyone holding it can re-sign a rewritten log
- the Admin account, which controls roles and keys
- users' private keys

For each threat I try to be honest about what's left over after my defenses, rather than
claiming more than the design delivers.

| # | Threat | Impact | Defense | Residual risk |
|---|---|---|---|---|
| T1 | Compromised Admin or server tries to read messages | Confidentiality | End-to-end encryption with private keys only on clients; no endpoint returns content to an Admin | None for existing messages. Future messages are at risk only if combined with T3. |
| T2 | Compromised Admin or server tries to identify senders | Anonymity | Blind signatures mean issuance can't be matched to use; no user id is stored on messages or sender-side log entries; the issuance table is deleted when each round ends | Timing and traffic analysis (T9) |
| T3 | Public key substitution: the Admin approves an attacker's key in place of Bob's | Future confidentiality | Clients pin each recipient's key fingerprint the first time they use it and refuse to send if it changes; key approvals are signed audit events; users can compare fingerprints in person | This is trust on first use. If the key is swapped before the first contact, pinning doesn't catch it; only an out-of-band fingerprint check does. I'm assuming the directory is honest at first contact. |
| T4 | Compromised Admin creates fake Sender accounts or mints tokens (Sybil attack) | Spam, quota bypass | Registrations and role grants are signed audit events; an alert fires if tokens issued in a round exceed the number of active Senders | Anyone with the round signing key can mint tokens directly. With a single issuer there's no way to fully prevent that. |
| T5 | A Sender shares their token with someone else | Accountability | Sharing doesn't create extra messages, since each token is good for one; a freeze applies no matter who used the token | This is inherent to bearer credentials. I can limit the damage, not prevent sharing. |
| T6 | Token forgery, reuse, or replay | Quota bypass | RSA-3072 with a full-domain hash; a UNIQUE `spent_tokens` table; the round id is part of what's signed, so old tokens don't validate; the message signature covers the round and recipient | Nothing practical without the signing key (see T4) |
| T7 | Flooding or denial of service | Availability | One token and one message per round, request size limits, login rate limiting, an alert on repeated invalid tokens | Bounded by the number of Senders. Network-level DoS is out of scope. |
| T8 | Repudiation ("I didn't send that" or "the server made that up") | Accountability | Each message is signed by a token key the server blind-certified, so it provably came from a valid token holder and can't be forged under that token without its private key. Privileged actions are logged with the actor's id and signed. Flags are checked against the sender's commitment. | Nonrepudiation here attaches to the anonymous token, not to a person, and that's intentional. The server's own log signatures only prove that the server recorded something, and are only as trustworthy as the server's key (T12). |
| T9 | Metadata and traffic analysis | Anonymity, privacy | Encryption protects contents, not metadata; the server still knows the recipient, the round, and when a request arrived. To reduce correlation, tokens are fetched separately from sending (e.g. at the start of the round), the client can add a random delay before sending, and the server doesn't log IP addresses or exact send times. | Someone watching live server traffic can still notice "Alice logged in, and an anonymous send showed up seconds later," especially with only a handful of users. Defeating that properly needs something like Tor or a mix network, which is out of scope. |
| T10 | Fraudulent flagging | Unfair moderation | Verifiable reveal (Section 6.4); alerts never freeze a token automatically, a moderator decides | Many people flagging harmless content is a policy problem, not a cryptographic one |
| T11 | Curious Moderator | Privacy | Moderators only see content a recipient chose to reveal, never identities; the Admin/Moderator separation of duties; moderator actions are logged | Flagged content is disclosed to moderators on purpose |
| T12 | Audit log tampering | Accountability | Append-only table, hash chain, per-entry signatures, and periodically copying the latest hash off the server (Section 7) | Someone with both the database and the audit key can rewrite history after the last copied hash |
| T13 | Database theft | Confidentiality | Only ciphertext is stored; passwords are hashed with scrypt; session ids are stored hashed | Metadata like per-round message counts per recipient is exposed |
| T14 | Privilege escalation or insecure direct object references | All | Deny by default, a single policy table, ownership checks, separation of duties, a test for every matrix row | Bugs in my own code, which I try to limit by keeping the attack surface small and testing it |
| T15 | Cross-site scripting through message text: a sender puts `<script>` in a compliment so it runs in the recipient's or a moderator's browser | Key theft, actions taken as the victim | Jinja autoescaping on every template (I never use `\|safe`); a strict Content-Security-Policy with no inline scripts; the server serves no HTML | A mistake in a template, which a dedicated test checks for |
| T16 | Other websites attacking the local UI (CSRF, DNS rebinding against 127.0.0.1) | A malicious page makes the user send, flag, or approve something | The UI binds to 127.0.0.1 only; every form carries a per-session CSRF token; the Host header must match 127.0.0.1 and the port; all state changes use POST; the private key is unlocked only after the user enters their password | A compromised local machine, which is out of scope |

---

## 6. Cryptographic Design

All the primitives come from Python's `cryptography` library. The one piece I write
myself is the blinding arithmetic for blind RSA, which is a few lines of modular math
with Python's built-in `pow`. Blind RSA doesn't have a high-level API, so Section 6.2
covers the pitfalls I'm guarding against.

### 6.1 Keys

| Key | Algorithm | Where the private key lives | Purpose |
|---|---|---|---|
| User encryption key | RSA-3072 with OAEP-SHA256 | Client only, encrypted with the user's password | Receiving messages |
| Token key | Ed25519, new for every token | Client only | Signing the one message the token sends |
| Round signing key | RSA-3072, new each round | Server | Blind-signing tokens |
| Audit log key | Ed25519 | Server, in a separate key file | Signing log entries |

### 6.2 Token issuance (Chaum-style blind RSA)

```
Sender's client                                     Server (round key: n, e, d)

1. make a new token key pair (sk_t, pk_t)
2. m = FDH(round_id || pk_t)
3. pick random r, compute blinded = m * r^e mod n
4. POST /tokens (logged in, sends only blinded) -->
                                                    5. check the user has the Sender role
                                                    6. INSERT issuance(user_id, round), UNIQUE
                                                    7. s' = blinded^d mod n
                              <-- s'
8. s = s' * r^-1 mod n, so s = m^d
9. check s^e == m mod n
   token = (round_id, pk_t, s)
```

FDH is a full-domain hash: SHA-256 output expanded to the full size of the RSA modulus.

The reason this is unlinkable is that `blinded` is uniformly random because of `r`, so the
server learns nothing about `m` when it signs. When the token is spent later, the server is
seeing `(pk_t, s)` for the first time and has nothing that would tie it back to a specific
issuance request. That holds even against an attacker with unlimited computing power,
because the blinding factor hides `m` completely.

Step 9 lets the client confirm the server actually signed honestly, rather than returning
something that would fail later.

I treat blind signatures as part of the core system rather than an extra, even though the
spec lists them as a bonus item. They're how the design actually meets the requirement
that tokens be unlinkable to identities. A plain server-issued pseudonym would only be
unlinkable if the server promised not to record who got which one, and I don't want
anonymity to depend on trusting the server.

Pitfalls I'm handling:
- Plain RSA is multiplicative, so signatures on two values can be combined into a signature on their product. Using a full-domain hash prevents that.
- Blind signing means the server signs whatever value it's given without seeing it. So the round key is used only for blind signing and never for anything else.
- Each round gets a new key, which limits the damage if one leaks.

### 6.3 Sending a message

The client does the following:

1. Generates a random AES-256-GCM key `k` and a nonce, and encrypts the compliment: `ct = AESGCM(k).encrypt(plaintext)`.
2. Wraps the key for the recipient with `wrapped_k = RSA-OAEP(recipient_pubkey, k)`. The recipient's key comes from the directory and is checked against the fingerprint pinned on first use.
3. Commits to the key: `commit = SHA-256(k)`.
4. Builds `envelope = {round, recipient_id, ct, nonce, wrapped_k, commit}` and signs it: `sig = Ed25519_sign(sk_t, envelope)`.
5. Posts `{envelope, sig, token}` to `/messages` with no session attached.

The server verifies the token and signature as described in Section 4.2. Then, in one
transaction, it marks the token spent and stores the message.

What gets stored: the recipient id (needed for delivery), the round, the ciphertext, nonce,
wrapped key, commitment, token public key, and signature.

What never gets stored: the sender's user id, IP addresses, the plaintext, the AES key, or
an exact send time. Messages only record which round they belong to.

### 6.4 Flagging with a verifiable reveal

The recipient decrypts locally. To flag a message, they send the server the message key
`k` along with a reason. The server accepts the flag only if both checks pass:
- `SHA-256(k)` matches the commitment the sender signed
- `AESGCM(k).decrypt(ct)` succeeds

Only then is the plaintext added to the moderator queue.

This means a recipient can't make up abusive content to frame a token, and moderators know
they're looking at exactly what was sent. It also covers the fact that AES-GCM on its own
isn't key-committing (a ciphertext can be crafted to decrypt under two different keys);
the signed commitment pins down the one key the sender used.

Flagging intentionally reveals that one message's contents to the moderators, and the UI
says so before the recipient confirms. Moderators see the plaintext, the reason, the
round, and the token id, but not the recipient's identity.

---

## 7. Audit Logging

Each log entry records a timestamp, an action, the role involved, and the minimum detail
needed to make sense of it.

| Event | Details | Identity recorded? |
|---|---|---|
| `user_registered`, `user_approved`, `role_assigned`, `key_approved`, `round_started`, `policy_changed` | Target user, new role or key fingerprint | Yes, the acting Admin. Privileged actions should be attributable. |
| `token_issued` | Round | No |
| `message_sent` | Round, token id (a hash of `pk_t`) | No, and the server doesn't know it anyway |
| `message_delivered` | Round, number of messages | No |
| `message_flagged` | Round, token id | No |
| `token_frozen`, `token_unfrozen` | Token id, reason | Yes, the acting Moderator |
| `access_denied` | Role, attempted permission | Role only |
| `alert_raised` | Rule, token id or round | No |

The guiding idea is to keep enough to hold privileged users accountable while recording
as little as possible about everyone else. A sender's actions can be traced to an
anonymous token, never to a person. I don't log IP addresses or user agents. The two events that come from anonymous senders, `token_issued` and `message_sent`, get their timestamps rounded down to the hour, so the log can't be used to match "Alice was online at 10:01" against "a message was sent at 10:01." The issuance
table is the only place that links a user to a round, and it exists only to enforce the
one-token-per-round quota, so I delete it as soon as the round ends.

For tamper evidence, the log is built up in layers:

- **Append-only.** The application has no code path that updates or deletes log entries, and SQLite triggers reject UPDATE and DELETE on the table.
- **Hash-chained.** Each entry stores the previous entry's hash: `entry_hash = SHA-256(prev_hash || canonical_json(entry))`. Changing any past entry breaks every hash after it.
- **Signed.** Each `entry_hash` is signed with the server's Ed25519 audit key.
- **Verifiable.** A `verify-log` command recomputes the whole chain, checks every signature, and reports the first entry that doesn't check out.

It's worth being clear about what this does and doesn't protect against. It makes tampering
detectable, not impossible. Someone who has both the database and the audit signing key
could rewrite the whole log and re-sign it. The practical defense is to periodically copy
the latest `entry_hash` somewhere off the server, for example by having a moderator record
it. Any rewrite of history before that point then becomes obvious. A Merkle tree would add
efficient inclusion proofs on top of this, but it wouldn't close that gap, which is part of
why I consider it optional.

---

## 8. Security Testing Plan

Meeting the requirements on paper doesn't make the system secure. So each mechanism gets
adversarial tests (in pytest) that try to break the property it's supposed to enforce.

| Area | Tests |
|---|---|
| RBAC and privilege escalation | Every role tried against every permission, with the expected results copied by hand from the matrix in Section 3, so the matrix and the code can't drift apart; missing or expired sessions get 401; an Admin granting themselves Moderator is refused; a Recipient reading or flagging someone else's message id gets 403 |
| Compromised Admin | An Admin session calling inbox, moderation, and message endpoints gets 403; a dump of the database contains no plaintext and no sender ids (the test searches the database file for the plaintext) |
| Token forgery, reuse, replay | A random signature is rejected; a token from round 1 is rejected in round 2; sending twice with the same token fails the second time; tampering with the message signature is rejected; a Recipient-only user calling `/tokens` gets 403; a second token request in the same round is rejected |
| Race conditions | 20 threads sending with the same token at once: exactly one succeeds; 20 concurrent token requests from one user: exactly one succeeds |
| Unlinkability | Issue tokens to two users, spend them in random order, and confirm nothing the server stored matches a spent token to its issuance request |
| Message tampering | Flipping a byte in the ciphertext, wrapped key, or commitment is caught by the signature check or by GCM authentication |
| Fraudulent flagging | Flagging with the wrong key is rejected; flagging with a valid key from a different message is rejected |
| Freezing | Sends from a frozen token are rejected and raise an alert; the frozen token's message is withdrawn from the inbox |
| Audit log | Modifying, deleting, or reordering an entry is caught by `verify-log`, which reports the exact entry; SQL UPDATE and DELETE are blocked by the triggers; every security-relevant action produces exactly one log entry |
| Metadata leakage | After a send, scan every log entry and table for the sender's user id or an IP address and find none; the issuance table is empty once the round ends |
| Web UI | A message containing `<script>` renders escaped in both the inbox and the moderator queue; a POST without a CSRF token gets 403; a foreign Host header gets 403; pages for roles the user doesn't have are hidden, and the server still rejects the underlying calls |

---

## 9. Requirements Coverage

This maps each required item from the project spec to where the design handles it.

| Requirement | How I meet it | Section | Verified by |
|---|---|---|---|
| Four roles, clearly enforced | `ROLE_PERMISSIONS` and `@require_permission` | 2, 3, 4 | RBAC matrix tests |
| Role-permission matrix | Section 3, mirrored in code | 3 | Generated matrix test |
| Access control model (ACL, capability, or rule-based) | Hybrid RBAC plus capability tokens | 4 | |
| Threat model covering admin compromise, shared tokens, and nonrepudiation, with at least 3 threats and defenses | T1 to T4, T5, T8, plus twelve more | 5 | |
| System overview and role descriptions | Sections 1 and 2 | 1, 2 | |
| Registration with an assigned role | Register, then the Admin approves and assigns a role | 1.1, 3 | Registration tests |
| Anonymous, unlinkable tokens, one per round | Blind RSA, UNIQUE issuance, new key each round | 1.4, 6.2 | Forgery, reuse, and unlinkability tests |
| Only Senders can submit messages | `token:request` is Sender-only, and sending requires a token | 4.2 | Role tests |
| Only Moderators can view flagged content | `moderation:read` is Moderator-only | 3 | Role tests |
| Admin can't view unflagged messages or sender info | No such endpoint, end-to-end encryption, no sender data stored | 4.1, 6.3 | Compromised-Admin tests |
| Logging of token issuance, sending, and flagging | Audit calls at each event | 7 | Log coverage test |
| A key pair for each user at signup | The client generates an RSA-3072 pair at registration | 6.1 | |
| Message submission using tokens | The `send` command and web form, posting anonymously to `/messages` | 6.3 | Send tests |
| Encryption with the recipient's public key; end-to-end with RSA or ECC | RSA-OAEP wrapping an AES-GCM key | 6.3 | Tampering tests |
| Stored with no readable metadata, encrypted at rest, no sender name | Ciphertext only, no sender id, IP, or exact time | 6.3 | Metadata leakage test |
| Recipients decrypt locally | Private keys exist only on the client | 6.1 | |
| Log time, action, and role, including delivery events, never sender identity | Log format in Section 7, including `message_delivered` | 7 | Metadata leakage test |
| One anonymous encrypted message per sender per round | One token per round, one message per token, UNIQUE constraints | 4.3 | Race condition tests |
| Recipients can flag; flagged messages go to a moderator queue | Verifiable reveal into the flag queue | 6.4 | Fraudulent flagging tests |
| Moderator dashboard; freezing tokens | Dashboard page and CLI view; `token:freeze` | 1.4, 3 | Freeze tests |
| Alerting rules, such as a flag threshold | Flags per round above the threshold raise an alert; repeated invalid tokens raise an alert | 5, 7 | Alert tests |
| Append-only, timestamped, tamper-resistant (signed) log | Triggers, hash chain, Ed25519 signatures | 7 | Tamper tests |
| Preventing spam, flooding, and identity abuse | Quotas, rate limits, alerts, separation of duties | 5 (T5 to T7) | Race and quota tests |
| Standard cryptographic libraries | Python `cryptography` | 6 | |
| Admin manages registration, roles, public keys, and policy | `user:approve`, `role:assign`, `key:approve`, `round:manage`, `policy:set` | 3 | Role tests |
| Final deliverables: repo and README, security report, RBAC matrix and threat model, sample audit log with analysis | `README.md` and the `docs/` folder | | |

Optional items from the spec that I'm not treating as core: a Merkle tree log, extra
intrusion detection rules, a public dashboard, and a demo video. Blind signatures are
already part of the core design, and the web UI's role-based pages are a start on the
role-adaptive front end.
