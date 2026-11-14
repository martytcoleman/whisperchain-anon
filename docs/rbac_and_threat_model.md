# RBAC Matrix and Threat Model

## Role-Permission Matrix

The policy is the `ROLE_PERMISSIONS` dictionary in `server/rbac.py`. Every server endpoint
declares its rule with a decorator, and an endpoint without one is refused (deny by
default). `tests/test_rbac.py` has this matrix typed out by hand and checks every role
against every permission, so the table and the code can't drift apart. A denied request gets
403 and an `access_denied` audit entry.

"Anon" means a request with no login.

| Permission | Action | Endpoint(s) | Sender | Recipient | Moderator | Admin | Anon |
|---|---|---|:-:|:-:|:-:|:-:|:-:|
| (public) | Register (account starts pending) | `POST /register` | - | - | - | - | Yes |
| (public) | Log in | `POST /login` | Yes | Yes | Yes | Yes | - |
| (login) | Log out, see own roles, request a key change | `POST /logout`, `GET /me`, `POST /me/key` | Yes | Yes | Yes | Yes | No |
| (public) | Get the current round's public signing key | `GET /round` | Yes | Yes | Yes | Yes | Yes |
| `user:approve` | List users, approve or reject a registration | `GET /admin/users`, `POST /admin/users/<id>/approve`, `.../reject` | No | No | No | Yes | No |
| `role:assign` | Change a user's roles | `POST /admin/users/<id>/roles` | No | No | No | Yes | No |
| `key:approve` | Approve a user's new public key | `POST /admin/users/<id>/key/approve` | No | No | No | Yes | No |
| `round:manage` | Start a new round | `POST /admin/rounds` | No | No | No | Yes | No |
| `policy:set` | View or change the flag threshold and token lifetime | `GET`/`POST /admin/policy` | No | No | No | Yes | No |
| `directory:read` | Look up recipients and their public keys | `GET /directory` | Yes | Yes | Yes | Yes | No |
| `token:request` | Get a blind-signed token (one per epoch) | `POST /tokens` | Yes | No | No | No | No |
| (token) | Send a message: needs a valid, unspent, unfrozen token and no login | `POST /messages` | via token | No | No | No | With token only |
| `inbox:read` | Fetch your own inbox (ciphertext only) | `GET /inbox` | No | Yes | No | No | No |
| `flag:create` | Flag a message in your own inbox | `POST /inbox/<id>/flag` | No | Yes | No | No | No |
| `moderation:read` | View the flag queue | `GET /moderation/flags` | No | No | Yes | No | No |
| `flag:resolve` | Dismiss a flag | `POST /moderation/flags/<id>/dismiss` | No | No | Yes | No | No |
| `token:freeze` | Freeze or unfreeze a token | `POST /moderation/tokens/<id>/freeze`, `.../unfreeze` | No | No | Yes | No | No |
| `audit:read` | Read and verify the audit log | `GET /audit`, `GET /audit/verify` | No | No | Yes | Yes | No |
| `alerts:read` | View alerts | `GET /alerts` | No | No | Yes | Yes | No |
| (none) | Decrypt a message | client only | No | Own only | No | No | No |
| (none) | Learn who sent a message | nowhere | No | No | No | No | No |

Additional rules:

- **Separation of duties:** no account can be both Admin and Moderator, and nobody can change
  their own roles (`check_role_change` in `server/rbac.py`).
- **Object ownership:** a Recipient only sees and flags messages where `recipient_id` is their
  own id. Being a Recipient doesn't give access to other recipients' messages.
- **Sending is a capability, not a role check.** The server never checks "is this user a
  Sender?" at send time, because that would identify the sender. RBAC decides who can get a
  token, and the token authorizes the send. `POST /messages` refuses any request that carries
  a login.
- **The last two rows are properties of the design,** not rules I enforce: the server has no
  private keys and stores no sender identity, so there is nothing to grant.

## Threat Model

**Assets:** message contents, sender anonymity, metadata (who receives how much, and when),
audit log integrity, fair quotas, availability.

**Adversaries:** a curious or malicious server operator or Admin, a malicious Sender, a
malicious Recipient, a curious Moderator, an outsider who steals the database, a network
observer.

**High-value targets:** the epoch signing key (can mint tokens), the audit signing key (can
re-sign a rewritten log), the Admin account (controls roles and keys), users' private keys.

| # | Threat | Impact | Defense | Residual risk |
|---|---|---|---|---|
| T1 | Compromised Admin or server tries to read messages | Confidentiality | End-to-end encryption; private keys exist only on clients; no endpoint returns content to an Admin | None for existing messages. Future messages are at risk only combined with T3. |
| T2 | Compromised Admin or server tries to identify senders | Anonymity | Blind signatures, so issuing a token can't be matched to using it; no sender id on messages or sender-side log entries; the issuance table is deleted when each epoch ends; sender-side log times rounded to the hour | Timing and traffic analysis (T9) |
| T3 | Public key substitution: an Admin approves an attacker's key in place of Bob's | Future confidentiality | Clients pin each recipient's fingerprint on first use and refuse to send if it changes; key approvals are signed audit events with the fingerprint; users can compare fingerprints in person | Trust on first use: a key swapped before first contact is only caught by an in-person fingerprint check |
| T4 | Compromised Admin creates fake Senders, or the signing key leaks and tokens are minted | Spam, quota bypass | Registrations and role grants are signed audit events; an alert fires if more distinct tokens are used in an epoch than the server issued | Minted tokens verify like real ones. With a single issuer this can be detected, not prevented. |
| T5 | A Sender shares their token | Accountability | A token is still only good for one message per round; a freeze applies to whoever holds it | Inherent to bearer tokens |
| T6 | Token forgery, reuse, or replay | Quota bypass | RSA-3072 blind signatures over a full-domain hash of `epoch || token public key`; a new signing key every epoch; the `spent_tokens` primary key allows one message per token per round, even under concurrent requests; the token key's signature covers the round and recipient | Nothing practical without the signing key (T4) |
| T7 | Flooding or denial of service | Availability | One token and one message per round; 64 KB request limit; account lockout after 5 failed logins; an alert after 5 invalid tokens in a round | Bounded by the number of Senders. Network-level DoS is out of scope. |
| T8 | Repudiation | Accountability | Each message is signed by a blind-certified token key; Admin and Moderator actions are logged with their user id and signed; flags are checked against the sender's commitment | Accountability attaches to the anonymous token, not a person, on purpose. Log signatures are only as trustworthy as the audit key (T12). |
| T9 | Metadata and traffic analysis | Anonymity | Tokens are fetched at login, separately from sending; the send uses a fresh connection with no login; no IP addresses or exact send times are stored | Someone watching live traffic can still correlate "Alice logged in" with "a message arrived soon after", especially with few users. Fixing that needs Tor or a mix network. |
| T10 | Fraudulent flagging | Unfair moderation | Verifiable reveal: the revealed key must match the sender's signed commitment and decrypt the ciphertext; alerts never freeze automatically | Many people flagging harmless content is a policy problem |
| T11 | Curious Moderator | Privacy | Moderators only see content a recipient chose to reveal, never the recipient or sender; Admin/Moderator separation; moderator actions are logged | Flagged content is disclosed on purpose |
| T12 | Audit log tampering | Accountability | Append-only triggers, hash chain, Ed25519 signature on every entry; moderators' clients save the latest head hash and check it is still present next time | Someone with both the database and the audit key can rewrite history after the last saved head |
| T13 | Database theft | Confidentiality | Only ciphertext stored; scrypt password hashes; session ids stored as hashes | Metadata such as message counts per recipient per round |
| T14 | Privilege escalation, insecure direct object references | All | Deny by default; one policy table; ownership checks; separation of duties; a test for every matrix cell | Bugs in my own code |
| T15 | Script injection through message text (XSS in the web UI, escape codes in the terminal) | Key theft, actions as the victim | Jinja autoescaping (no `\|safe` anywhere, checked by a test); a Content-Security-Policy that allows no scripts at all; the server serves no HTML; the CLI strips control characters before printing | A future template mistake, partly backstopped by the CSP |
| T16 | Other websites attacking the local UI (CSRF, DNS rebinding) | A malicious page makes the user send, flag, or approve | Binds to 127.0.0.1 only; CSRF token on every form including login; `SameSite=Strict` cookie; Host header must be `127.0.0.1` or `localhost` on the right port; state changes only via POST | A compromised local machine is out of scope |
| T17 | Stolen client key file | Confidentiality for that user | The private key file is encrypted with the user's password and readable only by the owner; it never leaves the client | The same password is used to log in, so a malicious server that also obtains the key file could decrypt it. Separate passwords would fix this at a usability cost. |
