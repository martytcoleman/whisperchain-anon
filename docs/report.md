# WhisperChain+ Security Design Report

## 1. Goals and Threats

In this project, the goal was to build an anonymous compliment platform for an educational environment, in which students, TAs, and faculty may send and receive anonymous compliments. I set out to build four distinct roles into the system: Sender, Recipient, Moderator, and Admin. 

The security goals associated with this project were as follows:

- Confidentiality: the messages senders send should only be readable by the recipient and not the server itself or an admin.
- Anonymity: no one (server included) should be able to tell who sent a message
- Proper limiting: one message per sender per round (round being the period that an admin starts and lasts until they start the next one)
- Protection from abuse: Recipients can report/flag messages, after which moderators can shut down the token responsible for a malicious message. 
- Accountability: Keeping admins/mods responsible by logging all of their actions with their name, keeping logs tamper-evident. 
- Least privilege: Each role only gets exactly what it needs, and nothing more. Admin and moderator are kept entirely separate.

Underpinning my implementation are several trust assumptions. This design is based on trust in the server to properly run rules for logins, quotas, freezes, etc without interruption. Though I trust it to run the rules, I do not trust it to hold the secrets themselves, as message content is encrypted and the sender identity is never revealed to the server at all (i.e. even if malicious server, they are protected). The system also places trust in the client (each user's computer) - and, as we know, if the medium of communication (the pipe) is secure, professional attackers pursue the endpoints. Another factor worth considering is that someone monitoring the network could see timing of requests, which may provide useful, potentially-compromising intelligence.

In order to accomplish these goals, I had to engage with an important tradeoff we learned in class: the tradeoff between accountability and anonymity, as I had to figure out a way to properly respond/react to abuse from someone the system cannot identify. In short, the way I addressed this was by designing the system such that accountability attaches to the anonymous token and not the person behind that token.

In terms of threats, I'm defending against a malicious or nosy server/admin, abusive senders, recipients false flagging, curious moderators, someone who has stolen the DB, and a network observer. For a technical breakdown, the full threat model (T1–T17) and RBAC matrix are in `docs/rbac_and_threat_model.md` in this repo. 

## 2. How It Works



### Registration

Walking through registration, first the user's own computer makes an RSA key pair. From that pair, the private key never leaves their machine, and is saved encrypted with their password. The public key, plus their user/password goes to the server. Accounts start pending with no roles auto-applied. Admin user must approve it and pick the roles, and this role assignment is logged (with the admin's ID, to hold them accountable). Since the private key stays off the server, it can't decrypt the messages, working to preserve confidentiality.

### Getting a token

In order to enable the sending of a message, the server needs to verify that you're an approved sender who hasn't gotten a token yet this epoch. An epoch is how long one signing key (and thus one token) stays valid (by default in this project 1 epoch = 1 round). If it were to make that check at send time then it would be effectively learning the identity of the sender, defeating the anonymity. My approach to this is to bifurcate this such that you prove who you are once to get the token, and then send your message with the token with no login attached. The mechanism behind this is the blind signature that RSA enables - the server signs the token without ever technically seeing it, such that later it can tell the token is genuine but cannot make the connection to the person it was issued to. 

The flow:

1. Client makes a fresh token key pair w/ Ed25519 digital signature algorithm.
2. Client blinds the token's public key with a random number and sends the blinded value.
3. Server checks the login, sender role, and that there was no token yet this epoch, recording (user, epoch) before signature so 2 simultaneous requests can't both get a token.
4. Server signs, then client unblinds and thereby gets a real signature on the token that the server never saw (the blind signature scheme)
5. Client gets the token at login and sends it later when the message is actually sent (so requests don't necessarily immediately reveal identity of sender). Issuance record (from step 3) deleted when epoch over.



### Sending

Assume Alice now has her token from login, and now sends a message to Bob (`client/core.py`, `send`):
The process goes as follows:

1. Check Bob's key against the remembered key fingerprint if present. On the first time that Alice messages Bob her client remembers his key's fingerprint (the SHA256 hash of his RSA public key from registration). If the server handed out a different key for Bob, the client would refuse to send the message, protecting against an admin swapping in their own key.
2. Hybrid encryption.
  - make a random one-time AES symmetric key and encrypt the message with it (AES-GCM, fast, any length)
  - Encrypt that AES key with Bob's RSA public key so Bob and only Bob can decrypt it to get the key
  - include a commitment, which is a hash of the AES key (matters for flagging).
3. Sign the whole encrypted package with the token's Ed25519 key
4. Send it with no login attached - plain request with no session, no cookies, and a new connection (all so that nothing ties it to the logged in session). Server rejects any send that has a login attached by default because that would identify Alice, violating anonymity.

During that process the server checks the following:

1. the RSA signature on the token - real and from this epoch?
2. Ed25519 signature on the message - did the token holder send exactly this?
3. round and recipient - for the current round, to real recipient?
4. is the token frozen?
5. has the token already been used this round? (`spent_tokens` enforces limit)

Server stores only the ciphertext, recipient (for delivery), the round, and token ID. Does not store sender, IP, or exact time. 

### Reading

1. Bob, logged into the system, fetches `/inbox`, and the server returns only his own messages (`WHERE recipient_id = Bob`), still encrypted.
2. Bob's client decrypts using his RSA private key, unwrapping the AES key, and the AES key then decrypts the message. The server never sees the plaintext, and delivery logged with just a count.

### Flagging

If Bob receives a malicious message - he can report it. To do this, he has to show the mods the message without being able to fabricate one (malicious recipient).

The process:

1. Bob sends the server the flagged message's AES symmetric key and a reason for flagging it.
2. Server first checks: A. does hash(key) match the commitment the sender signed (tamper-resistance, ensures the key is the one that the sender used) and B. does the key actually decrypt the ciphertext
3. If both of those checks pass, the plaintext goes into the mod's queue.

This protects against recipients framing a token by fabricating malicious/abusive text, since he can't produce a key that matches the sender's signed commitment, so mods know they're seeing exactly what was sent.

Important to note: The moderator can see the text / reason / round / token id, but not who received or sent the message. The actions they can take are to dismiss it or to freeze the token, which blocks the token and withdraws the message from recipient's inbox. The moderator (a person) always makes the decision, so alerts never freeze anything on their own.

## 3. Access Control

My full RBAC matrix table is in `docs/rbac_and_threat_model.md`. 

As previously established, the four roles are Sender, Recipient, Admin, and Moderator. For RBAC, each role has a set of permissions (e.g. `inbox:read` or `token:freeze`), which are all present in one dictionary `ROLE_PERMISSIONS` in `server/rbac.py`.
Every server endpoint declares which permissions it needs with a decorator, e.g. `@require_permission("inbox:read")`, and on every request, the server then checks: valid session? --> active account? --> do your roles grant the needed permission? If they don't you get a 403 (logged as `access_denied`). 
Critical: Sending itself cannot use RBAC because if you had to check "is this person a sender" at send time, you'd have to identify the sender, defeating anonymity. RBAC thus only decides who can get a token and possessing the token is what authorizes the send. 

Some safety mechanisms / security principles I implemented:

- Least privilege: every role gets only what it needs, and nothing more.
- Separation of duties: no accounts can be both Admin and Moderator, Admin and Mod are separate roles. Nobody can change their own roles.
- Roles re-read on every request so changed roles take effect immediately, not just per session. 
- Defense in depth: UI hides functionality your role doesn't permit, and, more importantly, server prevents you from reaching it too (i.e. Sender typing `/inbox` in browser gets rejected).
- DB constraint enforced quotas so multiple simultaneous requests can't succeed.



## 4. Cryptography


| What                                                                    | Algorithm                                                           | Why this one                                                                                                                                                                                                                                  |
| ----------------------------------------------------------------------- | ------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Encrypting the message key for the recipient (each user's own key pair) | RSA-3072 with OAEP padding (SHA-256)                                | Standard recommended key size, padding and OAEP for added randomness/padding. The asymmetric piece of my hybrid encryption implementation.                                                                                                    |
| Encrypting the message                                                  | AES-256-GCM                                                         | Symmetric piece of my hybrid encryption model. Fast and efficient for messages and the GCM piece adds authentication tag - so if ciphertext modified then decryption fails (tamper detection)                                                 |
| Tokens                                                                  | Blind RSA (3072-bit, full-domain hash)                              | Math in RSA enables the blind signature by letting you multiply a random number before signing, then dividing it out after so server never sees the token. Hash is of epoch and token public key such that token works only during its epoch. |
| Token key / message signature                                           | Ed25519                                                             | Signature of messages with token key; Messages can't be changed or faked.                                                                                                                                                                     |
| Commitment                                                              | SHA-256 of the AES key                                              | Hash of the message's AES key that goes in the token-key-signed envelope. Locks in the key without revealing it.                                                                                                                              |
| Passwords                                                               | scrypt                                                              | Great for passwords bc slow and memory heavy - counter to guessing from stolen DB, every one also has a random salt --> protection against rainbow table attack                                                                               |
| Session ids                                                             | random, stored only as SHA-256 hashes                               | No working sessions in stolen DB.                                                                                                                                                                                                             |
| Audit log                                                               | SHA-256 hash chain + Ed25519 signature per entry                    | Chain catches edits/deletions, makes the audit logs tamper-evident and protects their integrity. Signature stops someone from recomputing the chain without the audit key.                                                                    |
| Private key on disk                                                     | encrypted with the user's password, file readable only by the owner | Copied key file not useful without the user's password.                                                                                                                                                                                       |




## 5. Audit Logging

My audit logging system works as follows:

What is getting logged: Registrations, approvals, role changes (refused ones too), rounds, policy changes, tokens issued, messages sent/delivered, flags, freezes, denied access, invalid tokens, lockouts, and alerts. 

The logs do name the powerful role wielders (Administrators and Moderators actions record their user ID in logs), but they stay blind about senders since no user ID is revealed and times get rounded to the hour. 

This logging system practices defense in depth for its tamper evidence as follows:

DB refuses edits and deletes, hash chain (each entry has the hash of the one before it, so changing an old entry in an attempt to manipulate the logs messes everything up after it), every entry signed with the server's audit key so the chain can't be recomputed without that key, AND mods save the latest hash on their own machine which catches even someone who themselves has the key and is rewriting older history. 

### Sample log analysis

The sample log in `docs/audit_log_sample.md` is the output from `python -m scripts.audit_demo`, which runs a short scripted scenario and then tampers w/ a  DB copy to see if verify catches it.

The logs show that admins/mods are accountable in my design. the approvals, round starts, the freeze (#7-#12, #21, #26) all have the acting user's ID on them (admin is 1, mod is 5). Even the admin's refused attempt to make mod an admin too (#11) gets logged with the admin's ID- trying to break separation of duties leaves a record.

Aligning with my design goals, you can also follow one token's whole journey without ever seeing a name (my approach to managing the accountability-anonymity tradeoff).

Message gets sent (#16), bob flags it (#20), mod 5 freezes the token (#21),  sender tries to use frozen token again (#22), and an alert goes off (#23). All of these are tied together by the same token ID. None of them say who the sender was identity-wise. The log also shows other security events - sender trying to read the audit log (#17), a forged token (#18), and someone guessing alice's password 5 times, which locks the account and raises an alert (#24-#25).

On the sender side, the two token_issued entries (#13-#14) and the two message_sent entries (#15-#16) have no user ID and their timestamps are rounded down to the hour so it's much harder to link them. Also no way to tell which token issuance turned into which message due to blind signature.

For tampering, I edited #21 to hide which token got frozen and verify caught it right away (the contents didn't match the hash anymore). After that I made the same edit and recomputed every hash after it so the chain lined back up - verify still caught it, this time because of a bad signature, since the attacker doesn't have the audit key.

Weaknesses: Even though the sender timestamps are rounded, they still sit in order between entries that have exact times, so someone reading through the log in sequence can narrow down when a message was sent. Also #17 logs role: sender with an exact time, and with only two senders that isn't much cover. And if someone did get the audit key, they could rewrite and re-sign the log - the only thing that catches that is the head hash the mod saved off the server when they ran verify. Given the scope of this lab the relatively little traffic and thus logging taking place makes these logs more vulnerable to exploitation than a production app with a lot of activity would have. 

## 6. Testing

I run 196 automated tests with pytest. All of them pass in my current implementation. Every test spins up a fresh server with an empty DB, so the tests won't affect one another. The majority of the tests I wrote act like an attacker, sending malicious requests and checking that the server refuses them. Some run the real client against a real server over http to simulate activity better. For the concurrency testing it sends 20 requests at the same instant from separate threads to check that only one of them gets through (one token per sender, one message per token).

I organized them into 12 separate test files based on the functionality/modules they test. Here's the list of files to check out in the tests/ folder:

test_rbac.py, test_moderation.py, test_messages.py, test_auth.py, test_tokens.py, test_web.py, test_client_core.py, test_client_crypto.py, test_admin.py, test_audit.py, test_blind_rsa.py, test_db.py

## 7. Limitations

Organized by threat --> counter I would implement given more time.


| Limitation/threat                                                                                                                                                                                                                                                          | Counter given more time                                                                                                                                                                           |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Timing/traffic analysis - the server still sees when requests come in and from what IP. Grabbing the token at login helps, but with only a few users "alice logged in and then a message showed up a minute later" is still a pretty big hint.                             | Route sends through Tor or a mix network so the server can't see who they came from, or have the client wait a random amount of time before sending.                                              |
| Trust on first use - pinning only catches a swapped key after the first message. If an admin swaps bob's key before alice ever messages him, she'd just trust the fake one and never know.                                                                                 | Have people compare fingerprints in person, or publish every key in a public log anyone can check (key transparency) so a swap can't happen quietly.                                              |
| Leaked token signing key - whoever has it can make as many valid tokens as they want. The `unissued_tokens` alert would notice more tokens being used than the server issued, but it can't actually stop it.                                                               | Split the signing key across a few servers that all have to cooperate to sign, so breaking into one isn't enough.                                                                                 |
| Audit key holder could rewrite the log - signatures only help if the attacker doesn't have the key. If they do, the only thing that catches it is the head hash a mod saved off the server.                                                                                | Post the head hash somewhere public regularly, or ship the log to a separate append-only service the server can't touch.                                                                          |
| Anonymity vs accountability - with a fresh token every round (the default), a freeze only takes down that one message and the abuser just gets a new token next round. Making tokens last longer makes freezes hit harder but then messages become linkable to each other. | Schemes where identity is locked away and only unlocked after repeated abuse (escrowed identity / group signatures). Way more crypto than I could build and properly verify for this project tho. |
| Same password for login and the key file - the server sees your password when you log in, so a malicious server that also got your key file could unlock it.                                                                                                               | Separate passphrase just for the key file (more annoying for users though).                                                                                                                       |
| Metadata - server still knows who gets messages, how many, and in which round. It just doesn't know who sent them or what they say.                                                                                                                                        | Send dummy messages so the per-recipient counts don't really mean anything.                                                                                                                       |
| Scope - everything runs on localhost over plain HTTP, and network level DoS wasn't in scope.                                                                                                                                                                               | HTTPS if this were actually deployed, plus rate limiting in front of the server.                                                                                                                  |




## 8. Bonus / Extra Credit Features

I did 3 of the Bonus Advanced Extensions:

- Blind signature token issuance - `common/blind_rsa.py`
- Frontend that adapts to roles - my web UI menu/homepage adapt to the pages relevant to your role. Also even in CLI mode the help command hides commands your role can't do. Just defense in depth because the server enforces this either way. 
- Intrusion detection rule  - I did 5 of them: flag threshold per round, too many invalid tokens, frozen token reused, more messages than tokens issued, + account lockout.

