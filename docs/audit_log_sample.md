# Sample Audit Log

Run with `python -m scripts.audit_demo`, which runs a scripted scenario against a fresh
server, prints the resulting audit log, and then tampers with a copy of the database to show
`verify` catching it. My sample audit log analysis is in a dedicated section in my main `report.md`.

The analysis of this log is in section 5 of `docs/report.md`.

```
scenario:
  - admin bootstrapped from the server command line, logs in
  - alice, carol, bob, mod register; admin approves them
  - admin tries to make mod an admin too: refused (separation of duties)
  - admin starts round 1
  - everyone logs in; alice and carol pick up their tokens
  - alice and carol each send bob a message
  - alice tries to read the audit log: refused
  - someone sends with a forged token signature: refused
  - bob reads his inbox (2 messages)
  - bob flags carol's message
  - mod freezes the token behind the flagged message
  - carol tries to use her frozen token again: refused, alert raised
  - someone guesses alice's password 5 times: account locked, alert raised
  - mod verifies the log and saves the head hash on their machine
  - admin starts round 2 (new signing key, issuance records wiped)

  #  time (utc)            action                role        actor  details
--------------------------------------------------------------------------------------------------------------
  1  2026-11-14T20:24:28Z  user_registered       -           -      {"key_fingerprint": "f025:e518:d818:db6f:cf48:4c8e:3e24:f55d:b89e:0db9:fff9:a937:f8eb:7c72:efcc:07e5", "target": "admin"}
  2  2026-11-14T20:24:28Z  admin_bootstrapped    operator    -      {"target": 1}
  3  2026-11-14T20:24:28Z  user_registered       -           -      {"key_fingerprint": "61fd:370c:71e6:5384:ee75:9dc1:2bae:0dba:bbd4:471c:30db:6333:3633:7e0b:b2e0:645d", "target": "alice"}
  4  2026-11-14T20:24:29Z  user_registered       -           -      {"key_fingerprint": "9719:1cb7:1b7a:a942:b730:b982:1229:2bab:b0a6:325a:60d3:7bde:29a3:6881:577c:4823", "target": "carol"}
  5  2026-11-14T20:24:29Z  user_registered       -           -      {"key_fingerprint": "6e63:c9d8:7d0c:d5e3:398b:8a89:92a8:0fcc:5f36:574d:41f6:352f:ba7f:ee45:0016:685a", "target": "bob"}
  6  2026-11-14T20:24:29Z  user_registered       -           -      {"key_fingerprint": "4a4d:e587:b69d:852c:671b:ce2e:e8f5:d273:18c3:961b:d1da:137d:5fc2:dd20:8057:c0bf", "target": "mod"}
  7  2026-11-14T20:24:29Z  user_approved         admin       1      {"roles": ["sender"], "target": 2}
  8  2026-11-14T20:24:29Z  user_approved         admin       1      {"roles": ["sender"], "target": 3}
  9  2026-11-14T20:24:29Z  user_approved         admin       1      {"roles": ["recipient"], "target": 4}
 10  2026-11-14T20:24:29Z  user_approved         admin       1      {"roles": ["moderator"], "target": 5}
 11  2026-11-14T20:24:29Z  role_change_refused   admin       1      {"reason": "separation of duties: admin and moderator cannot be combined", "roles": ["admin", "moderator"], "target": 5}
 12  2026-11-14T20:24:29Z  round_started         admin       1      {"epoch": 1, "new_key": true, "round": 1}
 13  2026-11-14T20:00:00Z  token_issued          sender      -      {"epoch": 1}
 14  2026-11-14T20:00:00Z  token_issued          sender      -      {"epoch": 1}
 15  2026-11-14T20:00:00Z  message_sent          sender      -      {"round": 1, "token": "d76dc4e67bded8306b907fd2a9183eba5ae69974dd4224409193c40f9b46c2d9"}
 16  2026-11-14T20:00:00Z  message_sent          sender      -      {"round": 1, "token": "be3fa81ab7879d4b3fa976cc50820b0bf9fb93c63345d08352c32c7f635a56d5"}
 17  2026-11-14T20:24:30Z  access_denied         sender      -      {"permission": "audit:read"}
 18  2026-11-14T20:00:00Z  invalid_token         anonymous   -      {"reason": "token signature invalid or expired", "round": 1}
 19  2026-11-14T20:24:30Z  message_delivered     recipient   -      {"count": 2}
 20  2026-11-14T20:24:30Z  message_flagged       recipient   -      {"round": 1, "token": "be3fa81ab7879d4b3fa976cc50820b0bf9fb93c63345d08352c32c7f635a56d5"}
 21  2026-11-14T20:24:30Z  token_frozen          moderator   5      {"reason": "harassment, confirmed", "token": "be3fa81ab7879d4b3fa976cc50820b0bf9fb93c63345d08352c32c7f635a56d5", "withdrawn": 1}
 22  2026-11-14T20:00:00Z  frozen_token_used     anonymous   -      {"token": "be3fa81ab7879d4b3fa976cc50820b0bf9fb93c63345d08352c32c7f635a56d5"}
 23  2026-11-14T20:00:00Z  alert_raised          -           -      {"rule": "frozen_token_used", "token": "be3fa81ab7879d4b3fa976cc50820b0bf9fb93c63345d08352c32c7f635a56d5"}
 24  2026-11-14T20:24:30Z  account_locked        -           -      {"target": "alice"}
 25  2026-11-14T20:00:00Z  alert_raised          -           -      {"rule": "account_locked", "target": "alice"}
 26  2026-11-14T20:24:30Z  round_started         admin       1      {"epoch": 2, "new_key": true, "round": 2}

last entry (#26) in full:
  prev_hash  8c1b08fcb343225df7e5792f33231445e45cf59698e4a467f36f5393eb9f894d
  entry_hash bdb11dde938fef56b5214c3d52b52b444ff8210b778d0143bc89b8f3d1a2a1d4
  signature  duCQhA8kUztcx/QC4RNILYhOoN5lqOiaBIN33wPESXvSGSwV90khF68XOdxUT0eSjwrI4OAcxS7tRc5JEmboCg==

verify on the real log:
   (True, 'ok')

attacker edits entry #21 (token_frozen) to hide which token was frozen:
   (False, "entry 21: contents don't match its hash (entry was edited)")

attacker also recomputes every hash from that entry on, so the chain links up:
   (False, 'entry 21: bad signature (hash was recomputed without the audit key)')
```
