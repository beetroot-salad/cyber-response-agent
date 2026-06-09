---
id: elastic.sshd-session-lifecycle
status: established
---

## Goal

Retrieve PAM sshd session open and close events from `system.auth` for a specific user on a specific host, using message-text wildcard search for `pam_unix(sshd:session): session` and username mentions. Use to determine whether the SSH session was opened and subsequently closed, how long it lasted, and whether PAM clean-up completed — a complement to `sshd-auth-sequence-v2` which covers pre-session authentication events.

## What to summarize

- Session opened and closed event timestamps; derived session duration in seconds
- Presence or absence of `pam_unix(sshd:session): session opened` and `session closed` records
- PTY allocation indicator if visible in PAM session records
- Any other system.auth messages mentioning the user in the window

## Filter binding

- `${host}` — destination hostname; matched via `host.name`
- `${user}` — username; matched via wildcard in `message` field
- `start`, `end` — optional time bounds (ISO-8601); recommend post-login window
- `index` — `logs-system.auth-*`

## Query

```
data_stream.dataset:"system.auth" AND host.name:"${host}" AND (message:*"pam_unix(sshd:session): session"* OR message:*"${user}"*)
```

## Common pitfalls

- **Message wildcard is expensive on large indexes.** The `message:*"..."*` wildcard pattern scans all tokens — narrow `start`/`end` to the post-login window to avoid timeouts on high-volume auth indexes.
- **Co-dispatch with `sshd-auth-sequence-v2`.** Auth events (failures, the Accepted record) land in `sshd-auth-sequence-v2`; this template covers the PAM session lifecycle after auth. Dispatch both in the same lead for a complete sshd session picture.
