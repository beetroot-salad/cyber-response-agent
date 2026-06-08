---
id: elastic.sshd-auth-sequence-v2
status: established
---

## Goal

Retrieve sshd authentication events (accepted and failed) from a specific source IP to a target host within a narrow time window, using the structured `source.ip` field for precise filtering. Use when investigating an SSH login alert to recover the ordered auth sequence, confirm the auth method, and measure inter-failure timing. Prefer over message-text-search variants (`sshd-auth-from-source-ip`) when discriminating a specific source: the structured field returns a smaller, more targeted result set.

## What to summarize

- Count of Accepted and Failed auth events from the source IP in the window
- Auth method from Accepted log messages (password / publickey / gssapi)
- Chronological sequence of auth events with timestamps and outcomes
- Session open and close events; derived session duration in seconds
- PTY allocation if visible in sshd or PAM session records

## Filter binding

- `${src_ip}` — source IP address; matched via the structured `source.ip` field
- `${host}` — destination hostname; matched via `host.name`
- `start`, `end` — alert window bounds (ISO-8601); narrow to alert time ± margin
- `index` — `logs-system.auth-*`

## Query

```
data_stream.dataset: "system.auth" AND host.name: "${host}" AND source.ip: "${src_ip}"
```

## Common pitfalls

- **Use as a sweep pair with `sshd-baseline-7d`.** When investigating an SSH success alert, co-dispatch `sshd-auth-sequence-v2` for the alert window and `sshd-baseline-7d` for the 7-day pre-alert period; reconcile to answer whether this source IP + host pair is established or novel.
- **Message-search alternative when `source.ip` is sparse.** If the result set is unexpectedly small, try `sshd-auth-from-source-ip` which matches on `message: *"${src_ip}"*` — this catches syslog-style records that embed the IP only in the raw message text rather than in a structured field.
