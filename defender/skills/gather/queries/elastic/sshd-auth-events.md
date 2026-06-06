---
id: elastic.sshd-auth-events
status: established
filter_keys:
  index: logs-system.auth-*
  predicates:
    - {event_attr: host, op: eq, param: host}
---

## Goal

SSH authentication events (Accepted/Failed password/publickey) on a specific
host within a time window. Use to establish session timing, detect brute-force
patterns, and correlate interactive logins with downstream activity like file
modifications.

## What to summarize

- count of successful authentications (Accepted password / Accepted publickey)
- count of failed authentication attempts
- timestamp range of earliest and latest events in the window
- source IP address(es) from successful authentication messages (embedded in `message` field as OpenSSH syslog format `from <ip>` — not a structured field; extract by pattern match on `Accepted * for <user> from <ip>`)
- auth method distribution (password vs. publickey) — readable from the `message` filter that matched; present by construction in any record matching this template's query

## Query

```
data_stream.dataset: "system.auth" AND host.name: "${host}" AND (message: *"Accepted password"* OR message: *"Accepted publickey"* OR message: *"Failed password"*)
```

## Common pitfalls

- **No parsed user.name / source.ip.** Filebeat does not extract OpenSSH
  fields from the syslog message. User and source IP are embedded in the
  `message` field as substring patterns like "Accepted password for user from
  10.1.2.3" — treat them as queryable by wildcard only, not as structured
  fields. For precise user/IP filtering, run a secondary analysis pass on the
  raw message payloads.
- **Time window precision:** Use explicit `--start` and `--end` timestamps in
  ISO format (e.g., `2026-05-24T06:20:00Z`). The agent ship-time can drift
  relative to the alert timestamp; rounding hides millisecond ordering.

## Baseline (when applicable)

For establishing normal authentication rate and pattern on a host, run the
same query with a `shift` parameter offsetting the window backward (e.g., 1
day or 7 days prior over the same duration).
