---
id: elastic.sshd-auth-event-by-id
status: established
---

## Goal

Retrieve a single sshd / PAM authentication log entry from `logs-system.auth-*` by Elasticsearch document ID (`_id`). Use when an alert graph references a specific auth-log ancestor event by `_id` and you need the exact host, timestamp, actor, and session outcome — typical in cross-tier pivot investigations where each hop is identified by a document ID.

## What to summarize

- `host.name` of the matched event (which host produced the auth record)
- `@timestamp` of the event
- user identity extracted from `message` field substring (e.g., "Accepted password for alice" or "Failed password for alice")
- source IP extracted from `message` field substring (e.g., "from 10.1.2.3 port 22")
- outcome: Accepted or Failed, from `message` field prefix

## Query

```
_id: "${event_id}"
```

Index: `logs-system.auth-*`

## Common pitfalls

- **No structured user or source fields.** Filebeat does not extract OpenSSH fields from the syslog `message`. User identity and source IP are embedded in the raw message as substrings. Read the `message` value directly; do not rely on `user.name` or `source.ip` being populated.
- **`_id` vs. field value.** The `event_id` parameter is the Elasticsearch document ID (`_id`), not a value inside the `message` field. Retrieve via direct `_id` lookup, not a field query.
- **Index scope.** Auth-log events live in `logs-system.auth-*`; Falco events in `logs-falco.alerts-*`. Do not substitute indexes.
- **Sweep pair for multi-hop pivots.** When a lead resolves multiple ancestor sessions in one hop (e.g., a workstation-tier event and a prod-tier event), dispatch this template once per `_id` and reconcile `host.name` and user identity across the results in the gather summary.
- **`event_id` is a query-body substitution, not a CLI flag.** Pass `event_id` as a query param for substitution into `_id: "${event_id}"`. Passing it as `--event-id` to the CLI returns exit=2 with "error: unrecognized arguments: --event-id".
