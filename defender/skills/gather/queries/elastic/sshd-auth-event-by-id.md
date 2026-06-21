---
id: elastic.sshd-auth-event-by-id
status: established
filter_keys:
  index: logs-system.auth-*
  predicates:
    - {event_attr: event_id, op: eq, param: event_id}
---

## Goal

Retrieve a single sshd / PAM authentication log entry from `logs-system.auth-*` by Elasticsearch document ID (`_id`). Use when an alert graph references a specific auth-log ancestor event by `_id` and you need the exact host, timestamp, actor, and session outcome — typical in cross-tier pivot investigations where each hop is identified by a document ID.

## What to summarize

- `host.name` of the matched event (which host produced the auth record)
- `@timestamp` of the event
- user identity extracted from `message` field substring (e.g., "Accepted password for alice" or "Failed password for alice")
- source IP extracted from `message` field substring (e.g., "from 10.1.2.3 port 22")
- outcome: Accepted or Failed, from `message` field prefix
- event type from `system.auth.ssh.event` when populated (e.g., `Invalid`, `Accepted`, `Failed`) — present when Filebeat ECS-parses the syslog line; distinguishes "Invalid user" rejections (no auth method attempted) from outcome-carrying auth events

## Query

```
_id: "${event_id}"
```

Index: `logs-system.auth-*`

## Common pitfalls

- **Use `defender-elastic query`, NOT `esql`.** This is a raw single-document
  fetch (you want the full `_source`), not an aggregation. For counts/distributions
  of auth events use `sshd-auth-history` (ES|QL) instead.
- **Structured ECS fields may be populated.** For `Invalid user` events (observed in Filebeat 9.3.3), `user.name`, `source.ip`, and `system.auth.ssh.event` are all populated via ECS normalization — check structured fields first. For other event types (e.g., `Accepted password`, `Failed password`), `source.ip` may be absent; fall back to `message` substring extraction in that case.
- **`_id` vs. field value.** The `event_id` parameter is the Elasticsearch document ID (`_id`), not a value inside the `message` field. Retrieve via direct `_id` lookup, not a field query.
- **Index scope.** Auth-log events live in `logs-system.auth-*`; Falco events in `logs-falco.alerts-*`. Do not substitute indexes.
- **Sweep pair for multi-hop pivots.** When a lead resolves multiple ancestor sessions in one hop (e.g., a workstation-tier event and a prod-tier event), either dispatch this template once per `_id` and reconcile results in the gather summary, or batch both IDs in a single dispatch using `arg0` with the OR syntax: `_id: ("id1" OR "id2")`; both documents are returned in one shot.
- **`event_id` is a query-body substitution, not a CLI flag.** Pass `event_id` as a query param for substitution into `_id: "${event_id}"`. Passing it as `--event-id` to the CLI returns exit=2 with "error: unrecognized arguments: --event-id".
