---
id: elastic.sshd-auth-event-by-id
status: established
verb: query
params: [index]
body_substitutions: [event_id]
---

## Goal

Retrieve a single sshd / PAM authentication log entry from `logs-system.auth-*` by Elasticsearch document ID (`_id`). Use when an alert graph references a specific auth-log ancestor event by `_id` and you need the exact host, timestamp, actor, and session outcome — typical in cross-tier pivot investigations where each hop is identified by a document ID.

## Query

```
_id: "${event_id}"
```

Index: `logs-system.auth-*`

## Common pitfalls

- **Use the `query` verb, NOT `esql`.** This is a raw single-document
  fetch (you want the full `_source`), not an aggregation. For counts/distributions
  of auth events use `sshd-auth-history` (ES|QL) instead.
- **Read the structured fields; parse `message` only as a fallback.** On the
  OpenSSH-format lines these events are ECS-normalized: `user.name`,
  `source.ip`, `source.port`, `event.outcome`, `system.auth.ssh.event`
  (`Accepted` / `Failed` / `Invalid`) and `system.auth.ssh.method` (`password` /
  `publickey`) are populated in their own typed fields. Fall back to `message`
  substrings only for a value that is genuinely absent from the document.
- **A null structured field here is a parser gap, not an observation.** The
  same index holds `pam_unix(sshd:auth)`, session open/close, cron and
  `runuser` lines whose `user.name` and `system.auth.ssh.*` are null — read
  `message` on those rather than reporting a null actor. `Invalid user`
  rejections carry `event.outcome: "failure"`, `user.name` and `source.ip` but
  a null `system.auth.ssh.method` (no auth method was ever reached) — that null
  marks the missing *method*, not a missing outcome. And `Failed password for
  invalid user <u>` lands `user.name` with a **leading space** (`" dev.dana"`),
  where the sibling `Invalid user <u>` line lands it clean; compare
  `TRIM`-ed values, never raw ones.
- **`_id` vs. field value.** The `event_id` parameter is the Elasticsearch document ID (`_id`), not a value inside the `message` field. Retrieve via direct `_id` lookup, not a field query.
- **Index scope — and never the `.ds-` name from alert metadata.** Auth-log
  events live in `logs-system.auth-*`; Falco events in `logs-falco.alerts-*`. Do
  not substitute indexes. An alert's `ancestor_events[].index` is the concrete
  **backing** index (`.ds-logs-system.auth-default-2026.07.27-000004`); the
  adapter allowlists datastream *patterns*, so binding it verbatim is refused —
  map it to its pattern (`logs-system.auth-*`) first.
- **Sweep pair for multi-hop pivots.** When a lead resolves multiple ancestor sessions in one hop (e.g., a workstation-tier event and a prod-tier event), dispatch this template once per `_id` and reconcile the results in the gather summary, or batch both IDs in one `native_query` body using the OR syntax: `_id: ("id1" OR "id2")`; both documents are returned in one shot.
- **`event_id` is a query-body substitution into the `native_query`.** It is interpolated into `_id: "${event_id}"`; it is not a verb param of its own. A mistyped or unknown param name is rejected as a usage error (exit 64), naming the param.
