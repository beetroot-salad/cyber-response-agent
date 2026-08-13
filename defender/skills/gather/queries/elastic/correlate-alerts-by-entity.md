---
id: elastic.correlate-alerts-by-entity
status: established
verb: alerts
params: [end, start]
body_substitutions: [entity_filter]
---

## Goal

Detection-engine alerts naming a given entity over a window — the "is this
entity already on the SOC's radar" question, counted across EVERY rule rather
than one. The envelope's `total` IS the count; the returned `hits` are a capped
sample of it. Keyword recall: correlate alerts, same host, prior alert,
campaign, scoped count, unscoped count, kibana.alert, entity, radar, already
firing.

**Wide/superset** — narrow by writing a tighter `${entity_filter}`; widen by
dropping the disjuncts you have no value for.

## Query

Lucene/KQL against the alerts index. The verb defaults its `index` to
`ELASTIC_ALERTS_INDEX`, so there is no `FROM` to write and no `.internal.…`
name to spell — the body is the entity filter alone.

```
${entity_filter}
```

**You choose the fields.** This template used to hardcode a fixed disjunction
over `host.name`, `user.name` and `source.ip`, which fits alerts off
`logs-system.auth-*` and measures nothing on alerts off `logs-falco.alerts-*`:
there the only `host.name` is the shared VPS every containerized alert reports
from, `user.name` lives at `falco.output_fields.user.name`, and there is no
`source.ip` at all (#867). Bind whatever fields actually discriminate the alert
in front of you.

- *Scoped count*: the filter over the entities you judged central — `total` is
  the count of alerts naming them in the window.
- *Unscoped count*: the same window with the narrowing predicate dropped, so
  `total` covers the wider population the scoped number should be read against.
  Say which predicate produced which number.
- *A resolved entity SET*: OR the values inside one field —
  `user.name:("dev.dana" OR "svc.config-mgmt")` — rather than one query per value.
- Container and process axes live under `falco.output_fields.*` on falco-sourced
  alerts (`container.id`, `proc.name`, `proc.cmdline`); a target named only
  inside a command line is reachable with a wildcard on `proc.cmdline` and is
  worth more than the host it ran on.

## Pitfalls

- **`total` answers a counting question; `returned` does not.** `query`/`alerts`
  cap `hits` at 20 docs (`RETURNED_DOC_CAP`) and the envelope reports `total`,
  `returned` and `truncated` as three separate fields. `"total": 108,
  "returned": 20, "truncated": true` is a COMPLETE answer to "how many" — the cap
  bounds the sample, never the count. Do not reach for `esql` to re-derive a
  number `total` already gave you, and do not report a count as unavailable
  because `truncated` is set.
- **`host.name` is a bad axis in both directions here.** It is often null on
  correlation and sequence alerts — a cross-tier or EQL-sequence rule fires on a
  correlation, not a single host — so a host predicate silently excludes exactly
  the multi-host alerts a correlation lead most wants. And on every alert off
  `logs-falco.alerts-*` it is populated with the shared VPS name, so it selects
  the whole environment instead. Run other axes too, and say which count came
  from which predicate.
- **A bound value is matched as an EXACT TERM, and `user.name` can arrive with a
  LEADING SPACE.** `Failed password for invalid user <u>` lands `user.name` as
  `" dev.dana"` while the sibling `Invalid user <u>` line lands it clean
  (`skills/elastic/SKILL.md` §Gaps, `sshd-auth-history.md` §Pitfalls) — and an
  alert copies its source document's value verbatim, so an entity resolved off an
  ancestor document reaches this query space-prefixed. `user.name:" dev.dana"` is
  a different keyword term from `user.name:"dev.dana"` and matches nothing: a
  space-prefixed entity silently returns `"total": 0`, which reads as "no
  correlated alerts" rather than as a parser quirk. OR both spellings
  (`user.name:("dev.dana" OR " dev.dana")`) whenever a bound value is
  space-prefixed, and say which spelling produced the count.
- **Bind the window through the verb's own `start` / `end` params**, not a
  `@timestamp` clause in the Lucene body — they are declared params of `alerts`,
  and mixing the two makes the effective window unreadable from the queries table.
- **`elastic.detection-alerts` measures the same index over the same window** and
  is the one to bind when your grant reaches `esql`: it returns the per-rule
  histogram (`STATS COUNT(*) BY rule, severity, host.name`) this template cannot,
  in one call. Bind THIS one only when `esql` is withheld — a grant confined to
  the alerts index holds `alerts` and not `esql` — and read that sibling's
  pitfalls, which apply verbatim here. Both carry `correlate alerts` /
  `kibana.alert` keyword recall, so a `template_search` returns both, and
  `template_search` does NOT check your grant: a hit is not a promise you can
  run it.
- **Every alert in this environment carries `kibana.alert.workflow_status:
  "open"`.** Nothing in `playground-v2/` ever triages one, so "is this alert
  already benign-explained" is not a measurement this index can take — it is a
  constant. It is answerable only from `ticket` / `change-mgmt`, and only if the
  lead's grant reaches them; otherwise report it as not established rather than
  as a negative finding.
