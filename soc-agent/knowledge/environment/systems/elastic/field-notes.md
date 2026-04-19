---
tags: [elastic, fields, gotchas]
---

# Elastic Stack — Field & Query Gotchas

Obvious things to know at connect-time. Grows via post-mortem `/author` runs as real investigations surface more.

- **Query syntax is Lucene, not pure KQL.** The adapter passes query strings through to Elasticsearch's `query_string` clause directly — Elasticsearch does not natively accept KQL. For the common cases (`field: value`, `AND`/`OR`/`NOT`, ranges `[a TO b]`, quoted phrases) KQL and Lucene are interchangeable. Divergences to watch: KQL's `*` wildcard in field values works here too, but KQL's nested-field syntax (`parent:{ child: value }`) is **not** supported — use `parent.child: value` instead. KQL exists-checks (`field: *`) work. Reserved characters that need escaping in Lucene but not KQL: `+ - = && || > < ! ( ) { } [ ] ^ " ~ * ? : \ /`.
- **Two data surfaces, two subcommands.** `query` hits raw event data streams (`logs-*` by default). `alerts` hits the detection-engine signal alias (`.alerts-security.alerts-default`). Fields on the alerts surface are namespaced under `kibana.alert.*` (e.g. `kibana.alert.severity`, `kibana.alert.rule.name`, `kibana.alert.workflow_status`). Do **not** mix the two — an alert query with `event.outcome` will match nothing useful because signals don't carry that field in the shape raw events do.
- **`*` as the query argument is valid.** `alerts '*'` and `query '*'` both mean "match all" and are the right shape when you want a broad sweep scoped only by time. This bypasses the `query_string` fallback to `match_all` internally — no special casing needed on the caller side.
- **ECS is the baseline, but `data_stream.*` drives routing.** Events carry ECS fields (`event.dataset`, `event.action`, `event.outcome`, `user.name`, `host.name`, `source.ip`) and Elastic's `data_stream.*` metadata (`data_stream.dataset`, `data_stream.namespace`, `data_stream.type`). Filtering by `event.dataset` and `data_stream.dataset` usually returns the same set, but `data_stream.*` is the authoritative routing signal Fleet writes. Prefer ECS for investigation logic; use `data_stream.*` when you need to confirm which integration produced a doc.
- **`@timestamp` is the time field everywhere.** The adapter sorts and range-filters on `@timestamp` for both `query` and `alerts`. Alerts also carry `kibana.alert.start` / `kibana.alert.last_detected`; use those for "when did the rule first fire" semantics specifically, not for general time scoping.

<!-- grown via post-mortem /author runs -->
