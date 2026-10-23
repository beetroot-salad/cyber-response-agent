---
id: elastic.doc-fetch-by-id
status: established
verb: query
params: [index]
body_substitutions: [id, id1, id2]
---

## Goal

Fetch one or more Elasticsearch documents by exact document ID (`_id`) from a known index or data stream. Use when alert metadata, a prior query, or a sibling lead has surfaced specific document IDs and you need the complete field set of those records — e.g., retrieving the full system.auth event for a sshd login by its `_id`.

## Query

```
_id: "${id}"
```

For multiple IDs: `_id: ("${id1}" OR "${id2}")`. Scope to the specific data stream from alert metadata via the `index` param when available.

## Common pitfalls

- **Use the `query` verb, NOT `esql`.** This is a raw-document fetch — you
  want the complete `_source` of a specific record, not a server-side aggregation.
  The KQL `query` verb returns the doc; `esql` is for counts/distributions.
- **`_id:` prefix required**: The document-level filter is `_id:`, not a regular field match. Passing the ID as a bare term against a non-existent field like `document.id` returns all documents. Always use the `_id:` KQL syntax.
- **Count returned against IDs requested.** A document that does not exist
  simply does not come back — the fetch still exits 0. A short result is a
  not-found to report, not an empty index.
- **Read the structured fields.** A returned `_source` is ECS-normalized: for
  `logs-system.auth-*` documents the actor, source and outcome are already their
  own typed fields (`user.name`, `source.ip`, `source.port`, `event.outcome`,
  `system.auth.ssh.event`, `system.auth.ssh.method`). Do not re-extract them from
  `message`. Two caveats before you report one: those fields are populated on the
  OpenSSH-format lines only — the `pam_unix(sshd:auth)` / session / cron
  documents in the same index carry them null, and a null there is a parser gap,
  not an anonymous actor — and `Failed password for invalid user <u>` lands
  `user.name` with a **leading space** (`" dev.dana"`). Report the `TRIM`-ed
  value, and say when the raw one differed.
- **Index scope narrows precision — but map the alert's `.ds-` name first.** A
  wildcard index (`logs-*`) may surface the document if the ID exists in any
  stream, but risks false positives from ID reuse across data streams. Prefer the
  specific data stream — noting that `ancestor_events[].index` in the alert gives
  you the concrete **backing** index
  (`.ds-logs-system.auth-default-2026.07.27-000004`), which the adapter refuses:
  it allowlists datastream *patterns*. Bind the pattern
  (`logs-system.auth-*`), not the backing name.
