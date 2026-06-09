---
id: elastic.doc-fetch-by-id
status: established
filter_keys:
  predicates:
    - {event_attr: event_id, op: eq, param: id}
---

## Goal

Fetch one or more Elasticsearch documents by exact document ID (`_id`) from a known index or data stream. Use when alert metadata, a prior query, or a sibling lead has surfaced specific document IDs and you need the complete field set of those records — e.g., retrieving the full system.auth event for a sshd login by its `_id`.

## What to summarize

- Count of documents returned vs IDs requested (detect any not-found)
- All indexed fields for each returned document
- For system.auth events: `host.name`, `@timestamp`, `source.ip`, and auth outcome + target user extracted from `message` (OpenSSH syslog format: "Accepted/Failed password for \<user\> from \<ip\>")

## Query

```
_id: "${id}"
```

For multiple IDs: `_id: ("${id1}" OR "${id2}")`. Scope to the specific data stream from alert metadata via `--index` when available.

## Common pitfalls

- **`_id:` prefix required**: The document-level filter is `_id:`, not a regular field match. Passing the ID as a bare term against a non-existent field like `document.id` returns all documents. Always use the `_id:` KQL syntax.
- **Index scope narrows precision**: A wildcard index (`logs-*`) may surface the document if the ID exists in any stream, but risks false positives from ID reuse across data streams. Prefer the specific data stream from alert metadata.
