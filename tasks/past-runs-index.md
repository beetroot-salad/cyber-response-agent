---
title: Build past-runs index (SQLite/JSONL keyed by signature + entity-class hash)
status: backlog
groups: reliability, knowledge, past-runs
---

Per signature, extract: entity set (srcip, srcuser, host, image family, …), trace line, matched_archetype, disposition, confidence, key ++/-- observations from the investigation log.

Store as a flat index (SQLite or JSONL) keyed by signature_id + entity-class hash, so a query can land in <100ms without reading every run dir.
