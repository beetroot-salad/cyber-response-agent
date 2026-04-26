---
name: endpoint-context
phase: contextualize
target_vertex_kind: endpoint
lookup_cli: "python3 scripts/tools/stub_asset_cli.py lookup ip {identifier}"
context_file: "knowledge/environment/context/ip-ranges.md"
record_attr: cmdb_record
fallthrough_classification: unclassified-endpoint
---

## Goal

Enrich an endpoint vertex (source IP, target host, monitoring host, etc.)
with two pieces of context the alert itself doesn't carry:

1. A **classification label** derived from the org's IP-range conventions
   (`environment/context/ip-ranges.md`). Internal monitoring host,
   internal-other, DMZ, external — whatever the org has documented.
2. The **CMDB record** for the IP, if one exists. Hostname, role,
   owner team, environment — whatever the asset DB returns.

These attributes ride on the prologue vertex and are consumed by every
downstream phase. SCREEN's pattern matching reads `vertex.classification`
to decide a fast-path; PREDICT frames its predictions against the entity
baseline; REPORT cites the owner team.

## What the lead returns

- `classification` — one of the labels documented in
  `environment/context/ip-ranges.md`, or `unclassified-endpoint` when no
  rule applies.
- `cmdb_record` — the CMDB record for the IP (verbatim from the adapter),
  or `null` when the upstream has no record.

The CMDB record's field names are vendor-specific. The playground stub
returns `{hostname, role, owner_team, env}`; production deployments swap
in their own CMDB adapter and the field names follow.

## Common pitfalls

- **Not-found is a valid result, not an error.** A source IP that the
  CMDB doesn't know about is still useful information — `cmdb_record:
  null` says "this is not an inventoried asset," which is itself a
  classification signal.
- **CIDR matches are longest-prefix.** A host-specific entry beats a
  subnet entry; a more-specific subnet beats a less-specific one. RFC1918
  / loopback / external fallthrough only fires when no rule matches.
- **The classification rule lives in `ip-ranges.md`, not in this file.**
  When the org refines its classification scheme, update the prose in
  the context file. This lead definition shouldn't need to change.
