---
name: endpoint-context
target_vertex_kind: endpoint
lookup_cli: "python3 scripts/tools/stub_asset_cli.py lookup ip {identifier}"
context_file: "knowledge/environment/context/ip-ranges.md"
record_attr: cmdb_record
fallthrough_classification: unclassified-endpoint
---

## Goal

Enrich an endpoint vertex with two attributes the alert itself doesn't
carry:

1. A **classification label** derived from the org's classification rules
   for endpoint identifiers (whatever the deployment's `context_file`
   defines).
2. The **authoritative record** for the endpoint, if one exists, returned
   verbatim by the configured `lookup_cli` (CMDB / asset-DB / inventory).

These attributes ride on the prologue vertex and are read by every
downstream phase.

## What the lead returns

- `classification` — a label the deployment's `context_file` documents, or
  `fallthrough_classification` when no rule applies.
- The verbatim record from the configured CLI under the attribute name
  declared by `record_attr`, or `null` when the upstream has no record.

Record field names are vendor-specific; the lead does not normalize them.

## Common pitfalls

- **Not-found is a valid result, not an error.** A missing record is itself
  a signal — "this endpoint is not inventoried" is information the
  downstream phases use.
- **The classification rule lives in the `context_file`, not in this lead
  definition.** When the org refines its scheme, edit the context file.
  This definition shouldn't need to change.
