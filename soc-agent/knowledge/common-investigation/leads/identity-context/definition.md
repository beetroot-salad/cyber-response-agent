---
name: identity-context
target_vertex_kind: identity
lookup_cli: "python3 scripts/tools/stub_asset_cli.py lookup user {identifier}"
context_file: "knowledge/environment/context/identity-patterns.md"
record_attr: idp_record
fallthrough_classification: unclassified-identity
---

## Goal

Enrich an identity vertex with two attributes the alert itself doesn't
carry:

1. A **classification label** derived from the org's classification rules
   for identity strings (whatever the deployment's `context_file` defines).
2. The **authoritative record** for the identity, if one exists, returned
   verbatim by the configured `lookup_cli` (IdP / directory / user
   inventory).

These attributes ride on the prologue vertex and are read by every
downstream phase.

## What the lead returns

- `classification` — a label the deployment's `context_file` documents, or
  `fallthrough_classification` when no rule applies.
- The verbatim record from the configured CLI under the attribute name
  declared by `record_attr`, or `null` when the upstream has no record.

Record field names are vendor-specific; the lead does not normalize them.

## Common pitfalls

- **The alert's identifier may be a typed string, not a real account.**
  Some signatures fire on attempted-but-nonexistent identities. A `null`
  record from the IdP combined with a classification derived from the
  string itself is a *consistency* signal, not a contradiction.
- **The classification rule lives in the `context_file`, not in this lead
  definition.** When the org refines its scheme, edit the context file.
  This definition shouldn't need to change.
