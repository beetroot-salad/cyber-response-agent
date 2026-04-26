---
name: identity-context
phase: contextualize
target_vertex_kind: identity
lookup_cli: "python3 scripts/tools/stub_asset_cli.py lookup user {identifier}"
context_file: "knowledge/environment/context/identity-patterns.md"
record_attr: idp_record
fallthrough_classification: unclassified-identity
---

## Goal

Enrich an identity vertex (the username carried in the alert) with two
pieces of context the alert itself doesn't carry:

1. A **classification label** derived from the org's identity-pattern
   conventions (`environment/context/identity-patterns.md`). Monitoring
   pattern, service account, privileged account, generic / wordlist,
   unknown — whatever the org has documented.
2. The **IdP record** for the username, if one exists. Display name, type,
   owner team, MFA status — whatever the IdP returns.

These attributes ride on the prologue vertex and are consumed by every
downstream phase. SCREEN's monitoring-probe fast-path requires
`vertex.classification == monitoring-pattern`; PREDICT frames brute-force
predictions against `idp_record.type == service`; REPORT cites the
owner team.

## What the lead returns

- `classification` — one of the labels documented in
  `environment/context/identity-patterns.md` (`monitoring-pattern`,
  `service-account`, `privileged-account`, `generic-account`,
  `unclassified-identity`).
- `idp_record` — the IdP record for the username (verbatim from the
  adapter), or `null` when the upstream has no record.

For SSH-style alerts where the username is *attempted* (not a real
account), `idp_record: null` is the expected result — the rule fires
*because* the user doesn't exist. Combined with a wordlist-pattern
classification this is a strong external-bruteforce signal.

## Common pitfalls

- **Pattern match is on the typed string, not a real account.** For
  signatures like SSH-invalid-user (5710) the alert's `srcuser` is what
  the connecting party typed, not who connected. `nagios` matches the
  monitoring pattern even if no `nagios` account exists in the IdP — and
  the IdP returning `null` is a *consistency* signal, not a contradiction.
- **The classification rule lives in `identity-patterns.md`, not in this
  file.** When the org refines its identity-pattern conventions, update
  the prose in the context file. This lead definition shouldn't need to
  change.
