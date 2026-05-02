---
title: Dense `:R authz` parser projection isn't visible to validator's _iter_resolutions
status: backlog
groups: invlang, dense-format, validator
---

## Symptom

A dense `:R authz` row that fulfills an `authorization_contract` on a live-weight (`+`/`++`) hypothesis with `disposition: benign` produces:

```
hypothesis h-001: authorization_contract ac1 on a live-weight hypothesis
has no fulfilling authorization_resolutions entry, but conclude.disposition
is 'benign'. Resolve the contract against its declared anchor, or escalate.
```

…even though the dense fence contains a well-formed `:R authz` row whose `fulfills` cell points to `h-001.ac1`.

## Root cause

`scripts/handlers/_dense_parser.py::_project_resolution` projects `:R authz` rows to `lead.outcome.authorization_resolutions[]` (per the documented schema-mapping table at the top of the file).

`hooks/scripts/invlang_common.py::_iter_resolutions` walks only:
- `outcome.observations.edges[].authorization_resolutions[]` (inline on edge)
- `outcome.attribute_updates[].updates.authorization_resolutions[]`

The two locations don't intersect, so rule #21 / #26 / #27 / #28 never see dense-projected authz rows.

`tests/test_dense_parser.py::test_project_authz_resolution` asserts the parser's lead-level projection. `tests/test_invlang_authorization.py` builds companion dicts directly with INLINE-on-edge resolutions, bypassing the dense parser. No end-to-end test exercises a dense `:R authz` row through `validate_companion`, so the gap is silent in the test suite.

Live impact today: zero — no production run currently emits `:R authz` for a benign disposition (verified by grep across `runs/`). The first run that does will be incorrectly forced to escalate.

## Repro

```bash
.venv/bin/python /tmp/probe_validator.py    # script captured during the docs/invlang-dense-surface PR
```

## Fix sketch

Pick one (in declining order of locality):

1. Have the dense parser attach `:R authz` rows onto the corresponding `outcome.observations.edges[<id>].authorization_resolutions[]` based on the row's `edge` cell, instead of (or in addition to) the lead-level list. Mirrors the inline-on-edge shape the validator already reads.

2. Extend `_iter_resolutions` to also walk `outcome.authorization_resolutions[]`. Cheaper but mixes two layouts in the canonical dict.

3. Add a normalize step in `validate_companion` (between `_merge_blocks` and the rule checks) that folds lead-level `outcome.authorization_resolutions[]` onto the matching edge.

Add a regression test that runs a complete dense companion through `validate_companion` end-to-end, asserts no errors when `:R authz` fulfills a contract, and asserts the rule-#21 error when the contract is unfulfilled.

## Related

- Surfaced while validating examples in `soc-agent/knowledge/invlang/schema.md` for PR #172 (docs/invlang-dense-surface).
- The PR's worked example was switched to a `--`-refutation case to keep the doc validator-clean; the contract-resolution example remains in `docs/dense-investigation-format.md`.
