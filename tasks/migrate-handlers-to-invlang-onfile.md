---
title: Migrate handler on-disk format from yaml fences to ```invlang
status: backlog
groups: invlang, dense-onfile
---

Foundation for the dense on-disk format landed in branch `worktree-dense-onfile-foundation` (commits 0f26b62 + 5e23061): parser at `soc-agent/scripts/handlers/_dense_parser.py` (859 lines), primitives at `_dense_primitives.py` (353 lines), validator hook updates in `invlang_validate.py`, and parity tests (`test_dense_parser.py` 602 lines, `test_invlang_dense_parity.py` 312 lines).

Run #51 (eval `20260501-012101-rule100001`) confirmed the foundation does not regress the existing pipeline — full 2-loop completes, zero validator rejections — but every phase still wrote `` ```yaml `` fences. No phase has been migrated to emit `` ```invlang `` on disk yet, so the new parser path is unexercised end-to-end.

This task tracks the handler-by-handler migration of the on-disk format from `` ```yaml `` to `` ```invlang ``.

## Scope

- [ ] **CONTEXTUALIZE / prologue** — `_prologue_dense.py` already touched in foundation; finish the on-disk write path. Verify against `test_prologue_dense.py`.
- [ ] **PREDICT** — `_predict_dense.py` got 50 lines of foundation work; complete the disk-format swap. Subagent stdout already uses dense (`:H`, `:P`, `:R` rows) so the handler can round-trip through the new parser without prompting changes.
- [ ] **GATHER + GATHER-composite** — both write `findings:` YAML today. Decide whether to migrate the lead-outcome block first or land the whole gather payload at once. `gather-composite` is the higher-value target (larger blocks, more variance).
- [ ] **ANALYZE** — `_analyze_dense.py` (if present) or analyze handler. Resolutions block + self-report; needs round-trip parity tests against the existing YAML fixtures.
- [ ] **REPORT / CONCLUDE** — `_conclude_dense.py` got 25 lines of foundation work; finish the migration. Frontmatter is the report.md surface, not investigation.md, so this only touches the conclude block fenced inside investigation.md (if any).

## Acceptance

- Every phase emits `` ```invlang `` fences on disk; zero `` ```yaml `` fences in `investigation.md` after the migration.
- `invlang_validate.py` accepts the new fences and rejects the old ones (or accepts both during a transition window — decide explicitly).
- Round-trip parity tests pass: parse-dense → serialize-yaml → parse-yaml produces the same structured payload as the legacy direct path.
- One end-to-end live eval per signature (5710 scenario A or B, 100001, 100110) writes a fully-dense investigation.md with no rejections and lands a clean report.md.

## Order of leverage

Prologue → predict → analyze → gather/gather-composite. Conclude last (smallest delta, most fragile downstream readers).

## Out of scope

- Dense format design changes; the schema is locked by the foundation parser.
- Subagent prompt rewrites beyond what the on-disk swap requires (the stdout dense contract is already in place).
- Migration of the report.md frontmatter (separate concern).
