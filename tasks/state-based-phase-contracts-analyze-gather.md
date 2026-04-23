---
title: Move ANALYZE and gather-composite contracts from shape-based to state-based (invlang migration scope)
status: todo
groups: invlang, analyze, gather-composite, predict, contracts
---

Surfaced by orchestrator run `20260423-043856-rule100001` (rule-100001, `predict-phase-rename` branch). Run failed at loop-3 PREDICT with `OrchestrationError: mode 'fork' requires block_type 'hypothesize', got 'unknown'` after 1658s wall, but the true failure was upstream: loop-2 `gather-composite` silently ran only 1 of 2 prescribed leads and reported `status: ok`; loop-2 `analyze` noticed the scope mismatch in its Self-report narrative but had no contract obligation to act on it and routed back to PREDICT; loop-3 PREDICT then inherited a stable fork with one lead still unresolved — a legal investigation state the PREDICT contract can't express.

**Root cause (layer 1):** three phase contracts checking surface shapes instead of invlang state.

- `gather-composite` Level-1 `status` discriminator (from run #42) was violated: the subagent dispatched under a composite prescription, executed one lead, and marked `status: ok`. Correct behavior: `status: partial` with the dropped lead named, or block completion until the prescribed scope is met.
- `analyze` contract has no scope-check obligation. It should read prescribed leads from loop-N PREDICT's trailer, read actually-resolved leads from loop-N GATHER YAML, and route back to GATHER (not PREDICT) when the prescribed set isn't fully resolved.
- `predict` contract at `scripts/handlers/predict.py:585` enforces `mode=fork ⇒ block_type=hypothesize` / `mode=no-fork ⇒ block_type=unknown`. No legal mode for loop-N's most common state: "fork graph is stable from last loop, selecting the next discriminating lead against an existing unresolved hypothesis." Agent's only legal choices force either (a) duplicate re-authoring of the existing hypothesize block under `mode=fork`, or (b) a dishonest `mode=no-fork` when a fork is in flight.

**Root cause (layer 2):** "state of investigation" has no canonical representation — it lives fragmented across `investigation.md` prose, embedded invlang YAML blocks, and `state.json`'s phase history. Phase contracts validate against whichever is most convenient to parse at that point. The invlang migration is the opportunity to promote the embedded YAML to source-of-truth and make phase contracts validate state rather than authoring shape.

**Proposed contract changes** (implement as part of the invlang migration, not standalone):

1. **gather-composite:** honor the Level-1 finish discipline end-to-end. If the prescribed lead set is not fully executed, emit `status: partial` with `dropped_attempt[]` naming the skipped leads and the reason (budget / data-source unreachable / not-in-catalog). Reject `status: ok` writes on incomplete prescribed sets at handler validation. Checkpoint format (per run #42) already carries the per-lead shape — the discriminator just needs to be enforced on emission.

2. **analyze:** add a scope-check obligation to the routing decision.
   - Read prescribed leads from loop-N PREDICT trailer (`selected_lead`, and any composite members implied by the lead-catalog entry).
   - Read actually-resolved leads from loop-N GATHER YAML (`gather[*].lead` + `gather[*].status`).
   - Compute the prescribed-vs-resolved delta.
   - Route back to GATHER (not PREDICT) when the delta is non-empty, naming the missing leads in the routing trailer. Route to PREDICT only when the current lead set is fully resolved *and* the fork is undifferentiated.
   - Surface the scope-check result in the ANALYZE trailer so the handler can validate it rather than relying on Self-report prose.

3. **predict:** replace the shape-based `mode ⇒ block_type` check with a state-based validator against the invlang YAML on disk.
   - Valid loop-N PREDICT states: (a) new fork authored (current `mode=fork`), (b) existing fork continued with next lead selected (new — "stable-fork lead-selection"), (c) investigation cannot proceed — no discriminating lead available (current `mode=no-fork`).
   - Contract check reads the hypothesize YAML from investigation.md, verifies trailer references (selected_lead must match a known lead definition; hypothesis references in a continued-fork trailer must exist in the current hypothesize block).
   - "Did the agent re-author a hypothesize block this turn" stops being a first-class validation axis.

**Scope note.** This is a migration-completion task, not a standalone hot-fix. Doing only (1) or (2) without (3) leaves the PREDICT contract gap in place; doing only (3) without (1)+(2) means PREDICT keeps getting re-invoked on unchanged forks because the upstream scope-drop is never caught. The three belong in one PR.

**References:**
- Failure run: `/tmp/soc-agent-orchestrate-eval/20260423-043856-rule100001/runs/b7e1420e-347b-4a9a-9824-d4703eaeba37/`
- Current PREDICT contract: `soc-agent/scripts/handlers/predict.py:570-620`
- Gather-composite Level-1 reference: eval-run-table #42, `subagent_checkpoints/gather-composite-loop-{n}.yaml` format
- Invlang spec: `docs/investigation-language.md` v2.10
- Related: `make-analyze-dispatch-a-new-subagent.md`, `predict-phase-rename.md`
