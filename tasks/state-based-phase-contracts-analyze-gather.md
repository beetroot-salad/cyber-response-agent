---
title: Define ANALYZE contract and relax PREDICT cardinality gate (plus gather-composite scope-check)
status: done
groups: invlang, analyze, gather-composite, predict, contracts
---

Surfaced by orchestrator run `20260423-043856-rule100001` (rule-100001, `predict-phase-rename` branch). Run crashed at loop-3 PREDICT with `OrchestrationError: mode 'fork' requires block_type 'hypothesize', got 'unknown'` after 1658s wall, but the crash was downstream of two independent bugs that both need fixing.

## The two bugs

**Bug A — gather-composite silently drops prescribed leads.** Loop-2 PREDICT prescribed two leads (`correlated-falco-events` + `source-reputation`). Loop-2 gather-composite executed only the first, emitted `status: ok` with `dropped_attempts: []`. No handler check compared prescribed vs executed scope. Loop-2 ANALYZE noticed the gap in prose but had no structural obligation to act on it.

**Bug B — PREDICT has no contract shape for "continue a stable fork."** The current handler enforces `mode=fork ⇒ block_type=hypothesize` and `mode=no-fork ⇒ halt`. The common loop-N state — *"the fork is unchanged from the last loop; pick the next discriminating lead"* — has no legal representation. The subagent was forced to either re-author the hypothesize block (illegal under invlang v2.10: "no second top-level hypothesize block") or dishonestly claim `mode=no-fork` while a fork was in flight. On this run it did neither and was rejected.

Bug B fires on the **happy path** — every loop-N that continues an unchanged fork. Bug A only fires on scope drops. The two are orthogonal; the failure run happened to hit both.

## Role split (the reframe)

The ANALYZE handler hasn't been written yet (migration status: `doing`). Its input contract was assumed to match the pre-rename HYPOTHESIZE phase, which no longer fits. Start fresh:

- **PREDICT scaffolds decisions.** Emits what ANALYZE will need to interpret gather's output: hypotheses (single, fork, or zero new ones), predictions, refutation shapes, authorization contracts, impact vocabulary (drawn from the signature's `impact_profile`), and the `selected_lead`.
- **ANALYZE applies the scaffolding.** Interprets gather observations: did what we predicted happen? Is the edge authorized? Does it amount to a material impact? Writes `resolutions[]` with weight updates, `authorization_resolutions[]` on fulfilled-contract edges, `anchor_consultations[]` for baseline lookups, optionally an impact vertex. Decides whether the investigation is terminal (route: continue → PREDICT | halt → CONCLUDE).
- **ANALYZE is not in the business of deciding what next.** Continuation planning is PREDICT's job. ANALYZE's only routing decision is the binary "are we done?"

Most ANALYZE output derives mechanically from the companion YAML (hypothesis IDs, prediction IDs, lead IDs already exist); its added content is compact — weights, cited prediction IDs, severity-of-test, short reasoning, supporting_edges.

## Contract changes

### 1. PREDICT — collapse the `mode` gate to cardinality (fixes Bug B)

Replace the shape-based `mode ⇒ block_type` check with a cardinality-agnostic schema. PREDICT emits:

```yaml
new_hypotheses: [...]           # 0, 1, or N — whatever the loop needs
selected_lead: <name> | null    # null ⇒ halt to CONCLUDE
unresolved_prescribed_set: []   # optional; only present when preferentially re-prescribing
                                # after ANALYZE flagged a gather gap
```

The four loop states are cardinality variants of one shape:

| `new_hypotheses` | `selected_lead` | Meaning |
|---|---|---|
| N ≥ 2 | set | Loop-1 fork (or mid-loop fork expansion) |
| 1 | set | Single-story investigation or one-hypothesis refinement |
| 0 | set | **Continue existing stable fork, pick next lead** (the missing state) |
| 0 | null | Halt to CONCLUDE |

Emitted hypotheses land in the next lead's `new_hypotheses[]` per invlang v2.10 ("no second top-level hypothesize block"). `mode` stops being a primary axis. Validator reduces to two structural resolves: `selected_lead` exists in the lead catalog; any hypothesis references resolve against the accumulated companion state.

### 2. ANALYZE — greenfield handler + subagent contract (new)

Role: interpretation only. Input: the companion's accumulated state + the latest gather lead outcome. Output payload:

```yaml
resolutions: [...]                     # per-hypothesis weight updates, matched IDs, severity, reasoning
authorization_resolutions: [...]        # optional; on edges that fulfill a declared contract
anchor_consultations: [...]             # optional; on the lead outcome — baselines/registry/reference
impact_vertex: { ... } | null           # optional; materialize only when non-negligible
trailer:
  route: continue | halt
  termination_category: <enum> | null    # required when route=halt
  unresolved_prescribed_set: [lead-name, ...]  # optional; prescribed leads without resolutions
```

`unresolved_prescribed_set` is the backstop for Bug A: if gather-composite's scope-check is bypassed or itself buggy, ANALYZE will still notice that a prescribed lead produced no observations to interpret, and flag it on the trailer. PREDICT consumes the field next turn.

Impact-as-vertex semantics: per invlang spec, impact is a graph vertex, not a per-resolution field. ANALYZE materializes one only when observations meet the "worth flagging" threshold defined by the signature's `impact_profile`. Silence = negligible, which is the common case.

### 3. gather-composite — enforce the prescribed-vs-executed discriminator (fixes Bug A)

Handler reads the prescribed lead set from the PREDICT payload it already receives; diffs against emitted `leads[].lead + status`; rejects `status: ok` when prescribed scope isn't covered; requires `status: partial` with `dropped_attempts[]` naming each skipped lead and reason (budget / data-source unreachable / not-in-catalog / other). Checkpoint format already carries the per-lead shape — enforcement is new.

Plumbing check: confirm the gather-composite handler currently receives the PREDICT trailer; if not, this is also a small wiring change.

## Sequencing

(1) PREDICT relaxation and (2) ANALYZE contract are coupled — ANALYZE's trailer feeds PREDICT's `unresolved_prescribed_set`, and PREDICT's output shape is what ANALYZE reads to scope its interpretation. Land together.

(3) gather-composite is independent and can land first or alongside. Without it, the ANALYZE backstop still catches drops — slower but not broken.

All three in one PR is still the cleanest path; if split, the order is (3) then (1)+(2).

## References

- Failure run: `/tmp/soc-agent-orchestrate-eval/20260423-043856-rule100001/runs/b7e1420e-347b-4a9a-9824-d4703eaeba37/`
- Current PREDICT handler: `soc-agent/scripts/handlers/predict.py` (shape check around L570–620)
- Gather-composite checkpoint format: `subagent_checkpoints/gather-composite-loop-{n}.yaml`
- Invlang spec: `docs/investigation-language.md` v2.10 (top-level structure, impact vocabulary, no-second-hypothesize rule)
- Migration skill: `.claude/skills/migrate-state-machine/SKILL.md` (ANALYZE status: `doing`)
- Related tasks: `make-analyze-dispatch-a-new-subagent.md`, `predict-phase-rename.md`