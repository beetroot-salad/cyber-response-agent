---
title: Rename HYPOTHESIZE → PREDICT, reframe prompt, drop archetypes from its context
status: doing
groups: predict, hypothesize, state-machine, prompt
---

## Context — why this exists

Across ~10 PRs (#87 → #110) HYPOTHESIZE work has circled around one pattern: the error-analysis corpus shows **FM4 (legitimacy packed into classification name) in 79%** of blocks and **FM5 (parallel sanctioned/unsanctioned pair, same mechanism) in 46%** (`docs/experiments/hypothesize-error-analysis.md`). Every PR addressed it structurally (validator rules, prompt trims, archetype reframes, topology priors). None of them removed the underlying pressure: the word "hypothesize" and the prompt's "≥ 2 competing classifications" rule together pull the subagent toward enumeration even when the alert pins the mechanism and only authorization is open.

**The reframe**: the middle phase's job is not "propose theories." It is to **set up the next two phases** — choose the lead GATHER will fire, and pre-declare the predictions + refutation shapes + legitimacy contracts ANALYZE will read evidence against. That's a scaffolding deliverable, not a generation deliverable. The number of hypothesis entries (0, 1, many) is incidental to the deliverable: emit what ANALYZE needs to close the loop, no more.

The word retire is **PREDICT** — because the deliverable literally is predictions + refutation shapes. Operational takeaways to encode:
1. **Unknowns are first-class**: `pname=null` is not "a mechanism to guess between"; it's a structural gap the alert has left open. Name it, set up a lead that fills it. Do not enumerate mechanisms around it.
2. **Biases are first-class**: priors, seeds, archetypes, prompt examples — all exert pressure. Name the bias when it's load-bearing ("using top-1 historical scaffold; fall back to first principles if GATHER contradicts") so ANALYZE can challenge it.
3. **Don't eat more than we can chew**: acceptance test is "can GATHER + ANALYZE close this loop against the setup?" A scaffold whose predictions aren't resolvable by one lead's output is oversized.
4. **Adversaries use legitimate-looking tools; legitimate actors perform unusual modalities.** Mechanism discrimination is blind to authority. Use `legitimacy_contract` primitives (PR #88) for the authorization question; do not enumerate ci-pipeline-exec vs adversary-controlled-host-exec as peer mechanisms.

## In scope

**Prompt rewrite** (`soc-agent/agents/hypothesize.md` → `soc-agent/agents/predict.md`):
- Restore **ASSESS** as the first move *inside* PREDICT: "is the mechanism pinned? is authorization the only open question? are there unknowns to fill? are there genuinely plural mechanisms?" This is the gate that was folded into HYPOTHESIZE in PR #94 and drove the circling. Bring it back as the opening step; shape everything after it.
- Reframe the phase brief from "form hypotheses" to: *"Your job is to set up GATHER + ANALYZE. Pick the lead. Pre-declare the predictions and refutation shapes ANALYZE will read evidence against. Pre-declare any `legitimacy_contract` whose anchor verdict decides authorization."*
- **Rewrite rule 229** (currently `"No HYPOTHESIZE without a fork. Enter only when ≥ 2 competing classifications..."`): `"Emit as many mechanism stories as ANALYZE needs to route the disposition — usually ONE when the alert pins the mechanism and the open question is authorization; more when mechanisms genuinely diverge and the lead will discriminate."`
- **no-fork mode** currently emits no invlang block — loosen so single-hypothesis-with-legitimacy_contract is expressible. Options: (a) `mode: fork` accepts ≥ 1 hypothesis provided it carries a `legitimacy_contract`; (b) new `mode: single-mechanism`; (c) rename `mode:` values. Pick what reads cleanest with the reframe.
- Keep the lean-one-hop discipline, the causal-story requirement (PR #92), and the PR #88 legitimacy-contract vocabulary — they are the solid methodology. What changes is the framing around them.
- **Drop archetype context entirely.** The subagent's input should no longer include the archetype-scan output block, and the prompt should not instruct the agent to cross-reference playbook archetype names. Archetypes move to REPORT (separate task).
- **Update the three worked examples** to match: one pinned-mechanism example (single hypothesis + legitimacy_contract + discriminating lead), one genuinely-plural-mechanism example (NXDOMAIN spike: misconfigured-resolver vs DGA-beaconing, different discriminators), one unknown-fill example (`pname=null` → scaffold-to-get-ancestry with no mechanism enumeration).

**Priors reshape** (part of PREDICT's context-loader work in `scripts/handlers/_context_loader.py` and the priors renderer in `scripts/handlers/predict.py` — currently `hypothesize.py`):
- **Baseline-recommendation format.** When top-N peer classifications at this prologue topology have strong support (peer_count ≥ threshold AND mean effectiveness above threshold), render as: *"Strongest prior at this topology: `?runtime-exec-from-host` + contract on `deploy-runs` (7/9 cases, 64% `+` rate). Use this scaffold unless the alert specifically contradicts it."* When support is weak, render as: *"Priors at this topology are sparse — scaffold from first principles per takeaways (a)(b)."* Set explicit thresholds; emit one or the other.
- **Remove archetype peer-distribution from the priors block entirely** (today it drives enumeration). Priors carry only: (i) mechanism scaffolds that worked, (ii) legitimacy anchors consulted and their verdicts, (iii) leads that discriminated. No archetype labels.
- The prologue-keyed retrieval landed today on branch — `lead_effectiveness_for_prologue` + `peer_hypothesis_distribution_for_prologue` in `scripts/invlang/queries.py`. That retrieval is correct; what changes is the render shape.

**Handler + orchestrator renames**:
- `scripts/handlers/hypothesize.py` → `scripts/handlers/predict.py`.
- `scripts/orchestrate.py` Phase enum: `HYPOTHESIZE` → `PREDICT`. Update every handler-routing table, every `Phase.HYPOTHESIZE` reference.
- `_FAILURE_REMEDIATIONS` registry keys rename (`gather_block_in_hypothesize` → `gather_block_in_predict`, etc). Content unchanged.
- Any import paths: `scripts/handlers/__init__.py`, `run_orchestrator.py`, other handlers' cross-references.

**State-machine hooks**:
- `hooks/scripts/infer_state.py` and `hooks/scripts/infer_state_pre.py` parse `## PHASE` headers. Recognize `## PREDICT` as the new phase. **Hard cut** — do NOT alias `## HYPOTHESIZE` → PREDICT. Past corpus files stay queryable via invlang YAML parsing (block names unchanged); phase headers only matter on new runs. Aliasing rots.
- Phase validity tables / transition graphs updated.

**Test suite**:
- Rename `tests/test_hypothesize_*.py` → `tests/test_predict_*.py` where present. Update all fixture investigation.md files from `## HYPOTHESIZE` → `## PREDICT` headers. Update assertions + Phase enum references.
- **Invlang `hypotheses:` YAML block name stays unchanged** — corpus backward-compat requirement. Only phase headers and handler names change.

**Validation**:
- End-to-end eval via `playground/scripts/eval_run_orchestrate.sh 100001 --window 5m` after the changes land. Acceptance: PREDICT fires; output is **scaffold-shaped** (one mechanism story + legitimacy_contract OR genuinely distinct peers, per ASSESS); ANALYZE closes the loop against it; REPORT (still named CONCLUDE at this point) writes report.md. Compare output against the golden reference at `tasks-scratch/golden-rule100001-scenario-A.md` — specifically the "one mechanism + two contracts" positive pattern.

## Out of scope

- Moving archetype-scan dispatch from CONTEXTUALIZE to REPORT — that's the `report-phase-rename` task.
- Renaming CONCLUDE → REPORT — that's the `report-phase-rename` task.
- Updating handbook content, migration skill docs, loop diagrams, golden reference phase names — that's the `predict-report-docs-update` task.
- Invlang `hypotheses:` block schema changes (renaming the block, restructuring fields) — that's the `invlang-schema-assessment-post-predict-report` task.
- Re-writing past run investigation.md files to use new phase names — they stay as-is. Corpus queries parse YAML blocks, not headers; no regression.
- Adding new validator rules for "invoker-identity-differs-only-on-authorization" sibling check. Explicitly decided against: regex-on-adversarial-tokens is a bottomless pit. Semantic failure modes are prompt-level, not structural.

## Acceptance criteria

1. `soc-agent/agents/predict.md` exists with the reframed prompt; `hypothesize.md` is removed (or kept as a redirect-stub during transition if other tasks depend on it; preferred: removed).
2. `scripts/handlers/predict.py` handles what `hypothesize.py` handled; orchestrator routes to it.
3. `Phase.PREDICT` is live; `Phase.HYPOTHESIZE` removed.
4. Full test suite passes (`pytest soc-agent/tests/ -v -m "not llm"`).
5. End-to-end orchestrator eval on rule 100001 scenario A lands a REPORT (still named CONCLUDE) with the PREDICT output matching the golden pattern: one mechanism story + legitimacy_contract + discriminating lead, **NOT** a peer fork on invoker identity.
6. Priors output at loop 1 is in baseline-recommendation format (strong prior case) or named-sparse format (weak prior case) — never a 5-peer-list.

## Dependencies

None — this is step 1 of the migration. Blocks `report-phase-rename` and `predict-report-docs-update`.

## Notes

- Closes (for real) the `tasks/adversarial-as-attribute-not-hypothesis.md` work, which was marked `done` after PR #88 but whose *spirit* — the "drop the maintain-adversarial-hypothesis rule" from hypothesis enumeration — was only partially applied because line 229's ≥ 2 rule kept the enumeration pressure.
- The `/workspace/tasks-scratch/golden-rule100001-scenario-A.md` golden reference uses HYPOTHESIZE terminology throughout. It gets renamed as part of `predict-report-docs-update`, not here.
- Preserve PR #88's legitimacy-contract primitive, PR #92's causal-story discipline, and PR #109's topology-conditioned priors. These are the pieces that worked; what failed was the phase framing around them.
