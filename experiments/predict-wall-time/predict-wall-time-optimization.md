# PREDICT wall-time optimization

**Goal:** bring PREDICT subagent loop wall clock to **90-120s**, down from current ~314s on loop 1 (100001, run #44). Loops 2 and 3 already land near target (93s, 195s-with-pathology); the loop-1 outlier is the target.

## Baseline — this session's reference

Run #44 (orchestrator `20260423-195235-rule100001`, Sonnet 4.6, rule 100001 scenario A, full 3-loop):

| Loop | Duration | Prompt chars | Stdout chars |
|---|---|---|---|
| predict loop 1 | **314s** | 19,771 | 4,154 |
| predict loop 2 | 94s | 30,856 | 2,284 |
| predict loop 3 | 196s | 29,909 | 1 (stdout=1 M_last pathology + retry) |

Loop 1 transcript forensics (`dd637208-5f8a-4ba9-8971-d26fbccbcf4d.jsonl`):
- **2 thinking blocks, total 28,562 chars. First block = 27,778 chars (~4m 24s).**
- 2 tool calls: Bash (invlang corpus probe, 191B) + Write (checkpoint, 3,756B).
- 1 text block (4,153 chars — stdout).
- ~84% of wall time is pure upfront thinking ("restatement + reason" pattern).

## Recurrence — predict loop-1 variance across earlier runs

All same-signature (rule 100001, `docker exec -t target-endpoint bash -c whoami` scenario), same preload shape as run #44 (before today's signature-knowledge drop). Same playbook richness (6 archetypes, 12KB signature-knowledge block). Pattern is **highly consistent within this scenario**:

| Orchestrator run | Loop-1 wall | Stdout chars | Shape / pathology |
|---|---|---|---|
| `20260421-171849-rule100001` | 277s | 2,982 | clean; two-attempt retry on unrelated cause |
| `20260421-174559-rule100001` | 301s | 905 | short output, no retry |
| `20260421-175726-rule100001` | **144s** | 2,017 | fast clean success — last turn was TEXT not Write(M_last) |
| `20260421-181641-rule100001` | 165s → retry 31s | 1 → valid | stdout-empty M_last pathology; recovered |
| `20260421-183244-rule100001` | **324s** | 1,362 | slow upfront thinking block, no retry |
| `20260421-213431-rule100001` (testrun skill run #50) | 308s → retry 25s | 1 → valid | same M_last pathology; drove the `legitimacy_contract` list-shape schema finding |
| `20260423-195235-rule100001` (run #44, baseline above) | **314s** | 4,154 | clean; our forensic reference |

**Variance band: 144s–324s, same signature, same alert shape, same preload.** Documented in testrun meta-finding #17 and `/workspace/tasks-scratch/hypothesize-variance-analysis.md`. Two orthogonal drivers:

1. **Checkpoint-after-YAML ordering (M_last pathology)** — `agents/predict.md §Progress checkpoint` puts the checkpoint Write *after* the text response. When the model follows literally, last turn is `tool_use(Write)` and `claude --print` emits empty stdout, triggering a retry. ~1-in-3 first attempts on rule-100001. Responsible for the 25-31s retry tails, not for the 300s+ thinking-block outliers.
2. **Upfront thinking-block restatement** — the 27.7KB thinking block is stochastic but recurs on the same input. When it happens it's ~180-220s of pure thinking before any action, and sometimes stacks with deeper exploration to reach 300s+. The fast runs (144s) simply didn't trigger the full restatement pass. Run #44 landed on the "restates everything" branch.

**Implication:** 144s is the *best-case* on the current prompt at rule-100001's playbook richness; 314s is the bad-case. Optimization levers should target the restatement driver (prompt size, forcing functions on output order) because that's what distinguishes the two branches.

## Recurrence — richer-vs-thinner playbooks

Orchestrator-harness predict-phase data is detailed only for rule 100001 (thick playbook: 6 archetypes, ~12KB signature-knowledge). What we have on other signatures is coarser (total-run cost, not per-subagent), but the shape is informative:

| Signature | Playbook richness | Example run | Total wall | Loop count | Notes |
|---|---|---|---|---|---|
| **100001** (terminal shell in container) | 6 archetypes, no precedents, thick threat/risk/gap prose | #44 above | 1616s | 3-loop | our baseline |
| **100001** (same) | same | `20260422-074031-rule100001` | 3-loop clean + CONCLUDE timeout @ 300s | — | testrun meta-finding #22; drove CONCLUDE preload trimming |
| **100110** (DNS stress) | 1 archetype, no precedents, thin playbook | run #32 (`orchestrate.47`) | 1081s | 1-loop | single analyze dispatch fired cleanly under PR #77's `trust-and-act` contract — predict shape not isolated |
| **5710** (SSH invalid user) | 4 archetypes, 1 precedent (SEC-2024-001), screen table, mature starter-lead order | run #19 (`orchestrate.17`) | 589s | SCREEN-resolved, no predict dispatch | predict skipped entirely via SCREEN fast-path |
| **5710** (bait scenario) | same | run #42 (`changes.55`) | 1257s | 1-loop | single predict call, single-anchor stopping rule — cheaper than 100001 full-loop |

**Pattern:** playbook richness dominates predict cost more than loop count. 100001 at 3 loops = 1616s; 5710 at 1 loop post-refactor = 1257s; 100110 (thinnest) at 1 loop post-trust-and-act = 1081s. Each richness tier carries ~300-500s of fixed-cost preload-reconciliation work that doesn't vary with investigation depth. This is the signal that lever 1 (signature-knowledge drop) is specifically targeting: the fixed-cost reconciliation that scales with signature scaffolding size, not with investigation complexity.

## Failure mode we will NOT trade off for speed

Run #44 escalated cleanly after `correlated-falco-events` returned `data_missing` twice. No hallucination, no false narrative, no confident `++` on circumstantial evidence. This graceful-fail property is harder to get than wall-clock and must not regress.

## Lever inventory

Two categories: **obvious** (well-understood mechanism, low regression risk, ready to implement / measure) and **needs discussion** (real tradeoffs, regression risk, or architectural cost that hasn't been priced).

### Obvious

| # | Lever | Est. loop-1 delta | Effort | Status |
|---|---|---|---|---|
| 1 | Drop `<signature-knowledge>` from predict preload | **−222s measured (−71% on 100001)** | done | **landed and validated** — 100001 #45: 314s → 92s; 5710 #48: 65s. Both post-fix loop-1 measurements inside the 90-120s target band. |
| 2 | Force shape-decision-first in output format | −30-60s | small (~10 lines) | proposed; **deferred below #2a** since its baseline will shift after the loop-N preload trim |
| 2a | **Trim investigation.md in loop-N preloads** (keep CONTEXTUALIZE + latest ANALYZE + lead-outcome summaries; drop raw prior GATHER observations) | unquantified — primarily unblocks completion, secondarily trims wall | medium | **new top priority** per session finding #3 — this is now a completion-gating issue, not just speed |
| 2b | **Absorb query fallback ladders inside GATHER/CLI instead of paying another PREDICT loop** | **up to −396s full-loop on 100001 run #44** | medium | newly identified from raw transcript; not yet designed |

### Needs discussion

| # | Lever | Est. loop-1 delta | Key question |
|---|---|---|---|
| 3 | §Shapes prose → decision table + 5 canonical examples (one per D/E/I/A/M) | −15-30s | the 4 new examples must be correct against invlang v2.11; authoring cost + calibration effort is non-trivial |
| 4 | §Disciplines → inline "not-this" callouts on examples | −20-30s | some anti-patterns don't bind to a single shape; moving them inline may fragment the rule set |
| 5 | Drop 2-4-sentence causal-story → 1-sentence baseline link | −30-60s | conflicts with `feedback_playbook_lean_one_hop_layering`; risks falsifiability regression — the guard memory for `feedback_circumstantial_ne_authoritative` |
| 6 | Split predict-loop1 (fork authoring) from predict-loopN (lead-only) | high on loop-1, zero on loop-N | architectural cost (two prompts, handoff protocol); loops 2+ are already near target |

## Lever 1 — signature-knowledge drop (implemented, pending measurement)

**What changed**
- `scripts/handlers/predict.py::_assemble_prompt`: no longer calls `format_signature_text_block(signature_texts)`; the `<signature-knowledge>` XML block is gone from the preload.
- `agents/predict.md` frontmatter: `tools: Bash, Read, Write` (added Read for the on-demand escape hatch).
- `agents/predict.md` §Inputs: documents that playbook/context is not preloaded; available via `Read knowledge/signatures/<signature_id>/playbook.md` when shape calibration requires it.
- `tests/test_handlers_predict.py::test_prompt_inlines_all_deterministic_context`: asserts `<signature-knowledge>` and `<playbook>` are NOT in the prompt; other blocks still present.

**Why this is the biggest single lever**
- Removes ~12 KB (~60%) of the 19.7 KB prompt.
- Secondary win: the playbook content (hypothesis seeds, archetypes, composition rules) overlaps with what the subagent prompt itself describes (5-shape framework), forcing a reconciliation thinking pass. Dropping the playbook removes the reconciliation.
- CONTEXTUALIZE's narrative (loaded into `<investigation>`) already distills the relevant seeds/archetypes for this alert — which is the only subset that mattered for shape selection.

**What we're measuring**
- Run #45 (`20260423-202319-rule100001`) in flight at time of writing.
- Primary metric: predict loop 1 wall clock.
- Secondary: stdout quality (same disposition shape as run #44, no regression in hypothesis depth).

## Lever 2 — shape-decision-first output format (proposed, cheapest next move)

**What changes**
- `agents/predict.md` §Output format: prepend `**Shape:** <letter> — <one-line trigger>` as the literal first line of output, before any YAML fence.
- No change to handler — the line is informational for the transcript, not a machine-parsed field.

**Why it works**
- LLMs commit to the direction of their first output tokens. Currently the output is "invlang YAML first, shape never named explicitly" — so the model does all 5-shape exploration in thinking before the first output token. Forcing a shape letter as the first committed token compresses the exploration: the model picks the shape quickly and then justifies it in subsequent tokens rather than exploring the full space first.
- This is a forcing function, not a constraint. The model can still backtrack in thinking, but it pays for backtracking in a way it currently doesn't.

**Synergy**
- Combines multiplicatively with levers 3+4: a shape-first output means the example the model reaches for is the *single* shape example, not a mental composite of 5 shape descriptions. The 27.7K-char thinking restatement is driven partly by the need to hold all 5 shapes in mind until the commit point.

## Lever 3 — §Shapes prose → decision table + 5 canonical examples

**Current shape**
- 5 shapes described abstractly (D, E, I, A, M), each ~10-15 lines of prose about triggers and typical alerts.
- **Only Shape I has a worked example** (~90 lines of full YAML).
- Net: the model pattern-walks abstract rules for 4 of 5 shapes, pattern-matches against one example for the fifth.

**Proposed shape**
- **Decision table** (~15 lines): `if <trigger field> → Shape X` rows walked top-to-bottom.
- **5 compact YAML examples**, ~25-30 lines each (~125-150 lines total):
  - Shape D: EDR YARA hit with null write_actor
  - Shape E: rule-5710 SSH reject, loop 1, no baseline
  - Shape I: rule-5710 loop 2 (existing, trim to ~30 lines)
  - Shape A: Falco container-exec with runc parent (runs #44 scenario)
  - Shape M: Unbound NXDOMAIN spike (misconfig vs DGA)

**Why examples beat prose**
- Pattern-matching is cheaper than pattern-walking. One concrete `?underlying-host-exec` example with a `legitimacy_contract` on `ci-cd-job-record` is faster to reach for than 15 lines describing "mechanism pinned, only authorization open".
- The current asymmetry (1 example for 5 shapes) means the model has to imagine the YAML shape for D/E/A/M each time. Five examples remove that imagination step.

**Cost**
- Authoring 4 new examples. Each needs to be correct against the invlang v2.11 schema (legitimacy_contract shape, prediction/refutation-shape symmetry, one-observable-per-claim discipline).
- One-time effort; examples remain stable across signatures.

## Lever 4 — §Disciplines → inline "not-this" callouts on examples

**Current shape**
- §Disciplines is a 12-bullet "reference tail" at end of prompt listing anti-patterns (invoker-identity-as-classification, hypotheses-not-verdicts, one-observable-per-claim, legitimacy-contracts-answer-policy, etc.).
- Model re-checks the draft against 12 rules. Some rules are visually similar and require per-case reasoning to disambiguate.

**Proposed shape**
- Pair each anti-pattern with the shape where it typically applies, inline in the example:
  - Shape A example carries the "invoker-identity-as-classification" anti-pattern callout ("❌ `?ci-pipeline-exec` vs `?adversary-controlled-host-exec` is ONE mechanism with two verdicts — collapse to single hypothesis with legitimacy_contract").
  - Shape M example carries the "hypotheses are mechanisms, not verdicts" callout.
  - Shape E example carries the "labels vs stories" callout.
- Retain a short "always true" list (3-4 bullets) for rules not tied to a shape: weight=null, append-only, one-observable-per-claim.

**Why contextualized > abstract**
- "Don't make this mistake when you're in Shape A" is faster to apply than "walk 12 rules against your draft".
- Reduces the second biggest thinking sink (discipline recheck) from rule-enumeration to per-shape pattern-matching.

## Lever 5 — relax causal-story requirement (discuss)

**Current shape (agents/predict.md §Story authoring)**
- Story is 2-4 sentences.
- Each `prediction.claim` cites a story sentence via `from_story_link`.
- "Baseline required when history exists" enforces a baseline-grounding sentence.
- "Labels vs stories" enforces concrete causal phrasing over category-labels.

**Proposed relaxation**
- One sentence max: the baseline-grounding sentence only (or "no baseline" negation).
- `from_story_link` remains (prediction → baseline sentence), but predictions get to be less verbose.
- Drop labels-vs-stories prose (demonstrable via examples).

**Upside**
- 30-60s off loop 1. Story authoring is creative work — the model drafts, revises, checks discipline, revises again.

**Risk**
- `feedback_playbook_lean_one_hop_layering`: lean one-hop seeds with causal stories is the documented pattern — stories force falsifiable predictions. Dropping them risks drift back into "pattern consistency" claims that `feedback_circumstantial_ne_authoritative` guards against.
- Middle path: keep the baseline sentence, drop the 2-4 sentence expectation and the labels-vs-stories prose.

**Decision deferred** until we measure levers 1+2+3+4 together.

## Lever 6 — split predict into loop-1 vs loop-N subagents (deferred)

**Proposed split**
- `predict-bootstrap`: owns fork authoring (hypotheses, predictions, refutation shapes, contracts). Runs only at loop 1 or when a fork expansion is triggered.
- `predict-continue`: owns lead selection only. Runs at loop 2+.

**Why defer**
- Loops 2 and 3 are already near target. The architectural cost (two prompt surfaces, handoff protocol, main-loop conditional dispatch) isn't justified by the current data.
- Revisit if levers 1-4 plateau above 150s on loop 1.

## Meta-lever — prompt size ↔ upfront restatement

The 27.7K-char thinking block is Sonnet's "restatement pass" — echoing prompt content before reasoning. It scales with (a) prompt size and (b) how much the prompt implicitly asks the model to hold-in-mind.

- Lever 1 hits (a) directly: −60% prompt size.
- Levers 2, 3, 4 hit (b): a shape-first output with per-shape inline examples means the model only needs to hold ONE shape's context in mind once it commits, not all 5.
- These compose. The delta from lever 1 alone may not be the full story; the full win comes from **lever 1 + lever 2** combined, because lever 2 lets the restatement shrink to the fields relevant to the chosen shape.

## Session measured results (2026-04-23)

Lever 1 was the only code change landed this session. Three runs measured the delta:

| Run | Signature | Scenario | Fix state | Predict loop-1 | Prompt chars | Outcome |
|---|---|---|---|---|---|---|
| #44 `20260423-195235` | 100001 | A (thin data) | baseline (signature-knowledge present) | **314s** | 19,771 | 3-loop → escalated/inconclusive/low, clean |
| #45 `20260423-202319` | 100001 | A (thin data) | **lever 1** (signature-knowledge dropped) | **92s** | 6,231 | 2-loop → escalated/inconclusive/medium, clean |
| #48 `20260423-205026` | 5710 | B bait mid-burst (rich scaffolding + anchor data) | **lever 1** | **65s** | not captured | 2-loop → **loop-2 ANALYZE timeout @ 300s**, no report.md |

**Isolated lever-1 effect (holding signature constant on 100001): 314s → 92s = −71% on predict loop 1.** Both post-fix numbers (92s on 100001, 65s on 5710) land inside the 90-120s target band. Lever 1 alone closed the gap for loop-1.

Also measured: two 5710 SCREEN-resolved runs (scenario A clean, scenario B bait first-of-burst) landing at 179s and 210s total subagent wall — predict not exercised at all. 5710 scenario A is the clearest "rich scaffolding + working telemetry → SCREEN fast-path fires" datapoint.

## Recurring findings from this session

### 1. Signature-knowledge reconciliation is the dominant fixed cost on loop-1 predict

The −71% drop on 100001 loop-1 (314s → 92s, prompt 19.7KB → 6.2KB) is almost entirely the reconciliation pass: Sonnet was walking the 12KB playbook (6 archetypes, threat/risk/gap prose, starter-lead order) against the 5-shape framework in the subagent prompt. Dropping the playbook removed the reconciliation. This validates meta-finding #17(b)'s restatement driver as primarily prompt-size-sensitive, not just input-complexity-sensitive.

### 2. Lever 1 does NOT help with variable per-loop cost

The loop-2 predict prompt grows with investigation.md accumulation regardless of whether signature-knowledge is preloaded:
- 100001 #45 loop-2 predict prompt = 11,126 chars (accumulated GATHER + ANALYZE from loop 1)
- 5710 #48 loop-2 predict prompt = 29,909 chars (accumulated SCREEN output + GATHER + ANALYZE from loop 1 — larger because 5710's loop-1 investigation state is richer)

This matches testrun meta-finding #22's loop-N amplification pattern, and it's **orthogonal to lever 1**. The signature-knowledge drop addressed the one-time fixed cost; the per-loop variable cost from investigation.md accumulation remains untouched.

### 3. Loop-N ANALYZE timeout is now the dominant full-loop failure mode

Five observations of the same failure class:
- `20260422-044342-rule100001` — loop-2 HYPOTHESIZE timeout @ 450s (per testrun meta-finding #22)
- `20260422-074031-rule100001` — CONCLUDE timeout @ 300s (same meta-finding)
- `20260422-085126-rule100001` — CONCLUDE full-context fallback timeout @ 300s (fixed in run via mechanical compose)
- `20260423-205026-rule5710` (this session) — **loop-2 ANALYZE timeout @ 300s**, no report.md

All share the same driver: the subagent's investigation.md preload grows through the investigation, Sonnet's upfront thinking restatement scales with it, and fixed-ceiling timeouts catch loop-N. The fix from meta-finding #22 — **trim investigation.md in loop-N preloads to keep CONTEXTUALIZE + latest ANALYZE + lead-outcomes summary, drop raw prior GATHER observations** — generalizes to all narrative-synthesis subagents. This is now the next lever (ahead of lever 2 in priority) because it gates completion, not just speed.

### 4. Scaffolding × telemetry is binary, not a sliding scale, for SCREEN eligibility

- 5710 scenario A (rich scaffolding + working anchor data) = SCREEN fast-path fires, 179s total, predict never runs.
- 5710 scenario B first-of-burst (same signature, harness quirk) = SCREEN matches, 210s total, predict never runs.
- 5710 scenario B mid-burst via `--offset=2` (same signature, SCREEN correctly falls through) = full loop, hit the loop-N timeout.
- 100001 (rich scaffolding but anchors don't map to reachable data) = no SCREEN table at all; always full loop.

Implication: the scaffolding-maturity investment (lever outside this doc — signature-by-signature SCREEN table + anchor-grounding recipes) is what delivers the bulk of the wall-clock wins in production. Predict-phase optimization only matters for the minority of alerts that correctly fall through SCREEN.

### 5. The `inconclusive` vocabulary unification was a prerequisite

Prior to this session, ANALYZE emitted `disposition: escalated` while the report frontmatter enum used `inconclusive` + `status: escalated`. This enum split crashed the orchestrator handler (`_VALID_DISPOSITIONS` rejected `escalated` → OrchestrationError) and blocked all full-loop 100001 runs at ANALYZE route-validation. The unification (one enum `{benign, false_positive, true_positive, inconclusive}`, outcome `status` derived at REPORT from the disposition) was the unblocker. Without it, none of the measurements above would have been possible.

### 6. Harness `--offset` works but is under-advertised

`fetch_alert.py --offset N` and `eval_run_orchestrate.sh --offset N` both exist and pass through cleanly. This is the reliable way to get a mid-burst alert that fails `attempt_count_5min=1` and forces predictable full-loop runs on 5710 bait. The testrun skill's "known harness quirks" section said this was a gap (`--offset` support requested); it was actually already implemented. Worth a skill-doc update.

### 7. Checkpoint-and-recovery fired in the wild on loop-2 gather-composite

In run #48, the first loop-2 gather-composite dispatch returned stdout=750 (partial/short). Main agent recognized the short stdout as a recovery trigger per SKILL.md cue, re-dispatched with the existing checkpoint, and the retry returned full 6,530-byte stdout cleanly. First confirmed in-the-wild validation of the gather-composite Level 2 checkpoint mechanism under Sonnet cadence (prior validation was in run #42).

### 8. Recoverable query drift was paid as a full extra loop

Run #44's raw transcript shows a recoverable field-path issue stretching across loop 2 and loop 3 instead of being resolved inside the original `correlated-falco-events` dispatch:
- loop-2 GATHER (`fab61747-8fad-4224-8be8-12cf543cb083`) tried 4 near-duplicate Wazuh queries: container-id scoped rule set, rule-only probe, free-text container-id within target rules, then free-text container-id across all rules.
- loop-2 ANALYZE inferred the likely cause correctly: the container-id path looked unindexed / mismatched, not "true zero events".
- loop-3 PREDICT then spent another 196s re-selecting the **same lead** with a rewritten hint (`container.name:target-endpoint` coverage probe + retry), after which loop-3 GATHER confirmed the window cleanly.

Quantitatively, the recovery tail was:
- predict loop 3: 196s
- gather loop 3: 100s
- analyze loop 3: 100s

That is **~396s of extra wall time** to recover a query-path mismatch that was already visible by the end of loop 2. This is not a "predict needs better reasoning" problem; it is a "GATHER/CLI should own the fallback ladder" problem. The discriminating recovery logic should live where the query is executed:
- try primary structured field path
- if rule-only probe is hot but scoped query is cold, automatically try known aliases / coverage probe
- only return `data_missing` after the fallback ladder is exhausted

This is the highest-value full-loop save still visible after lever 1, because it removes an entire predict/analyze cycle when the failure is mechanical.

### 9. Generic Wazuh docs were low-signal for this failure class

The same loop-2 GATHER transcript reread:
- `knowledge/environment/systems/wazuh/SKILL.md`
- `knowledge/common-investigation/leads/ad-hoc/definition.md`
- `knowledge/environment/systems/wazuh/field-quirks.md`

But the actual failure was a container field-path/indexing mismatch. `field-quirks.md` is mostly authentication-oriented (`srcuser`/`dstuser`, NTSTATUS, auth-type caveats) plus generic reminders like `data.*` prefix and `rule.id` as string. It does **not** contain the container-path aliasing needed for this recovery. So "read more generic vendor docs on demand" is not enough here; the recovery recipe needs to be encoded closer to execution:
- in the lead definition itself (`correlated-falco-events`)
- in `wazuh_cli.py` as a scoped fallback ladder
- or in a small, field-family-specific query cookbook instead of broad vendor prose

This matters for wall clock because each low-signal reread adds another think/reconcile pass without reducing the search space.

## Proposed sequence (updated)

1. ✅ **Lever 1 landed and measured — closed the loop-1 gap.** 314s → 92s on 100001, 65s on 5710, both inside the 90-120s target.
2. 🆕 **New priority: investigation.md loop-N preload trim** (per meta-finding #22 + session finding #3). This now gates completion on full-loop runs, not just speed. Keep CONTEXTUALIZE + latest ANALYZE + per-lead outcome summaries; drop raw prior GATHER observations. Applies to predict, analyze, and conclude subagents.
3. 🆕 **Next highest-value full-loop win: absorb query fallback ladders into GATHER/CLI** so recoverable field-path mismatches do not burn another predict/analyze cycle.
4. Lever 2 (shape-decision-first output format) — still proposed, still cheap. Defer until after #2/#3 because both will change the steady-state measurement baseline.
5. Levers 3-6 stay in "needs discussion" bucket. Revisit only if 1+2+3+4 don't close the steady-state full-loop gap.

## Open questions

- Does the signature-knowledge drop regress quality on alerts where CONTEXTUALIZE didn't surface the load-bearing seed? (e.g., a signature with 8+ archetypes where CONTEXTUALIZE only ranks top-3 — the other 5 archetypes are now invisible to predict.) Worth a probe on a thin-CONTEXTUALIZE signature after we confirm the 100001 A/B.
- Does shape-first output cause the model to over-commit when the shape is genuinely ambiguous? Counter: the decision procedure already says "stop at first match" — forcing first-match commitment in output is consistent with that rule.
- Does lever 3's decision table risk becoming out-of-date with §Shapes prose? Probably — but if lever 3 lands, §Shapes prose is **replaced** by table + examples, not duplicated.
