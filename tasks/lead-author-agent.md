---
title: Lead-author agent — post-mortem seed maintenance with selection-test gates
status: todo
groups: defender, lead-author, post-mortem, knowledge-base
---

**Motivation.** Post-investigation, the agent should self-improve its lead catalog: fold lessons into existing seeds when neighbors already cover the executed shape, add new seeds only when no neighbor does, and verify both moves with a selection-test gate that catches the empirically-observed failure modes (no-match collapse, near-duplicate confusion, blank-Goal nullification). A new seed without verification is a precision tax on neighbors and a dispatch trap if its template fails.

This task implements the **lead-author agent**: an offline post-mortem actor that proposes seed edits (via PR per existing post-mortem convention), gated by a structural checklist and an empirical Haiku-driven test suite.

## Empirical grounding

Three experiments under `experiments/lead-seed-haiku/` frame this work. Read those writeups (`results/validation.md`, `results/final.md`, `results/arm_a_final.md`) for the data — summary below.

### Insight 1 — seeds work as customization targets (Arm B, 87% effective at 3 trials)

Haiku reliably adapts a seed's intent + example to specific needs: window-shifting, entity-field swaps, multi-rule filters, composite RFC1918 negations all hit 100% across 3 trials each. The one stable failure (F-cust-04 forward-bracket, 1/3) was a **seed defect** — the template's example was internally inconsistent with the intent prose, and Haiku faithfully copied the broken example 2/3 trials. *Implication:* intent ↔ example consistency is load-bearing; the author must verify the example demonstrates the intent's claim before shipping.

### Insight 2 — selection collapses on no-match goals as catalog grows (Arm A)

3 trials × 14 fixtures × 3 catalog sizes = 126 calls. Per-class:

| Class | N=8 | N=58 | N=158 |
|---|---|---|---|
| Ambiguous (composite) | 9/9 ✅ | 9/9 ✅ | 9/9 ✅ |
| Clear-match | 24/24 | 17/24 + 5 partial | 16/24 + 5 partial |
| **No-match** | 7/9 | 5/9 | **0/9 ❌** |

The no-match collapse is the dominant failure mode. Haiku picks any distractor whose name semantically matches the goal — even stubs with no implementation. *Implication:* explicit applicability prose ("do not use when…") on every seed is the #1 author primitive; manifest hygiene (no entry without backing definition + template) is #1a.

### Insight 3 — near-duplicate confusion is stable, not random (Arm A F1, F6)

F1 went 0/3 at N=58 because `auth-failure-burst-detector` (an adjacent-named distractor) deterministically beat `authentication-history` when the NL goal mentioned "burst." F6 over-selected `account-naming-pattern` alongside `user-analysis` 3/3 at N=58. *Implication:* adjacent-named seeds impose a precision tax on their neighbors. Author discipline: before adding a seed, audit semantic neighbors and prefer sharpening the existing one over forking a new one.

### Insight 4 — manifest structure is non-negotiable (F7 root cause)

`ad-hoc/definition.md` used `## When this applies` instead of `## Goal`; the manifest extractor returned an empty goal line; Haiku saw `ad-hoc | [] |` and made decisions against a blank. The seed was silently nullified at selection time without any error. After adding a proper `## Goal` with sharpened trigger framing, F7 recovered 6/9 → 9/9 across all catalog sizes. *Implication:* structural conformance (every seed has `## Goal`) is a first-class validator check, not boilerplate.

### Insight 5 — composite selection works natively; do NOT enforce uniqueness (Arm A ambiguous)

9/9 at every N. When the goal spans two seeds, Haiku surfaces both comma-separated. The author should NOT design distinctness rules around "this seed must be the sole winner" — that's not how the runtime decides, and it would over-constrain the catalog.

## Lead-writing discipline (post-mortem flow)

For each investigation that successfully executed at least one lead, the author agent runs this sequence:

1. **Extract the executed lead queries.** From `runs/<run>/tool_audit.jsonl`, pull every actual SIEM query string the gather subagent executed, paired with the lead it was dispatched under and the intent prose that motivated it.

2. **Search for semantic neighbors.** For each executed (lead, query) pair, scan the existing catalog for seeds whose example query shape and Goal prose overlap with the executed query and the motivating intent. Two seeds overlap when (a) their example queries share entity-field tokens, filters, or aggregation shape, AND (b) their Goal prose describes an evidence need within one semantic step of the motivating intent.

3. **Branch on overlap:**
   - **Overlap exists → sharpen the existing seed.** Prefer this branch. Edit the existing seed's `## Goal` to absorb the new applicability case (one sentence), and tighten its "do not use when…" if the executed shape was previously ambiguous. Do NOT add a new seed when sharpening covers the case.
   - **No overlap → add this lead.** Author a new seed: frontmatter + `## Goal` with selection-trigger framing + `## When to use` with explicit applicability bounds + per-vendor `templates/<vendor>.md` with at least one worked example.

4. **Run Tier 1 validation on the edited/new seed.** Block the PR if Tier 1 fails (see test-suite design below).

5. **Open PR (per post-mortem convention).** Branch + commit + PR with the executed-lead provenance in the body — case IDs that motivated the edit, the executed query strings, the diff against the prior catalog state.

The discipline matches the prior-feedback memory **Post-mortem flow ships PRs, not proposals.md** — no proposals surface; the author opens a real PR with the candidate edit.

## Test-suite design (per-seed)

Lives alongside the seed:

```
leads/<name>/
  definition.md
  templates/<vendor>.md
  tests/
    positive.yaml      # 3–5 NL goals → expect SELECT <name>
    negative.yaml      # 3–5 NL goals near-miss → expect NOT this seed (PROPOSE_NEW or named neighbor)
    neighbors.yaml     # paired NL goals, one per declared neighbor: goal_A → this, goal_B → that
    customization.yaml # 2–3 adaptation tasks: seed + alert + need → expected substrings in adapted query
```

Test classes map directly to the empirical failure modes:

- **Positive selection** — catches blank-Goal nullification (Insight 4) and ensures the seed wins on its canonical needs.
- **Negative selection** — catches no-match collapse (Insight 2). Must assert *both* "this seed isn't picked" AND the expected positive (PROPOSE_NEW or named neighbor) — otherwise tests rot as the catalog changes (negative passes for the wrong reason when a new seed absorbs the goal).
- **Neighbors** — catches near-duplicate confusion (Insight 3). One paired test per declared neighbor.
- **Customization** — catches intent ↔ example drift (Insight 1). Modeled after the Arm B fixture format (`fixtures/customization/*.json`): substring rubric scoring.

### Tier 1 vs Tier 2 (agreed)

- **Tier 1 — every edit.** Static checklist + customization test (1 fixture, 3 trials). ~1–2 min wall. Blocks the PR on regression.
  - Static checklist: frontmatter present; `## Goal` non-empty; if meta-lead, Goal names selection trigger; `## When to use` applicability prose present; per-vendor template file exists; example query syntactically reproduces intent's claim (a static check where possible, defer to customization test where not).
  - Customization test: ≥ 1 fixture × 3 trials. Pass = 2/3 correct.

- **Tier 2 — daily OR after ~10 edits, whichever first.** Full selection suite — positive + negative + neighbor pairs across the *current* catalog. ~5 min wall (proportional to per-seed test count × Haiku per call). Catches catalog-level regressions: a seed edit that fixed its own test may have broken a neighbor's negative test.
  - Trigger: cron at 03:00 local OR pending-edits-since-last-tier2 counter ≥ 10.
  - Threshold per seed: positive ≥ 3/3; negative ≥ 3/3; neighbor pairs ≥ 3/3 both directions. Regressions block subsequent edits until the regressed seed is sharpened or its tests revised.

Run cadence:
- Tier 1 runs synchronously inside the lead-author agent before opening the PR.
- Tier 2 runs as a background routine; results posted to a dedicated tracking file (`experiments/lead-suite/results/tier2-<date>.md` or similar) and surfaced to the author agent on its next run if regressions exist.

## Scope and non-scope

**In scope (this task):**
- Lead-author agent skill: post-mortem extract → neighbor search → fold-or-add decision → seed edit → Tier 1 validation → PR.
- Per-seed test-file format and validator.
- Tier 1 test runner (synchronous, invoked by author agent).
- Tier 2 test runner (background routine + trigger).
- Backfill test files for the 8 existing real seeds (otherwise Tier 2 has nothing to validate against).

**Out of scope (deferred to later tasks):**
- Lead-author agent for archetypes (not seeds). Different surface, different precision concerns.
- Auto-merging Tier 1 passing PRs. Initial version requires human review on the PR.
- Mining the corpus for "leads that are never picked across N investigations" — pruning by usage trace (Insight: corpus mining). Should land after the author agent is shipping seeds at all.
- Cross-vendor seed authoring. Most existing seeds are Wazuh-only; the cross-vendor port path is a separate problem.

## Sequencing — one PR each

- [ ] **Lead test-file format + validator.** Define `tests/{positive,negative,neighbors,customization}.yaml` schemas; build a per-file validator + Tier 1 runner that wraps Arm A's `arm_a_harness.py` and Arm B's `harness.py`. Backfill test files for the 8 existing real seeds. PR validates by running Tier 1 on every seed and reporting current baseline pass rates.
- [ ] **Lead-author agent skill.** New `soc-agent/skills/lead-author/SKILL.md` (or extension of existing `author/`). Inputs: a run directory or list. Procedure: extract executed leads → search neighbors → propose fold-or-add → run Tier 1 → open PR. Uses worktree convention per existing memory.
- [ ] **Tier 2 background routine.** A scheduled job (cron or `/schedule`) that runs the full selection suite, writes results to a tracked file, and signals regressions back to the author agent. Threshold: regression on any seed blocks subsequent edits to that seed until resolved.
- [ ] **Backfill applicability prose.** Audit the 8 real seeds for "do not use when…" prose (the no-match collapse fix). Edit those missing it, verify Tier 1 passes, and run an ad-hoc Tier 2 against the same Arm A fixtures to verify aggregate improvement vs the baseline (`experiments/lead-seed-haiku/results/arm_a_final.md`).

## Open questions

- **Negative-test ground truth specification.** Should `negative.yaml` name the expected positive outcome (`PROPOSE_NEW` or `<neighbor-name>`)? Strong argument yes — protects against neighbor-coupling rot (a passing negative for the wrong reason). Cost: more authoring upfront and brittleness if the right neighbor is itself unstable. Default: require the expected positive on every negative entry; allow `PROPOSE_NEW` as a wildcard for genuinely-unmatched cases.

- **Neighbor declaration source.** Does each seed declare its semantic neighbors statically (in its definition.md frontmatter)? Or is the neighbor list computed by the author agent at test time from catalog similarity? Static declaration is auditable but rots; computed is current but non-deterministic. Default: static declaration in frontmatter; author agent suggests neighbor edits when it adds/folds seeds.

- **What counts as "executed lead queries"?** Only successful gather runs, or also gather errors with informative queries? Including errored queries surfaces leads where the template was wrong (useful for sharpening); but errored queries also include genuinely broken cases that shouldn't drive catalog changes. Default: successful gather runs only; errored cases feed a separate "template-defect" surface (e.g., the F-cust-04 fix flow).

- **Where do Tier 1/2 results live?** Per-run telemetry (`runs/<run>/lead_author/`) or a global tracking file (`experiments/lead-suite/`)? The former is auditable; the latter is queryable. Probably both: per-run for provenance, global for aggregate signal.
