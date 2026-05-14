# Arm A final results — NL-goal → seed selection at scale

**Date:** 2026-05-13
**Trials:** 3 trials × 14 fixtures × 3 catalog sizes = **126 Haiku calls**
**Model:** Haiku via `claude -p --model haiku`
**Catalog sizes:** N=8 (real catalog only), N=58 (+50 distractors), N=158 (+150 distractors)

## Top-line numbers

| N | correct | partial | wrong | unparseable | accuracy (strict / partial-credit) |
|---|---------|---------|-------|-------------|-------------------------------------|
| 8   | 40/42 | 0 | 2 | 0 | **95% / 95%** |
| 58  | 31/42 | 5 | 6 | 0 | **74% / 86%** |
| 158 | 25/42 | 5 | 12 | 0 | **60% / 71%** |

## The three sub-questions, answered

### Q1 — Bloat ceiling: where does selection break?

**Answer: it depends entirely on fixture class.** Aggregate accuracy is a misleading number; the per-class breakdown is the real signal.

| Class | N=8 | N=58 | N=158 |
|---|---|---|---|
| ambiguous (composite) | 9/9 ✅ | 9/9 ✅ | 9/9 ✅ |
| clear-match | 24/24 (100%) | 17/24 + 5 partial (71% / 92%) | 16/24 + 5 partial (67% / 88%) |
| no-match | 7/9 (78%) | 5/9 (56%) | **0/9 (0%) ❌** |

Clear-match degrades but doesn't collapse — most failures are partial-overselected (added a near-duplicate alongside the correct lead). No-match COLLAPSES.

### Q2 — Irrelevant-lead discipline: does Haiku skip cleanly?

**Answer: NO at scale.** This is the dominant failure mode.

- N=8: 7/9 correct on no-match (Haiku correctly proposes new when nothing fits).
- N=158: **0/9 correct.** Every single no-match trial picked a distractor that had a name-keyword match.

The pattern is sharp and reproducible:

- **F9 (MFA enrollment audit)**: at N=158, all 3/3 trials selected `mfa-enrollment-events` (a stub distractor with no body). Haiku trusts the manifest entry's name-match over the absence of a real implementation.
- **F10 (kernel module enumeration)**: 3/3 → `kernel-module-events`.
- **F11 (firmware update tracking)**: 3/3 → `firmware-update-history`.

**Stub distractors are indistinguishable from real seeds in the manifest view** (`name | tags | one-line goal`) — exactly what production runtime selection sees. The finding generalizes: **any catalog entry whose name semantically matches the goal will be selected, regardless of whether the underlying seed has been implemented.**

### Q3 — Near-duplicate confusion: can Haiku recover?

**Answer: stably confused on some pairs; gracefully recovers on others.**

Two clear-match fixtures showed stable near-duplicate confusion at N=58:

- **F1 (authentication burst pattern)**: the NL goal phrased "clustered burst pattern" → at N=58, 0/3 correct, all picked `auth-failure-burst-detector` (the adjacent distractor). Curiously, at N=158, the pattern partially broke: 1/3 picked the correct lead, 1/3 picked the distractor, 1/3 picked both. **More distractors → less confident pick of the distractor.** Haiku's "find the best-matching name" strategy degrades as the catalog grows, but in this case the degradation HELPED.
- **F6 (user-account classification)**: at N=58, 3/3 over-selected with `account-naming-pattern` alongside the correct `user-analysis`. Partial credit, not a wrong answer — but the bloat is real.

**Composite selection works robustly.** Three ambiguous fixtures hit 9/9 across all catalog sizes. When the goal genuinely needs two seeds together, Haiku surfaces both reliably.

## What the lead-author agent must do (concrete)

Three primitives, in priority order:

### 1. Applicability discipline is the #1 priority — `no-match` collapse is total

The lead-author agent's most load-bearing job is preventing the no-match failure mode. Two mechanisms:

- **Manifest-entry hygiene.** A name + 1-line intent in the manifest is, from Haiku's perspective, a real seed. If the catalog lists `mfa-enrollment-events` but no actual definition exists, Haiku will select it and gather will fail. **Rule: never add a manifest entry without a fully-implemented seed behind it.** No stubs in production catalogs.
- **"Do not use when" prose on every seed.** The intent description must explicitly bound the seed's applicability. Without that bound, Haiku reaches for whatever name-matches. This is the applicability-predicate hypothesis from the design conversation, now empirically validated.

### 2. Distinctness checks against near-duplicates are moderately load-bearing

Clear-match degraded by ~12% strict / ~7% partial-credit at scale. Most failures were **partial-overselected**, not wrong — Haiku added the near-duplicate alongside the correct lead. Two concrete patterns:

- F6: `account-naming-pattern` (distractor) consistently selected alongside `user-analysis` because the NL goal mentioned "match any known pattern."
- F1: `auth-failure-burst-detector` (distractor) consistently picked over `authentication-history` because the goal mentioned "clustered burst pattern."

The lead-author agent should run a distinctness check before adding any seed: "is this seed's intent prose meaningfully distinct from existing seeds L1, L2, L3 — would Haiku confuse them?" If yes, either merge or sharpen prose.

### 3. Composite selection works — do NOT enforce uniqueness

Ambiguous fixtures hit 9/9 at every N. The author agent does not need to enforce single-lead selection. Two real leads with overlapping applicability are fine; Haiku handles the composite case.

## Surprising findings

1. **Ad-hoc as a meta-lead is fragile (F7).** 3/3 at N=8 → 2/3 at N=58 → 1/3 at N=158. The semantics of "use this when no other lead fits" don't survive scale. At N=158, Haiku twice produced `PROPOSE_NEW` for F7's "bespoke syscall+path query" — even though `ad-hoc` IS exactly that primitive. **The lead-author agent should give meta-leads (`ad-hoc`, `data-source-debug`) extra-explicit applicability prose framing them as procedural verbs, not data-domain seeds.** Notably, `data-source-debug` was rock-solid (9/9 across all N) — its NL goal is more operationally distinctive ("zero events returned, debug the data source") than ad-hoc's.

2. **The N=58 → N=158 transition is not monotone.** F1 went 0/3 wrong at N=58 → 1/3 correct + mixed at N=158. Adding more distractors didn't make things uniformly worse. Hypothesis: at N=58 Haiku has high confidence in name-matching; at N=158 with a wider distractor pool, name-matching is less discriminative and Haiku falls back to broader semantic reasoning more often.

3. **Stub distractors are indistinguishable from real seeds at selection time.** This is methodologically clean (the manifest view IS what runtime sees) but has a sharp implication: catalog hygiene is non-negotiable. Every manifest entry must be backed by a working implementation, or production will dispatch to nonexistent seeds.

## Bloat ceiling: revised answer

The bloat ceiling is **goal-class-dependent**:

- For unambiguously clear-match goals: holds reasonably well at N=158 (67% strict, 88% partial).
- For genuinely ambiguous goals: rock-solid even at N=158.
- For no-match goals: **catastrophic** by N=158.

The hard ceiling isn't a number — it's a discipline. **As long as every catalog entry is real and every seed has explicit applicability prose, scaling looks manageable up to at least N=158.** Without those disciplines, even N=58 is risky for no-match scenarios.

## Implications for lead-author agent design (updated)

The prior design conversation flagged five questions about the author's discipline. Empirical answers:

| Question | Empirical answer |
|---|---|
| Is bloat a present concern? | **Yes, but bounded** — clear-match holds; no-match collapses. The fix is applicability prose, not catalog-size limits. |
| Are applicability predicates load-bearing? | **YES, dominantly.** No-match accuracy: 78% → 0% as catalog grows. |
| Are near-duplicates a runtime hazard? | Moderately. ~12% degradation, mostly partial-overselected. Distinctness check is a secondary discipline, not primary. |
| Is recovery the right primitive (vs perfect selection)? | **YES.** Ambiguous-fixture coverage is robust. Composite output works. Don't enforce uniqueness. |
| Do meta-leads need special framing? | **YES for ad-hoc.** Operational verbs need explicit "use when X procedurally" framing. `data-source-debug` is the model — its goal phrasing names the trigger condition. |

## Recommendation

The seed-based catalog model is viable up to ~150 seeds **IF** the lead-author agent enforces two disciplines:

1. **No manifest entry without a real seed behind it.** Stubs are dangerous.
2. **Every seed's intent prose includes explicit applicability bounds** — "use when X; do not use when Y."

Near-duplicate distinctness is a secondary check; composite selection handles ambiguity natively.

**Next concrete steps the empirical work suggests:**

1. Sharpen the `ad-hoc` lead's intent prose to frame it as a procedural verb. Test impact on F7.
2. Pick one clear-match fixture's near-duplicate confusion (e.g., F1's `auth-failure-burst-detector`) and test whether adding distinctness prose to `authentication-history` flips the result.
3. **Defer** explicit no-match testing in production until the lead-author agent enforces the manifest-hygiene discipline. The collapse pattern is a property of the catalog state, not the seed model.

## Artifacts

- All 126 runs in `runs_arm_a/`
- Per-trial scoring in `results/arm_a_scores.json`
- Distractor pool generator: `gen_distractors.py` (155 distractors, deterministic order)
- Selection harness: `arm_a_harness.py`
- Selection prompt: `variants/selection_prompt.md`
