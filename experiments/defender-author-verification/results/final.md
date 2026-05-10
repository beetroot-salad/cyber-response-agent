# Defender author verification — final experiment results

**Question:** Which lightweight per-edit verification check (forward, reverse, regression) correlates well enough with a full-Sonnet-rerun oracle to gate author commits in V0.1, without paying oracle cost on every edit?

**Method:** 8 hand-crafted (case, lesson) pairs — 4 intentionally-bad lessons (T2/T3/T4 typology), 4 intentionally-good lessons. For each:
- N=3 Haiku-judged trials per check (forward, reverse, regression) → 72 lightweight trials
- 1 full Sonnet defender investigation with the lesson preloaded → 8 oracle runs

Oracle verdict per lesson: GOOD if rerun disposition matches ground truth, BAD if it diverges.

## Headline result

**Forward alone is the recommended V0.1 gate.** TNR=100%, TPR=83%, oracle agreement 88%. Clears the strong-win bar (TNR ≥ 90% AND TPR ≥ 80%) set in the experiment plan.

## Confusion matrices vs oracle

Lightweight check majority-vote (≥2/3 reps say BAD → check verdict BAD):

| Lesson | Oracle | Forward | Reverse | Regression |
|---|---|---|---|---|
| L1 zero-success-spray | BAD | BAD ✓ | BAD ✓ | BAD ✓ |
| L2 burst-escalate | GOOD | BAD ✗ FP | BAD ✗ FP | BAD ✗ FP |
| L3 pname-null-escalate | BAD | BAD ✓ | GOOD ✗ FN | BAD ✓ |
| L4 high-entropy-c2 | GOOD | GOOD ✓ | BAD ✗ FP | BAD ✗ FP |
| L5 monitoring-username | GOOD | GOOD ✓ | BAD ✗ FP | BAD ✗ FP |
| L6 burst-not-disqualifying | GOOD | GOOD ✓ | BAD ✗ FP | GOOD ✓ |
| L7 container-shell-baseline | GOOD | GOOD ✓ | BAD ✗ FP | GOOD ✓ |
| L8 multi-domain-rotation | GOOD | GOOD ✓ | BAD ✗ FP | BAD ✗ FP |

| Check | TNR | TPR | Oracle agreement |
|---|---|---|---|
| **forward** | **2/2 = 100%** | **5/6 = 83%** | **7/8 = 88%** |
| reverse | 1/2 = 50% | 0/6 = 0% | 1/8 = 13% |
| regression | 2/2 = 100% | 2/6 = 33% | 4/8 = 50% |

## Key findings

1. **Forward is the only check worth shipping.** Reverse is dead (0/6 TPR — flags every good lesson). Regression catches all bad lessons but false-positives on 4/6 oracle-good lessons; not usable as gate, marginal as advisory.

2. **The same-case oracle has a structural blind spot.** Two of four hand-crafted bad lessons (L2 burst-escalate, L4 high-entropy-c2) didn't change disposition on their original case, so oracle says GOOD. By construction these lessons fail in the *regresses-elsewhere* / *overgeneralized-misframe* mode — they're correct on the original, wrong on variants. **No same-case oracle can detect that failure mode.** Forward inherits this blind spot — its oracle agreement is high partly because the oracle agrees the lessons don't break the original case.

3. **Pre-experiment per-label scoring was misleading in both directions.** Against my hand labels, forward looked weak (75% TNR) and regression looked strong (100% TNR). Against the oracle, the picture inverts: forward is strong, regression is noisy. This is why oracle comparison was load-bearing.

4. **The single forward FP (L2) is informative.** Forward predicted the lesson would change disposition; oracle says it didn't. Forward over-weighted the lesson's influence relative to the agent's evidence integration. Worth flagging that forward's failure mode is over-rejection on plausible-but-non-decisive lessons.

## Recommendation for V0.1

**Ship forward alone as the auto-gate.** Concretely:
- After each new/folded lesson is written, run forward check (Haiku, single rep) on the lesson against its source case's transcript.
- If forward verdict = GOOD: lesson commits.
- If forward verdict = BAD: lesson is held back, surfaced in commit message / PR description for human review.
- Single rep (no replication) is fine at edit time; replication only matters when measuring TNR statistically.

**Accept the oracle's blind spot.** T2/T4-style regresses-elsewhere bad lessons will slip past forward (since the oracle itself can't catch them on a same-case basis). Catch them via:
- PR-review surface — humans can spot overgeneralized phrasing when reading the lesson body.
- Post-deployment observability — once corpus is large enough, A/B test new lessons against held-out cases.
- Future experiment: cross-case oracle that runs the lesson on a *different* case where it should/shouldn't apply, requires labeled variant cases.

**Skip reverse and regression in V0.1.** Reverse is dead; regression's FP rate (4/6 on oracle-good) makes it noise, not signal.

## Caveats

- N=8 lessons; per-class power weak. Oracle-bad n=2, oracle-good n=6. One mislabeled lesson swings TNR/TPR materially.
- Lessons hand-crafted by author of this experiment — may share blind spots.
- Sonnet rerun used live SIEM data; different SIEM state could shift L2's disposition.
- Forward's prompt asks "would lesson preserve ground-truth disposition" — works because we have ground truth in the original transcript. For lessons emitted on cases where ground truth is uncertain, forward isn't applicable. Mitigation: run author + forward only on cases that reached a confident disposition.

## Future work

1. **Cross-case oracle** for T2/T4 detection — requires labeled variant cases per lesson; expensive to construct.
2. **Tighten regression prompt** — current version is too eager to find hypothetical failure cases; constrained "systematic misclassification only" wording might recover usable signal.
3. **Replicate at N=5 with broader fixture set** — to firm up TNR/TPR estimates before final V0.1 implementation.
