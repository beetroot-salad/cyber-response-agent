# Round 1 v2 — Comparison (hypothesis-atomicity fix)

**Fixture:** `case-rule5710-loop1` with `?monitoring-loop-broken` split into
`?probe-retry-stuck` and `?probe-enumeration-misconfigured`.
**Arms:** A (minimal) / B (+ pre-commitments) / C (+ org context)
**Model:** Sonnet across all arms
**Change from Round 1:** the ambiguous hypothesis defined as
"misconfigured OR stuck in a retry loop" was split into two sharp
hypotheses, each with a single mechanism and a single prediction shape.
Ground truth updated accordingly.

---

## Headline

**Grade variance collapsed to zero.** All three arms scored **6/6**
exact on grades against the updated ground truth. The drift observed
in Round 1 (Arms B and C upgrading `?monitoring-loop-broken` from
`-` to `+`) is gone, confirming that the Round 1 failures were
caused by hypothesis-level ambiguity, not by ANALYZE-phase reasoning
defects or missing context.

The checklist-bias hypothesis from Round 1 is **not** supported by
this round: Arm B had the same prediction-checklist format as in
Round 1 and still graded correctly, because the predictions now
name observable shapes that directly discriminate the mechanisms
("repeated attempts on ONE username" vs "rotation through the full
set"), leaving no room for the grade to drift away from the
reasoning.

---

## Grade accuracy

| Hypothesis | Ground | Arm A | Arm B | Arm C |
|---|---|---|---|---|
| `?probe-retry-stuck` | `--` | `--` ✓ | `--` ✓ | `--` ✓ |
| `?probe-enumeration-misconfigured` | `+` | `+` ✓ | `+` ✓ | `+` ✓ |
| `?monitoring-bait-triggered` | `+` | `+` ✓ | `+` ✓ | `+` ✓ |
| `?monitoring-host-compromise` | `-` | `-` ✓ | `-` ✓ | `-` ✓ |
| `?internal-credential-guessing` | `--` | `--` ✓ | `--` ✓ | `--` ✓ |
| `?compromise-followup` | `--` | `--` ✓ | `--` ✓ | `--` ✓ |
| **Total correct** | | **6/6** | **6/6** | **6/6** |

---

## Routing decision

| | Chose | Rationale |
|---|---|---|
| Arm A | HYPOTHESIZE | Enumerates a workload-ownership lead (crontab/file-read on monitoring-host) as a potential discriminator; acknowledges it may not be accessible |
| Arm B | CONCLUDE | "No further lead is likely to resolve the bait vs. enumeration-misconfig ambiguity with available tooling" |
| Arm C | CONCLUDE | Archetype/anchor gate drives routing — no archetype fits, so escalation is structurally required |

Ground-truth text says CONCLUDE; original agent behavior ran a loop
2 anyway. Routing split across arms suggests the same variance as
Round 1: without explicit org context about the archetype gate and
tooling boundaries, Arm A defaults toward "try another lead"; with
pre-commitments listing the unavailable refutation paths (Arm B) or
the archetype gate explicitly (Arm C), the arms route to CONCLUDE.

**The routing signal is still too weak to decide the contract fork
on.** It correlates with context level, not with correctness.

---

## Dimension-by-dimension

| Dimension | Arm A | Arm B | Arm C |
|---|---|---|---|
| Grade correctness | 6/6 exact | 6/6 exact | 6/6 exact |
| Refutation-attempt discipline | ✓ cited multi-username refutation of retry-stuck, no false `++` | ✓ applied named cap rules; no false `++` | ✓ named archetype gate + cap rules |
| Adversarial preservation (`?compromise` at `-`) | ✓ | ✓ | ✓ |
| Bait-vs-enumeration indistinguishability correctly flagged | ✓ explicitly noted | ✓ explicitly noted | ✓ explicitly noted |
| Hallucinated context | ✓ none | ✓ none | ✓ none |

All three arms independently identified the `?bait` vs
`?probe-enumeration-misconfigured` observational indistinguishability
as the core epistemic limit — a reasoning quality that Round 1
partially masked behind grade drift.

---

## Key finding — hypothesis atomicity is upstream of ANALYZE quality

Round 1 comparison attributed B/C failures to a "checklist-bias in
pre-commitments extraction." Round 1-v2 disproves that attribution:

- Arm B still uses the prediction-checklist format
- Arm B still lists predictions for `?probe-enumeration-misconfigured`
  as a bulleted list ("rotation ✓, cron active ✓, zero successful
  logins ✓, zero non-5710 alerts ✓")
- Arm B still grades `+`, matching ground truth

What changed: the prediction now names an observable shape
(**rotation through the full sentinel set**) that the evidence either
directly exhibits or contradicts. There is no disjunct the subagent
can silently pick from. When the prediction is sharp, the checklist
format is fine.

The Round 1 drift was not about format. It was about two mechanisms
sharing a name. Fix the name, the drift disappears.

---

## Revised load-bearing classification

Round 1 claimed "pre-commitments extraction is harmful on the margin."
Round 1-v2 invalidates that claim: pre-commitments worked correctly
when the underlying hypotheses were atomic. The revised view:

| Item | Classification | Evidence |
|---|---|---|
| Prior investigation log (CONTEXTUALIZE + HYPOTHESIZE prose) | **Necessary** | All arms depend on it; none hallucinated |
| Lead output | **Necessary** | Obvious |
| Structured pre-commitment extraction (Arm B) | **Neutral-to-helpful** when hypotheses are atomic; harmful when they aren't | Compare Round 1 vs Round 1-v2: same format, different accuracy driven by hypothesis quality |
| Adversarial status flagged explicitly | **Nice-to-have** | All arms got adversarial preservation right from raw prose |
| Archetype + anchor gate context (Arm C) | **Load-bearing for routing** | Arm C's CONCLUDE routing is driven by the archetype gate; Arms A/B route differently without it |
| Environment readiness / preflight | **Nice-to-have** | No arm depended on it for grades |
| Loop budget | **Ignored** | No arm cited it |

---

## Implications

1. **Hypothesis atomicity is a HYPOTHESIZE-phase quality invariant**
   — it is not an ANALYZE problem at all. Any ANALYZE (inline or
   subagent, any model) inherits ambiguity from upstream. See
   `tasks/hypothesis-atomicity-invariant.md`.

2. **The ANALYZE-extraction question is now cleaner.** With
   atomized hypotheses, grade drift across context bundles has
   collapsed. Sonnet-subagent ANALYZE with a minimal bundle (Arm A)
   is as accurate as Sonnet-subagent ANALYZE with a full bundle
   (Arm C) on grades. The remaining open question is routing —
   and that's the contract fork the pilot was set up to test.

3. **Routing correctness is still unmeasured** because the fixture
   has ambiguous routing ground truth. Round 2 needs a fixture
   with a crisp routing answer to make the contract fork decidable.

4. **The checklist-bias concern from Round 1 is retracted.** The
   pre-commitments extraction format is not the issue; it surfaces
   defects when underlying hypothesis claims are ambiguous. With
   atomic hypotheses, the format is neutral-to-helpful.

---

## Recommendations for Round 2

1. **Keep the atomized hypothesis format going forward** as a
   baseline — future fixtures should not repeat the disjunctive-claim
   failure mode.

2. **Select a fixture with crisp routing ground truth** (unchanged
   from Round 1's recommendation — the fixture's ambiguity is the
   main remaining obstacle to contract-fork evaluation).

3. **Drop the "Arm B′ mechanism-statements" variant from Round 2**
   — Round 1-v2 already tests it implicitly (the atomized
   predictions ARE mechanism statements) and they work without
   reformatting the supplement structure.

4. **Include a mid-loop fixture** to exercise rollup-drift, still
   unmeasured.
