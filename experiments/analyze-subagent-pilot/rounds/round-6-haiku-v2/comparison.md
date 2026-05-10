# Round 6 Haiku v2 — Comparison

**Question:** Does the routing-gate fix from round-5's comparison close
the over-commit failure mode, and does Haiku hold up under compound
failure modes (two stressors at once)?

**Method:** Same Arm A minimal bundle, revised prompt with explicit
routing gate + sibling-discrimination rule + "no `--` on absence" rule.
Five arms: two retests (P2 ambiguous-routing, P5 mixed-evidence) and
three compound fixtures (C1–C3).

## Scorecard

| # | Fixture / stressors | Routing | Grades | Verdict vs round 5 |
|---|---|---|---|---|
| P2-retest | ambiguous routing | **HYPOTHESIZE** ✓ (was CONCLUDE) | 5/6 exact; `?probe-enumeration-misconfigured` corrected `++` → `+` ✓ | **Improved** (with adversarial regression, see below) |
| P5-retest | mixed evidence | **HYPOTHESIZE** ✓ (was CONCLUDE) | Calibrated `+`/`+`/`--`/live; named discriminating lead | **Fixed** |
| C1 | poisoned rollup + total data gap | **HYPOTHESIZE** ✓ | Held prior weights (correct), flagged poisoned `++` in self-report | **PASS** |
| C2 | mixed usernames + 1 successful login on ambiguous-profile account (`deploy`) | **HYPOTHESIZE** ✓ | `?compromise-followup` `++` ✓, but `?targeted-brute-force` `+` → `-` (over-corrected) | **PASS with over-refutation** |
| C3 | poisoned rollup + partial forward-window data gap | **HYPOTHESIZE** ✓ | Opp `++` ✓, `?compromise-followup` held live-unrefuted ✓, targeted `++` → `-` (not `--`; poisoned-prior hedge) | **PASS** |

## The fix worked on its target

**P5 (mixed evidence) is cleanly fixed.** Round 5: CONCLUDE with
`matched_archetype: targeted-brute-force`. Round 6: HYPOTHESIZE,
citing the routing gate directly, named a discriminating lead
(6-hour prior-window recon check). The self-report is explicit:
"routing gate is not satisfied because two `+` hypotheses have
conflicting archetypes and dispositions."

**P2 (ambiguous routing) is also fixed on the core bug.** The round-5
over-upgrade (`?probe-enumeration-misconfigured`: `++`) is gone;
round-6 gives it `+` and names process-execution history on
monitoring-host as the discriminator. Routing flipped from CONCLUDE
to HYPOTHESIZE.

## But the fix introduced a secondary regression

**P2 adversarial hypothesis: round-5 correctly kept `?monitoring-host-
compromise` at `-` live. Round-6 graded it `--`.** The v2 prompt's
"all `--` grades justified by direct evidence" rule pushed Haiku to
justify `--` by enumerating refutation checks (no rotation, no
sustained burst, no successful login, no precursors). But the
fixture's ground-truth preserves `-` live because the adversary may
stay within the sentinel set deliberately — absence of rotation is
not proof of innocence.

This is the classic adversarial-preservation failure: aggressively
refuting the adversarial hypothesis with indirect evidence. The v2
prompt inadvertently rewards this by making `--` easier to justify
to the routing gate.

**C2 targeted over-refutation.** Haiku graded `?targeted-brute-force`
as `-` (was `+`) on the mixed 74/26 fixture with a successful login.
Ground-truth-ish: should remain `+` (env-specific names present,
can't be refuted; successful login on `deploy` is ambiguous between
opp-hit and targeted-hit). Same failure mode as P2 — the prompt
pushes toward justifying stronger refutation.

The routing decision is still correct (HYPOTHESIZE with post-session
forensics), so the downstream impact is limited, but the grading is
miscalibrated.

## Compound failure handling

**C1 (poisoned rollup + total data gap):** Haiku held the poisoned
`++` on `?targeted-brute-force` forward (correct — no evidence to
refute it) while flagging the concern in self-report. Did not
auto-correct without evidence. Held `?compromise-followup` as live
unrefuted (correct). Routed HYPOTHESIZE with host-log fallback
(correct). **No compound-failure amplification.**

**C3 (poisoned rollup + partial data gap):** Haiku correctly treated
the two stressors as independent: (a) corrected the poisoned `++` on
targeted using the preceding-window evidence (100% generic
usernames refutes targeted directly), (b) refused to grade
`?compromise-followup` on the forward-window absence, held it live.
Routed HYPOTHESIZE for forward-window retry. **Clean compound
handling.** Minor: targeted graded `-` rather than `--`; reasonable
hedge given the prior was poisoned.

**C2 (mixed + successful login):** The hardest compound — genuine
opp/targeted ambiguity *and* an active compromise signal. Haiku
graded `?compromise-followup` `++` (correct) and routed HYPOTHESIZE
toward post-session forensics (correct). The cost: over-refuted
targeted to `-`. But this is a grading miscalibration, not a routing
failure. The investigation can recover — next lead will re-expose
targeted-vs-opp discrimination.

## Net assessment

**Primary fix: successful.** Round-5's signature failure (CONCLUDE on
ambiguity) is gone. Both ambiguous fixtures (P2, P5) now route
HYPOTHESIZE, cite the routing gate explicitly, and name
discriminating leads.

**Secondary regression: real but manageable.** The "no `--` on
absence" rule combined with "all `--` justified by direct evidence"
pushed Haiku to over-refute adversarial and targeted hypotheses in
P2 and C2. This did not corrupt routing in any of the 5 cases, but
it did move grades away from ground-truth calibration.

**Compound-failure handling: robust.** All three compound fixtures
passed. Haiku treated stressors as independent, did not cascade
errors, and preserved data-absence discipline under compound load.

## Recommended next contract iteration

The routing gate worked. The grading rule added alongside it
(implicit "justify `--` by direct evidence") is slightly too sharp
and needs softening for adversarial hypotheses specifically.

Proposed v3 addition to the weight semantics section:

> **Adversarial hypothesis refutation bar.** Grading an adversarial
> hypothesis `--` requires direct evidence against a core prediction,
> not the *absence* of predicted indicators. An attacker who
> deliberately stayed within expected patterns would produce the same
> "absence of anomaly" signal as a benign event. When unsure, grade
> `-` and keep the hypothesis live — the routing gate accepts `-`
> live for the adversarial hypothesis.

This should restore P2's `?monitoring-host-compromise` at `-` live
without re-introducing the round-5 CONCLUDE bias.

## Open items

1. **Run v3 prompt on P2 + C2** — confirm adversarial-preservation
   restored without re-introducing over-commitment.
2. **Stress variance** — round 6 is single-run per fixture. Run
   P5 twice under v3 to verify the routing-gate decision is stable
   across Haiku runs (round 4 showed zero variance on the clean
   fixture; ambiguous fixtures may be less stable).
3. **Trust handoff under v3** — once adversarial preservation is
   clean, hand a v3 Haiku ANALYZE to a Sonnet main agent and measure
   handoff acceptance (as round-3-stress did for Sonnet → Sonnet).
4. **Over-refutation of non-adversarial hypotheses (C2 targeted `-`)**
   — if the v3 adversarial softening doesn't also relax the rule for
   ordinary hypotheses, add a separate note: "For non-adversarial
   hypotheses, evidence that is *consistent with* a sibling hypothesis
   is not a refutation — it's a discriminator question. Grade `+` or
   `-` based on own-prediction match, and emit a discriminating lead."
