# Round 1 — Comparison

**Fixture:** `case-rule5710-loop1`
**Arms:** A (minimal) / B (+ pre-commitments) / C (+ org context)
**Model:** Sonnet across all arms

---

## Headline

**Extra context did not monotonically improve grade accuracy.** Arm A
(minimal — just truncated log + lead output + schema) graded 5/5
correctly against ground truth. Arms B and C both drifted on
`?monitoring-loop-broken`, upgrading it from ground-truth `-` to `+`.
The drift traces to the structured pre-commitments extraction itself:
presenting predictions as a checklist biased the subagents toward
"count items met → +" rather than "mechanism refuted by a different
observation → -". **Pre-extraction is not free — it can anchor on the
wrong axis.**

Routing varied across arms in an unexpected way: Arm B chose CONCLUDE
(matching ground-truth text), Arms A and C chose HYPOTHESIZE (matching
what the *original agent actually did* — it ran a loop 2 despite its
own ANALYZE text saying CONCLUDE). The routing signal is too noisy
from a single fixture to conclude.

---

## Grade accuracy

| Hypothesis | Ground | Arm A | Arm B | Arm C |
|---|---|---|---|---|
| `?monitoring-loop-broken` | `-` | `-` ✓ | `+` ✗ | `+` ✗ |
| `?monitoring-bait-triggered` | `+` | `+` ✓ | `+` ✓ | `+` ✓ |
| `?monitoring-host-compromise` | `-` | `-` ✓ | `-` ✓ | `-` ✓ |
| `?internal-credential-guessing` | `--` | `--` ✓ | `--` ✓ | `--` ✓ |
| `?compromise-followup` | `--` | `--` ✓ | `--` ✓ | `--` ✓ |
| **Total correct** | | **5/5** | **4/5** | **4/5** |

---

## Dimension-by-dimension scoring

| Dimension | Arm A | Arm B | Arm C |
|---|---|---|---|
| Grade correctness (±1 step) | 5/5 exact | 4/5 exact, 1 off-by-one | 4/5 exact, 1 off-by-one |
| Rollup drift | n/a (loop 1, no history) | n/a | n/a |
| Refutation-attempt discipline (no false `++`) | ✓ no `++` awarded | ✓ explicitly cited pre-commit cap | ✓ explicitly cited pre-commit cap |
| Adversarial preservation (`?compromise` live at `-`, not `--`) | ✓ | ✓ | ✓ |
| Route compliance (fixture had no lead-level predictions) | n/a | n/a | n/a |
| Archetype/anchor gate reasoning | Implicit — mentioned in routing rationale | Weak — mentioned monitoring-probe closest but didn't cite SCREEN refutation cleanly | ✓ Explicit — named archetype gate as routing driver |
| YAML well-formedness | n/a (prose output requested) | n/a | n/a |
| Hallucinated context | ✓ none | ✓ none | ✓ none |

---

## Routing decision

| | Chose | Matches ground truth? |
|---|---|---|
| Arm A | HYPOTHESIZE (FIM probe / process-lineage replay / cron inventory) | Text says CONCLUDE; original agent's behavior says HYPOTHESIZE. Matches behavior. |
| Arm B | CONCLUDE (escalate) | Matches text. |
| Arm C | HYPOTHESIZE (script-ownership / auth-log on monitoring-host) | Matches behavior. |

The fixture has an **ambiguous ground truth on routing**: the original
ANALYZE block said "Next action: CONCLUDE" but the investigation ran
a second loop anyway. So we cannot read routing accuracy from this
fixture. It does reveal something about *how* each arm reasons about
routing: Arm A and C both argued "more leads could discriminate bait
vs loop-broken," while Arm B argued "no accessible leads would
change the grade distribution."

---

## Load-bearing classification (tentative — one fixture)

| Item | Classification | Evidence |
|---|---|---|
| Prior investigation log (CONTEXTUALIZE + HYPOTHESIZE prose) | **Necessary** | Arm A used it to reconstruct predictions, pitfalls, and refutation shapes; none hallucinated |
| Lead output | **Necessary** | Obviously |
| Structured pre-commitment extraction (Arm B) | **Harmful on the margin** | Introduced `+` drift on `?loop-broken`; otherwise redundant with raw HYPOTHESIZE prose |
| Adversarial status flagged explicitly | **Nice-to-have** | All arms got adversarial preservation right, even Arm A which only saw it in prose |
| Archetype + anchor gate context (Arm C) | **Nice-to-have for routing clarity** | Arm C explicitly cited it as routing driver; without it Arm A still routed reasonably |
| Signature threat model / target sensitivity | **Ignored in this fixture** | No arm cited it; target wasn't high-sensitivity |
| Environment readiness / preflight | **Nice-to-have** | Arm C used it for `?compromise-followup` `--` ("fully operational Wazuh means absence is informative") — valid but Arms A/B reached same conclusion without |
| Loop budget | **Ignored in this fixture** | No arm mentioned budget pressure on loop 1 |

**Items that NEVER showed up in any arm's reasoning**: pitfalls from
`leads/{lead}/definition.md`, past-investigation corpus queries,
explicit invlang schema concerns.

---

## Key finding — why Arms B and C drifted on `?loop-broken`

Ground truth reasoning:
> "A broken retry loop on a single sentinel would cluster on ONE
> username, not rotate through 5. The 5-distinct-sentinel cycling is
> not characteristic of a probe stuck in a retry loop — it is
> characteristic of a script iterating a list. Weakly refuted by the
> username rotation shape."

Ground truth reached `-` by focusing on one distinctive observation
(5-username rotation) that **refutes the mechanism**, not the
checklist.

Arm B reached `+` by tabulating predictions:
> "Predictions: sentinel usernames only ✓, burst window ✓, no
> successful login ✓, no parallel alerts on monitoring-host ✓. Cron
> is active ✓."

Then added "against" context but kept it at `+` because predictions
were partially met. The structured pre-commitments format (the Arm B
supplement restating predictions as a bullet list) seems to have
nudged toward checklist-counting rather than mechanism-refutation
reasoning.

Arm C inherited the same format and drifted identically.

**Hypothesis for Round 2:** if the pre-commitments are formatted as
*mechanism statements* ("a broken loop would cluster on ONE username")
rather than *prediction lists* ("sentinel usernames ✓"), the drift
should disappear. Worth testing.

---

## Contract decision signal (weak — one fixture)

**Favoring assessment-only contract:**
- Arm A produced the most accurate grades with minimal context
- Routing accuracy cannot be measured cleanly (ambiguous ground truth)
- Arm C's extra org context helped routing *clarity* but not *accuracy*

**Favoring decision-owning contract:**
- Arm B reached CONCLUDE autonomously (matches ground-truth text)
- The pre-commitments correctly gate `++` and `--`, preventing
  overconfident routing

**Neither conclusive.** Need more fixtures — specifically one where
routing has a crisp ground truth (e.g., a clean archetype match that
CONCLUDEs without ambiguity, or a mid-loop fork with a provably
correct next lead).

---

## Recommendations for Round 2

1. **Select a fixture with crisp routing ground truth.** The
   rule-5710 case has ambiguous routing. Need a case where the next
   action is unambiguous — e.g., a fast-resolve match at SCREEN, or
   a loop that ended at CONCLUDE without follow-on.

2. **Add an Arm B′ variant** that restates pre-commitments as
   mechanism statements rather than prediction checklists. Tests
   the checklist-bias hypothesis.

3. **Include a mid-loop fixture** (loop 3+ with prior ANALYZE grade
   history) to exercise the rollup-drift dimension that this round
   could not test.

4. **Defer the trust-check arm** until grades are reliably matching
   ground truth. No point testing handoff acceptance if the handoff
   content is wrong.

5. **Drop structured pre-commitments extraction from the default
   bundle** unless Round 2 shows it adds value on a different
   fixture. Current signal: raw HYPOTHESIZE prose carries enough
   signal; restating it biases reasoning.

---

## Self-report observations across arms

All three arms flagged the same two missing items in their own
self-reports:
- File-integrity coverage on monitoring-host (affects `?compromise` grade)
- Authoritative `monitoring_bait.sh` confirmation (affects `?bait` ceiling)

These are **investigation-scope concerns, not ANALYZE-context
concerns** — they are the same items a human analyst would flag as
"we can't resolve this without more tooling." An ANALYZE subagent
receiving them wouldn't change the grade — it would just move the
escalation rationale earlier. This is a hint that the loud
missing-context items for ANALYZE are not about adding more bundle
content; they're about tooling reach.
