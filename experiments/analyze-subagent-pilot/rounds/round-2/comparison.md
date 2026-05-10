# Round 2 — Comparison (case-ssh-brute-loop3)

**Fixture:** `case-ssh-brute-loop3` — mid-loop (loop 3) external
SSH brute-force, crisp CONCLUDE routing, true weight reversal
on `?targeted-brute-force` (`+` → `--`), first `++` award in
the pilot.
**Arms:** A (minimal) / B (+ pre-commitments) / C (+ org context +
archetype anchors + trust-root policy)
**Model:** Sonnet across all arms

---

## Headline

**All three arms converged to perfect grades and routing.** Every
arm produced the correct `++` / `--` / `--` / `--` rollup, cited
the attempted-refutation discipline when awarding `++`, and routed
to CONCLUDE with `disposition: true_positive`, `matched_archetype:
opportunistic-scanner`. No drift, no disagreement.

This is the pilot's decisive result: **when the fixture has atomic
hypotheses, pre-committed refutation shapes, and a crisp
ground truth, Sonnet-subagent ANALYZE with minimal context (Arm A)
performs as well as the fully-enriched variant (Arm C).** The
extra context is not load-bearing for accuracy in this regime.

---

## Grade accuracy (rollup-aware)

| Hypothesis | Prior (loop 2) | Ground | Arm A | Arm B | Arm C |
|---|---|---|---|---|---|
| `?opportunistic-scanner` | `+` | `++` | `++` ✓ | `++` ✓ | `++` ✓ |
| `?targeted-brute-force` | `+` | `--` | `--` ✓ | `--` ✓ | `--` ✓ |
| `?credential-stuffing-external` | `-` | `--` | `--` ✓ | `--` ✓ | `--` ✓ |
| `?compromise-followup` | live | `--` | `--` ✓ | `--` ✓ | `--` ✓ |
| **Total correct** | | | **4/4** | **4/4** | **4/4** |

**Weight reversal correctness:** all three arms correctly flipped
`?targeted-brute-force` from `+` to `--` with explicit citation of
the pre-committed refutation shape (generic wordlist entries with
zero env-specific names).

---

## Routing decision

| | Chose | Disposition | Archetype | Matches ground truth? |
|---|---|---|---|---|
| Arm A | CONCLUDE | true_positive | opportunistic-scanner | ✓ |
| Arm B | CONCLUDE | true_positive | opportunistic-scanner | ✓ |
| Arm C | CONCLUDE | true_positive | opportunistic-scanner | ✓ |

All three arms independently reached the same disposition and
archetype match. **Routing is decidable** — this round
retires the Round 1 concern that routing variance is driven by
context level. With clear evidence, all arms route the same way.

---

## `++` discipline (first time exercised in the pilot)

All three arms awarded `?opportunistic-scanner: ++` with an
explicitly named **attempted refutation that failed**: the check for
environment-specific usernames. This is the refutation-attempt
discipline the weight semantics require, and all arms applied it:

- **Arm A:** "Pre-committed refutation check passed: usernames are
  not ≤2 names, and zero env-specific names appeared."
- **Arm B:** "Attempted refutation (check for env-specific names)
  failed — zero environment-specific names found."
- **Arm C:** "Attempted refutation path (env-specific names or ≤2
  names) was not triggered — the opposite holds."

No false `++` awards; all citations were grounded in the lead output.

---

## Dimension-by-dimension

| Dimension | Arm A | Arm B | Arm C |
|---|---|---|---|
| Grade correctness | 4/4 | 4/4 | 4/4 |
| Rollup drift (prior weights carried correctly) | ✓ | ✓ | ✓ |
| Weight reversal (`?targeted`: `+` → `--`) | ✓ | ✓ | ✓ |
| Refutation-attempt discipline for `++` | ✓ | ✓ | ✓ |
| Adversarial preservation until explicit refutation | ✓ | ✓ | ✓ |
| Route to CONCLUDE | ✓ | ✓ | ✓ |
| Disposition + archetype + confidence | ✓ true_positive / opportunistic-scanner / high | ✓ | ✓ |
| Hallucinated context | none | none | none |

---

## Self-report — what each arm said about context

Arm self-reports are instructive about which context items carried
weight vs. were redundant:

**Arm A** flagged missing access to the archetype README
(`required_anchors`) as the main context gap, but the ANALYZE still
reached the correct disposition without it. Reconstructed archetype
match from the HYPOTHESIZE predictions and CONTEXTUALIZE playbook
summary. No grade drift.

**Arm B** used every pre-commitment check and flagged only minor
concerns (forward-window margin, attribution gap from the threat-intel
timeout). No items were ignored as actively harmful.

**Arm C** described the archetype anchor requirements as "the primary
grading engine" and the trust-root policy as "load-bearing for the
CONCLUDE routing decision." Both claims are true in that the org
context provided deterministic rules — but Arms A and B reached the
same answers without them, using the HYPOTHESIZE predictions as the
implicit anchor set. **Nice-to-have, not load-bearing** in this
regime.

---

## Revised load-bearing view (combining Round 1-v2 and Round 2)

| Item | Classification | Evidence |
|---|---|---|
| Prior investigation log (with prior ANALYZE loops) | **Necessary** | Rollup correctness depends on prior weights being in the log |
| Lead output | **Necessary** | Obvious |
| Atomic hypothesis claims (one mechanism, one prediction shape) | **Necessary upstream (HYPOTHESIZE quality bar)** | Round 1 failure traced to this; Round 1-v2 and Round 2 confirm fix |
| Pre-committed refutation shapes (in HYPOTHESIZE prose) | **Necessary** | All arms relied on these to justify `++` / `--` |
| Structured pre-commitments supplement (Arm B) | **Nice-to-have** | Arm A reached same grades without it; Arm B used it mechanically |
| Archetype + anchor gate context (Arm C) | **Nice-to-have** | Arm C called it "primary" but Arms A/B reached same answers from implicit anchors |
| Trust-root policy | **Nice-to-have** | Arm A inferred it from CONTEXTUALIZE ("v-001 is external, no accessible upstream") |
| Loop budget | **Ignored** | No arm depended on it |
| Environment readiness | **Ignored** | No arm depended on it in Round 2 |

---

## Contract decision signal

Taking Rounds 1-v2 and 2 together:

**Favoring decision-owning contract** (the subagent owns routing,
produces CONCLUDE with disposition + archetype):
- All three arms independently reached correct CONCLUDE routing
  on Round 2 when evidence warranted it
- All three arms correctly held to HYPOTHESIZE on Round 1-v2 when
  evidence required another loop
- No arm drifted to premature CONCLUDE on Round 1-v2 (ambiguous
  case) despite having the option

**Favoring assessment-only contract**:
- Minimal-context arm (A) needed to reconstruct archetype match
  from HYPOTHESIZE prose in Round 2 — works, but a dedicated
  routing step could cleanly separate concerns
- Round 2's Arm C self-reported that org context was "primary"
  for its routing — a routing-only caller could inject exactly that
  context without bloating ANALYZE input

**Signal leans toward decision-owning.** The subagent is competent
at routing when given only the truncated investigation log +
HYPOTHESIZE predictions + lead output. Extra org context is
nice-to-have, not a routing prerequisite. A decision-owning contract
is viable with a minimal bundle.

---

## What this retires

- **Concern from Round 1 that checklist-bias corrupts grading** —
  retired in Round 1-v2; Round 2 reconfirms.
- **Concern from Round 1 that routing variance is context-driven** —
  retired; Round 2 shows all arms converge on routing when
  evidence is crisp.
- **Concern that `++` discipline can't survive extraction** —
  retired; all three arms applied refutation-attempt discipline
  correctly.
- **Concern that rollup drift would accumulate error across loops**
  — retired; all three arms carried prior weights faithfully and
  applied the weight reversal correctly.

---

## Remaining open questions

1. **Trust-handoff test** (original Arm D) — the pilot has not yet
   tested whether a caller agent trusts the subagent's output and
   uses it, vs. re-runs queries. This is the deferred trust-check
   arm. Now that grades are reliable, this is the next logical step.

2. **Model-tier question** — all arms were Sonnet. Does Haiku
   sustain the same accuracy with the atomic-hypothesis fixtures?
   Worth one round to find out before committing to Sonnet in
   production.

3. **Adversarial / edge-case fixtures** — the pilot has two
   fixtures, both with "reasonable" investigations. An adversarial
   fixture (e.g., a case where the prior ANALYZE loops contain a
   subtle error the subagent must notice on rollup) would stress
   the rollup-drift dimension further.

---

## Recommendations

1. **Decide the contract fork as decision-owning** — the subagent
   produces ANALYZE output including the routing decision and, when
   routing to CONCLUDE, the disposition + archetype + confidence.
   Evidence from Rounds 1-v2 and 2 supports this.

2. **Minimal bundle is sufficient** — ship the ANALYZE subagent
   with: (a) truncated investigation log (with prior ANALYZE blocks
   for rollup context), (b) GATHER lead output. The pre-commitments
   supplement and org-context supplement are both nice-to-have but
   not necessary for the bundle that ships. Start minimal; add
   context if production evaluation reveals failures.

3. **Enforce hypothesis atomicity upstream** — see
   `tasks/hypothesis-atomicity-invariant.md`. This is the load-bearing
   upstream invariant; without it, ANALYZE correctness collapses.

4. **Test with Haiku and the trust-handoff** as the next pilot
   rounds — these are the remaining unknowns before production
   extraction.
