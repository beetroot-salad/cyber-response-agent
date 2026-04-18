# Round 5 Haiku Stress — Comparison

**Question:** Does Haiku on the Arm A minimal bundle hold up across
diverse failure patterns, or does it fail on specific stressor shapes?

**Method:** Five parallel Haiku arms, one per failure pattern, all
using the same Arm A minimal bundle (truncated investigation + lead
output only). No ground-truth leakage, no notes.md, no cross-round
reads.

## Scorecard

| # | Pattern | Grades | Adversarial | Routing | Verdict |
|---|---|---|---|---|---|
| 1 | Poisoned rollup (var1) | 4/4 exact ✓ | `?compromise-followup` → `--` on forward-window refutation ✓ | CONCLUDE true_positive opportunistic-scanner ✓ | **PASS** |
| 2 | Ambiguous routing (rule5710-loop1) | 5/6 exact (over-upgrade `++` on `?probe-enumeration-misconfigured`; gt `+`) | `?monitoring-host-compromise` held at `-` live ✓ | CONCLUDE escalate monitoring-probe::config-burst-ambiguous ✓ | **PASS (with over-upgrade)** |
| 3 | Inverted evidence (alt1) | All 4 correctly flipped ✓ — opp `--`, targeted `++`, cred-stuff `--`, compromise `++` | `?compromise-followup` upgraded to `++` on successful login ✓ | CONCLUDE true_positive targeted-brute-force (notes accepted either CONCLUDE-escalate or HYPOTHESIZE pivot) | **PASS** |
| 4 | Data gap (alt2) | All held at prior weights — no `--` awarded on empty result ✓ | `?compromise-followup` held "live, unevaluated" ✓ | HYPOTHESIZE host-log fallback ✓ | **PASS** |
| 5 | Mixed evidence (alt3) | 4/4 calibrated correctly — opp `-` (not `--`), targeted `+` (not `++`), cred-stuff `-`, compromise `--` ✓ | `?compromise-followup` → `--` on zero successes ✓ | **CONCLUDE true_positive targeted-brute-force** — expected HYPOTHESIZE to discriminate hybrid vs masked | **PARTIAL FAIL** |

## Pattern-by-pattern notes

### Pattern 1 — Poisoned rollup (PASS)

Haiku detected the unjustified loop-2 `++` on `?targeted-brute-force`
and flagged it explicitly in the self-report:
> "The `++` assignment appears to have pre-judged the outcome without
> committing to explicit refutation criteria in advance. Loop 3
> confirms the error: the username scatter immediately revokes the
> `++` via direct contradiction…"

This is the same structural-consistency reasoning Sonnet produced in
round-3-stress — Haiku does it too, via internal comparison of the
loop-2 text against the refutation semantics. The detection is not
lexical (no "poisoned" hint was visible; the fixture is
`case-ssh-brute-loop3-var1`, a neutral name).

### Pattern 2 — Ambiguous routing (PASS with over-upgrade)

Haiku produced 5/6 grades exactly matching ground truth. The one miss:
`?probe-enumeration-misconfigured` graded `++` vs ground-truth `+`.

Ground truth held at `+` because the mechanism is
"observationally indistinguishable from bait without workload
ownership evidence" — the hypothesis's core prediction is met but
cannot be *cleanly discriminated* from a sibling hypothesis, so `++`
is unearned. Haiku missed this discriminative nuance and counted
passed refutation checks in isolation.

Routing correct (CONCLUDE → escalate, archetype
`monitoring-probe::config-burst-ambiguous`). Adversarial preserved
at `-` live.

**Failure mode:** treating independent refutation-check passage as
sufficient for `++`, without asking "does this evidence discriminate
from a sibling hypothesis at the same weight?"

### Pattern 3 — Inverted evidence (PASS)

All four hypotheses correctly flipped: opportunistic `+` → `--`,
targeted `+` → `++`, credential-stuffing `-` → `--`,
compromise-followup `live` → `++`. Haiku explicitly named the
pre-committed refutation shapes and showed they failed for
opportunistic and succeeded for targeted. The successful `webapp-deploy`
login was correctly interpreted as confirming compromise-followup.

Minor note: the disposition is correct (true_positive,
targeted-brute-force) but the routing choice — CONCLUDE vs
HYPOTHESIZE a post-compromise pivot — is debatable. The fixture
notes.md accepted either; Haiku chose CONCLUDE with a recommendation
to escalate to host-forensics/active-response. Defensible.

### Pattern 4 — Data gap (PASS)

Haiku handled the epistemically tricky case correctly: the query
returned an error (indexer 504), not zero events. Haiku did **not**
grade any hypothesis `--` on the empty result. All weights held at
prior values. `?compromise-followup` explicitly noted as "live,
unevaluated" rather than refuted.

Routing: HYPOTHESIZE a host-log fallback (auth.log via host_query) —
exactly the right move. Self-report explicitly flagged the preflight
gap and identified uncertainty about host_query availability.

This is the cleanest pass in the round — arguably harder than the
clean baseline, because it requires distinguishing absence-of-data
from data-of-absence, a known trap in weighted assessment.

### Pattern 5 — Mixed evidence (PARTIAL FAIL)

Grading is correctly calibrated: Haiku resisted `++` on opportunistic
(wisely, given 26% env-specific names) and resisted `--` on targeted
(wisely, given env-specific names are present). Opportunistic `-`,
targeted `+`, both accurately reflect genuine ambiguity.

**But routing failed.** Haiku CONCLUDEd with `matched_archetype:
targeted-brute-force` and `confidence: moderate`, with an escalation
flag in the prose. Expected: HYPOTHESIZE a discriminating lead (e.g.,
recon-history correlation, timing-cluster analysis of env-specific
vs generic names) because the two candidate hypotheses cannot be
discriminated from the evidence in hand.

Haiku's own self-report names the ambiguity:
> "The 74/26 split alone does not discriminate between [hybrid
> opportunistic and masked targeted] without additional intent
> signals (e.g., are the env-specific names in any particular order?
> are they clustered temporally?…)"

Despite recognizing the missing discriminator, Haiku still routed
CONCLUDE. **This is the signature failure mode: Haiku prefers
committing to an archetype over emitting a follow-on lead when it
has noticed ambiguity.**

## Cross-pattern patterns

**Grading is strong.** Haiku graded correctly in 18/19 total
hypothesis assessments across the 5 patterns (one over-upgrade in
pattern 2). Adversarial hypothesis handling was correct in all 5.

**Data-absence discipline is strong.** Pattern 4 shows Haiku
distinguishes absence-of-data from data-of-absence — a subtle
epistemic move.

**Routing under genuine ambiguity is the weak spot.** Patterns 2 and
5 both show the same bias: when grading splits into multiple weak-
positive hypotheses, Haiku prefers CONCLUDE (with escalation or
archetype commitment) over HYPOTHESIZE (emit a discriminating lead).
Both patterns had at least one `+` hypothesis where a follow-on lead
would materially reduce uncertainty; Haiku CONCLUDEd instead.

**Rollup trust is correct.** Pattern 1 proves Haiku will override a
prior grade when the refutation discipline says to — it does not
blindly propagate.

## Contract implications

**Clean case + adversarial stressors: Haiku is viable for the
decision-owning ANALYZE contract.** Grade accuracy, rollup-correction,
adversarial preservation, and data-absence discipline all hold up.

**Genuine-ambiguity cases need guard-rail.** The routing bias toward
CONCLUDE on ambiguous evidence is the one behavior that warrants a
contract change. Options:

1. **Prompt-level:** add a routing gate — "If any two hypotheses are
   both graded `+` on evidence that does not discriminate between
   them, your default action is HYPOTHESIZE (emit a discriminating
   lead), not CONCLUDE."
2. **Decision-splitting:** keep the assessment-only contract for
   ambiguous cases — grading goes to Haiku, routing stays with the
   main Sonnet agent which has broader loop-budget context.
3. **Loop-budget awareness:** expand the bundle to include current
   loop number and max loop budget; a Haiku at loop 3/3 with
   ambiguous evidence *should* CONCLUDE-escalate, but at loop 1/3
   it should HYPOTHESIZE.

Option 1 is the cheapest test — single prompt edit, one re-run of
patterns 2 and 5. Option 3 is the correct long-term answer but
requires broader bundle changes.

## Recommended next action

1. Add the routing-gate instruction to the Arm A prompt (option 1).
2. Re-run patterns 2 and 5 on Haiku with the amended prompt.
3. If both pattern 2 and pattern 5 flip to HYPOTHESIZE correctly:
   lock decision-owning Haiku contract with the routing-gate line.
4. If they still CONCLUDE: fall back to option 2 (assessment-only on
   ambiguous cases; routing stays with main agent).

Defer the Haiku trust-handoff test until the routing bias is resolved.
Handing a miscalibrated routing decision to a main-agent caller would
poison the handoff measurement.
