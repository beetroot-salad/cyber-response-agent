# Harder round — stacked-`++` trap + attacker-mimic probe on modest grades

Tests the two failure modes the earlier rounds didn't exercise:

1. Does ANALYZE itself fall for the **Example 2 stacked-circumstantial
   `++` trap** on a fixture it hasn't seen?
2. Does the attacker-mimic probe **over-revise** when applied to outputs
   where the highest grade is `+` or `-` — i.e. when there's no
   over-confident `++` to dismantle?

## The fixture

Alert: `svc:reporting-api` issued 47 DB reads against PII tables in 10
minutes (17× daily baseline). Pre-set so that:

- **Loop 1** resolves legitimacy (role-authorized via iam-registry)
- **Loop 2 GATHER** confirms p2 (bounded-SELECT with WHERE) but `session_tag`
  is empty across all 47 queries — no job-correlator
- **Archetype `scheduled-reporting-pipeline`** has three required_anchors:
  correlator (a1), column-scope (a2), SLA-volume (a3). Only a2 is
  confirmed.
- **The trap:** stack "bounded-SELECT shape matches reporting" +
  "principal role authorized" → upgrade `?scheduled-reporting-pipeline`
  to `++`, claim the archetype, CONCLUDE benign. Exactly Example 2's
  pattern in a DB domain.

Ground truth: HYPOTHESIZE — next lead must query the job-scheduler for
a declared job covering this window.

## Part 1 — does ANALYZE resist the trap unaided?

**3/3 trials resisted cleanly.**

| Trial | `?scheduled-reporting-pipeline` | `?adversary-controlled-service-principal` | Routing | Discriminator asked |
|---|---|---|---|---|
| 1 | `-` (was `+`) | `+` (was `+`) | HYPOTHESIZE | job registry + SLA band |
| 2 | `+` (was `+`) | `-` (was `+`) | HYPOTHESIZE | job scheduler + bind parameter date spans |
| 3 | `-` (was null) | `-` (was null) | HYPOTHESIZE | job schedule + declared volume SLA |

No trial upgraded `?scheduled-reporting-pipeline` to `++`. None claimed
`matched_archetype`. None routed CONCLUDE. All three asked the
*correct* discriminator — the job-registry lookup that the fixture's
ground truth identifies.

Reasoning quality was strong across trials. Every trial noticed that:
- p1 (session correlator) was directly contradicted by `session_tag`
  empty
- r1 (refutation shape) was not fully matched — r1 required BOTH "lack
  correlator" AND "bulk-column SELECT with no date bound", and the
  second conjunct failed
- max warranted grade was `+` (or `-` when p1 failure outweighed p2
  confirmation)

**Variance across trials is real but discipline-aligned.** Trial 1 and
trial 3 downgraded `?scheduled-reporting-pipeline` below its prior loop
grade on p1's failure. Trial 2 held at `+`. All three took different
paths to the same correct HYPOTHESIZE routing.

## Part 2 — does attacker-mimic probe over-revise on modest grades?

On each ANALYZE output (no `++` present, highest grade is `+` or `-`),
ran one attacker-mimic Haiku probe + one Sonnet defense.

| Trial | Source grade of probed hyp | Probe target | Verdict | New grade |
|---|---|---|---|---|
| 1 | `?adv-controlled: +` | "attacker compromised the principal and used its credentials" | **revise** | `+` (grade same, reasoning revised) |
| 2 | `?scheduled: +` (or `?adv: -`, probe targeted h-002) | "attacker used the principal's own query templates" | **revise** | `- → +` |
| 3 | both at `-` | "attacker mimicked legitimate query patterns" | **defend** | — |

**No over-caution in the sense we worried about** (no forced downgrades to
`--` based on "but an attacker could do X"). What the probe actually did
was distinct and more interesting:

### Trial 2's revise — attacker-mimic caught a hypothesis-formulation flaw

Source ANALYZE graded `?adversary-controlled-service-principal` at `-`
because the hypothesis's p2 predicted "wide column selection, minimal or
absent WHERE filters" — bulk-extraction shape — which the observed
bounded-SELECT queries contradicted. So ANALYZE treated the query shape
as partial evidence against h-002.

The probe pointed out: **a compromised `svc:reporting-api` would emit
bounded-SELECT date-range queries because that's the service's existing
template.** An attacker exercising these credentials would inherit the
service's query patterns. p2 was formulated naively — it assumed an
attacker acts "crudely" independent of the credential context.

Sonnet engaged with this and lifted the grade back to `+` with explicit
reasoning: *"p2 was built on a naive threat-model assumption… Removing
the p2 weight restores h-002 to `+`, correctly reflecting that query
shape does not discriminate here."*

This is not over-caution — it's the probe finding a real prediction-
formulation flaw in the HYPOTHESIZE block and correcting a
downward-biased grade. The correction aligns with the fixture's ground
truth (h-002 should stay live at `+` until the job-registry lookup
disambiguates).

### Trial 1's "revise" is a reasoning update, not a grade change

`?adv-controlled` was `+` in source, `+` after. Verdict: revise. The
rationale reframed why the grade holds (removed the p2 moderation noted
above) without changing the grade value. Bookkeeping revise.

### Trial 3's defend is the over-caution guard working

With both hypotheses at `-`, the probe asked "how do you know h-001
isn't an attacker mimicking?" Sonnet's defense: *"Accepting the probe's
framing would require treating every prediction mismatch as a potential
mimicry artifact, which is unfalsifiable and would make h-002 ungradeably
immune to any query-shape evidence."* The subagent correctly identified
that attacker-theoretical possibility without concrete evidence isn't
grounds for downgrade.

This is the over-caution mitigation in action: **concrete attacker
scenarios matter, attacker-in-principle does not.** Sonnet can tell the
difference.

## Combined takeaways

1. **ANALYZE handles the stacked-`++` trap unaided.** 3/3 on a DB fixture
   the subagent hasn't seen before. The Example 2 warning is internalized
   and generalizes across domains. This removes a significant fraction
   of the residual risk the framing experiment was worried about.

2. **Attacker-mimic probe adds value at the HYPOTHESIZE-formulation
   layer.** The most useful probe outcome wasn't dismantling a bad `++`
   — it was catching a naively-formulated prediction that was biasing
   the adversary hypothesis downward. That's a different and more subtle
   failure mode than the one the probe was originally designed for.

3. **No forced `--` over-caution observed.** Even when the probe targeted
   hypotheses at `-`, Sonnet held ground when the probe relied on
   attacker-theoretical possibility alone.

4. **Residual risk the probe doesn't catch:** if the HYPOTHESIZE block's
   refutation shape is ALSO naively formulated (e.g. h-002's r1 required
   a scheduled-job correlator to appear — but a compromised principal
   would never produce one), the probe currently has no purchase. Rule 5
   + rule 25 (validator) would catch mis-cited IDs but not poorly-designed
   shapes. Refutation-shape quality is a HYPOTHESIZE-time concern.

5. **Probe value on authority-backed `++` vs. modest grades differs.**
   - On strong `++` (framing-ab fixture): 8/9 defends, probe surfaces
     investigation gaps or confirms defensibility
   - On stacked-`++` trap (this fixture, had it triggered): untested
     because ANALYZE didn't produce a stacked `++` — the subagent was
     too robust to need the probe's help
   - On modest grades: probe can catch naive HYPOTHESIZE-time prediction
     formulation, which is an unexpected bonus

## Recommendation for a future sensitivity probe

The probe's value proposition has shifted from what the framing experiment
suggested. It's less about catching bad `++` grades (ANALYZE is robust)
and more about **auditing the HYPOTHESIZE block's prediction and
refutation shapes against adversary-mimicry scenarios**. That's a
HYPOTHESIZE-time probe, not an ANALYZE-time probe.

Different shape worth testing separately: run attacker-mimic probe on
HYPOTHESIZE block output before any GATHER fires. "Given this mechanism
and these predictions, could an attacker produce the predicted-negative
shape?" If yes, the prediction is over-specified or the refutation
shape is too narrow. Not blocking; run it here if the cutover scope
expands.

## Caveats

- **N=3 per trial, one fixture, one trap shape.** Directional.
- **Fixture is synthetic** — real past investigations might exhibit the
  trap more cleanly. The fact that 3/3 resisted is encouraging but not
  conclusive.
- **Attacker-mimic probe ran once per ANALYZE output.** Variance in the
  probe itself (different probes might target different angles) is not
  measured. Running 3 probes per output would strengthen the claim.
