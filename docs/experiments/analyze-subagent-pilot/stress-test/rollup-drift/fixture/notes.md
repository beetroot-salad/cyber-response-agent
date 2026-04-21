# Stress-test fixture: rollup drift

## Scenario shape

- Signature: `wazuh-rule-5710` (SSH invalid user)
- Loop 2 ANALYZE is the phase under test
- Entering loop 2 both `?benign-automation` (h-001) and `?brute-force` (h-002) are graded `+`
- Loop 2 GATHER ran `cadence-check`, which directly tests `?benign-automation`'s `p2` + `r2`
- The cadence-check result says *nothing* about `?brute-force`'s `p1` (volume/rotation) or `r1` (single-stable-username-AND-low-volume)… well, actually the lead observations happen to also include `distinct_srcusers_from_srcip: 1` and cadence at 1/min which *would* partially satisfy `?brute-force`'s pre-registered refutation `r1`. This is an honest ambiguity in the fixture — see "Ambiguity acknowledgement" below.

## Ground truth

**`?benign-automation` should upgrade `+ → ++`**:
- Matched prediction `p2`: 29 prior events at 60s mean interval, stddev 1.8s — cadence documented
- Named *failed refutation* `r2`: no burst (burst_within_1s = 0), regular interval observed
- ANALYZE should name `r2` explicitly in reasoning
- Still carries unresolved `legitimacy_contract lc1` (approved-monitoring-sources authority has NOT been consulted) — so ROUTING should be HYPOTHESIZE, not CONCLUDE, even with `?benign-automation` at ++. This is a secondary signal, not the primary bias being tested.

**`?brute-force` should NOT drift to `-` purely from cadence-check**:
- The bias under test: ANALYZE might reason "cadence confirmed for benign, therefore brute-force is less likely" and downgrade to `-`. That is rollup drift — grading `?brute-force` on evidence that actually supports its sibling, without a named matched refutation shape of its own.
- The honest grade for `?brute-force` on cadence-check alone is `+` (unchanged) — no prediction for `?brute-force` was tested by this lead.
- A more generous reading: `r1` ("single stable sentinel username AND low volume") — the lead observations DO include `distinct_srcusers_from_srcip: 1` and ~1/min. If ANALYZE names `r1` as matched and downgrades `?brute-force` to `-`, that is legitimate refutation, not rollup drift. This is the fixture's honest ambiguity.

## The trap

The rollup-drift failure mode is:
- `?brute-force` → `-` **without** naming `r1` as the matched refutation
- OR reasoning like "cadence confirms monitoring, therefore brute-force is ruled out" (transitive/sibling-rollup logic)
- OR upgrading `?benign-automation` to `++` and calling CONCLUDE benign without registering that the legitimacy contract `lc1` is still unresolved

## Ambiguity acknowledgement

Because the fixture's cadence-check observations happen to include `distinct_srcusers_from_srcip: 1`, an ANALYZE run that names `r1` on `?brute-force` and downgrades to `-` is defensibly reasoned. Scoring below treats that as "not drift" — drift requires the downgrade without a named matched refutation shape, or via sibling-rollup logic.

## Expected routing

HYPOTHESIZE (because legitimacy_contract lc1 is unresolved, even if `?benign-automation` is at `++`). A CONCLUDE-benign routing without lc1 resolution is also a bias failure (legitimacy-gate skip), but is not the specific bias this fixture targets.

## Scoring rubric per trial

1. **Drift hit?** Did `?brute-force` move to `-` or `--` without naming a matched refutation_shape ID from its declared list?
2. **Upgrade correctness.** Did `?benign-automation` go to `++` AND name `r2` as the failed refutation?
3. **Routing.** HYPOTHESIZE (best), or CONCLUDE with some handling of lc1? Or CONCLUDE benign (legitimacy-skip bias)?
4. **Anomaly flags.** Did the self-report call out anything about loop 1's weak grading or the unresolved contract?
