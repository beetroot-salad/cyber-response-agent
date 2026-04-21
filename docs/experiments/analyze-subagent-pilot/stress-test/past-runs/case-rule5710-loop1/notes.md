# Fixture: case-rule5710-loop1

**Source:** `docs/experiments/investigation-language-pilot/case-real-rule5710/` (real rule-5710 investigation, 2026-04-14).

**Cut point:** immediately before `## ANALYZE (loop 1)`. The subagents
receive CONTEXTUALIZE + SCREEN + HYPOTHESIZE (loop 1) + GATHER (loop 1)
and must produce the ANALYZE (loop 1) block.

**Shape the fixture exercises:**
- Escalation pathway — adversarial `?monitoring-host-compromise` must
  be preserved live at `-`, not dropped or promoted to `--`.
- Archetype/anchor gate — `monitoring-probe` archetype is the only
  benign option; its `approved-monitoring-sources` anchor is
  *refuted* by burst cadence at SCREEN, so no archetype fast-path.
- Refutation-attempt discipline — multiple `--` grades demand
  cited refutations (`?compromise-followup`: zero 5501/5715 in
  forward window; `?internal-credential-guessing`: username set).
- Multi-hypothesis weighing across 6 hypotheses (after the
  Round-1-v2 hypothesis-atomicity split — see below).
- Next-action decision — CONCLUDE-escalate vs HYPOTHESIZE loop 2.
  Ground truth is CONCLUDE; loop 2 was actually pursued in the
  original investigation but is out of scope for this fixture.

**Ground-truth highlights** (what a good ANALYZE should produce):
- `?probe-retry-stuck`: `--` (refuted — predicts clustering on ONE sentinel; observed 5 distinct)
- `?probe-enumeration-misconfigured`: `+` (supported but indistinguishable from bait without ownership evidence)
- `?monitoring-bait-triggered`: `+` (not `++` — circumstantial only)
- `?monitoring-host-compromise`: `-` (NOT `--` — adversarial stays live)
- `?internal-credential-guessing`: `--` (refuted by username set)
- `?compromise-followup`: `--` (refuted authoritatively by 0 successes)

**Hypothesis-atomicity split (Round 1 v2):** the original fixture
used a single `?monitoring-loop-broken` hypothesis that conflated two
distinct mechanisms ("misconfigured OR stuck in a retry loop"). Round
1 exposed that this ambiguity caused cross-arm grade drift — different
arms picked different mechanisms. For v2 the hypothesis is split into
`?probe-retry-stuck` (retry on one sentinel) and
`?probe-enumeration-misconfigured` (iterate the full list in one
tick), each with a single mechanism and prediction shape.
- Archetype fit: `monitoring-probe` refuted (anchor's failure-mode
  condition met); no other archetype matches → no fast-path resolution.
- Next action: CONCLUDE — escalate with `disposition: inconclusive`.

**Known fixture limitation:** the original investigation ran a second
loop after this ANALYZE and only concluded at loop 2. A subagent that
routes to HYPOTHESIZE (loop 2) is not *wrong* — it matches the
original agent's behavior. But the ground-truth ANALYZE text says
"Next action: CONCLUDE — escalate". The tension is itself interesting
data: the original agent's ANALYZE text said CONCLUDE but the actual
trace continued to loop 2. Score both routing choices as acceptable
with commentary.
