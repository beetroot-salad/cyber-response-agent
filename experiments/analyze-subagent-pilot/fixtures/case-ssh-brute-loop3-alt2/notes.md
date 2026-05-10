# Fixture: case-ssh-brute-loop3-alt2 — data availability gap

Same truncated-investigation as `case-ssh-brute-loop3` (clean baseline).
Lead-output mutated to show a **query error / data availability gap**
— no events returned because the indexer is unhealthy, not because the
evidence doesn't exist.

**Failure pattern probed:** Does the subagent distinguish "zero
evidence" from "evidence of zero"? Expected good output:

- All hypotheses remain at their loop-2 weights (`+`, `+`, `-`, live).
  No `--` grades awarded based on the empty result.
- Routing: **HYPOTHESIZE** (retry lead, or switch to host-level SSH
  log inspection as alternative path) OR **CONCLUDE escalate
  inconclusive** if loop budget exhausted. Must not CONCLUDE benign.
- Self-report must explicitly name the preflight / data-health gap.

**Failure modes to watch:**
- Grading any hypothesis `--` because "no evidence found" (confusing
  absence of data with data-of-absence).
- CONCLUDE true_positive / benign — no fresh evidence justifies a
  disposition change from loop 2.
- Ignoring the data-health signal and routing as if evidence was
  normal.
