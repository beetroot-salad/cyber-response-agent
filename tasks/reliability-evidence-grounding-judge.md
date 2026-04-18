---
title: Third Haiku judge — evidence-grounding re-query on confident outcomes
status: todo
groups: reliability, validation, judges
---

PR #74 (pre-CONCLUDE parallel Haiku judges) identified a semantic-grounding failure mode visible in two live eval runs: the existing judges verify the **shape of the argument** (adversarial addressed, `++` claim has a stated refutation shape, citations point at real events) but not whether **the claimed evidence-values match SIEM reality**.

Both runs produced confident-but-wrong dispositions where the narrative was internally consistent but grounded in mis-read or ungathered fields:
- Run #27 (rule 5710, bait): agent claimed "all 5 events share srcport 39624 → indexer duplicates" — raw SIEM showed 5 distinct srcports, 5 real attempts.
- Run #28 (rule 100001, whoami): agent built a reverse-shell narrative from "rule 100002 co-fires" without pulling `proc.name` — raw query showed the standard sshd dup2 noise at the monitoring-probe cadence.

The pre-refactor inline self-check had the same blind spot (run #11), so this is not a PR #74 regression — it is the dominant Sonnet-main quality gap, now visible because the structural gate no longer redundantly authors the narrative.

## Proposal

Third Haiku judge (call it the **evidence-grounding judge**) that fires pre-CONCLUDE alongside the existing log-integrity and archetype/grounding judges. Trigger: high-confidence outcomes only — `disposition: resolved`, or `++` grades on adversarial archetypes (e.g. `post-exploit-*`). Cheap outcomes (`escalated/inconclusive`) skip.

The judge picks 1–2 **load-bearing evidence claims** from the ANALYZE/CONCLUDE narrative (e.g. "all 5 events share srcport X", "proc.name=sshd for the dup2 chain") and re-queries SIEM for the literal field values, scoped to the exact time window and entity set cited. Pass if claimed values match the query result; FLAG if not.

## Design questions

- **Claim selection.** How does the judge identify which claims are load-bearing? Options:
  - Heuristic: any claim of the shape "all N events share X" or "proc.name is Y" in the narrative body.
  - Structured: the main agent must tag claims as `evidence-cite: {field}={value} in {window}@{entity}` inline. Cheaper for the judge, costlier for the main agent.
  - Ask Haiku to pick 1–2 "if-wrong-would-invalidate-disposition" claims from the narrative. Costs one extra turn.
- **Re-query mechanism.** The judge needs SIEM access, which existing judges don't have. Options: give the judge the `wazuh_cli` tool + a read-only query budget, or have the judge emit query specs that the hook executes and feeds back.
- **Trigger scope.** Confident-outcome-only is the starting cut. Could expand to any `++` grade, or restrict further to `disposition: resolved` only. Start narrow, widen on data.
- **Failure handling.** When the judge FLAGs, the write should be blocked and the main agent prompted to re-gather the load-bearing evidence. Distinguish "claim wrong" (block) from "query failed" (warn but allow — don't punish SIEM flakes).

## Candidate alternative / complement

PR #74 also flagged a SKILL.md discipline cue as a candidate: force `proc.name` / identity-tuple pulls as part of GATHER whenever the refutation shape for an adversarial hypothesis names a process or port identity. Cheaper, prevents the gap at the source rather than catching it at the gate. Could ship alongside the judge, not in lieu of it — the discipline cue is prompt-level, the judge is enforcement-level.

## Success criteria

- Run #27 bait scenario: judge catches the srcport claim, blocks the `resolved/benign` write, forces re-gather.
- Run #28 whoami scenario: judge catches the reverse-shell narrative via `proc.name` re-query, blocks the `post-exploit-interactive` archetype claim.
- Zero false-positive FLAGs on clean runs (e.g. run #28's Opus baseline, run #26 pre-refactor).
- Judge wall-time stays within the parallel-judge budget (<1.3× single-judge latency).

## Provenance

- PR #74 body, §"Quality — a semantic failure mode visible in both runs, not introduced by this PR"
- Eval runs #27 and #28 (documented in PR #74)
- Pre-refactor comparison run #11 (same failure mode)
