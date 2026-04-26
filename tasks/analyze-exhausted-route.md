---
title: ANALYZE `exhausted` route — terminate at current weights when the frontier is closed
status: todo
groups: analyze, orchestrator, routing
---

**Goal.** Add a third route to the ANALYZE subagent's output schema: `continue | exhausted | converged`. `exhausted` triggers when (a) the loop produced zero new resolutions AND (b) no remaining hypothesis prediction or refutation shape is addressable by an executable lead. The orchestrator routes `exhausted` to REPORT with current hypothesis weights — disposition mapped per the standing rules (any surviving `+`/`-` adversarial → escalated; surviving `+` benign with confirmed authorization but unsatisfied refutation → escalated/inconclusive/medium; etc.).

## Why

Run `20260426-020541-rule5710` postmortem: 14-phase history (3 PREDICT/GATHER/ANALYZE loops) on a bait scenario, ~26m45s wall, final disposition `escalated/unclear/low`. The pre-PR-#88 reference dispositions for the same scenario (runs #6/#9/#16/#22/#34) all converged on `escalated/benign/medium` in 2 loops or fewer. The structural driver for the cost balloon was loop 3 ANALYZE returning **`(no resolutions this loop)` and routing `continue` anyway**, then loop 4 PREDICT scaffolding yet another lead against the same unreachable refutation surface (`/etc/cron.d/` deny-listed, `connection-list rc=127`).

This is the `feedback_unknown_hypothesis_discipline` pattern at the routing layer: the loop's job is to traverse the graph, not to hammer at a closed surface. When the surface is closed and no new evidence is being produced, the loop is done — the disposition is whatever the partial traversal supports. Today ANALYZE has no way to declare that. `continue` is the implicit default, `halt`/`converged` requires `++`/`--` resolutions that the strict PREDICT contract makes structurally unreachable on deny-listed surfaces.

This is independent of PREDICT's contract design (strict vs permissive — see the trust-but-verify discussion). Either posture survives a closed surface only if ANALYZE has a clean exit.

## Scope

**In:**
- Extend `agents/analyze.md` route enum: `continue | exhausted | converged`. Schema doc for each. Discipline cue: `exhausted` is named, not implicit — ANALYZE must explicitly declare the frontier-closed state, with one-sentence rationale citing which prediction/refutation IDs are addressable-by-no-executable-lead.
- Define "executable lead" deterministically. A refutation/prediction is **non-executable** if (i) it cites a deny-listed path / surface (per `host_query.py` deny-list), (ii) the matching tool has returned non-zero rc on a prior loop in this run, (iii) PREDICT pre-marks the shape as `surface_reachable: false` (new optional field — see related task on PREDICT shape declarations). One of the three is sufficient.
- Update `scripts/handlers/analyze.py` (or wherever the route dispatch lives) to consume the new route. `exhausted` advances state machine to REPORT; `converged` keeps current behavior; `continue` keeps current behavior.
- Update `scripts/handlers/report.py` to handle `routing_source: exhausted` — disposition mapping rules:
  - any surviving `+` adversarial → `status: escalated, disposition: escalated, confidence: medium`
  - one surviving `+` benign with confirmed authorization (legitimacy_contract resolves authorized) AND no surviving adversarial → `status: escalated, disposition: inconclusive, confidence: medium` (the "trust-but-verify residual gap" outcome)
  - all hypotheses graded `-`/`--` → `status: escalated, disposition: inconclusive, confidence: low` (frontier exhausted with no live hypothesis)
- New invlang validator rule: a `findings:` block whose ANALYZE routes `exhausted` must contain at least one resolution citing the addressable-frontier check. (Prevents using `exhausted` as a generic escape hatch.)
- Add `exhausted` to the parallel Haiku judges' rubric (PR #74 architecture): a CONCLUDE write whose `routing_source: exhausted` is structurally distinct from `converged` — judge B should verify the frontier-closed claim against the investigation's executed lead history.

**Out:**
- PREDICT-side `surface_reachable` pre-marking. That's a future enhancement that makes `exhausted` cheaper to detect; the initial implementation derives non-executability from prior-loop tool errors + the deny-list, both of which are observable from the run dir.
- Auto-halting on a wall-clock or loop-count budget. `exhausted` is a frontier-closed signal, not a budget signal. Budget enforcement stays in `budget_enforcer.py`.
- Disposition rule changes for `converged` runs. Only `exhausted` introduces new disposition-mapping logic.

## Acceptance

- A 5710 bait fixture where the audit-channel refutation is structurally unreachable (current playground state) routes `exhausted` after at most 2 loops and lands `escalated/inconclusive/medium` with `routing_source: exhausted` recorded in `state.json` and `report.md` frontmatter.
- The same fixture without the deny-list (e.g. `host_query.py` deny-list temporarily relaxed for the test) routes `converged` to the same disposition, demonstrating the route is a function of frontier reachability, not just hypothesis weights.
- Tier 2 judge (PR #74 architecture) PASSes both routes on first write.
- Unit test in `soc-agent/tests/test_analyze_routing.py` covering: `(no resolutions, frontier closed) → exhausted`, `(no resolutions, frontier open) → continue`, `(resolutions present, ungraded predictions remain) → continue`, `(resolutions present, all hypotheses graded) → converged`.
- No regression on the orchestrator full-loop fixtures: 5710 scenario A SCREEN-resolved, 5710 bait with intact refutation surface, 100001 whoami.

## Reference

- Run `20260426-020541-rule5710`: full breakdown in the testrun skill cost-baseline table (when promoted from this conversation). 14-phase history, loop 3 ANALYZE returned `(no resolutions this loop)` then routed `continue`.
- Run #37: first PR #88 live eval that hit the same class of structural trap. EVIDENCE_SUFFICIENCY rubric vs analyze.md grading-discipline tension flagged as unresolved.
- `feedback_unknown_hypothesis_discipline` memory: same shape at the hypothesis layer. This is the routing-layer analog.
- `soc-agent/agents/analyze.md` — current route enum + grading discipline.
- `soc-agent/hooks/scripts/validate_report.py` — Tier 1+2 validator; needs the disposition-mapping update for `routing_source: exhausted`.
