---
title: ANALYZE X5 / rule #36 violation on 5710 bait — no orchestrator recovery
status: backlog
groups: analyze, orchestrator
---

**Goal.** When the analyze subagent emits a structurally-clean dense trailer whose `:A routing` shape violates invlang rule #36 (X5 — `disposition: true_positive` without an adversarial-token surviving hypothesis at `++`), the orchestrator must either (a) accept the routing if the validator can be relaxed for this case, (b) re-dispatch analyze with a targeted remediation prompt, or (c) downgrade the disposition to `unclear` mechanically. Today the orchestrator aborts with `exit=1` and no `report.md` lands.

This task is **self-contained** — it captures the failing run's evidence, the structural defect, and the fix candidates without depending on any other task.

## Evidence

Run dir: `/tmp/soc-agent-orchestrate-eval/20260429-202152-rule5710/runs/e00fe8c3-7c47-400e-8df0-ee276651ecc1/`.

Branch: `main` at commit `9be69cd` (post PR #155 merge), with the contextualize-prologue dense migration from PR #156 applied — the prologue change is wire-format only and orthogonal to this failure.

Trigger: `monitoring_bait.sh` 5-attempt burst on `zabbix`, 2026-04-29T20:21:05Z; alert fetched mid-burst via `--offset 2`.

Path: `CONTEXTUALIZE → SCREEN → PREDICT → GATHER → PREDICT → GATHER → ANALYZE → orchestrator-exit-1`. 8 subagents, all `rc=0`:

```
ticket-context           haiku   31.4s rc=0 stdout=1151B
contextualize-prologue   haiku   43.2s rc=0 stdout=355B
screen                   sonnet  83.4s rc=0 stdout=4621B   (no_match, fell through)
predict (loop 1)         sonnet  56.7s rc=0 stdout=1706B
gather-composite (loop 1) sonnet 226.0s rc=0 stdout=9246B
predict (loop 2)         sonnet 274.7s rc=0 stdout=5315B
gather-composite (loop 2) sonnet 117.3s rc=0 stdout=4157B
analyze                  sonnet 318.6s rc=0 stdout=2034B
```

Driver final line:

```
[orchestrator] FAILED: analyze subagent: envelope shape violation —
analyze :A routing disposition=true_positive requires at least one surviving
hypothesis whose name carries an adversarial token AND whose final weight is
++ (X5, validator rule #36); surviving=['h-002']
```

No `report.md` written. The analyze subagent's stdout was structurally well-formed — 2034 bytes, parsed cleanly by `_output_parser` — but the routing decision shape failed the X5 cross-block check.

## Structural defect

`disposition: true_positive` per invlang v2.14 rule #36 (PR #144's affirmative-true_positive discipline) requires:

1. At least one hypothesis in `surviving_hypotheses` whose name carries an adversarial token (`?adversary-…`, `?compromise-…`, `?post-exploit-…`, etc.).
2. That hypothesis's final weight in `:T resolutions` must be `++`.

ANALYZE on this run emitted `surviving=['h-002']` with `disposition=true_positive`. h-002 was either non-adversarial-named or graded below `++` — the dense trailer in `subagent_outputs/*-analyze-*.txt` would confirm which (worth pulling for the fix).

The handler's parse step (`_predict_dense.parse_predict_dense` analog for analyze in `_output_parser.parse_analyze_envelope`) raises on X5 with an `AnalyzeOutputError`, but **the analyze handler treats this as fatal** — same shape as the run #46 grounding_kind drift and the run #44 `report` Sonnet fallback timeout (meta-finding §"No orchestrator-level remediation path for invlang validator failures").

## Fix candidates, ranked by leverage

(a) **Re-dispatch with X5 remediation.** Analyze handler catches `AnalyzeOutputError` whose message includes `(X5, …)`, builds a remediation prompt that surfaces the rule + the agent's own `surviving=[…]` + the disposition catalog (`unclear` is the correct route when no `++` adversarial survives), and re-runs the subagent at most once. Same pattern PR #154 / `_predict_dense.py` uses for predict envelope errors. Estimated: ~30 LOC in `scripts/handlers/analyze.py` plus a new test fixture.

(b) **Mechanical downgrade.** When X5 fires, the handler rewrites `disposition: true_positive` to `disposition: unclear` and routes through, with a `## NOTE (handler):` line in investigation.md citing the rule. Cheaper than (a) but loses the evidence the agent had in mind for routing `true_positive`. Use only as a fallback if (a) fails.

(c) **Subagent-side prevention.** Add an explicit X5 example to `agents/analyze.md` showing the "true_positive needs adversarial-token + ++ surviving" rule, with the wrong-shape pattern (single benign-mechanism hypothesis surviving with anchor unconfirmed → route `unclear`, not `true_positive`). Closes the prompt drift that lets the subagent emit this shape; layered with (a) is the right combination.

(d) **Generalize to all X-class rule violations.** X1 (surviving completeness), X2 (termination polarity), X4 (disposition gating), X5 (true_positive shape), X6 (authz fulfillment) all have the same handler-fatal blast radius today. A single `_remediate_analyze_envelope_error` helper that takes the rule code + offending payload + builds a remediation prompt would close the class. Tracked separately if (a) ships first.

## Verification

After (a) + (c):

1. Re-run the same trigger:
   ```
   docker exec monitoring-host /opt/workloads/monitoring_bait.sh
   playground/scripts/eval_run_orchestrate.sh 5710 --window 5m --offset 2
   ```
2. Confirm at most one X5 retry (visible in driver.log + a second analyze entry in `subagent_audit.jsonl`).
3. Confirm `report.md` lands with `disposition: unclear` or `disposition: escalated`.
4. Unit test: feed `_output_parser.parse_analyze_envelope` a fixture with `:A routing disposition=true_positive surviving=[h-001]` where h-001 is named `?monitoring-bait-misconfig` (no adversarial token) — confirm `AnalyzeOutputError` raised; then feed the analyze handler a mock subagent that returns the X5-violating output once and a clean output on retry — confirm one re-dispatch and `report.md` lands.

## Out of scope

- Tightening rule #36 itself — the rule is correct; this task is about handler recovery, not rule design.
- Cross-validator generalization — see fix candidate (d), separate task if pursued.
- The run's *substantive* failure mode (was h-002 actually graded `++` and merely missing the adversarial token in its name? or graded below `++` despite the agent intending it to survive?) — answer that when reading the analyze trailer in the run dir, but the handler-recovery fix is needed regardless.
