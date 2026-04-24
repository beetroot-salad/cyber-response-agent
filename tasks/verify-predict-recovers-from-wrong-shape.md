---
title: Verify the loop recovers from a wrong-shape/wrong-lead PREDICT call
status: done
groups: predict, investigation-loop, evaluation
---

**Findings (2026-04-24).** Recovery confirmed on both axes against the
rule-5710 monitorprobe fixture (the worked example in
`agents/predict.md`). Harness: `/tmp/predict_recovery_harness.py` builds
fresh run dirs with synthetic loop-1 PREDICT/GATHER/ANALYZE state, then
dispatches the real `predict` subagent for loop 2 via
`scripts/handlers/predict.handle`. Results: `/tmp/predict_recovery_results.json`.

- **Wrong-shape recovery (loop 1 = Shape M, h-001 ?retry-misfire vs h-002
  ?config-drift on cadence — non-discriminating).** Loop 2 pivoted to
  Shape A: `?monitoring-system-is-the-actor` (h-003) carrying
  `authorization_contract` against `approved-monitoring-sources`, paired
  with `?adversary-controlled-process-on-source` (h-004) integrity peer
  per schema rule #32. Selected lead: `monitoring-probe` (the playbook
  composite — registry + scheduler-audit). Output mirrors the §Shape A
  worked example in `agents/predict.md` almost verbatim.
- **Wrong-lead recovery (loop 1 = Shape E with `host-query`; ANALYZE
  flagged `unresolved_prescribed_set: [authentication-history]`).** Loop
  2 re-prescribed `authentication-history` and emitted a full Shape E
  branch_plan (lp1 forward-success → escalate; lp2 periodic cadence →
  fork-at-identity-of-use; lp3 insufficient cadence history → fork
  without baseline). Lead hint includes the 1h-backward + 60s-forward
  window and the cluster-stat shape ANALYZE will read against.

**Cost envelope.**

| Scenario | Attempts | Wall-clock |
|---|---|---|
| A (wrong-shape) | 2 (1st missed rule #32 integrity peer; remediation note added it on retry) | 132s + 79s = 211s |
| B (wrong-lead)  | 1 | 109s |

Both inside the ~3 min/loop target. The retry on A was a single-rule
fix (validator-caught, handler-remediated automatically), not a full
re-thinking — the remediation pathway works as designed.

**Verdict.** The "agile fast loop, recover via next iteration"
hypothesis holds on this fixture: a wasted/wrong loop costs one
additional ~3 min step, not a cascade. Caveats: single fixture (not
3-5 as the methodology section called for), and corpus priors were
empty (synthetic alert id), so this measures the prompt's intrinsic
recovery rather than prior-conditioned scaffold choice. Broader fixture
sweep is the natural follow-up if we want statistical confidence.

---

**Context.** The PREDICT subagent was redesigned to bias toward Shape E and away from premature forking — collapsing E/D/I/A/M → E/A/M, stripping archetype labels from its preload, and adding a default-bias toward E when uncertain. The design hypothesis: a wasted enrichment loop is cheaper than a premature fork that has to be torn down, and the system iterates (ANALYZE routes `continue` when grading is ambiguous; the next PREDICT re-prescribes).

We need empirical evidence that this actually holds.

**What to verify.**

1. **Wrong-shape recovery.** Force PREDICT to pick Shape E on loop 1 when the evidence supports Shape A (e.g. a clear container-exec with `pname=runc` where authorization is the open question). Does loop-2 ANALYZE route `continue` with a clean `unresolved_prescribed_set` or `anomalies[]` signal that steers loop-2 PREDICT to Shape A? Does the overall run converge to the correct disposition?

2. **Wrong-lead recovery.** Force PREDICT to pick a non-discriminating lead (e.g. pick `host-query` when `authentication-history` is the real discriminator for a 5710 burst). Does ANALYZE's `unresolved_prescribed_set` / `data_wishes[]` signal get threaded into the next PREDICT prompt, and does the subagent re-prescribe the right lead?

3. **Cost envelope.** Measure wall-clock per loop under the new prompt. Target: ~3 min/loop under Sonnet. If a "wasted" loop (E when A was correct) adds only one loop of ~3 min, the agile framing is viable at scale. If it adds two loops (E-then-wrong-A-then-right-A), the framing breaks down.

**Method.**

- Construct 3–5 fixture alerts where the "right" shape is unambiguous from the evidence.
- Run the orchestrator against each fixture with a seed-patched PREDICT that forces the wrong shape on loop 1 (test-only monkeypatch; no production change needed).
- Score: does the run converge to the correct disposition, and how many loops did it take?
- Compare against an unpatched baseline to quantify the recovery overhead.

**Why this matters.**

The "work fast, get feedback, iterate" framing is attractive if it holds — and toxic if it doesn't. Without empirical verification, we're guessing whether bad first-loop judgment calls recover gracefully or cascade. Baseline Sonnet loop is currently 400–600s; if we can get it to ~3 min AND the loop tolerates wrong initial calls, the strategy becomes viable. Both halves need to land.

**Related.**

- `predict-prompt-redesign` (the change that motivates this) — see `agents/predict.md` §Shapes, §Decision procedure, and the default-bias-toward-E language.
- `testrun` skill's meta-finding #17 (thinking-restatement variance) — cutting per-loop wall is partly addressed by the archetype strip + shape collapse, but needs measurement.
