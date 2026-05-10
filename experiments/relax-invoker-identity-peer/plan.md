## Question

**engineering** — does removing the invoker-identity peer prohibition (validator rule #32 + the matching `_check_sibling_prediction_divergence` generalization + the predict-prompt prose) let the agent fork early on rule-5710 bait when the contract sits at `partial`, without spuriously forking on scenario A clean — and at acceptable cost?

The current Shape A discipline collapses "registered actor" vs "different actor using the credentials" into one hypothesis + contract. On bait, where the only authoritative anchor (`approved-monitoring-sources`) is missing and only context-doc lookups are available, the contract sits at `partial` and the hypothesis stalls at `-` for multiple loops with no escape valve (run #52 baseline: 3 loops, ~22min wall, ~bait.50 est, escalated/unclear/medium). A peer hypothesis whose predictions diverge on `proc.name` / process-ancestry / session-origin would give ANALYZE a different observable channel to grade against; the question is whether the agent will (a) actually use it on bait and (b) not spuriously emit it on the trivially-benign scenario A.

## Variants

### current (regression)

`hooks/scripts/invlang_validate.py:472-473` registers both:
```python
errors.extend(_check_sibling_prediction_divergence(merged))
errors.extend(_check_integrity_peer_discipline(merged))
```

`agents/predict/SKILL.md` carries three pieces of prohibitive prose:

- **line 70** (Shape A): *"A peer hypothesis is justified only when integrity implies a different upstream mechanism … If you're not confident those observable differences exist and are testable with available leads, keep it as one hypothesis … Don't emit a peer whose predictions are just negations or duplicates of the main hypothesis's — that's the invoker-identity anti-pattern (§Disciplines), and the validator will reject it."*
- **line 384** (Disciplines): *"Invoker-identity-as-classification is an anti-pattern. … Rule #32 rejects this shape. … If you're unsure whether the divergence is real and testable with available leads, default to one hypothesis and let upstream loops fork if evidence forces it."*
- **line 393** (Disciplines): *"Hypotheses are mechanisms, not verdicts. If removing an `authorization_contract` makes two hypotheses indistinguishable on every forward-looking prediction, it's an authorization fork — collapse to Shape A."*
- **line 395** (Disciplines): *"A separate peer hypothesis is justified only when integrity implies a testably-different upstream mechanism (see invoker-identity anti-pattern above)."*

### proposed

**Validator** — short-circuit both functions to return `[]` (preserves imports + signatures so we can revert with one revert):
```diff
 def _check_integrity_peer_discipline(merged):
+    return []  # disabled by relax-invoker-identity-peer experiment
     errors: list[str] = []
     ...

 def _check_sibling_prediction_divergence(merged):
+    return []  # disabled by relax-invoker-identity-peer experiment
     errors: list[str] = []
     ...
```

**Prompt** — replace the four prohibitive paragraphs with permissive guidance:

- line 70: *"A peer hypothesis is welcome when integrity-of-use is genuinely an open question — even if the divergence is on a single observable field (process ancestry, session origin, parent uid, audit trail). The agent's discipline is to keep predictions specific and testable; structural rejection is no longer enforced."*
- line 384: *"A peer fork on actor identity is permitted. Keep its predictions concrete (name the field that distinguishes the two) and avoid emitting peers whose predictions you cannot actually test against any available lead — that's wasted weight, not wrong shape."*
- line 393: removed.
- line 395: *"Authorization vs integrity. Authorization contracts answer policy. Integrity is an attribute of the parent vertex; in the common case the contract's anchor attests to identity-of-use as well, but a separate integrity peer is fine when the agent expects observable divergence."*

**One variable changes between cells**: peer-fork structural prohibition (validator + prompt) on or off. Validator and prompt edits are bundled because lifting one without the other has no effect (validator rejects what prompt allows, or prompt forbids what validator permits) — they are one variable in two files.

## Fixtures

Four real Wazuh alerts triggered live by playground workloads. Shape-current (post-PR-#174 dense invlang surface, run #51/#52 era). Two probe whether the rule is load-bearing in the productive direction (a fork that earns its keep), two stress-test the failure mode the rule was originally written against (a fork that doesn't):

- **Fixture 1 — 5710 scenario B (bait, primary)** — `docker exec monitoring-host /opt/workloads/monitoring_bait.sh` produces a 5-attempt SSH burst from `nagios@172.22.0.10`. Triggers full-loop investigation; `approved-monitoring-sources` anchor lands `partial` (no authoritative registry surface in playground). This is the case where the fork is load-bearing — Shape A locks the agent into one mono-hypothesis at `-` for multiple loops in the current arm. *Probes: does removing the rule unstick the investigation?*

- **Fixture 2 — 5710 scenario A clean (mild regression check)** — wait for the `:X0:02` cron tick of `monitoring_probe.sh nagios` (or trigger one when no cron probe has fired in the prior 5 minutes). SCREEN-resolves on the current arm; the proposed arm should not spuriously fork. *Probes: easy benign cases stay easy.*

- **Fixture 3 — 100001 verdict-flip bait (stress: agent must self-discipline)** — `docker exec -t target-endpoint bash -c whoami` produces a `Terminal shell in container` alert with `proc.pname=containerd-shim`, `bash -c <oneliner>`. The naive 2N actor-fork tempts: `?operator-runtime-debug` vs `?adversary-controlled-runc-debug-running-as-operator`. Both go through the same `containerd-shim → runc → bash` ancestry; both predict the same `image-baseline` shape and the same composition-rule co-fires; the only honest discriminator is the `deploy-runs` legitimacy contract. **A peer hypothesis here is verdict-flipping pretending to be a mechanism fork** — exactly what rule #32 was written to forbid. *Probes: with the rule removed, does the agent emit the spurious peer (failure of self-discipline) or hold to one hypothesis + contract (correct behavior, internalized)?* This is the canonical failure mode the original rule guarded against.

- **Fixture 4 — 100110 actor-divergence on proc.name (stress: fork earns its keep)** — `docker exec target-endpoint /opt/workloads/dns_stress.sh` produces high-entropy DNS queries to unrecognized parents; the underlying falco event carries `proc.name` of the *actual* querying process on the container, plus `proc.pname` for ancestry. Two genuinely different actors are observable: tooling using the system resolver (`proc.name=monitoring-agent`, parent=cron) vs an unrelated container process (`proc.name=node`/`python`/whatever, parent=runtime-spawned). These two actor hypotheses diverge on a real, queryable observable — `proc.name` on the falco event itself — and the legitimacy contract on a single hypothesis can't capture that divergence because both actors might or might not be authorized depending on which one fired. *Probes: with the rule removed, does the agent emit a peer with predictions on `proc.name` / `proc.pname` and use it to route the investigation more cleanly than mono-hypothesis Shape A would?*

`fixtures/` directory holds harness recipes (trigger command + alert-fetch command + expected-shape notes), not literal alert.json — alerts are fetched fresh per trial after triggering the workload.

## Trials

**Validation pass** — 1 trial per variant per fixture (8 trials total). Confirm:
1. variant runs pass invlang validation end-to-end (no patch broke anything else)
2. proposed-variant predict on Fixture 1 emits a peer with predictions on observable upstream fields
3. proposed-variant predict on Fixture 3 (verdict-flip bait) does NOT emit a spurious peer — agent self-disciplines
4. proposed-variant predict on Fixture 4 emits a peer with predictions on `proc.name` / `proc.pname`
5. proposed-variant Fixture 2 behaves like current (no spurious fork on the cron-probe SCREEN-resolved path)

If validation surfaces a fixture mismatch (e.g., agent forks on Fixture 3 — failure of self-discipline), pause and decide whether the relaxation is viable at all before scaling.

**Scale-up** — n=3 per cell, 24 trials total (2 variants × 4 fixtures × 3). Sonnet-main, orchestrator harness (`eval_run_orchestrate.sh`).

`tasks-scratch/relax-invoker-identity-peer/analyze.py` written before scale-up. Aggregates per-trial:
- `hypothesis_count_max` (parse investigation.md `:H` blocks across all loops)
- `peer_emitted_at_loop` (lowest loop_n where ≥2 hypotheses present)
- `peer_predictions_diverge_on` (list of fields named in `:P h-*.preds` across siblings — flagged as `observable-divergence` if ≥1 field is in {proc.name, proc.pname, process_ancestry, session_origin, parent_uid, audit_trail_kind} and `verdict-flip-only` otherwise)
- `peer_serves_investigation` (boolean, derived: were peer-specific predictions actually queried by GATHER, and did ANALYZE grade siblings on distinct evidence?)
- `analyze_grade_per_hypothesis` (final weight per h-id from final ANALYZE)
- `disposition / confidence / matched_archetype / matched_ticket_id` (report frontmatter)
- `wall_seconds`, `subagent_count`, `tool_calls`, `validator_rejections`, `loops_to_disposition` (from driver.log + budget.json + state.json)
- per-phase wall-clock distribution (`subagent_audit.jsonl` group-by `agent`)
- `narrative_honesty` flags (LLM-judged via judge-runner with a single judge prompt — see Section 7): does the report's adversarial reasoning track the evidence or paper over `partial` anchors with confident benign language; do peer hypotheses (when present) cite distinct evidence per grade or share the same evidence across siblings (the bookkeeping failure mode)

Mid-run analysis at trial 8 of 24 (33%): pause, run analyze.py, decide continue/abort/adjust.

## Decision criteria

Five named axes, each scored per fixture per cell (3 trials), then aggregated:

**(a) Forking serves the investigation, no bookkeeping** — when a peer is emitted, its predictions name fields the agent actually queries (not just renamed-verdict statements), and ANALYZE grades the siblings on *distinct* evidence rows. Bookkeeping failure: peer present, peer predictions never queried, ANALYZE reuses the same lead/observation to assign opposite weights to two hypotheses.

**(b) Cleanliness** — fewer loops to disposition, fewer phase-history wobbles, fewer validator/state-machine rejections. Compared to current arm on the same fixture.

**(c) Effectiveness** — peer hypothesis (when emitted) materially routes the investigation: it picks a different lead than mono-hypothesis would have, or it lets ANALYZE close out a branch faster.

**(d) Honesty / rigor** — judged from the report narrative + investigation.md: does the agent describe the partial-anchor situation accurately, refuse to over-claim, and cite each grade's evidence concretely, or does it paper over uncertainty with confident-sounding prose?

**(e) Correctness** — final disposition matches the alert's ground truth on each fixture (escalated/unclear/medium for Fixture 1 bait; resolved/benign/high for Fixture 2; escalated/inconclusive/medium for Fixture 3 with archetype-shape-disqualified; escalated/unclear/high for Fixture 4 with the adversarial branch held open per the legitimacy-gated machinery).

**proposed wins** if all four hold:
1. **Fixture 1 (bait)** — ≥2/3 trials emit a peer with `observable-divergence` predictions AND `peer_serves_investigation=true` AND ≤current arm's loops_to_disposition
2. **Fixture 3 (verdict-flip bait)** — ≤1/3 trials emit a peer (agent self-disciplines under the relaxed rule); when emitted, the peer is corrected/abandoned by ANALYZE rather than carried into REPORT
3. **Fixture 4 (clean fork)** — ≥2/3 trials emit a peer on `proc.name`/`proc.pname` divergence AND that peer earns its keep (different lead pursued, distinct evidence in grades)
4. **Across all 4 fixtures** — correctness preserved AND wall + cost within 30% of current arm averages AND honesty/rigor non-regressing per judge

**current retained** if any:
- Fixture 1 peers don't emerge or emerge but ANALYZE bookkeeps them (no real signal gain) — the rule's removal has no upside
- Fixture 3 spurious peer ≥2/3 (agent does NOT self-discipline under freedom — the rule was load-bearing for the failure mode it was written against)
- Fixture 4 peers don't emerge or emerge without `proc.name`/`proc.pname` predictions — the relaxation didn't unlock the productive case
- Correctness regresses on any fixture
- Cost > 30% above baseline on the regression fixtures

**inconclusive → defer** if Fixtures 1+4 win but Fixture 3 fails (productive cases work, but agent fails self-discipline on the bait): the structural rule is doing real work; consider replacing rule with a softer discipline-cue prompt instead of removing it. Documented as the follow-up experiment.

## Layout

```
tasks-scratch/relax-invoker-identity-peer/
  plan.md                      # this file
  variants/
    current/                   # symlinks or notes pointing at HEAD
    proposed/
      invlang_validate_diff    # quoted patch
      predict_skill_diff       # quoted patch
  fixtures/
    bait.md                    # trigger recipe + alert-fetch command
    scenario-a.md              # trigger recipe + alert-fetch command
  runs/
    current-bait-1/            # symlink to /tmp/soc-agent-orchestrate-eval/<ts>-rule5710/
    current-bait-2/
    current-bait-3/
    current-scenarioA-{1,2,3}/
    proposed-bait-{1,2,3}/
    proposed-scenarioA-{1,2,3}/
  analyze.py                   # written before trial 5
  results/
    validation.md              # 4-trial validation pass writeup
    midrun-trial4.md           # 33% checkpoint
    final.md                   # full analysis + decision
```

## Notes

- Trial cadence: must wait ≥5 min between Fixture 2 trials to keep the SCREEN window clean (per harness quirk #11). Fixture 1/3/4 trials can fire back-to-back. Fixture 4 needs `dns_stress.sh` to land falco events with concrete `proc.name` — confirm the falco rule populates it before scaling.
- Cost ceiling per trial: bait.50 worst case for 5710 (run #52), bait.50 worst case for 100001 (run #25), bait.50 worst case for 100110 (run #31). 24 trials × bait.50 = ~$36 budget; expected actual ~$22 with most trials in the bait.50–.50 range.
- Judge prompt for honesty/rigor scoring written before scale-up under `tasks-scratch/relax-invoker-identity-peer/variants/judge_honesty.md`. Single judge per trial, Haiku-backed via `hooks/scripts/judge_runner.py`.
- `feedback_isolate_one_variable_in_experiments` honored: validator + prompt edits are one variable across two files (lifting one without the other has no effect).
- `feedback_minimal_ab_for_repro` honored: n=3 per cell is the minimum to detect "fork emerges" vs "fork doesn't emerge" without statistical noise dominating.
- `feedback_rank_by_normalized_effectiveness` honored: aggregations use per-occurrence mean with `n` shown.
- The repeated-data-source-exhaustion pattern is OUT OF SCOPE for this experiment — flagged as a follow-up after results.
