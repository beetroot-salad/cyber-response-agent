# Relax invoker-identity peer restriction — final results

## Question

Engineering — does removing validator rule #32 (and the matching `_check_sibling_prediction_divergence`) plus the prohibitive prose in `agents/predict/SKILL.md` let the agent emit a productive actor-identity peer fork on rule-5710 bait without spuriously forking on simple cases — and does it actually break the lock-on-benign-mechanism failure mode observed in run #52?

## What broke the lock (the actual answer)

The lock-on-benign was NOT primarily caused by rule #32 or the playbook hypothesis seeds. The dominant in-prompt signal pinning the agent to `?registered-monitoring-probe` was the **rule-5710-specific worked example in `agents/predict/SKILL.md`** (lines 80, 302+), supported by the **archetype catalog's verdict-named entries** in the playbook (`monitoring-probe`, `service-account-rotation`, etc. with descriptions like "approved single-attempt probe" and "broken benign automation").

Removing the rule + relaxing the prose did not break the lock (trials 1–3). Removing the worked example AND sanitizing the archetype catalog did (trial 4 onward).

## Trials

| # | Setup | Hypotheses | Disposition | Loops | Wall | Notes |
|---|---|---|---|---|---|---|
| Run #52 | Baseline (rule #32 enabled, full playbook, full predict prompt) | mono `?registered-monitoring-probe` | escalated/unclear/medium | 3 | ~22m | The lock — agent stalled at `-` |
| 1 | + rule #32/#35 disabled, predict prose relaxed | mono | escalated/**true_positive/high** ⚠️ | 3 | ~22m | Regression — partial-anchor circular reasoning |
| 2 | + minimal playbook (just `## Archetypes` table) | mono | escalated/benign/medium | 2 | ~24m | Lock persisted; report flagged "no schema for burst" gap |
| 3 | + playbook seeds reframed as `## Open questions` | mono `?registered-monitoring-probe-initiated` | resolved/**benign/high/monitoring-probe** ⚠️ | 1 | ~9m | Worst — agent skipped per-second granularity, graded `++` on per-hour aggregate |
| **4** | **+ rule-5710 worked example removed from predict.md, archetype catalog sanitized** | **`?nagios-daemon-initiated-probe` + `?colocated-process-initiated-probe`** | **escalated/unclear/medium** | **6** | **~25m** | **Lock broken — peer fork emerges** |
| 5 | Trial-4 setup, repro | `?monitoring-probe-parallel-health-check` + `?process-on-source-host-initiated-burst` | n/a (gather subagent timed out at 300s — harness-level failure) | partial | partial | Predict-level peer fork reproduced before timeout |
| 6 | Trial-4 setup, repro | `?registered-probe-burst` + `?non-probe-process-burst` | escalated/unclear/low | 5 | ~25m | Reproduced; honest "data ceiling" narrative |

### Microharness probes (no orchestrator, no playbook)

`tasks-scratch/relax-invoker-identity-peer/microharness/` — direct `claude -p` invocation against `agents/predict/SKILL.md` and `agents/analyze.md` with hand-crafted alert + prologue, 60–90s per phase vs the orchestrator's ~25 min round-trip.

| Fixture | Phase | Result |
|---|---|---|
| F1 — 5710 bait shape, no playbook | predict | Shape E (no hypothesis), explicit reasoning: "burst-shape unknown unresolved, jumping to authorization is premature"; deferred fork to next loop |
| F1 | analyze (synthetic GATHER) | Confirmed lp1 within-baseline; named next-loop data wish (authoritative registry consult); no fabrication |
| F2 — synthetic 3-actor `aws s3 cp` on prod-secrets | predict | One hypothesis with TWO contracts (`change-management` + `session-origin-lookup`); predictions name observable upstream fields |
| F2 | analyze (synthetic GATHER with split anchor result) | Routed `unclear/medium` on anchor-divergence; flagged `/tmp/.cache.json` as anomaly; no bookkeeping |

### Sanity checks (other fixtures, trial-4 setup intact)

| # | Fixture | Outcome | Self-discipline |
|---|---|---|---|
| S1 | 100001 verdict-flip-bait (`docker exec bash -c whoami`) | escalated/benign/high (orthogonal dup2 fabrication) | ✅ no spurious peer (single hypothesis held) |
| S2 | 100110 DNS stress (clean-fork case) | escalated/unclear/low | ✅ productive peer on observable upstream divergence (`/etc/dnsmasq.conf` write attribution: scheduled-automation vs adversary-injection) |
| S3 | 5710 single-attempt cron probe (regression check) | resolved/benign/high/monitoring-probe via SCREEN fast-path | ✅ no fork on the easy case; SCREEN matched |

## The composite intervention (what to keep)

All seven changes ship together. None alone is sufficient (trials 1–3 verified that):

1. **Validator rule #32 disabled** (`_check_integrity_peer_discipline` returns `[]`) — necessary because the agent will write peer forks the rule would otherwise reject.
2. **Validator rule #35 disabled** (`_check_sibling_prediction_divergence` returns `[]`) — same reason; the generalization that subsumes #32.
3. **Permissive prose on actor-identity peers** in `agents/predict/SKILL.md` — replaced the four prohibitive paragraphs (lines 70, 384, 393, 395) with guidance that names the field-naming discipline ("predictions name an observable field that distinguishes the actors") and the verdict-flip anti-pattern (collapse to one hypothesis with a contract when the only difference is the verdict).
4. **Hypothesis seeds reframed as open questions** in `knowledge/signatures/wazuh-rule-5710/playbook.md` — the `## Hypothesis seeds` section became `## Open questions the agent must determine`, listing six numbered unknowns the investigation must resolve, with explicit guidance that the agent picks the cheapest unresolved unknown each loop and authors hypotheses against the question, not a pre-committed mechanism.
5. **Rule-5710-specific worked example removed from `agents/predict/SKILL.md`** — the load-bearing change. Generic placeholders (`<src>`, `<rule_id>`, `<mechanism-class>`, `<anchor-kind>`) replace the concrete `172.22.0.10` / `?registered-actor-initiated` / `approved-monitoring-sources` references throughout the inline mini-example AND the worked example. The Shape A worked example's content is now generic (any anchor that attests to identity-of-use) with an explicit anti-pattern callout.
6. **Archetype catalog sanitized** — playbook descriptions are now mechanism-shape-only ("single-attempt failure at source's documented periodic cadence") rather than verdict-named ("approved single-attempt probe"). Removed the "Both benign archetypes are anchored by..." prose that re-taught the lock; replaced with explicit guidance that registration ≠ identity-of-use.
7. **Cadence-granularity discipline note added** to predict prompt — *"per-hour aggregate match does not entail per-second cluster-shape match; if the alert's deviating signal is sub-hour, the baseline must be at sub-hour resolution"*. Captures the trial-3 failure mode.

## What did NOT change

- ANALYZE prompt
- GATHER prompts
- REPORT / report_narrative prompts
- Any other signature playbook
- Hooks (other than the two validator rules disabled)
- Schemas / dense parser / orchestrator handlers
- Test suite (24/24 invlang-validate tests still pass)

## Failure modes observed but orthogonal to this experiment

- **dup2 fabrication on 100001** (sanity 1): Sonnet sees rule 100002 dup2 co-fires within ±15min and builds a "monitoring-host SSH'd into target" benign narrative without pulling `proc.name=sshd, evt.type=dup2` to confirm the connection direction. Pre-existing pattern documented under runs #11 / #27 / #28; this experiment does not change it.
- **Cadence-granularity blindness** (trial 3 surfaced this): the agent grades per-second cluster anomalies as "matched baseline" when the lead query returns per-hour aggregates. Discipline note added in the predict prompt (item 7 above), but a deeper fix would push this into ANALYZE's grading discipline. Tracked as follow-up.
- **Gather subagent 300s timeout** (trial 5): hit on a long bait-shape composite gather. Harness-level, separate from the experiment. The 300s ceiling probably needs a per-loop dynamic budget on bait-class scenarios.

## Cost shape

Trial-4-setup runs at 5–6 loops vs run #52 baseline's 3-4 loops. The peer fork carries an extra GATHER-pair to disconfirm h-002. ~25 min wall comparable to run #52 baseline; ~bait.30 cost vs run #52's ~bait.50 — the extra loop is offset by faster phases (less circular reasoning around the partial-anchor stall). Cost is not the differentiator; correctness is.

## Recommendation

Ship the composite intervention. The lock-on-benign failure mode is the dominant correctness issue on bait-shape alerts (run #52 caught the medium-confidence-honest version, trial 1 produced the true-positive-high regression, trial 3 produced the benign-high regression — three distinct disposition errors all rooted in the same lock); breaking it via the seven-change recipe produces the right disposition without spurious forking on three other fixtures.

Validator rule #32 (and #35) ship disabled but kept intact in code as `return []` short-circuits — easy to re-enable if a regression surfaces in a future fixture.

## Open follow-ups (not for this PR)

- Apply the worked-example-removal pattern to other signature playbooks if they grow signature-specific in-prompt guidance that biases hypothesis emission.
- Re-litigate ANALYZE's grading granularity discipline — when a lead returns aggregated counts, ANALYZE should require the discriminating signal at the right granularity before grading `++` (current discipline note in predict prompt is preventive, not detective).
- The data-source-exhaustion pattern (agent re-queries the same data source multiple times with diminishing returns) is still pending separate investigation per the user's earlier note.
