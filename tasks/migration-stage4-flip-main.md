---
title: Flip main agent to Sonnet
status: backlog
groups: sonnet-migration, cost
---

Primary plan for the Opus → Sonnet migration. Stages 2 and 3 (phase-specific splits) are deferred; the direct flip is the active path per the 2026-04-13 decision-doc revision. See `docs/decision-opus-sonnet-migration.md` for the data behind this (runs #11–#14).

Prerequisites:
- Signature-scaffolding maturation on 100001 and any other thin-playbook signatures — the #11 failure was a scaffolding gap, not a model-capability gap. Primary defense per the decision doc.
- `/evaluate` suite larger than 1 run per configuration, including at least one deliberately-degraded data source run per the real-world caveat.
- Post-mortem screen-miss detection (reliability-screen-miss-detection) landed and catalogued.

Sub-tasks:
- Flip `SOC_EVAL_MODEL=sonnet` in eval_run.sh default, and pin the main agent to Sonnet in plugin.json
- Re-run full eval suite across Scenario A (monitoring-probe, SCREEN fast-path) and Scenario B (monitoring-bait, full loop)
- Safety metrics to watch: adversarial hypothesis refutation timing, state-machine bypass attempts, Tier 2 judge retry count, budget overruns, lead-choice diagnosticity
- Revert immediately if any safety metric regresses meaningfully
