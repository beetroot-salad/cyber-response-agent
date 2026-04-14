---
title: Migration Stage 4: flip main agent to Sonnet (after stages 1–3 are clean)
status: backlog
groups: sonnet, cost
---

Do not attempt until:
- Stages 1–3 all merged and have at least 5 clean eval runs each showing no regression on: adversarial-hypothesis discipline, Tier 2 judge pass rate, state-machine phase progression, report schema validity
- /evaluate eval suite is larger than 1 run per configuration
- Post-mortem screen-miss detection is implemented and has catalogued what fraction of "escalated benign" runs should have been SCREEN-resolved

Sub-tasks:
- Change claude invocation in eval_run.sh and plugin.json to pin main agent to Sonnet
- Re-run full eval suite across Scenario A (monitoring-probe, SCREEN fast-path) and Scenario B (monitoring-bait, full loop)
- Safety metrics to watch: adversarial hypothesis refutation timing, state-machine bypass attempts, Tier 2 judge retry count, budget overruns, lead-choice diagnosticity
- Revert immediately if any safety metric regresses meaningfully
