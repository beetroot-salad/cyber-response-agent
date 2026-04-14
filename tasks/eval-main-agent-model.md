---
title: Main-agent --model flag in eval_run.sh
status: done
groups: evaluation, sonnet-migration, cost
---

`playground/scripts/eval_run.sh` now passes `--model "${SOC_EVAL_MODEL:-opus}"` to `claude`, so a matched Opus-vs-Sonnet eval pair can be run by flipping the env var without editing the script. Default stays Opus; the actual flip-to-Sonnet promotion decision is tracked under migration-stage4-flip-main.
