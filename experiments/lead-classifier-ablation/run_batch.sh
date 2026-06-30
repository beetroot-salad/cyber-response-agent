#!/usr/bin/env bash
# run_batch.sh <trials-per-arm-per-fixture> [parallelism]
# Emits one job line per (arm,fixture,trial) and runs them via xargs -P.
set -uo pipefail
N="${1:-1}"; P="${2:-3}"
EXP=/workspace/experiments/lead-classifier-ablation
FIXTURES="atomic-control sweep-srcip-host join-cross-system baseline-shift-two-window"
ARMS="current proposed"
for arm in $ARMS; do for fx in $FIXTURES; do for t in $(seq 1 "$N"); do
  echo "$arm $fx $t"
done; done; done | xargs -P "$P" -L1 bash "$EXP/run_trial.sh"
echo "=== batch done ==="
