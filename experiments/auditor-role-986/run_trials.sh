#!/usr/bin/env bash
# Fire N trials of the frontier-injection arm against the live playground.
#
# ONE ARM ONLY. The baseline is `20260830T100154Z-fresh-alert-input`, already on disk — the
# current agent's behaviour on this fixture is observed, not re-measured. The whole budget goes
# here, because that is the arm we cannot read from a single run.
#
# `--model glm-5.2` is not a default: it is what the baseline run used (its wire log records
# `accounts/fireworks/models/glm-5p2`). A trial on any other model is not comparable to it.
set -uo pipefail

cd "$(dirname "$0")/../.."

ALERT="${ALERT:-/workspace/.defender-runs/fresh-alert-input.json}"
PREFIX="${PREFIX:-b986}"
FIRST="${1:?usage: run_trials.sh <first-index> <last-index>}"
LAST="${2:?usage: run_trials.sh <first-index> <last-index>}"
OUT="experiments/auditor-role-986/runs"

mkdir -p "$OUT"
for i in $(seq "$FIRST" "$LAST"); do
    id="${PREFIX}-t${i}"
    echo "==> ${id}"
    DEFENDER_RUNS_BASE=/workspace/.defender-runs \
        DEFENDER_BOX_RUNTIME=runc \
        timeout 5400 defender/.venv/bin/python defender/run.py "$ALERT" \
        --model glm-5.2 --run-id "$id" --no-learn \
        > "${OUT}/t${i}.log" 2>&1
    echo "    exit=$? $(tail -1 "${OUT}/t${i}.log" 2>/dev/null | head -c 120)"
done
