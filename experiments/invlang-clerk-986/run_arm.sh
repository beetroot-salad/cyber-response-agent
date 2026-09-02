#!/usr/bin/env bash
# Run one arm's trials CONCURRENTLY on one fixture (staggered starts), then wait for all.
#   run_arm.sh <A|C|D> <fixture-dir> <first> <last>
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ARM="${1:?}"; FIX="${2:?}"; FIRST="${3:?}"; LAST="${4:?}"
pids=()
for i in $(seq "$FIRST" "$LAST"); do
    "$HERE/run_trials.sh" "$ARM" "$FIX" "$i" "$i" &
    pids+=($!)
    sleep 25
done
for p in "${pids[@]}"; do wait "$p"; done
echo "arm $ARM $FIRST..$LAST done $(date -u +%H:%M:%SZ)"
