#!/usr/bin/env bash
# All three arms CONCURRENTLY on one fixture, one trial index each, staggered 25 s.
#   run_arm.sh <fixture-dir> <first> <last>      (runs trial i of every arm before i+1)
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
FIX="${1:?}"; FIRST="${2:?}"; LAST="${3:?}"
for i in $(seq "$FIRST" "$LAST"); do
    pids=()
    for arm in current glm-flash ds-flash; do
        "$HERE/run_trials.sh" "$arm" "$FIX" "$i" "$i" &
        pids+=($!); sleep 25
    done
    for p in "${pids[@]}"; do wait "$p"; done
    echo "trial $i of all arms done $(date -u +%H:%M:%SZ)"
done
