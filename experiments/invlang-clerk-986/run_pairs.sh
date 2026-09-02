#!/usr/bin/env bash
# Run A and C together on one fixture, index by index, so both arms see the same live-world
# conditions (baseline generators, time of day) — pairs are serial, the two arms in a pair
# run concurrently.   run_pairs.sh <fixture-dir> <first> <last>
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
FIX="${1:?}"; FIRST="${2:?}"; LAST="${3:?}"
for i in $(seq "$FIRST" "$LAST"); do
    "$HERE/run_trials.sh" A "$FIX" "$i" "$i" &
    pa=$!
    sleep 20   # stagger the two starts so run-dir creation and the first ES burst don't collide
    "$HERE/run_trials.sh" C "$FIX" "$i" "$i" &
    pc=$!
    wait "$pa"; wait "$pc"
    echo "pair $i done $(date -u +%H:%M:%SZ)"
done
