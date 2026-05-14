#!/bin/bash
# Driver for Arm A validation pass.
# Usage: arm_a_drive.sh <trial> [--parallel N]
# Runs all 14 fixtures × all catalog sizes for one trial number, with bounded parallelism.

set -u
cd "$(dirname "$0")"

TRIAL="${1:-1}"
PARALLEL="${2:-6}"

CATALOGS=(8 58 158)
FIXTURES=(F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 F11 F12 F13 F14)

run_one() {
    local fixture="$1" size="$2"
    python3 arm_a_harness.py "fixtures/selection/${fixture}.json" \
        --catalog-size "$size" --trial "$TRIAL" 2>&1 | tail -1
}

# Spawn with bounded parallelism: launch N at a time, wait for any to finish, then launch more.
running=0
for size in "${CATALOGS[@]}"; do
    for fixture in "${FIXTURES[@]}"; do
        run_one "$fixture" "$size" &
        running=$((running + 1))
        if [ "$running" -ge "$PARALLEL" ]; then
            wait -n
            running=$((running - 1))
        fi
    done
done
wait
echo "trial $TRIAL done"
