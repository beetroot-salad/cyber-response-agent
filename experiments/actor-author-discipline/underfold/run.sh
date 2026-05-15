#!/usr/bin/env bash
# Run N underfold trials, each one author_actor invocation against
# the seeded fixture (3 seeds + 4 probes).
#
# Usage: ./run.sh [N] [parallel]
#   N        — number of trials (default 4)
#   parallel — "parallel" to run trials concurrently in different
#              worktrees, anything else for serial (default serial).
#
# Each trial:
#   - resets a dedicated worktree under /tmp/exp-actor-author/uf-trial-{i}
#   - copies seeds + probes from this dir into the worktree
#   - invokes author_actor.py with model=sonnet
#   - snapshots commit + final lessons-actor + queue under
#     underfold/runs-out/trial-{i}/
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXP_DIR="$(cd "$HERE/.." && pwd)"
N="${1:-4}"
MODE="${2:-serial}"

OUT_ROOT="$HERE/runs-out"
mkdir -p "$OUT_ROOT"

run_one() {
  local i="$1"
  local trial_out="$OUT_ROOT/trial-$i"
  local worktree="/tmp/exp-actor-author/uf-trial-$i"
  mkdir -p "$trial_out"
  python3 "$EXP_DIR/harness.py" \
    --variant v2 \
    --model sonnet \
    --trial "$i" \
    --worktree "$worktree" \
    --fixture-dir "$HERE" \
    --out "$trial_out" \
    2>&1 | tee "$trial_out/runner.log"
}

if [[ "$MODE" == "parallel" ]]; then
  pids=()
  for i in $(seq 1 "$N"); do
    run_one "$i" &
    pids+=($!)
  done
  for pid in "${pids[@]}"; do wait "$pid"; done
else
  for i in $(seq 1 "$N"); do
    run_one "$i"
  done
fi

echo "All $N trials complete. Run analyze.py next."
