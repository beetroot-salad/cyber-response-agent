#!/usr/bin/env bash
# Serial effort-tradeoff validation: 2 fixtures x 3 efforts = 6 runs, one at a time.
# Clean wall-clock per cell (no rate-limit contention). --no-learn isolates the
# investigation loop. Each arm sets CLAUDE_EFFORT *and* --effort so the 6
# `subagent_type: claude` subagents can't read a stale inherited effort.
set -u
cd /workspace/defender-v2-tree

EXP=/workspace/experiments/effort-tradeoff
RUNS_BASE=/tmp/defender-runs-v2
PY=defender/.venv/bin/python3
MANIFEST=$EXP/results/run_manifest.jsonl
: > "$MANIFEST"

declare -A FIX=(
  [mal]="$EXP/fixtures/malicious-cross-tier-probe.json"
  [ben]="$EXP/fixtures/benign-cross-tier-pivot.json"
)

# Order interleaves fixtures so an early failure still yields cross-effort coverage.
for effort in high medium low; do
  for fx in mal ben; do
    rid="xt-${fx}-${effort}"
    alert="${FIX[$fx]}"
    start=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)
    echo "### $(date -u +%H:%M:%S) START $rid effort=$effort fixture=$fx"
    CLAUDE_EFFORT="$effort" DEFENDER_RUNS_BASE="$RUNS_BASE" \
      "$PY" defender/run.py "$alert" --run-id "$rid" --no-learn --effort "$effort" \
      > "$EXP/runs/${rid}.stdout" 2> "$EXP/runs/${rid}.stderr"
    rc=$?
    end=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)
    echo "### $(date -u +%H:%M:%S) END   $rid rc=$rc"
    python3 - "$rid" "$effort" "$fx" "$start" "$end" "$rc" "$RUNS_BASE/$rid" >> "$MANIFEST" <<'PY'
import json,sys
rid,effort,fx,start,end,rc,rundir=sys.argv[1:8]
print(json.dumps({"run_id":rid,"effort":effort,"fixture":fx,
                  "harness_start":start,"harness_end":end,"rc":int(rc),"run_dir":rundir}))
PY
  done
done
echo "### ALL DONE $(date -u +%H:%M:%S)"
