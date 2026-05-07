#!/usr/bin/env bash
# defender/run.sh — invoke the defender on one alert.json fixture.
#
# Usage:
#   defender/run.sh <alert.json> [run_id]
#
# Creates a dedicated run dir under $DEFENDER_RUNS_BASE (default
# /tmp/defender-runs/) with alert.json + gather_raw/, then spawns
# `claude -p` against defender/SKILL.md. Stream output is captured
# to tool_trace.jsonl. The defender authors investigation.md,
# report.md, and lead_sequence.yaml inside the run dir; afterward
# run.sh renders transcript.html via visualize_run.py.
#
# Runs land in /tmp by default to keep the repo clean and to give the
# investigation a writable scratch space outside the source tree.
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <alert.json> [run_id]" >&2
  exit 64
fi

ALERT_PATH="$(realpath "$1")"
[[ -f "$ALERT_PATH" ]] || { echo "alert not found: $ALERT_PATH" >&2; exit 1; }

DEFENDER_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$DEFENDER_DIR/.." && pwd)"
RUNS_BASE="${DEFENDER_RUNS_BASE:-/tmp/defender-runs}"

if [[ $# -ge 2 ]]; then
  RUN_ID="$2"
else
  STEM="$(basename "$ALERT_PATH" .json)"
  RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$STEM"
fi

RUN_DIR="$RUNS_BASE/$RUN_ID"
if [[ -e "$RUN_DIR" ]]; then
  echo "run dir already exists: $RUN_DIR" >&2
  exit 1
fi
mkdir -p "$RUN_DIR/gather_raw"
cp "$ALERT_PATH" "$RUN_DIR/alert.json"

TRACE="$RUN_DIR/tool_trace.jsonl"
MODEL="${DEFENDER_MODEL:-claude-sonnet-4-6}"

PROMPT=$(cat <<EOF
Read defender/SKILL.md and follow it end-to-end.

## Run context
case_id: $RUN_ID
run_dir: $RUN_DIR
alert: $RUN_DIR/alert.json

The run dir already exists with alert.json copied in and an empty
gather_raw/ subdirectory. It lives under /tmp — write all run
artifacts (investigation.md, report.md, lead_sequence.yaml,
gather_raw/*) there, not under the repo. Work through ORIENT → PLAN
→ GATHER → ANALYZE → REPORT, dispatching gather subagents per
defender/SKILL.md §GATHER. After REPORT, run:

  python3 defender/scripts/project_lead_sequence.py $RUN_DIR

to emit lead_sequence.yaml. Stop when investigation.md, report.md,
and lead_sequence.yaml all exist.
EOF
)

SETTINGS_JSON=$(cat <<'EOF'
{"permissions":{"allow":["Bash(*)","Read(*)","Write(*)","Edit(*)","Grep(*)","Glob(*)","Task(*)","Skill(*)"]}}
EOF
)

echo "[run.sh] run_id=$RUN_ID model=$MODEL" >&2
echo "[run.sh] run_dir=$RUN_DIR" >&2

cd "$REPO_ROOT"
printf '%s' "$PROMPT" | claude -p \
  --model "$MODEL" \
  --output-format stream-json \
  --include-hook-events \
  --verbose \
  --permission-mode acceptEdits \
  --settings "$SETTINGS_JSON" \
  --add-dir "$RUN_DIR" \
  > "$TRACE"

python3 defender/scripts/visualize_run.py "$RUN_DIR" >&2 || true

echo "[run.sh] artifacts:" >&2
ls -1 "$RUN_DIR" >&2
