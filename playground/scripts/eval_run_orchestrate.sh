#!/usr/bin/env bash
# Run the soc-agent Python state-machine orchestrator (scripts/orchestrate.py)
# against a real alert from the playground. Counterpart to eval_run.sh — that
# script invokes the main-agent /investigate skill; this one invokes the
# Python orchestrator directly.
#
# Differences from eval_run.sh:
#   - No main-agent `claude --print` invocation. The Python driver drives the
#     state machine; subagents are still spawned via `claude -p` by
#     `scripts/handlers/_subagent.py`.
#   - No plugin snapshot. The orchestrator imports from /workspace/soc-agent
#     directly; subagents are dispatched with `--plugin-dir /workspace/soc-agent`
#     by the shared wrapper.
#   - No transcript.jsonl. Per-subagent transcripts land under
#     {run_dir}/subagent_outputs/*.txt and subagent_audit.jsonl.
#   - No main-agent allowlist. Subagent tool allowlists come from their
#     frontmatter.
#
# Usage:
#   playground/scripts/eval_run_orchestrate.sh <rule_id> [--window 4h] [--offset 0]
#
# Outputs (under /tmp/soc-agent-orchestrate-eval/{run_id}/):
#   alert.json          — the raw alert this run is investigating
#   driver.log          — stdout+stderr of the driver (phase banner, errors)
#   runs/{uuid}/        — the soc-agent run directory (investigation.md,
#                         state.json, subagent_outputs/, subagent_audit.jsonl,
#                         report.md on success, ...)

set -euo pipefail

RULE_ID="${1:-}"
shift || true
WINDOW="4h"
OFFSET="0"

while [ $# -gt 0 ]; do
    case "$1" in
        --window) WINDOW="$2"; shift 2 ;;
        --offset) OFFSET="$2"; shift 2 ;;
        *) echo "error: unknown argument: $1" >&2; exit 2 ;;
    esac
done

if [ -z "$RULE_ID" ]; then
    echo "Usage: $0 <rule_id> [--window 4h] [--offset 0]" >&2
    exit 2
fi

REPO_ROOT=/workspace
SOURCE_PLUGIN_DIR="$REPO_ROOT/soc-agent"
TOOLS_VENV="$SOURCE_PLUGIN_DIR/.venv/bin/python3"
FETCH_ALERT="$SOURCE_PLUGIN_DIR/scripts/fetch_alert.py"
DRIVER="$SOURCE_PLUGIN_DIR/scripts/run_orchestrator.py"

if [ ! -x "$TOOLS_VENV" ]; then
    echo "error: soc-agent venv not found at $TOOLS_VENV" >&2
    echo "hint: cd $SOURCE_PLUGIN_DIR && uv sync --extra dev" >&2
    exit 2
fi

if [ ! -f "$REPO_ROOT/.env" ]; then
    echo "error: $REPO_ROOT/.env not found (required for Wazuh credentials)" >&2
    exit 2
fi

# shellcheck disable=SC1090
set -a; source "$REPO_ROOT/.env"; set +a

# shellcheck disable=SC1091
source "$SOURCE_PLUGIN_DIR/.venv/bin/activate"

RUN_ID="$(date +%Y%m%d-%H%M%S)-rule${RULE_ID}"
EVAL_DIR="/tmp/soc-agent-orchestrate-eval/$RUN_ID"
mkdir -p "$EVAL_DIR/runs"

echo "[+] Orchestrator eval run: $RUN_ID"
echo "    dir: $EVAL_DIR"

echo "[+] Fetching alert (rule.id:$RULE_ID, window=$WINDOW, offset=$OFFSET)..."
if ! "$TOOLS_VENV" "$FETCH_ALERT" "$RULE_ID" --window "$WINDOW" --offset "$OFFSET" > "$EVAL_DIR/alert.json"; then
    echo "error: fetch_alert.py failed" >&2
    exit 1
fi

ALERT_TS=$(python3 -c "import json; print(json.load(open('$EVAL_DIR/alert.json'))['timestamp'])")
ALERT_DESC=$(python3 -c "import json; print(json.load(open('$EVAL_DIR/alert.json'))['rule']['description'])")
ALERT_SRCIP=$(python3 -c "import json; print(json.load(open('$EVAL_DIR/alert.json')).get('data',{}).get('srcip',''))")
ALERT_SRCUSER=$(python3 -c "import json; print(json.load(open('$EVAL_DIR/alert.json')).get('data',{}).get('srcuser',''))")
echo "    alert: [$ALERT_TS] $ALERT_DESC"
echo "    srcip=$ALERT_SRCIP srcuser=$ALERT_SRCUSER"

# Compact single-line JSON for the argv string.
ALERT_JSON=$(python3 -c "
import json
a = json.load(open('$EVAL_DIR/alert.json'))
a.pop('full_log', None)
print(json.dumps(a, separators=(',',':')))
")

export SOC_AGENT_RUNS_DIR="$EVAL_DIR/runs"

SIGNATURE_ID="wazuh-rule-$RULE_ID"

echo "[+] Launching orchestrator (driver log → $EVAL_DIR/driver.log)..."
echo "    SOC_AGENT_RUNS_DIR: $SOC_AGENT_RUNS_DIR"
echo

set +e
stdbuf -oL -eL "$TOOLS_VENV" "$DRIVER" "$SIGNATURE_ID" "$ALERT_JSON" \
    2>&1 | tee "$EVAL_DIR/driver.log"
DRIVER_EXIT=${PIPESTATUS[0]}
set -e

echo
echo "[+] Run complete: $RUN_ID (driver exit=$DRIVER_EXIT)"
echo "    driver log: $EVAL_DIR/driver.log"
echo "    runs:       $EVAL_DIR/runs/"
ls "$EVAL_DIR/runs/" 2>/dev/null | head -5 || true

exit "$DRIVER_EXIT"
