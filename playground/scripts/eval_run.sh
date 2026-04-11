#!/usr/bin/env bash
# Run the soc-agent /investigate skill against a real alert from the playground,
# in an isolated environment with full transcript capture.
#
# Isolation strategy:
#   - Run dir lives outside /workspace, so the project CLAUDE.md (/workspace/CLAUDE.md)
#     and the conversation auto-memory (/root/.claude/projects/-workspace/) are not
#     auto-loaded by claude's traversal. We get a clean context.
#   - --plugin-dir loads the soc-agent plugin for this session only.
#   - --setting-sources user keeps user-level settings but skips project/local
#     (which would be empty in /tmp anyway, but explicit is better).
#   - --strict-mcp-config + --mcp-config loads only the wazuh MCP server,
#     not whatever else might be configured at user level.
#   - --no-session-persistence avoids polluting ~/.claude/projects with eval runs.
#
# Transcript capture:
#   - --output-format stream-json + --include-hook-events emits every event
#     (model messages, tool calls, hook events, subagent invocations) as JSONL.
#   - We tee that to {eval_dir}/transcript.jsonl for postmortem analysis.
#
# Usage:
#   playground/scripts/eval_run.sh <rule_id> [--window 4h] [--offset 0]
#
# Outputs (under /tmp/cra-eval/{run_id}/):
#   alert.json        — the raw alert this run is investigating
#   transcript.jsonl  — full event stream (model + tool + hook events)
#   runs/{uuid}/      — the soc-agent run directory (investigation.md, report.md, state.json, ...)

set -euo pipefail

# ---------------------------------------------------------------------------
# Args
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

REPO_ROOT=/workspace
PLUGIN_DIR="$REPO_ROOT/soc-agent"
MCP_CONFIG="$REPO_ROOT/.claude/mcp_config.json"
WAZUH_CLI_VENV="$PLUGIN_DIR/scripts/siem/.venv/bin/python3"
FETCH_ALERT="$PLUGIN_DIR/scripts/fetch_alert.py"

if [ ! -x "$WAZUH_CLI_VENV" ]; then
    echo "error: wazuh cli venv not found at $WAZUH_CLI_VENV" >&2
    echo "hint: run $PLUGIN_DIR/scripts/siem/setup.sh" >&2
    exit 2
fi

if [ ! -f "$REPO_ROOT/.env" ]; then
    echo "error: $REPO_ROOT/.env not found (required for Wazuh credentials)" >&2
    exit 2
fi

# Wazuh credentials for fetch_alert.py (and any agent-side queries)
# shellcheck disable=SC1090
set -a; source "$REPO_ROOT/.env"; set +a

# Activate the wazuh_cli venv so the agent's `python3 scripts/siem/wazuh_cli.py`
# invocations resolve to the venv interpreter (which has opensearchpy). System
# python3 is missing the SIEM client deps, so without this every lead query
# would crash on ModuleNotFoundError.
# shellcheck disable=SC1091
source "$PLUGIN_DIR/scripts/siem/.venv/bin/activate"

# ---------------------------------------------------------------------------
# Run dir
# ---------------------------------------------------------------------------

RUN_ID="$(date +%Y%m%d-%H%M%S)-rule${RULE_ID}"
EVAL_DIR="/tmp/cra-eval/$RUN_ID"
mkdir -p "$EVAL_DIR/runs"

echo "[+] Eval run: $RUN_ID"
echo "    dir: $EVAL_DIR"

# ---------------------------------------------------------------------------
# Fetch alert
# ---------------------------------------------------------------------------

echo "[+] Fetching alert (rule.id:$RULE_ID, window=$WINDOW, offset=$OFFSET)..."
if ! "$WAZUH_CLI_VENV" "$FETCH_ALERT" "$RULE_ID" --window "$WINDOW" --offset "$OFFSET" > "$EVAL_DIR/alert.json"; then
    echo "error: fetch_alert.py failed" >&2
    exit 1
fi

ALERT_TS=$(python3 -c "import json; print(json.load(open('$EVAL_DIR/alert.json'))['timestamp'])")
ALERT_DESC=$(python3 -c "import json; print(json.load(open('$EVAL_DIR/alert.json'))['rule']['description'])")
echo "    alert: [$ALERT_TS] $ALERT_DESC"

# Compact the JSON to a single line for the prompt argument. Slash command
# args are whitespace-tokenized but honor shell-style quoting, so the JSON
# (which contains spaces in fields like timestamp) MUST be passed wrapped in
# single quotes — see PROMPT below. We strip insignificant whitespace via
# json.dumps separators to keep the prompt smaller; internal spaces inside
# string values still survive (and require the single-quote wrap).
ALERT_JSON=$(python3 -c "import json,sys; print(json.dumps(json.load(open('$EVAL_DIR/alert.json')), separators=(',',':')))")
if printf '%s' "$ALERT_JSON" | grep -q "'"; then
    echo "error: alert JSON contains a literal single-quote, which would break the single-quoted prompt arg" >&2
    echo "       (consider switching to base64 encoding if this becomes recurring)" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Invoke claude in isolated mode with transcript capture
# ---------------------------------------------------------------------------

# soc-agent run dir lives inside the eval dir so it's also isolated
export SOC_AGENT_RUNS_DIR="$EVAL_DIR/runs"

cd "$EVAL_DIR"

# The skill expects the full signature_id (matching the directory name under
# knowledge/signatures/), not the bare numeric rule ID. All signatures in this
# repo are wazuh-rule-*, so prefix accordingly.
SIGNATURE_ID="wazuh-rule-$RULE_ID"
PROMPT="/investigate $SIGNATURE_ID '$ALERT_JSON'"

echo "[+] Launching claude (isolated, transcript → $EVAL_DIR/transcript.jsonl)..."
echo "    cwd: $(pwd)"
echo "    SOC_AGENT_RUNS_DIR: $SOC_AGENT_RUNS_DIR"
echo

# stdbuf to keep the tee buffer flushing in real time
stdbuf -oL -eL claude \
    --allowedTools \
        "Bash(cd *)" \
        "Bash(ls *)" \
        "Bash(pwd)" \
        "Bash(python3 scripts/resolve_imports.py *)" \
        "Bash(python3 scripts/setup_run.py *)" \
        "Bash(python3 scripts/search_precedents.py *)" \
        "Bash(python3 scripts/workspace_map.py *)" \
        "Bash(python3 scripts/siem/wazuh_cli.py *)" \
        "Bash(python3 scripts/host_query.py *)" \
        "Bash(python3 hooks/scripts/write_state.py *)" \
        "Bash(python3 /workspace/soc-agent/scripts/resolve_imports.py *)" \
        "Bash(python3 /workspace/soc-agent/scripts/setup_run.py *)" \
        "Bash(python3 /workspace/soc-agent/scripts/search_precedents.py *)" \
        "Bash(python3 /workspace/soc-agent/scripts/workspace_map.py *)" \
        "Bash(python3 /workspace/soc-agent/scripts/siem/wazuh_cli.py *)" \
        "Bash(python3 /workspace/soc-agent/scripts/host_query.py *)" \
        "Bash(python3 /workspace/soc-agent/hooks/scripts/write_state.py *)" \
        "mcp__wazuh__*" \
        "Task" \
        "Agent" \
    --plugin-dir "$PLUGIN_DIR" \
    --add-dir "$PLUGIN_DIR" \
    --setting-sources user \
    --strict-mcp-config \
    --mcp-config "$MCP_CONFIG" \
    --print \
    --output-format stream-json \
    --include-hook-events \
    --verbose \
    --no-session-persistence \
    --permission-mode acceptEdits \
    "$PROMPT" \
    | tee "$EVAL_DIR/transcript.jsonl"

echo
echo "[+] Eval run complete: $RUN_ID"
echo "    transcript: $EVAL_DIR/transcript.jsonl"
echo "    runs:       $EVAL_DIR/runs/"
ls "$EVAL_DIR/runs/" 2>/dev/null | head -5 || true
