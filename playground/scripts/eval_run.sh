#!/usr/bin/env bash
# Run the soc-agent /investigate skill against a real alert from the playground,
# in an isolated environment with full transcript capture.
#
# Isolation strategy:
#   - Run dir lives under /tmp/soc-agent-eval/ (outside /workspace) so no
#     CLAUDE.md on the cwd→root traversal path leaks into the agent.
#   - Plugin is COPIED to $EVAL_DIR/plugin at run start and --plugin-dir points
#     at the copy, not /workspace/soc-agent. The agent sees a snapshot of the
#     plugin — it cannot mutate the canonical source, and plugin edits made
#     during a running eval are not picked up by that eval. If you want your
#     plugin edits reflected, start a new eval after saving.
#   - --setting-sources user keeps user-level settings but skips project/local.
#   - --strict-mcp-config + --mcp-config loads only the wazuh MCP server,
#     not whatever else might be configured at user level.
#   - --no-session-persistence avoids polluting ~/.claude/projects with eval runs,
#     and keeps auto-memory from loading (cwd-keyed).
#
# Transcript capture:
#   - --output-format stream-json + --include-hook-events emits every event
#     (model messages, tool calls, hook events, subagent invocations) as JSONL.
#   - We tee that to {eval_dir}/transcript.jsonl for postmortem analysis.
#
# Usage:
#   playground/scripts/eval_run.sh <rule_id> [--window 4h] [--offset 0]
#
# Outputs (under /tmp/soc-agent-eval/{run_id}/):
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
SOURCE_PLUGIN_DIR="$REPO_ROOT/soc-agent"
MCP_CONFIG="$REPO_ROOT/.claude/mcp_config.json"
TOOLS_VENV="$SOURCE_PLUGIN_DIR/.venv/bin/python3"
FETCH_ALERT="$SOURCE_PLUGIN_DIR/scripts/fetch_alert.py"

if [ ! -x "$TOOLS_VENV" ]; then
    echo "error: soc-agent venv not found at $TOOLS_VENV" >&2
    echo "hint: cd $SOURCE_PLUGIN_DIR && uv sync --extra dev" >&2
    exit 2
fi

if [ ! -f "$REPO_ROOT/.env" ]; then
    echo "error: $REPO_ROOT/.env not found (required for Wazuh credentials)" >&2
    exit 2
fi

# Wazuh credentials for fetch_alert.py (and any agent-side queries)
# shellcheck disable=SC1090
set -a; source "$REPO_ROOT/.env"; set +a

# Activate the soc-agent venv so `python3 scripts/tools/wazuh_cli.py`
# invocations resolve to the venv interpreter (which has opensearch-py).
# Deps are declared as extras in pyproject.toml; install with:
#   cd soc-agent && uv sync --extra dev
# shellcheck disable=SC1091
source "$SOURCE_PLUGIN_DIR/.venv/bin/activate"

# ---------------------------------------------------------------------------
# Run dir + plugin snapshot
# ---------------------------------------------------------------------------

RUN_ID="$(date +%Y%m%d-%H%M%S)-rule${RULE_ID}"
EVAL_DIR="/tmp/soc-agent-eval/$RUN_ID"
PLUGIN_DIR="$EVAL_DIR/plugin"
mkdir -p "$EVAL_DIR/runs" "$PLUGIN_DIR"

echo "[+] Eval run: $RUN_ID"
echo "    dir: $EVAL_DIR"

# Snapshot the plugin so the agent cannot mutate the canonical source and so
# in-flight edits to /workspace/soc-agent don't bleed into the run. Skips the
# venv (shell activates the source venv for python deps) and dev/build cruft.
echo "[+] Snapshotting plugin → $PLUGIN_DIR"
tar -C "$SOURCE_PLUGIN_DIR" \
    --exclude='./.venv' \
    --exclude='./.pytest_cache' \
    --exclude='./__pycache__' \
    --exclude='./runs' \
    --exclude='./.git' \
    -cf - . | tar -C "$PLUGIN_DIR" -xf -

# ---------------------------------------------------------------------------
# Fetch alert
# ---------------------------------------------------------------------------

echo "[+] Fetching alert (rule.id:$RULE_ID, window=$WINDOW, offset=$OFFSET)..."
if ! "$TOOLS_VENV" "$FETCH_ALERT" "$RULE_ID" --window "$WINDOW" --offset "$OFFSET" > "$EVAL_DIR/alert.json"; then
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
# full_log is dropped: it duplicates the structured syscheck/data fields and
# always contains literal single-quotes in FIM events (e.g. 'Old md5sum was: ...')
# which would break the single-quoted shell argument.
ALERT_JSON=$(python3 -c "
import json, sys
a = json.load(open('$EVAL_DIR/alert.json'))
a.pop('full_log', None)
print(json.dumps(a, separators=(',',':')))
")

# ---------------------------------------------------------------------------
# Invoke claude in isolated mode with transcript capture
# ---------------------------------------------------------------------------

# soc-agent run dir lives inside the eval dir so it's also isolated
export SOC_AGENT_RUNS_DIR="$EVAL_DIR/runs"
# Corpus lives in the canonical runs tree, not the per-eval tmpdir. Without
# this override, invlang.corpus falls back to SOC_AGENT_RUNS_DIR (empty here)
# and PREDICT priors always come back "0 cases matched".
export INVLANG_CORPUS_ROOT="${INVLANG_CORPUS_ROOT:-$REPO_ROOT/runs}"

# Point the Stop hook (investigation_summary.py) at the tee'd transcript.
# --no-session-persistence means the path Claude Code passes into the hook
# is a 1-line ai-title stub, not the full transcript — this env var
# overrides it so token and model counts actually populate in audit.jsonl.
export SOC_AGENT_TRANSCRIPT_PATH="$EVAL_DIR/transcript.jsonl"

cd "$EVAL_DIR"

# The skill expects the full signature_id (matching the directory name under
# knowledge/signatures/), not the bare numeric rule ID. All signatures in this
# repo are wazuh-rule-*, so prefix accordingly.
SIGNATURE_ID="wazuh-rule-$RULE_ID"
PROMPT="/investigate $SIGNATURE_ID '$ALERT_JSON'"
if [ -n "${SOC_EVAL_PROMPT_SUFFIX:-}" ]; then
    PROMPT="$PROMPT

$SOC_EVAL_PROMPT_SUFFIX"
fi

echo "[+] Launching claude (isolated, transcript → $EVAL_DIR/transcript.jsonl)..."
echo "    cwd: $(pwd)"
echo "    SOC_AGENT_RUNS_DIR:   $SOC_AGENT_RUNS_DIR"
echo "    INVLANG_CORPUS_ROOT:  $INVLANG_CORPUS_ROOT"
echo

# stdbuf to keep the tee buffer flushing in real time
# Main-agent model — override via SOC_EVAL_MODEL env var (e.g. SOC_EVAL_MODEL=sonnet)
# `set +e` around the pipeline so a non-zero claude exit (timeouts, hook
# failures, judge denials, etc.) doesn't prevent the transcript renderer
# from running. We still report the exit status afterwards.
set +e
EFFORT_ARGS=()
if [ -n "${SOC_EVAL_EFFORT:-}" ]; then
    EFFORT_ARGS=(--effort "$SOC_EVAL_EFFORT")
fi

stdbuf -oL -eL claude \
    --model "${SOC_EVAL_MODEL:-sonnet}" \
    "${EFFORT_ARGS[@]}" \
    --allowedTools \
        "Bash(cd *)" \
        "Bash(ls *)" \
        "Bash(pwd)" \
        "Bash(python3 scripts/contextualize_preload.py *)" \
        "Bash(python3 scripts/preflight.py *)" \
        "Bash(python3 scripts/resolve_imports.py *)" \
        "Bash(python3 scripts/setup_run.py *)" \
        "Bash(python3 scripts/search_precedents.py *)" \
        "Bash(python3 scripts/workspace_map.py *)" \
        "Bash(python3 scripts/tools/wazuh_cli.py *)" \
        "Bash(python3 scripts/tools/data_source_health_wazuh.py *)" \
        "Bash(python3 scripts/tools/host_query.py *)" \
        "Bash(python3 scripts/tools/ticket_context.py *)" \
        "Bash(python3 scripts/invlang/cli.py *)" \
        "Bash(bash scripts/invlang/run.sh *)" \
        "Bash(python3 hooks/scripts/write_state.py *)" \
        "Bash(python3 $PLUGIN_DIR/scripts/contextualize_preload.py *)" \
        "Bash(python3 $PLUGIN_DIR/scripts/preflight.py *)" \
        "Bash(python3 $PLUGIN_DIR/scripts/resolve_imports.py *)" \
        "Bash(python3 $PLUGIN_DIR/scripts/setup_run.py *)" \
        "Bash(python3 $PLUGIN_DIR/scripts/search_precedents.py *)" \
        "Bash(python3 $PLUGIN_DIR/scripts/workspace_map.py *)" \
        "Bash(python3 $PLUGIN_DIR/scripts/tools/wazuh_cli.py *)" \
        "Bash(python3 $PLUGIN_DIR/scripts/tools/data_source_health_wazuh.py *)" \
        "Bash(python3 $PLUGIN_DIR/scripts/tools/host_query.py *)" \
        "Bash(python3 $PLUGIN_DIR/scripts/tools/ticket_context.py *)" \
        "Bash(python3 $PLUGIN_DIR/scripts/invlang/cli.py *)" \
        "Bash(bash $PLUGIN_DIR/scripts/invlang/run.sh *)" \
        "Bash(python3 $PLUGIN_DIR/hooks/scripts/write_state.py *)" \
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
CLAUDE_EXIT=${PIPESTATUS[0]}
set -e

echo
echo "[+] Eval run complete: $RUN_ID (claude exit=$CLAUDE_EXIT)"
echo "    transcript: $EVAL_DIR/transcript.jsonl"
echo "    runs:       $EVAL_DIR/runs/"
ls "$EVAL_DIR/runs/" 2>/dev/null | head -5 || true

# Render single-file HTML timeline for quick visual inspection.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python3 "$SCRIPT_DIR/render_transcript.py" "$EVAL_DIR" || \
    echo "[!] render_transcript.py failed (non-fatal)"

exit "$CLAUDE_EXIT"
