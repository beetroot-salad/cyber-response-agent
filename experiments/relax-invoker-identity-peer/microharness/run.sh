#!/usr/bin/env bash
# Microharness — invokes predict subagent directly with a fixture, then
# (after manually authoring synthetic GATHER) invokes analyze.
# No orchestrator, no playbook loader, no run_dir bookkeeping.
#
# Usage:
#   run.sh predict <fixture-name>          → outputs predict stdout
#   run.sh analyze <fixture-name>          → outputs analyze stdout (requires
#                                            outputs/<fixture>-predict.txt
#                                            and outputs/<fixture>-gather.md
#                                            already to exist)
set -euo pipefail

cd "$(dirname "$0")"
ROOT=/workspace/soc-agent
PHASE="${1:?phase required: predict|analyze}"
FIXTURE="${2:?fixture name required (without .md), e.g. f1-5710-bait}"
FIXTURE_FILE="fixtures/${FIXTURE}.md"
OUT_DIR="outputs"
[ -f "$FIXTURE_FILE" ] || { echo "fixture not found: $FIXTURE_FILE"; exit 1; }
mkdir -p "$OUT_DIR"

case "$PHASE" in
  predict)
    SYS="$ROOT/agents/predict/SKILL.md"
    OUT="$OUT_DIR/${FIXTURE}-predict.txt"
    PROMPT_FILE="$(mktemp)"
    cat "$FIXTURE_FILE" > "$PROMPT_FILE"
    ;;
  analyze)
    SYS="$ROOT/agents/analyze/SKILL.md"
    [ -f "$ROOT/agents/analyze/SKILL.md" ] || SYS="$ROOT/agents/analyze.md"
    OUT="$OUT_DIR/${FIXTURE}-analyze.txt"
    PREDICT_OUT="$OUT_DIR/${FIXTURE}-predict.txt"
    GATHER_FILE="$OUT_DIR/${FIXTURE}-gather.md"
    [ -f "$PREDICT_OUT" ] || { echo "missing $PREDICT_OUT — run predict first"; exit 1; }
    [ -f "$GATHER_FILE" ] || { echo "missing $GATHER_FILE — author synthetic gather first"; exit 1; }
    PROMPT_FILE="$(mktemp)"
    {
      cat "$FIXTURE_FILE"
      echo
      echo "## PREDICT (loop 1) — author's output"
      echo
      cat "$PREDICT_OUT"
      echo
      echo "## GATHER (loop 1) — synthetic outcomes"
      echo
      cat "$GATHER_FILE"
      echo
      echo "## Phase entry"
      echo "You are ANALYZE loop 1. Grade each hypothesis against the synthetic GATHER outcomes above per analyze.md grading discipline. Route the next phase."
    } > "$PROMPT_FILE"
    ;;
  *) echo "unknown phase: $PHASE"; exit 2 ;;
esac

[ -f "$SYS" ] || { echo "system prompt not found: $SYS"; exit 1; }

# Strip frontmatter from agent SKILL.md
SYS_BODY="$(mktemp)"
python3 -c "
import sys, re
text = open('$SYS').read()
m = re.match(r'^---\n.*?\n---\n', text, re.DOTALL)
sys.stdout.write(text[m.end():] if m else text)
" > "$SYS_BODY"

claude -p \
  --model sonnet \
  --system-prompt-file "$SYS_BODY" \
  --output-format text \
  < "$PROMPT_FILE" \
  > "$OUT" 2>&1

rm -f "$PROMPT_FILE" "$SYS_BODY"
echo "wrote: $OUT  ($(wc -c < "$OUT") bytes)"
