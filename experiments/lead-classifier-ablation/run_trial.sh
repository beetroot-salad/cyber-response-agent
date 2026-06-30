#!/usr/bin/env bash
# Run one lead-author trial: run_trial.sh <current|proposed> <fixture-name> <trial-idx>
# Picks the harness from the matching worktree (current=classifier present,
# proposed=removed), runs it against the fixture, and writes verdict.txt into
# runs/<arm>/<fixture>/<trial>/ (first line = PASS|WEAK-PASS|FAIL, for analyze.py).
set -uo pipefail

ARM="$1"; FIXTURE="$2"; TRIAL="$3"
EXP=/workspace/experiments/lead-classifier-ablation
case "$ARM" in
  current)  WT=/workspace/.claude/worktrees/lead-classifier-ablation ;;
  proposed) WT=/workspace/.claude/worktrees/lead-classifier-ablation-proposed ;;
  *) echo "bad arm: $ARM" >&2; exit 2 ;;
esac
HARNESS="$WT/defender/evals/harness_lead.py"
OUT="$EXP/runs/$ARM/$FIXTURE/$TRIAL"
mkdir -p "$OUT"

export LEARNING_VERIFIER_PYTHON=/workspace/defender/.venv/bin/python3
/workspace/defender/.venv/bin/python3 "$HARNESS" "$EXP/fixtures/$FIXTURE" \
    >"$OUT/harness.stdout" 2>"$OUT/harness.stderr"
RC=$?
# The harness prints "verdict=X" to stderr; lift it to verdict.txt line 1.
VERDICT=$(grep -oE 'verdict=[A-Z-]+' "$OUT/harness.stderr" | tail -1 | cut -d= -f2)
[ -z "$VERDICT" ] && VERDICT="MISSING(rc=$RC)"
{ echo "$VERDICT"; grep -E '^\[harness\]   - ' "$OUT/harness.stderr"; } > "$OUT/verdict.txt"
echo "[$ARM/$FIXTURE/$TRIAL] verdict=$VERDICT rc=$RC"
