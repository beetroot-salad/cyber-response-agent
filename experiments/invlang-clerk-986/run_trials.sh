#!/usr/bin/env bash
# Fire N serial trials of one arm on one fixture against the live playground.
#
#   run_trials.sh <A|C> <fixture-dir> <first-index> <last-index>
#
# A = current (MAIN authors invlang rows itself).
# C = clerk   (MAIN records prose; a clerk role compiles the rows). Selected purely by env —
#     DEFENDER_INVLANG_CLERK=1 — so both arms run the same checkout.
# D = clerk on deepseek-v4-flash (C with only the clerk model changed).
# E = clerk on glm-5.3-flash.
#
# `--model glm-5.2` is what every prior run on these fixtures used; the clerk's own model is
# CLERK_MODEL (default kimi-k2.6). Every launch is appended to runs/manifest.jsonl so
# analyze.py never has to infer an arm from a run dir.
set -uo pipefail

CALLER_PWD="$(pwd)"
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE/../.."

ARM="${1:?usage: run_trials.sh <A|C> <fixture-dir> <first> <last>}"
FIX="$(cd "$CALLER_PWD" && cd "${2:?usage: run_trials.sh <A|C> <fixture-dir> <first> <last>}" && pwd)"
FIRST="${3:?usage: run_trials.sh <A|C> <fixture-dir> <first> <last>}"
LAST="${4:?usage: run_trials.sh <A|C> <fixture-dir> <first> <last>}"

ALERT="$FIX/alert.json"
[ -f "$ALERT" ] || { echo "no alert.json under $FIX" >&2; exit 2; }
FIXNAME="$(basename "$FIX")"
LABEL="$(grep -m1 '^disposition:' "$FIX/label.yaml" 2>/dev/null | awk '{print $2}')"
CLERK_MODEL="${CLERK_MODEL:-kimi-k2.6}"
MAIN_MODEL="${MAIN_MODEL:-glm-5.2}"
RUNS_BASE="${DEFENDER_RUNS_BASE:-/workspace/.defender-runs}"
OUT="$HERE/runs"; mkdir -p "$OUT"

case "$ARM" in
  A) ARM_ENV=() ;;
  C) ARM_ENV=(DEFENDER_INVLANG_CLERK=1 "DEFENDER_CLERK_MODEL=$CLERK_MODEL") ;;
  D) CLERK_MODEL=deepseek-v4-flash; ARM_ENV=(DEFENDER_INVLANG_CLERK=1 "DEFENDER_CLERK_MODEL=$CLERK_MODEL") ;;
  E) CLERK_MODEL=glm-5.3-flash;     ARM_ENV=(DEFENDER_INVLANG_CLERK=1 "DEFENDER_CLERK_MODEL=$CLERK_MODEL" DEFENDER_CLERK_EFFORT=low) ;;
  *) echo "arm must be A, C, D or E" >&2; exit 2 ;;
esac

for i in $(seq "$FIRST" "$LAST"); do
    id="ic986-${ARM}-${FIXNAME}-t${i}"
    echo "==> ${id}"
    start="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    env "${ARM_ENV[@]}" \
        DEFENDER_RUNS_BASE="$RUNS_BASE" \
        DEFENDER_BOX_RUNTIME=runc \
        timeout 5400 defender/.venv/bin/python defender/run.py "$ALERT" \
        --model "$MAIN_MODEL" --run-id "$id" --no-learn \
        > "${OUT}/${id}.log" 2>&1
    rc=$?
    end="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf '{"run_id":"%s","arm":"%s","fixture":"%s","label":"%s","main_model":"%s","clerk_model":"%s","started":"%s","ended":"%s","exit":%d}\n' \
        "$id" "$ARM" "$FIXNAME" "$LABEL" "$MAIN_MODEL" "$([ "$ARM" != A ] && echo "$CLERK_MODEL" || echo "")" "$start" "$end" "$rc" \
        >> "$OUT/manifest.jsonl"
    echo "    exit=$rc $(tail -1 "${OUT}/${id}.log" 2>/dev/null | head -c 120)"
done
