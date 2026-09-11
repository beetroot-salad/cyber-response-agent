#!/usr/bin/env bash
# Fire N serial trials of one arm on one fixture against the live playground.
#
#   run_trials.sh <current|glm-flash|ds-flash> <fixture-dir> <first-index> <last-index>
#
# The arm is exactly one env var, DEFENDER_GATHER_MODEL (variants/<arm>.env). MAIN stays on
# its glm-5.3 default and the review gate on kimi-k3 — no --model, which would move both.
# Every launch is appended to runs/manifest.jsonl so analyze.py never infers an arm from a
# run dir.
set -uo pipefail

CALLER_PWD="$(pwd)"
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE/../.."

ARM="${1:?usage: run_trials.sh <arm> <fixture-dir> <first> <last>}"
FIX="$(cd "$CALLER_PWD" && cd "${2:?}" && pwd -P)"
FIRST="${3:?}"; LAST="${4:?}"

[ -f "$HERE/variants/$ARM.env" ] || { echo "no variants/$ARM.env" >&2; exit 2; }
GATHER_MODEL="$(sed -n 's/^DEFENDER_GATHER_MODEL=//p' "$HERE/variants/$ARM.env")"
ALERT="$FIX/alert.json"
[ -f "$ALERT" ] || { echo "no alert.json under $FIX" >&2; exit 2; }
FIXNAME="$(basename "$FIX")"
LABEL="$(grep -m1 '^disposition:' "$FIX/label.yaml" 2>/dev/null | awk '{print $2}')"
RUNS_BASE="$HERE/runs"; mkdir -p "$RUNS_BASE"

for i in $(seq "$FIRST" "$LAST"); do
    id="${ARM}-${FIXNAME%%-*}-t${i}"
    echo "==> ${id}"
    start="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    env DEFENDER_GATHER_MODEL="$GATHER_MODEL" \
        DEFENDER_RUNS_BASE="$RUNS_BASE" \
        DEFENDER_BOX_RUNTIME=runc \
        timeout 5400 defender/.venv/bin/python defender/run.py "$ALERT" \
        --run-id "$id" --no-learn \
        > "${RUNS_BASE}/${id}.log" 2>&1
    rc=$?
    end="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf '{"run_id":"%s","arm":"%s","fixture":"%s","label":"%s","gather_model":"%s","started":"%s","ended":"%s","exit":%d}\n' \
        "$id" "$ARM" "$FIXNAME" "$LABEL" "$GATHER_MODEL" "$start" "$end" "$rc" \
        >> "$RUNS_BASE/manifest.jsonl"
    echo "    exit=$rc $(tail -1 "${RUNS_BASE}/${id}.log" 2>/dev/null | head -c 120)"
done
