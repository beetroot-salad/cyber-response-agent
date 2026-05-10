#!/usr/bin/env bash
# Single-turn hypothesize trial with extended thinking enabled.
# Captures stream-json transcript so thinking tokens are visible.
#
# Usage: run_thinking_trial.sh <staged_run_dir> <signature_id> <loop_n> <effort> <out_file>
#
# out_file.transcript.jsonl — raw stream-json events
# out_file.output.md       — final assistant text (YAML block + Selected lead + Pitfalls)
#
# Thinking accounting is extracted via tally_thinking.py.

set -euo pipefail

STAGED="$1"
SIG_ID="$2"
LOOP_N="$3"
EFFORT="$4"
OUT="$5"

HYPOTHESIZE_MD="/workspace/soc-agent/agents/hypothesize.md"
KNOWLEDGE_DIR="/workspace/soc-agent/knowledge"

# Strip frontmatter from hypothesize.md for the system prompt append.
SYS_PROMPT=$(awk 'BEGIN{n=0} /^---$/{n++; next} n>=2{print}' "$HYPOTHESIZE_MD")

USER_PROMPT="You are acting as the hypothesize subagent.
Caller substitutions:
- run_dir = ${STAGED}
- signature_id = ${SIG_ID}
- loop_n = ${LOOP_N}

Read the four required files per your instructions and emit the loop-${LOOP_N} HYPOTHESIZE or GATHER block exactly per the output schema. No preamble."

echo "[+] trial: $OUT (effort=$EFFORT, sig=$SIG_ID, loop=$LOOP_N)" >&2
echo "[+] staged: $STAGED" >&2

stdbuf -oL -eL claude \
    -p \
    --model sonnet \
    --effort "$EFFORT" \
    --output-format stream-json \
    --verbose \
    --allowedTools "Read Bash" \
    --append-system-prompt "$SYS_PROMPT" \
    --add-dir "$STAGED" \
    --add-dir "$KNOWLEDGE_DIR" \
    <<< "$USER_PROMPT" \
    | tee "${OUT}.transcript.jsonl" >/dev/null

# Extract final assistant text
/workspace/soc-agent/.venv/bin/python3 - "${OUT}.transcript.jsonl" "${OUT}.output.md" <<'PY'
import json, sys
tr, out = sys.argv[1], sys.argv[2]
pieces = []
with open(tr) as f:
    for line in f:
        try: ev = json.loads(line)
        except: continue
        m = ev.get('message', {})
        if m.get('role') == 'assistant':
            for block in (m.get('content') or []):
                if block.get('type') == 'text':
                    pieces.append(block.get('text', ''))
with open(out, 'w') as f:
    f.write('\n\n'.join(pieces))
print(f'[+] wrote {out}')
PY
