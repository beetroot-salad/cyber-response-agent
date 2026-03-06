#!/usr/bin/env bash
# post-mortem.sh - Extract lessons and update knowledge base after investigation
#
# Reads investigation summary JSON on stdin.
# Updates knowledge/signatures/{id}/lessons.md with new observations.

set -euo pipefail

PLUGIN_DIR="${SOC_AGENT_PLUGIN_DIR:-$(cd "$(dirname "$0")/../.." && pwd)}"

INPUT=$(cat)

signature_id=$(echo "$INPUT" | jq -r '.signature_id // ""')
ticket_id=$(echo "$INPUT" | jq -r '.ticket_id // ""')
disposition=$(echo "$INPUT" | jq -r '.disposition // ""')
report_body=$(echo "$INPUT" | jq -r '.report_body // ""')

if [ -z "$signature_id" ] || [ -z "$ticket_id" ]; then
  exit 0
fi

LESSONS_FILE="$PLUGIN_DIR/knowledge/signatures/$signature_id/lessons.md"

if [ ! -f "$LESSONS_FILE" ]; then
  exit 0
fi

# Extract key evidence for lesson
evidence=$(echo "$INPUT" | jq -r '.evidence // {} | to_entries[] | "  - \(.key): \(.value)"' 2>/dev/null || true)

if [ -z "$evidence" ] && [ -z "$report_body" ]; then
  exit 0
fi

# Check for duplicate (same ticket_id already referenced)
if grep -q "@${ticket_id}" "$LESSONS_FILE" 2>/dev/null; then
  exit 0
fi

# Append observation to Patterns Observed section
pattern_line="**${disposition}**: $(echo "$INPUT" | jq -r '.recommendation // "unknown"') - $(echo "$evidence" | head -1 | sed 's/^  - //') @${ticket_id}"

# Insert before the Environment-Specific Notes section
if grep -q "## Patterns Observed" "$LESSONS_FILE"; then
  # Find the placeholder line and add after it, or add before next section
  sed -i "/## Patterns Observed/,/## /{
    /^\*\*(No patterns/a\\
- ${pattern_line}
  }" "$LESSONS_FILE" 2>/dev/null || true
fi
