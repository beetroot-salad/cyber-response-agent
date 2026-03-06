#!/usr/bin/env bash
# audit-logger.sh - Append JSONL audit entries
#
# Reads JSON event on stdin, appends to audit log with timestamp.
# Audit dir: $SOC_AGENT_AUDIT_DIR (default: ./runs/audit)

set -euo pipefail

AUDIT_DIR="${SOC_AGENT_AUDIT_DIR:-./runs/audit}"
mkdir -p "$AUDIT_DIR"

AUDIT_FILE="$AUDIT_DIR/audit.jsonl"

INPUT=$(cat)

# Add timestamp and write as single JSONL line
echo "$INPUT" | jq -c '. + {audit_timestamp: (now | todate)}' >> "$AUDIT_FILE"
