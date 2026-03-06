#!/usr/bin/env bash
# test-hooks.sh - Test hook scripts I/O contracts
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PLUGIN_DIR="$SCRIPT_DIR/.."

PASS=0
FAIL=0
ERRORS=""

assert_ok() {
  local name="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    PASS=$((PASS+1))
  else
    FAIL=$((FAIL+1))
    ERRORS="$ERRORS\nFAIL: $name"
  fi
}

assert_json_field() {
  local name="$1" output="$2" field="$3" expected="$4"
  local actual
  actual=$(echo "$output" | jq -r ".$field")
  if [ "$actual" = "$expected" ]; then
    PASS=$((PASS+1))
  else
    FAIL=$((FAIL+1))
    ERRORS="$ERRORS\nFAIL: $name - expected $field='$expected', got '$actual'"
  fi
}

echo "=== Hook I/O Tests ==="

# Test 1: Confidence scorer produces valid JSON
output=$(echo '{"agent_confidence":"high","matched_tier":"gold","has_precedent":true}' | "$PLUGIN_DIR/hooks/scripts/confidence-scorer.sh")
assert_json_field "scorer_valid_json" "$output" "confidence_score" "0.95"
assert_json_field "scorer_has_decision" "$output" "decision" "auto_close"

# Test 2: Confidence scorer handles empty input
output=$(echo '{}' | "$PLUGIN_DIR/hooks/scripts/confidence-scorer.sh")
assert_json_field "scorer_empty_input" "$output" "confidence_score" "0.15"

# Test 3: Decision router produces valid JSON
output=$(echo '{"scorer_output":{"confidence_score":0.95,"decision":"auto_close"},"alert_data":{},"recommendation":"benign"}' | "$PLUGIN_DIR/hooks/scripts/decision-router.sh")
assert_json_field "router_valid_json" "$output" "action" "auto_close"
assert_json_field "router_has_disposition" "$output" "disposition" "benign"

# Test 4: Audit logger creates file
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT
echo '{"event":"test","ticket_id":"TEST-001"}' | SOC_AGENT_AUDIT_DIR="$TMPDIR" "$PLUGIN_DIR/hooks/scripts/audit-logger.sh"
if [ -f "$TMPDIR/audit.jsonl" ]; then
  # Validate it's valid JSONL
  if jq empty "$TMPDIR/audit.jsonl" 2>/dev/null; then
    PASS=$((PASS+1))
  else
    FAIL=$((FAIL+1))
    ERRORS="$ERRORS\nFAIL: audit_logger_valid_jsonl"
  fi
else
  FAIL=$((FAIL+1))
  ERRORS="$ERRORS\nFAIL: audit_logger_creates_file"
fi

# Test 5: Audit logger appends (not overwrites)
echo '{"event":"test2","ticket_id":"TEST-002"}' | SOC_AGENT_AUDIT_DIR="$TMPDIR" "$PLUGIN_DIR/hooks/scripts/audit-logger.sh"
line_count=$(wc -l < "$TMPDIR/audit.jsonl")
if [ "$line_count" -eq 2 ]; then
  PASS=$((PASS+1))
else
  FAIL=$((FAIL+1))
  ERRORS="$ERRORS\nFAIL: audit_logger_appends - expected 2 lines, got $line_count"
fi

# Test 6: hooks.json is valid JSON
if jq empty "$PLUGIN_DIR/hooks/hooks.json" 2>/dev/null; then
  PASS=$((PASS+1))
else
  FAIL=$((FAIL+1))
  ERRORS="$ERRORS\nFAIL: hooks_json_valid"
fi

echo ""
echo "=== Results ==="
echo "PASS: $PASS"
echo "FAIL: $FAIL"
if [ -n "$ERRORS" ]; then
  echo -e "$ERRORS"
fi
echo ""
if [ $FAIL -eq 0 ]; then
  echo "All tests passed!"
  exit 0
else
  echo "Some tests failed!"
  exit 1
fi
