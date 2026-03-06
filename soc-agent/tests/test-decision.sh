#!/usr/bin/env bash
# test-decision.sh - Tests for decision router: escalation patterns, permission toggles
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROUTER="$SCRIPT_DIR/../hooks/scripts/decision-router.sh"
FIXTURES="$SCRIPT_DIR/fixtures/decision"

PASS=0
FAIL=0
ERRORS=""

assert_action() {
  local name="$1" input="$2" expected_action="$3"
  local output
  output=$(echo "$input" | "$ROUTER" 2>&1) || { FAIL=$((FAIL+1)); ERRORS="$ERRORS\nFAIL: $name - script error: $output"; return; }
  local actual_action
  actual_action=$(echo "$output" | jq -r '.action')
  if [ "$actual_action" = "$expected_action" ]; then
    PASS=$((PASS+1))
  else
    FAIL=$((FAIL+1))
    ERRORS="$ERRORS\nFAIL: $name - expected action '$expected_action', got '$actual_action' (full: $output)"
  fi
}

assert_disposition() {
  local name="$1" input="$2" expected_disp="$3"
  local output
  output=$(echo "$input" | "$ROUTER" 2>&1) || { FAIL=$((FAIL+1)); ERRORS="$ERRORS\nFAIL: $name - script error: $output"; return; }
  local actual_disp
  actual_disp=$(echo "$output" | jq -r '.disposition')
  if [ "$actual_disp" = "$expected_disp" ]; then
    PASS=$((PASS+1))
  else
    FAIL=$((FAIL+1))
    ERRORS="$ERRORS\nFAIL: $name - expected disposition '$expected_disp', got '$actual_disp'"
  fi
}

echo "=== Decision Router Tests ==="

# Create temp permissions files for testing
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

# Permissions with escalation patterns
cat > "$TMPDIR/perms-with-escalation.yaml" << 'EOF'
schema_version: "1.0"
allowed_dispositions:
  - benign
  - false_positive
auto_close:
  enabled: true
escalation_patterns:
  srcuser:
    - "^admin$"
    - "^root$"
  srcip:
    - "^203\."
reproduction:
  enabled: true
  max_timeout_seconds: 300
EOF

# Permissions with auto_close disabled
cat > "$TMPDIR/perms-no-autoclose.yaml" << 'EOF'
schema_version: "1.0"
allowed_dispositions:
  - benign
auto_close:
  enabled: false
escalation_patterns: {}
reproduction:
  enabled: true
  max_timeout_seconds: 300
EOF

# Permissions with reproduction disabled
cat > "$TMPDIR/perms-no-repro.yaml" << 'EOF'
schema_version: "1.0"
allowed_dispositions:
  - benign
auto_close:
  enabled: true
escalation_patterns: {}
reproduction:
  enabled: false
  max_timeout_seconds: 300
EOF

# Test 1: Basic auto_close passthrough (no permissions file)
assert_action "basic_auto_close" \
  '{"scorer_output":{"confidence_score":0.95,"decision":"auto_close"},"alert_data":{},"recommendation":"benign"}' \
  "auto_close"

# Test 2: Basic escalate passthrough
assert_action "basic_escalate" \
  '{"scorer_output":{"confidence_score":0.15,"decision":"escalate"},"alert_data":{},"recommendation":"escalate"}' \
  "escalate"

# Test 3: Basic reproduce passthrough
assert_action "basic_reproduce" \
  '{"scorer_output":{"confidence_score":0.65,"decision":"reproduce"},"alert_data":{},"recommendation":"benign"}' \
  "reproduce"

# Test 4: Escalation pattern match on srcuser
assert_action "escalation_pattern_srcuser" \
  "{\"scorer_output\":{\"confidence_score\":0.95,\"decision\":\"auto_close\"},\"alert_data\":{\"srcuser\":\"admin\"},\"permissions_file\":\"$TMPDIR/perms-with-escalation.yaml\",\"recommendation\":\"benign\"}" \
  "escalate"

# Test 5: Escalation pattern match on srcip
assert_action "escalation_pattern_srcip" \
  "{\"scorer_output\":{\"confidence_score\":0.95,\"decision\":\"auto_close\"},\"alert_data\":{\"srcip\":\"203.0.113.50\"},\"permissions_file\":\"$TMPDIR/perms-with-escalation.yaml\",\"recommendation\":\"benign\"}" \
  "escalate"

# Test 6: No escalation pattern match (internal IP, normal user)
assert_action "no_escalation_match" \
  "{\"scorer_output\":{\"confidence_score\":0.95,\"decision\":\"auto_close\"},\"alert_data\":{\"srcip\":\"10.0.1.50\",\"srcuser\":\"jsmith\"},\"permissions_file\":\"$TMPDIR/perms-with-escalation.yaml\",\"recommendation\":\"benign\"}" \
  "auto_close"

# Test 7: Auto-close disabled -> escalate
assert_action "autoclose_disabled" \
  "{\"scorer_output\":{\"confidence_score\":0.95,\"decision\":\"auto_close\"},\"alert_data\":{},\"permissions_file\":\"$TMPDIR/perms-no-autoclose.yaml\",\"recommendation\":\"benign\"}" \
  "escalate"

# Test 8: Reproduction disabled -> escalate on reproduce decision
assert_action "reproduction_disabled" \
  "{\"scorer_output\":{\"confidence_score\":0.65,\"decision\":\"reproduce\"},\"alert_data\":{},\"permissions_file\":\"$TMPDIR/perms-no-repro.yaml\",\"recommendation\":\"benign\"}" \
  "escalate"

# Test 9: Disposition for auto_close with benign recommendation
assert_disposition "disposition_benign" \
  '{"scorer_output":{"confidence_score":0.95,"decision":"auto_close"},"alert_data":{},"recommendation":"benign"}' \
  "benign"

# Test 10: Disposition for auto_close with false_positive recommendation
assert_disposition "disposition_false_positive" \
  '{"scorer_output":{"confidence_score":0.95,"decision":"auto_close"},"alert_data":{},"recommendation":"false_positive"}' \
  "false_positive"

# Test 11: Disposition for escalate
assert_disposition "disposition_escalated" \
  '{"scorer_output":{"confidence_score":0.15,"decision":"escalate"},"alert_data":{},"recommendation":"benign"}' \
  "escalated"

# Test 12: Disposition for reproduce
assert_disposition "disposition_inconclusive" \
  '{"scorer_output":{"confidence_score":0.65,"decision":"reproduce"},"alert_data":{},"recommendation":"benign"}' \
  "inconclusive"

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
