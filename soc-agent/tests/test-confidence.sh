#!/usr/bin/env bash
# test-confidence.sh - Port of all 25 Python test cases for confidence scoring + decision matrix
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SCORER="$SCRIPT_DIR/../hooks/scripts/confidence-scorer.sh"
FIXTURES="$SCRIPT_DIR/fixtures/confidence"

PASS=0
FAIL=0
ERRORS=""

assert_score() {
  local name="$1" input="$2" expected_score="$3"
  local output
  output=$(echo "$input" | "$SCORER" 2>&1) || { FAIL=$((FAIL+1)); ERRORS="$ERRORS\nFAIL: $name - script error: $output"; return; }
  local actual_score
  actual_score=$(echo "$output" | jq -r '.confidence_score')
  if [ "$(echo "scale=2; $actual_score == $expected_score" | bc -l)" = "1" ]; then
    PASS=$((PASS+1))
  else
    FAIL=$((FAIL+1))
    ERRORS="$ERRORS\nFAIL: $name - expected score $expected_score, got $actual_score"
  fi
}

assert_decision() {
  local name="$1" input="$2" expected_decision="$3"
  local output
  output=$(echo "$input" | "$SCORER" 2>&1) || { FAIL=$((FAIL+1)); ERRORS="$ERRORS\nFAIL: $name - script error: $output"; return; }
  local actual_decision
  actual_decision=$(echo "$output" | jq -r '.decision')
  if [ "$actual_decision" = "$expected_decision" ]; then
    PASS=$((PASS+1))
  else
    FAIL=$((FAIL+1))
    ERRORS="$ERRORS\nFAIL: $name - expected decision '$expected_decision', got '$actual_decision'"
  fi
}

assert_score_gte() {
  local name="$1" input="$2" min_score="$3"
  local output
  output=$(echo "$input" | "$SCORER" 2>&1) || { FAIL=$((FAIL+1)); ERRORS="$ERRORS\nFAIL: $name - script error: $output"; return; }
  local actual_score
  actual_score=$(echo "$output" | jq -r '.confidence_score')
  if [ "$(echo "$actual_score >= $min_score" | bc -l)" = "1" ]; then
    PASS=$((PASS+1))
  else
    FAIL=$((FAIL+1))
    ERRORS="$ERRORS\nFAIL: $name - expected score >= $min_score, got $actual_score"
  fi
}

echo "=== Confidence Score Tests ==="

# Test 1: High agent confidence (0.85 - 0.15 no tier = 0.70)
assert_score "high_agent_confidence" \
  '{"agent_confidence":"high"}' "0.70"

# Test 2: Medium agent confidence (0.60 - 0.15 = 0.45)
assert_score "medium_agent_confidence" \
  '{"agent_confidence":"medium"}' "0.45"

# Test 3: Low agent confidence (0.30 - 0.15 = 0.15)
assert_score "low_agent_confidence" \
  '{"agent_confidence":"low"}' "0.15"

# Test 4: High confidence + gold tier (0.85 + 0.10 = 0.95)
assert_score "high_confidence_gold_tier" \
  '{"agent_confidence":"high","matched_tier":"gold"}' "0.95"

# Test 5: Medium confidence + silver tier (0.60 + 0.05 = 0.65)
assert_score "medium_confidence_silver_tier" \
  '{"agent_confidence":"medium","matched_tier":"silver"}' "0.65"

# Test 6: Reproduction confirmed (0.60 + 0.05 + 0.15 = 0.80)
assert_score "reproduction_confirmed" \
  '{"agent_confidence":"medium","matched_tier":"silver","reproduction_result":"confirmed"}' "0.80"

# Test 7: Reproduction refuted (0.85 + 0.10 - 0.30 = 0.65)
assert_score "reproduction_refuted" \
  '{"agent_confidence":"high","matched_tier":"gold","reproduction_result":"refuted"}' "0.65"

# Test 8: Critical asset penalty (0.85 + 0.10 - 0.15 = 0.80)
assert_score "critical_asset_penalty" \
  '{"agent_confidence":"high","matched_tier":"gold","asset_criticality":"critical"}' "0.80"

# Test 9: Clamp to 1.0 (0.85 + 0.10 + 0.15 = 1.10 -> 1.0)
assert_score "clamp_to_max" \
  '{"agent_confidence":"high","matched_tier":"gold","reproduction_result":"confirmed"}' "1.00"

# Test 10: Clamp to >= 0.0 (0.30 - 0.15 - 0.30 - 0.15 = -0.30 -> 0.0)
assert_score_gte "clamp_to_min" \
  '{"agent_confidence":"low","matched_tier":null,"reproduction_result":"refuted","asset_criticality":"critical"}' "0.00"

# Test 11: Defaults (low=0.30, no tier=-0.15 = 0.15)
assert_score "defaults" \
  '{}' "0.15"

# Test 12: Invalid confidence defaults to low
assert_score "invalid_confidence_defaults_to_low" \
  '{"agent_confidence":"invalid"}' "0.15"

echo ""
echo "=== Decision Matrix Tests ==="

# Test 13: No precedent always escalate (high)
assert_decision "no_precedent_high" \
  '{"agent_confidence":"high","has_precedent":false}' "escalate"

# Test 14: No precedent always escalate (medium)
assert_decision "no_precedent_medium" \
  '{"agent_confidence":"medium","has_precedent":false}' "escalate"

# Test 15: No precedent always escalate (low)
assert_decision "no_precedent_low" \
  '{"agent_confidence":"low","has_precedent":false}' "escalate"

# Test 16: Reproduction refuted escalates
assert_decision "reproduction_refuted_escalates" \
  '{"agent_confidence":"high","has_precedent":true,"reproduction_result":"refuted"}' "escalate"

# Test 17: Reproduction confirmed + high -> auto_close
assert_decision "reproduction_confirmed_high" \
  '{"agent_confidence":"high","has_precedent":true,"reproduction_result":"confirmed"}' "auto_close"

# Test 18: Reproduction confirmed + medium -> auto_close
assert_decision "reproduction_confirmed_medium" \
  '{"agent_confidence":"medium","has_precedent":true,"reproduction_result":"confirmed"}' "auto_close"

# Test 19: Standard + high confidence + medium severity -> auto_close
assert_decision "standard_high_confidence_medium" \
  '{"agent_confidence":"high","has_precedent":true,"asset_criticality":"standard","signature_severity":"medium"}' "auto_close"

# Test 20: Standard + medium confidence + medium severity -> reproduce
assert_decision "standard_medium_confidence_medium" \
  '{"agent_confidence":"medium","has_precedent":true,"asset_criticality":"standard","signature_severity":"medium"}' "reproduce"

# Test 21: Standard + low confidence + medium severity -> escalate (fallback)
assert_decision "standard_low_confidence_medium" \
  '{"agent_confidence":"low","has_precedent":true,"asset_criticality":"standard","signature_severity":"medium"}' "escalate"

# Test 22: Critical asset + high confidence + high severity -> escalate
assert_decision "critical_asset_escalates" \
  '{"agent_confidence":"high","has_precedent":true,"asset_criticality":"critical","signature_severity":"high"}' "escalate"

# Test 23: Critical severity + medium confidence -> escalate (fallback)
assert_decision "critical_severity_medium_confidence" \
  '{"agent_confidence":"medium","has_precedent":true,"asset_criticality":"standard","signature_severity":"critical"}' "escalate"

# Test 24: Missing severity defaults to medium (high conf + standard = auto_close)
assert_decision "defaults_to_medium_severity" \
  '{"agent_confidence":"high","has_precedent":true,"asset_criticality":"standard","signature_severity":null}' "auto_close"

# Test 25: Missing criticality defaults to standard (high conf + medium = auto_close)
assert_decision "defaults_to_standard_criticality" \
  '{"agent_confidence":"high","has_precedent":true,"asset_criticality":null,"signature_severity":"medium"}' "auto_close"

# Test 26: Low severity + medium confidence on standard -> auto_close
assert_decision "low_severity_medium_confidence" \
  '{"agent_confidence":"medium","has_precedent":true,"asset_criticality":"standard","signature_severity":"low"}' "auto_close"

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
