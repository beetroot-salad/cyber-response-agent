#!/usr/bin/env bash
# test-siem-mapping.sh - Validate SIEM mapping files against schema
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PLUGIN_DIR="$SCRIPT_DIR/.."

PASS=0
FAIL=0
ERRORS=""

assert_valid_mapping() {
  local name="$1" file="$2"
  if [ ! -f "$file" ]; then
    FAIL=$((FAIL+1))
    ERRORS="$ERRORS\nFAIL: $name - file not found: $file"
    return
  fi

  # Check valid JSON
  if ! jq empty "$file" 2>/dev/null; then
    FAIL=$((FAIL+1))
    ERRORS="$ERRORS\nFAIL: $name - invalid JSON"
    return
  fi

  # Check required top-level fields
  local siem_name
  siem_name=$(jq -r '.siem_name // ""' "$file")
  if [ -z "$siem_name" ]; then
    FAIL=$((FAIL+1))
    ERRORS="$ERRORS\nFAIL: $name - missing siem_name"
    return
  fi

  # Check required operations
  local has_search has_agent
  has_search=$(jq -r '.operations.search_events.tool // ""' "$file")
  has_agent=$(jq -r '.operations.get_agent_info.tool // ""' "$file")

  if [ -z "$has_search" ]; then
    FAIL=$((FAIL+1))
    ERRORS="$ERRORS\nFAIL: $name - missing required operation: search_events"
    return
  fi

  if [ -z "$has_agent" ]; then
    FAIL=$((FAIL+1))
    ERRORS="$ERRORS\nFAIL: $name - missing required operation: get_agent_info"
    return
  fi

  # Check each operation has required fields
  local ops
  ops=$(jq -r '.operations | keys[]' "$file")
  for op in $ops; do
    local tool desc
    tool=$(jq -r ".operations[\"$op\"].tool // \"\"" "$file")
    desc=$(jq -r ".operations[\"$op\"].description // \"\"" "$file")
    if [ -z "$tool" ]; then
      FAIL=$((FAIL+1))
      ERRORS="$ERRORS\nFAIL: $name - operation '$op' missing 'tool'"
      return
    fi
    if [ -z "$desc" ]; then
      FAIL=$((FAIL+1))
      ERRORS="$ERRORS\nFAIL: $name - operation '$op' missing 'description'"
      return
    fi
  done

  PASS=$((PASS+1))
}

assert_invalid_mapping() {
  local name="$1" json="$2" expected_error="$3"
  # Check that required fields trigger validation failure
  local siem_name
  siem_name=$(echo "$json" | jq -r '.siem_name // ""')
  local has_search
  has_search=$(echo "$json" | jq -r '.operations.search_events.tool // ""')
  local has_agent
  has_agent=$(echo "$json" | jq -r '.operations.get_agent_info.tool // ""')

  if [ -z "$siem_name" ] || [ -z "$has_search" ] || [ -z "$has_agent" ]; then
    PASS=$((PASS+1))
  else
    FAIL=$((FAIL+1))
    ERRORS="$ERRORS\nFAIL: $name - expected validation failure for: $expected_error"
  fi
}

echo "=== SIEM Mapping Validation Tests ==="

# Test 1: Default Wazuh mapping validates
assert_valid_mapping "wazuh_default" "$PLUGIN_DIR/config/siem-mapping.json"

# Test 2: Splunk example validates
assert_valid_mapping "splunk_example" "$PLUGIN_DIR/config/examples/splunk-mapping.json"

# Test 3: Missing siem_name caught
assert_invalid_mapping "missing_siem_name" \
  '{"operations":{"search_events":{"tool":"x","description":"x","param_mapping":{}},"get_agent_info":{"tool":"x","description":"x","param_mapping":{}}}}' \
  "missing siem_name"

# Test 4: Missing search_events caught
assert_invalid_mapping "missing_search_events" \
  '{"siem_name":"test","operations":{"get_agent_info":{"tool":"x","description":"x","param_mapping":{}}}}' \
  "missing search_events"

# Test 5: Missing get_agent_info caught
assert_invalid_mapping "missing_get_agent_info" \
  '{"siem_name":"test","operations":{"search_events":{"tool":"x","description":"x","param_mapping":{}}}}' \
  "missing get_agent_info"

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
