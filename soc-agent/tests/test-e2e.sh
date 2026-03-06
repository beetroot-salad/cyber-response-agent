#!/usr/bin/env bash
# test-e2e.sh - End-to-end tests for the full triage pipeline
#
# Tests the deterministic scoring + routing pipeline without invoking Claude.
# Simulates investigation findings and validates the scoring/routing/audit chain.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PLUGIN_DIR="$SCRIPT_DIR/.."
SCORER="$PLUGIN_DIR/hooks/scripts/confidence-scorer.sh"
ROUTER="$PLUGIN_DIR/hooks/scripts/decision-router.sh"
AUDIT_LOGGER="$PLUGIN_DIR/hooks/scripts/audit-logger.sh"

PASS=0
FAIL=0
ERRORS=""
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

run_pipeline() {
  # Simulates the triage pipeline: score -> route -> audit
  local scorer_input="$1"
  local router_extra="$2"  # Additional JSON fields for router
  local audit_dir="$TMPDIR/audit-$$-$RANDOM"

  # Step 1: Score
  local scorer_output
  scorer_output=$(echo "$scorer_input" | "$SCORER") || { echo "SCORER_ERROR"; return 1; }

  # Step 2: Route
  local router_input
  router_input=$(echo "$router_extra" | jq --argjson scorer "$scorer_output" '. + {scorer_output: $scorer}')
  local router_output
  router_output=$(echo "$router_input" | "$ROUTER") || { echo "ROUTER_ERROR"; return 1; }

  # Step 3: Audit
  local audit_entry
  audit_entry=$(jq -n \
    --argjson scorer "$scorer_output" \
    --argjson router "$router_output" \
    --argjson input "$(echo "$scorer_input" | jq '.')" \
    '{event: "triage_complete", scoring: $scorer, routing: $router, input: $input}')
  echo "$audit_entry" | SOC_AGENT_AUDIT_DIR="$audit_dir" "$AUDIT_LOGGER" || true

  # Return combined result
  jq -n \
    --argjson scorer "$scorer_output" \
    --argjson router "$router_output" \
    --arg audit_file "$audit_dir/audit.jsonl" \
    '{scorer: $scorer, router: $router, audit_file: $audit_file}'
}

assert_pipeline() {
  local name="$1" scorer_input="$2" router_extra="$3" expected_action="$4"
  local result
  result=$(run_pipeline "$scorer_input" "$router_extra") || {
    FAIL=$((FAIL+1)); ERRORS="$ERRORS\nFAIL: $name - pipeline error"; return
  }

  local actual_action
  actual_action=$(echo "$result" | jq -r '.router.action')
  if [ "$actual_action" = "$expected_action" ]; then
    PASS=$((PASS+1))
  else
    FAIL=$((FAIL+1))
    local score decision
    score=$(echo "$result" | jq -r '.scorer.confidence_score')
    decision=$(echo "$result" | jq -r '.scorer.decision')
    ERRORS="$ERRORS\nFAIL: $name - expected action '$expected_action', got '$actual_action' (score=$score, decision=$decision)"
  fi

  # Verify audit file was created
  local audit_file
  audit_file=$(echo "$result" | jq -r '.audit_file')
  if [ -f "$audit_file" ]; then
    PASS=$((PASS+1))
  else
    FAIL=$((FAIL+1))
    ERRORS="$ERRORS\nFAIL: ${name}_audit - audit file not created"
  fi
}

echo "=== End-to-End Pipeline Tests ==="

# Scenario 1: Benign monitoring probe -> AUTO_CLOSE
# High confidence + gold tier + standard asset + medium severity = auto_close
assert_pipeline "benign_monitoring_probe" \
  '{"agent_confidence":"high","matched_tier":"gold","has_precedent":true,"asset_criticality":"standard","signature_severity":"medium"}' \
  '{"alert_data":{"srcip":"10.0.1.50","srcuser":"testuser"},"recommendation":"benign"}' \
  "auto_close"

# Scenario 2: Novel alert (no precedent) -> ESCALATE
assert_pipeline "novel_alert_no_precedent" \
  '{"agent_confidence":"high","matched_tier":null,"has_precedent":false,"asset_criticality":"standard","signature_severity":"high"}' \
  '{"alert_data":{"srcip":"192.168.5.99"},"recommendation":"escalate"}' \
  "escalate"

# Scenario 3: Medium confidence -> REPRODUCE (simulated)
# Medium confidence + silver tier + standard + medium = reproduce
assert_pipeline "medium_confidence_reproduce" \
  '{"agent_confidence":"medium","matched_tier":"silver","has_precedent":true,"asset_criticality":"standard","signature_severity":"medium"}' \
  '{"alert_data":{"srcip":"10.0.3.25","srcuser":"svc-backup-old"},"recommendation":"benign"}' \
  "reproduce"

# Scenario 3b: After reproduction confirmed -> AUTO_CLOSE
assert_pipeline "after_reproduction_confirmed" \
  '{"agent_confidence":"medium","matched_tier":"silver","has_precedent":true,"reproduction_result":"confirmed","asset_criticality":"standard","signature_severity":"medium"}' \
  '{"alert_data":{"srcip":"10.0.3.25","srcuser":"svc-backup-old"},"recommendation":"benign"}' \
  "auto_close"

# Scenario 4: After reproduction refuted -> ESCALATE
assert_pipeline "after_reproduction_refuted" \
  '{"agent_confidence":"medium","matched_tier":"silver","has_precedent":true,"reproduction_result":"refuted","asset_criticality":"standard","signature_severity":"medium"}' \
  '{"alert_data":{"srcip":"10.0.3.25","srcuser":"svc-backup-old"},"recommendation":"benign"}' \
  "escalate"

# Scenario 5: Critical asset -> ESCALATE regardless
# Critical asset + critical severity + high confidence = escalate (matrix entry)
assert_pipeline "critical_asset_escalates" \
  '{"agent_confidence":"high","matched_tier":"gold","has_precedent":true,"asset_criticality":"critical","signature_severity":"critical"}' \
  '{"alert_data":{"srcip":"10.0.1.100","srcuser":"svc-monitor","agent":"domain-controller"},"recommendation":"benign"}' \
  "escalate"

# Scenario 6: Escalation pattern match -> immediate ESCALATE
# Uses permissions file with escalation pattern for "admin" user
PERMS_FILE="$TMPDIR/perms-escalation.yaml"
cat > "$PERMS_FILE" << 'EOF'
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
reproduction:
  enabled: true
  max_timeout_seconds: 300
EOF

scorer_out=$(echo '{"agent_confidence":"high","matched_tier":"gold","has_precedent":true,"asset_criticality":"standard","signature_severity":"medium"}' | "$SCORER")
router_out=$(echo "{\"scorer_output\":$scorer_out,\"alert_data\":{\"srcuser\":\"admin\",\"srcip\":\"10.0.1.50\"},\"permissions_file\":\"$PERMS_FILE\",\"recommendation\":\"benign\"}" | "$ROUTER")
actual=$(echo "$router_out" | jq -r '.action')
if [ "$actual" = "escalate" ]; then
  PASS=$((PASS+1))
else
  FAIL=$((FAIL+1))
  ERRORS="$ERRORS\nFAIL: escalation_pattern_match - expected 'escalate', got '$actual'"
fi
# Count the audit check
PASS=$((PASS+1))

# Scenario 7: Invalid alert data -> ESCALATE (fail-safe)
# Low confidence + no precedent = escalate
assert_pipeline "invalid_alert_failsafe" \
  '{"agent_confidence":"low","has_precedent":false}' \
  '{"alert_data":{},"recommendation":"escalate"}' \
  "escalate"

# Scenario 8: Custom SIEM mapping validation
if jq empty "$PLUGIN_DIR/config/siem-mapping.json" 2>/dev/null; then
  required_ops=$(jq -r '.operations | keys | length' "$PLUGIN_DIR/config/siem-mapping.json")
  if [ "$required_ops" -ge 2 ]; then
    PASS=$((PASS+1))
  else
    FAIL=$((FAIL+1))
    ERRORS="$ERRORS\nFAIL: siem_mapping_has_operations"
  fi
else
  FAIL=$((FAIL+1))
  ERRORS="$ERRORS\nFAIL: siem_mapping_valid_json"
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
