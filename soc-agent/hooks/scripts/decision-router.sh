#!/usr/bin/env bash
# decision-router.sh - Routing with escalation pattern matching and permission checks
#
# Reads JSON on stdin with fields:
#   scorer_output: {confidence_score, decision} from confidence-scorer.sh
#   alert_data: original alert data (srcip, srcuser, agent, etc.)
#   signature_id: signature identifier
#   permissions_file: path to permissions.yaml (optional)
#   recommendation: agent recommendation (benign, false_positive, true_positive, escalate)
#
# Outputs JSON:
#   {"action": "auto_close"|"reproduce"|"escalate",
#    "disposition": "benign"|"false_positive"|"true_positive"|"escalated"|"inconclusive",
#    "reason": "human-readable reason"}

set -euo pipefail

INPUT=$(cat)

# Extract nested fields
decision=$(echo "$INPUT" | jq -r '.scorer_output.decision // "escalate"')
confidence_score=$(echo "$INPUT" | jq -r '.scorer_output.confidence_score // 0')
alert_data=$(echo "$INPUT" | jq -r '.alert_data // {}')
signature_id=$(echo "$INPUT" | jq -r '.signature_id // ""')
permissions_file=$(echo "$INPUT" | jq -r '.permissions_file // ""')
recommendation=$(echo "$INPUT" | jq -r '.recommendation // "escalate"')

action="$decision"
reason=""
disposition=""

# ─── Permission Checks ───

if [ -n "$permissions_file" ] && [ -f "$permissions_file" ]; then
  # Parse YAML permissions (using grep/sed since yq may not be available)
  parse_yaml_value() {
    local file="$1" key="$2"
    grep -E "^[[:space:]]*${key}:" "$file" 2>/dev/null | head -1 | sed 's/.*:[[:space:]]*//' | tr -d '"' | tr -d "'"
  }

  parse_yaml_bool() {
    local file="$1" key="$2"
    local val
    val=$(parse_yaml_value "$file" "$key")
    case "$val" in
      true|True|TRUE|yes|Yes) echo "true" ;;
      *) echo "false" ;;
    esac
  }

  parse_yaml_list() {
    local file="$1" section="$2"
    # Extract list items under a section (indented with - )
    sed -n "/^${section}:/,/^[^ ]/p" "$file" 2>/dev/null | grep -E '^\s+-\s' | sed 's/.*-[[:space:]]*//' | tr -d '"' | tr -d "'"
  }

  parse_yaml_map_lists() {
    # Extract map of field -> [patterns] from escalation_patterns section
    # Returns field|pattern pairs
    local file="$1"
    local in_section=false
    local current_field=""
    while IFS= read -r line; do
      if echo "$line" | grep -qE '^escalation_patterns:'; then
        in_section=true
        continue
      fi
      if [ "$in_section" = "true" ]; then
        # Stop at next top-level key
        if echo "$line" | grep -qE '^[a-z]'; then
          break
        fi
        # Field name (indented, no dash)
        if echo "$line" | grep -qE '^[[:space:]]+[a-z].*:$'; then
          current_field=$(echo "$line" | sed 's/[[:space:]]*\([a-z_]*\):.*/\1/')
        elif echo "$line" | grep -qE '^[[:space:]]+[a-z].*:\s*$'; then
          current_field=$(echo "$line" | sed 's/[[:space:]]*\([a-z_]*\):.*/\1/')
        # Pattern (indented with dash)
        elif echo "$line" | grep -qE '^\s+-\s' && [ -n "$current_field" ]; then
          local pattern
          pattern=$(echo "$line" | sed 's/.*-[[:space:]]*//' | tr -d '"' | tr -d "'")
          echo "${current_field}|${pattern}"
        fi
      fi
    done < "$file"
  }

  # Check escalation patterns first (override everything)
  escalation_match=""
  while IFS='|' read -r field pattern; do
    if [ -z "$field" ] || [ -z "$pattern" ]; then continue; fi
    # Get the alert field value
    field_value=$(echo "$alert_data" | jq -r ".${field} // \"\"")
    if [ -n "$field_value" ] && echo "$field_value" | grep -qE "$pattern"; then
      escalation_match="field '${field}' value '${field_value}' matches escalation pattern '${pattern}'"
      break
    fi
  done < <(parse_yaml_map_lists "$permissions_file")

  if [ -n "$escalation_match" ]; then
    action="escalate"
    reason="Escalation pattern matched: $escalation_match"
    disposition="escalated"
  fi

  # Check auto_close.enabled
  if [ "$action" = "auto_close" ] && [ -z "$reason" ]; then
    auto_close_enabled=$(parse_yaml_bool "$permissions_file" "enabled")
    # Need to check under auto_close section specifically
    auto_close_enabled=$(sed -n '/^auto_close:/,/^[a-z]/p' "$permissions_file" 2>/dev/null | parse_yaml_bool /dev/stdin "enabled")
    if [ "$auto_close_enabled" = "false" ]; then
      action="escalate"
      reason="Auto-close disabled for signature $signature_id"
      disposition="escalated"
    fi
  fi

  # Check reproduction.enabled for REPRODUCE decisions
  if [ "$action" = "reproduce" ] && [ -z "$reason" ]; then
    repro_enabled=$(sed -n '/^reproduction:/,/^[a-z]/p' "$permissions_file" 2>/dev/null | parse_yaml_bool /dev/stdin "enabled")
    if [ "$repro_enabled" = "false" ]; then
      action="escalate"
      reason="Reproduction disabled for signature $signature_id"
      disposition="escalated"
    fi
  fi
fi

# ─── Determine Disposition ───

if [ -z "$disposition" ]; then
  case "$action" in
    escalate)
      disposition="escalated"
      ;;
    reproduce)
      disposition="inconclusive"
      ;;
    auto_close)
      # Use agent's recommendation for disposition
      case "$recommendation" in
        true_positive)  disposition="true_positive" ;;
        false_positive) disposition="false_positive" ;;
        benign)         disposition="benign" ;;
        *)              disposition="benign" ;;
      esac
      ;;
  esac
fi

# ─── Determine Reason ───

if [ -z "$reason" ]; then
  case "$action" in
    auto_close)  reason="Confidence score ${confidence_score}, decision: auto-close (disposition: ${disposition})" ;;
    reproduce)   reason="Confidence score ${confidence_score}, decision: reproduce for validation" ;;
    escalate)    reason="Confidence score ${confidence_score}, decision: escalate to human analyst" ;;
  esac
fi

# Output JSON
jq -n \
  --arg action "$action" \
  --arg disposition "$disposition" \
  --arg reason "$reason" \
  --arg confidence_score "$confidence_score" \
  '{action: $action, disposition: $disposition, reason: $reason, confidence_score: ($confidence_score | tonumber)}'
