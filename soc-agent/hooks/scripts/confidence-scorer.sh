#!/usr/bin/env bash
# confidence-scorer.sh - Deterministic confidence scoring and decision routing
#
# Reads JSON on stdin with fields:
#   agent_confidence: "high"|"medium"|"low" (default: "low")
#   matched_tier: "gold"|"silver"|"bronze"|null (default: null -> -0.15)
#   reproduction_result: "confirmed"|"refuted"|null (default: null -> 0.0)
#   asset_criticality: "standard"|"elevated"|"critical" (default: "standard")
#   has_precedent: true|false (default: false)
#   signature_severity: "low"|"medium"|"high"|"critical" (default: "medium")
#
# Outputs JSON:
#   {"confidence_score": 0.85, "decision": "auto_close"|"reproduce"|"escalate"}

set -euo pipefail

# ─── Functions ───

normalize() {
  local val default allowed
  val=$(echo "$1" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')
  default="$2"
  allowed="$3"
  if echo " $allowed " | grep -q " $val "; then
    echo "$val"
  else
    echo "$default"
  fi
}

lookup_decision() {
  local c="$1" s="$2" conf="$3"
  case "${c}|${s}|${conf}" in
    # Critical assets - always escalate unless low severity
    "critical|critical|high")   echo "escalate" ;;
    "critical|critical|medium") echo "escalate" ;;
    "critical|critical|low")    echo "escalate" ;;
    "critical|high|high")       echo "escalate" ;;
    "critical|medium|high")     echo "reproduce" ;;
    "critical|low|high")        echo "reproduce" ;;
    # Elevated assets
    "elevated|critical|high")   echo "escalate" ;;
    "elevated|high|high")       echo "reproduce" ;;
    "elevated|medium|high")     echo "auto_close" ;;
    "elevated|medium|medium")   echo "reproduce" ;;
    "elevated|low|high")        echo "auto_close" ;;
    "elevated|low|medium")      echo "reproduce" ;;
    # Standard assets - most permissive
    "standard|critical|high")   echo "reproduce" ;;
    "standard|high|high")       echo "reproduce" ;;
    "standard|high|medium")     echo "escalate" ;;
    "standard|medium|high")     echo "auto_close" ;;
    "standard|medium|medium")   echo "reproduce" ;;
    "standard|low|high")        echo "auto_close" ;;
    "standard|low|medium")      echo "auto_close" ;;
    *)                          echo "" ;;
  esac
}

matrix_lookup_with_fallback() {
  local crit="$1" sev="$2" conf="$3"
  local severity_order="critical high medium low"
  local criticality_order="critical elevated standard"

  # Find starting indices
  local sev_start=0 idx=0
  for s in $severity_order; do
    if [ "$s" = "$sev" ]; then sev_start=$idx; break; fi
    idx=$((idx + 1))
  done

  local crit_start=0
  idx=0
  for c in $criticality_order; do
    if [ "$c" = "$crit" ]; then crit_start=$idx; break; fi
    idx=$((idx + 1))
  done

  # Hierarchical fallback
  local crit_idx=0 first_crit=true
  for c in $criticality_order; do
    if [ $crit_idx -lt $crit_start ]; then
      crit_idx=$((crit_idx + 1))
      continue
    fi

    local sev_idx=0
    for s in $severity_order; do
      if [ "$first_crit" = "true" ] && [ $sev_idx -lt $sev_start ]; then
        sev_idx=$((sev_idx + 1))
        continue
      fi

      local result
      result=$(lookup_decision "$c" "$s" "$conf")
      if [ -n "$result" ]; then
        echo "$result"
        return
      fi
      sev_idx=$((sev_idx + 1))
    done

    first_crit=false
    crit_idx=$((crit_idx + 1))
  done

  echo "escalate"
}

# ─── Main ───

INPUT=$(cat)

# Extract fields with defaults
agent_confidence=$(echo "$INPUT" | jq -r '.agent_confidence // "low"')
matched_tier=$(echo "$INPUT" | jq -r '.matched_tier // "none"')
reproduction_result=$(echo "$INPUT" | jq -r '.reproduction_result // "none"')
asset_criticality=$(echo "$INPUT" | jq -r '.asset_criticality // "standard"')
has_precedent=$(echo "$INPUT" | jq -r '.has_precedent // false')
signature_severity=$(echo "$INPUT" | jq -r '.signature_severity // "medium"')

# Normalize
agent_confidence=$(normalize "$agent_confidence" "low" "high medium low")
asset_criticality=$(normalize "$asset_criticality" "standard" "standard elevated critical")
signature_severity=$(normalize "$signature_severity" "medium" "low medium high critical")

# ─── Confidence Score Calculation ───

case "$agent_confidence" in
  high)   base="0.85" ;;
  medium) base="0.60" ;;
  *)      base="0.30" ;;
esac

case "$matched_tier" in
  gold)   tier_mod="0.10" ;;
  silver) tier_mod="0.05" ;;
  bronze) tier_mod="0.00" ;;
  *)      tier_mod="-0.15" ;;
esac

case "$reproduction_result" in
  confirmed) repro_mod="0.15" ;;
  refuted)   repro_mod="-0.30" ;;
  *)         repro_mod="0.00" ;;
esac

case "$asset_criticality" in
  elevated) crit_penalty="-0.05" ;;
  critical) crit_penalty="-0.15" ;;
  *)        crit_penalty="0.00" ;;
esac

confidence_score=$(echo "scale=2; t = $base + ($tier_mod) + ($repro_mod) + ($crit_penalty); if (t < 0) t = 0; if (t > 1) t = 1; t" | bc -l)

# Ensure leading zero
if [[ "$confidence_score" == .* ]]; then
  confidence_score="0${confidence_score}"
elif [[ "$confidence_score" == -.* ]]; then
  confidence_score="0.00"
fi

# ─── Decision Matrix ───

decision=""

# Pre-matrix rule 1: No precedent -> ESCALATE
if [ "$has_precedent" = "false" ]; then
  decision="escalate"
fi

# Pre-matrix rule 2: Reproduction refuted -> ESCALATE
if [ -z "$decision" ] && [ "$reproduction_result" = "refuted" ]; then
  decision="escalate"
fi

# Pre-matrix rule 3: Reproduction confirmed + medium+ confidence -> AUTO_CLOSE
if [ -z "$decision" ] && [ "$reproduction_result" = "confirmed" ]; then
  if [ "$agent_confidence" = "high" ] || [ "$agent_confidence" = "medium" ]; then
    decision="auto_close"
  fi
fi

# Matrix lookup with hierarchical fallback
if [ -z "$decision" ]; then
  decision=$(matrix_lookup_with_fallback "$asset_criticality" "$signature_severity" "$agent_confidence")
fi

# Output JSON
jq -n \
  --arg score "$confidence_score" \
  --arg decision "$decision" \
  '{confidence_score: ($score | tonumber), decision: $decision}'
