#!/usr/bin/env bash
# Lead: lead-name-here
# Data tags: tag1, tag2
#
# One-line description of what this script queries.
# Returns structured summary with verification metadata.
#
# The agent reads this script to understand what it does and how.
# Comments explain investigative rationale, not just code mechanics.

set -euo pipefail

# --- Parameter parsing ---
# Entity: any identifier relevant to the investigation (user, ip, host, etc.)
# Not a closed list — the script handles the entity type it was built for,
# and reports clearly if asked for something it doesn't support.
ENTITY=""
VALUE=""
CENTER=""
WINDOW="2h"
BEFORE="" ; AFTER=""
START="" ; END=""
BASELINE_OFFSET=""
SELF_TEST=false

while [[ $# -gt 0 ]]; do
  case $1 in
    --entity)   ENTITY="$2";   shift 2;;
    --value)    VALUE="$2";    shift 2;;
    --center)   CENTER="$2";   shift 2;;
    --window)   WINDOW="$2";   shift 2;;
    --before)   BEFORE="$2";   shift 2;;
    --after)    AFTER="$2";    shift 2;;
    --start)    START="$2";    shift 2;;
    --end)      END="$2";      shift 2;;
    --baseline-offset) BASELINE_OFFSET="$2"; shift 2;;
    --self-test) SELF_TEST=true; shift;;
    *) echo "Unknown param: $1" >&2; exit 1;;
  esac
done

# --- Validation ---

validate_duration() {
  [[ $1 =~ ^[0-9]+(m|h|d|w)$ ]] || { echo "Invalid duration: $1" >&2; exit 1; }
}

if [[ -z "$ENTITY" || -z "$VALUE" ]]; then
  echo "Error: --entity and --value are required" >&2
  exit 1
fi

# Validate time mode: exactly one of (center) or (start+end) must be set
if [[ -n "$CENTER" && ( -n "$START" || -n "$END" ) ]]; then
  echo "Error: use --center/--window OR --start/--end, not both" >&2
  exit 1
fi

if [[ -n "$CENTER" ]]; then
  validate_duration "$WINDOW"
  [[ -n "$BEFORE" ]] && validate_duration "$BEFORE"
  [[ -n "$AFTER" ]]  && validate_duration "$AFTER"
fi

[[ -n "$BASELINE_OFFSET" ]] && validate_duration "$BASELINE_OFFSET"

# --- Time computation ---
# Compute START/END from center+window or center+before/after if needed.
# For the template, this section is a placeholder — implement per system.

if [[ -n "$CENTER" ]]; then
  if [[ -n "$BEFORE" && -n "$AFTER" ]]; then
    MODE="asymmetric"
    TIME_DISPLAY="$BEFORE before to $AFTER after $CENTER"
  else
    MODE="centered"
    TIME_DISPLAY="$WINDOW window around $CENTER"
  fi
else
  MODE="absolute"
  TIME_DISPLAY="$START to $END"
fi

if [[ -n "$BASELINE_OFFSET" ]]; then
  MODE="${MODE}+baseline"
  TIME_DISPLAY="${TIME_DISPLAY} (baseline offset: $BASELINE_OFFSET)"
fi

# --- Environment config ---
# Source system-specific settings (index names, field mappings, credentials).
# The script never hardcodes these — they come from environment config.
# Credentials are sourced here, never passed as parameters.
#
# SYSTEM env var selects the vendor (e.g., "wazuh", "splunk").
# Default to "wazuh" if not set — it's the only system in the current deployment.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SYSTEM="${SYSTEM:-wazuh}"
CONFIG_ENV="${SOC_AGENT_DIR:-${SCRIPT_DIR}/../../..}/knowledge/environment/systems/${SYSTEM}/config.env"

if [[ -f "$CONFIG_ENV" ]]; then
  # shellcheck source=/dev/null
  source "$CONFIG_ENV"
else
  echo "Warning: config not found at $CONFIG_ENV" >&2
fi

# --- Self-test mode ---
# Verifies config and connectivity, independent of live investigation data.
# Run after modifying the script to catch configuration regressions.
if [[ "$SELF_TEST" == true ]]; then
  echo "Self-test: checking config and connectivity..."
  HEALTH_CHECK="${SOC_AGENT_DIR:-${SCRIPT_DIR}/../../..}/knowledge/environment/systems/${SYSTEM}/health-check.sh"
  if [[ -x "$HEALTH_CHECK" ]]; then
    "$HEALTH_CHECK"
  else
    echo "Warning: no health-check.sh found for system $SYSTEM" >&2
  fi
  echo "Self-test: PASS (config loaded, system reachable)"
  exit 0
fi

# --- Query construction ---
# This is the core knowledge the script carries.
# Each filter should be commented with WHY it exists.
# When this script returns wrong results, update the query here.
#
# TODO: Replace this placeholder with actual query logic for your system.
QUERY="<placeholder — build query from ENTITY=$ENTITY VALUE=$VALUE>"

# --- Execution ---
# Execute via the configured query tool (MCP, API, CLI).
# The script is the credential trust boundary — credentials are used here
# and never exposed in output.
#
# TODO: Replace with actual execution against your SIEM/data source.
MATCH_COUNT=0
TOTAL_INDEX_EVENTS=0
LATEST_EVENT_TIMESTAMP="unknown"
DATA_SOURCE="${SYSTEM}"
SAMPLE_EVENTS="(no results)"
COUNT_BREAKDOWN="(no results)"

# --- Output format (standard for all lead scripts) ---
cat <<RESULT
## Lead: lead-name-here
**Mode:** ${MODE}
**Parameters:** entity=${ENTITY}, value=${VALUE}, window=${TIME_DISPLAY}
**Query executed:** ${QUERY}
**Time range:** ${TIME_DISPLAY}

### Data Source Health
- **Source:** ${DATA_SOURCE}
- **Most recent event in index:** ${LATEST_EVENT_TIMESTAMP}
- **Index event count (unfiltered, same window):** ${TOTAL_INDEX_EVENTS}

### Summary
- **Matching events:** ${MATCH_COUNT}

### Sample Events (first 5)
${SAMPLE_EVENTS}

### Raw Event Count Breakdown
${COUNT_BREAKDOWN}
RESULT
