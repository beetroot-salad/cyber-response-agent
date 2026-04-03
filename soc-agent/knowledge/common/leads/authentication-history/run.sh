#!/usr/bin/env bash
# Lead: authentication-history
# Data tags: auth-events
#
# Queries authentication events from Wazuh for a given entity and time window.
# Returns structured summary with verification metadata.
#
# The agent reads this script to understand what it does and how.
# Comments explain investigative rationale, not just code mechanics.
#
# Supported entities: ip (srcip), user (srcuser for SSH, dstuser for AD),
#                     host (agent.name — the target host, not the source).
# See field-quirks.md for why these field mappings differ by event type.

set -euo pipefail

# --- Parameter parsing ---
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
  echo "Usage: $0 --entity {ip|user|host} --value VALUE --center TIME --window DURATION" >&2
  exit 1
fi

# Validate time mode: exactly one of (center) or (start+end) must be set
if [[ -n "$CENTER" && ( -n "$START" || -n "$END" ) ]]; then
  echo "Error: use --center/--window OR --start/--end, not both" >&2
  exit 1
fi
if [[ -z "$CENTER" && ( -z "$START" || -z "$END" ) ]]; then
  echo "Error: must specify --center or both --start and --end" >&2
  exit 1
fi

if [[ -n "$CENTER" ]]; then
  validate_duration "$WINDOW"
  [[ -n "$BEFORE" ]] && validate_duration "$BEFORE"
  [[ -n "$AFTER" ]]  && validate_duration "$AFTER"
fi

[[ -n "$BASELINE_OFFSET" ]] && validate_duration "$BASELINE_OFFSET"

# --- Time computation ---
# Convert durations to seconds for arithmetic.
# All timestamps are ISO 8601 UTC. date(1) handles the conversion.

duration_to_seconds() {
  local val="${1%[mhdw]}"
  local unit="${1: -1}"
  case "$unit" in
    m) echo $(( val * 60 ));;
    h) echo $(( val * 3600 ));;
    d) echo $(( val * 86400 ));;
    w) echo $(( val * 604800 ));;
  esac
}

iso_to_epoch() { date -d "$1" +%s; }
epoch_to_iso() { date -u -d "@$1" +"%Y-%m-%dT%H:%M:%SZ"; }

if [[ -n "$CENTER" ]]; then
  CENTER_EPOCH=$(iso_to_epoch "$CENTER")
  if [[ -n "$BEFORE" && -n "$AFTER" ]]; then
    MODE="asymmetric"
    BEFORE_SECS=$(duration_to_seconds "$BEFORE")
    AFTER_SECS=$(duration_to_seconds "$AFTER")
    START_EPOCH=$(( CENTER_EPOCH - BEFORE_SECS ))
    END_EPOCH=$(( CENTER_EPOCH + AFTER_SECS ))
    TIME_DISPLAY="$BEFORE before to $AFTER after $CENTER"
  else
    MODE="centered"
    HALF_WINDOW=$(( $(duration_to_seconds "$WINDOW") / 2 ))
    START_EPOCH=$(( CENTER_EPOCH - HALF_WINDOW ))
    END_EPOCH=$(( CENTER_EPOCH + HALF_WINDOW ))
    TIME_DISPLAY="$WINDOW window around $CENTER"
  fi
else
  MODE="absolute"
  START_EPOCH=$(iso_to_epoch "$START")
  END_EPOCH=$(iso_to_epoch "$END")
  TIME_DISPLAY="$START to $END"
fi

# Apply baseline offset — shift the entire window back by the offset amount.
# The query structure stays identical; only the time range changes.
# This enables direct comparison: "47 events in alert window vs 3 in baseline."
if [[ -n "$BASELINE_OFFSET" ]]; then
  OFFSET_SECS=$(duration_to_seconds "$BASELINE_OFFSET")
  START_EPOCH=$(( START_EPOCH - OFFSET_SECS ))
  END_EPOCH=$(( END_EPOCH - OFFSET_SECS ))
  MODE="${MODE}+baseline"
  TIME_DISPLAY="${TIME_DISPLAY} (baseline offset: -${BASELINE_OFFSET})"
fi

QUERY_START=$(epoch_to_iso "$START_EPOCH")
QUERY_END=$(epoch_to_iso "$END_EPOCH")

# --- Environment config ---
# Source Wazuh-specific settings (index, endpoint, retention).
# Credentials are NOT in config.env — they come from environment variables.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SYSTEM="${SYSTEM:-wazuh}"
CONFIG_ENV="${SOC_AGENT_DIR:-${SCRIPT_DIR}/../../..}/knowledge/environment/systems/${SYSTEM}/config.env"

if [[ -f "$CONFIG_ENV" ]]; then
  # shellcheck source=/dev/null
  source "$CONFIG_ENV"
else
  echo "Warning: config not found at $CONFIG_ENV — using defaults" >&2
  WAZUH_INDEX="wazuh-alerts-*"
  WAZUH_API_ENDPOINT="https://wazuh-manager:55000"
fi

# --- Self-test mode ---
# Verifies config loading and Wazuh API connectivity.
# Run after modifying the script to catch configuration regressions.
if [[ "$SELF_TEST" == true ]]; then
  echo "Self-test: authentication-history"
  echo "  Config: ${CONFIG_ENV}"
  echo "  Index: ${WAZUH_INDEX}"
  echo "  Endpoint: ${WAZUH_API_ENDPOINT}"
  HEALTH_CHECK="${SOC_AGENT_DIR:-${SCRIPT_DIR}/../../..}/knowledge/environment/systems/${SYSTEM}/health-check.sh"
  if [[ -x "$HEALTH_CHECK" ]]; then
    echo "  Running health check..."
    "$HEALTH_CHECK"
  else
    echo "  Warning: no health-check.sh found" >&2
  fi
  echo "Self-test: PASS"
  exit 0
fi

# --- Entity → query field mapping ---
# SSH events use data.srcuser for the authenticating user.
# Windows AD events use data.dstuser (see field-quirks.md for why).
# This script targets SSH (rule.groups:sshd). For AD, a separate script
# or entity mapping would be needed.
case "$ENTITY" in
  ip|srcip)
    ENTITY_FIELD="data.srcip"
    ;;
  user|srcuser)
    # data.srcuser is correct for SSH. For Windows AD, this would need
    # to be data.dstuser — see field-quirks.md.
    ENTITY_FIELD="data.srcuser"
    ;;
  host)
    # agent.name is the host where the Wazuh agent runs — the target
    # of the auth attempt, not the source. See field-quirks.md.
    ENTITY_FIELD="agent.name"
    ;;
  *)
    echo "Error: unsupported entity type '$ENTITY'. Use: ip, user, host" >&2
    exit 1
    ;;
esac

# --- Query construction ---
# Core query: all SSH authentication events for this entity in the time window.
# rule.groups:sshd scopes to SSH events only (not Windows, not PAM).
# The entity field filter narrows to the specific source being investigated.
QUERY="rule.groups:sshd AND ${ENTITY_FIELD}:${VALUE}"

# Time range filter (Wazuh API format)
TIME_FILTER="timestamp:[${QUERY_START} TO ${QUERY_END}]"

# Full query combining entity filter and time range
FULL_QUERY="${QUERY} AND ${TIME_FILTER}"

# --- Execution ---
# Authenticate to Wazuh API, then execute queries.
# The script is the credential trust boundary — creds used here, never in output.

WAZUH_USER="${WAZUH_API_USER:-wazuh-wui}"
WAZUH_PASS="${WAZUH_API_PASSWORD:?WAZUH_API_PASSWORD must be set}"

# Get JWT token
TOKEN=$(curl -s -k -u "${WAZUH_USER}:${WAZUH_PASS}" \
  -X POST "${WAZUH_API_ENDPOINT}/security/user/authenticate" \
  --max-time 10 | python3 -c "import sys,json; print(json.load(sys.stdin).get('data',{}).get('token',''))" 2>/dev/null)

if [[ -z "$TOKEN" ]]; then
  echo "Error: Wazuh API authentication failed" >&2
  exit 1
fi

AUTH_HEADER="Authorization: Bearer ${TOKEN}"

# Helper: run a Wazuh API alerts query and return the JSON response
wazuh_query() {
  local q="$1"
  local limit="${2:-500}"
  curl -s -k -H "$AUTH_HEADER" \
    "${WAZUH_API_ENDPOINT}/alerts?q=${q}&limit=${limit}&sort=-timestamp" \
    --max-time 30
}

# Query 1: Filtered events (matching entity + time range)
FILTERED_RESPONSE=$(wazuh_query "${FULL_QUERY}")

# Query 2: Unfiltered index count (same time range, no entity filter)
# Purpose: scale reference — 0 filtered from 500K = good filtering;
# 0 filtered from 0 = dead source.
UNFILTERED_QUERY="rule.groups:sshd AND ${TIME_FILTER}"
UNFILTERED_RESPONSE=$(wazuh_query "${UNFILTERED_QUERY}" 1)

# --- Parse results ---
# Extract counts, samples, and breakdowns from API responses.

MATCH_COUNT=$(echo "$FILTERED_RESPONSE" | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(data.get('data', {}).get('total_affected_items', 0))
" 2>/dev/null || echo "0")

TOTAL_INDEX_EVENTS=$(echo "$UNFILTERED_RESPONSE" | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(data.get('data', {}).get('total_affected_items', 0))
" 2>/dev/null || echo "0")

# Most recent event timestamp — data freshness canary.
# If this is hours old, the data pipeline may be stale.
LATEST_EVENT_TIMESTAMP=$(echo "$FILTERED_RESPONSE" | python3 -c "
import sys, json
items = json.load(sys.stdin).get('data', {}).get('affected_items', [])
print(items[0].get('timestamp', 'none') if items else 'no matching events')
" 2>/dev/null || echo "unknown")

# Sample events (first 5) — sanity check for the agent to verify
# events match expectations (correct entity, correct time range).
SAMPLE_EVENTS=$(echo "$FILTERED_RESPONSE" | python3 -c "
import sys, json
items = json.load(sys.stdin).get('data', {}).get('affected_items', [])[:5]
if not items:
    print('(no matching events)')
else:
    for i, evt in enumerate(items, 1):
        rule = evt.get('rule', {})
        data = evt.get('data', {})
        print(f'{i}. [{evt.get(\"timestamp\",\"?\")}] rule:{rule.get(\"id\",\"?\")} '
              f'srcip:{data.get(\"srcip\",\"?\")} srcuser:{data.get(\"srcuser\",\"?\")} '
              f'agent:{evt.get(\"agent\",{}).get(\"name\",\"?\")} '
              f'desc:{rule.get(\"description\",\"?\")[:80]}')
" 2>/dev/null || echo "(parse error)")

# Count breakdown — quantified summary for the main agent.
COUNT_BREAKDOWN=$(echo "$FILTERED_RESPONSE" | python3 -c "
import sys, json
from collections import Counter
items = json.load(sys.stdin).get('data', {}).get('affected_items', [])
if not items:
    print('(no data)')
    sys.exit(0)

# By rule ID (distinguishes failed vs successful vs other SSH events)
rules = Counter(e.get('rule',{}).get('id','?') for e in items)
print('By rule:')
for rid, cnt in rules.most_common():
    desc = next((e.get('rule',{}).get('description','') for e in items if e.get('rule',{}).get('id')==rid), '')
    print(f'  rule.id:{rid} ({desc}): {cnt}')

# By source IP
srcips = Counter(e.get('data',{}).get('srcip','?') for e in items)
print(f'By source IP ({len(srcips)} unique):')
for ip, cnt in srcips.most_common(10):
    print(f'  {ip}: {cnt}')

# By username
users = Counter(e.get('data',{}).get('srcuser','?') for e in items)
print(f'By username ({len(users)} unique):')
for u, cnt in users.most_common(10):
    print(f'  {u}: {cnt}')

# By hour (timing pattern)
hours = Counter(e.get('timestamp','')[:13] for e in items)
print('By hour:')
for h, cnt in sorted(hours.items()):
    print(f'  {h}: {cnt}')
" 2>/dev/null || echo "(parse error)")

# --- Output format (standard for all lead scripts) ---
cat <<RESULT
## Lead: authentication-history
**Mode:** ${MODE}
**Parameters:** entity=${ENTITY}, value=${VALUE}
**Query executed:** ${FULL_QUERY}
**Time range:** ${QUERY_START} to ${QUERY_END} (${TIME_DISPLAY})

### Data Source Health
- **Source:** Wazuh SIEM (${WAZUH_API_ENDPOINT})
- **Most recent matching event:** ${LATEST_EVENT_TIMESTAMP}
- **Index event count (SSH events, same window):** ${TOTAL_INDEX_EVENTS}

### Summary
- **Matching events:** ${MATCH_COUNT}

### Sample Events (first 5)
${SAMPLE_EVENTS}

### Raw Event Count Breakdown
${COUNT_BREAKDOWN}
RESULT
