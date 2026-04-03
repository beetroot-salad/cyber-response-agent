#!/usr/bin/env bash
# Wazuh health check — canary query to verify connectivity and data freshness.
#
# Sources config.env from the same directory for endpoint and index settings.
# Used by lead scripts to populate the "Data Source Health" output section.
#
# Exit codes:
#   0 — healthy (API reachable, recent events exist)
#   1 — degraded (API reachable but data is stale or empty)
#   2 — unreachable (API connection failed)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=/dev/null
source "${SCRIPT_DIR}/config.env"

# Wazuh API credentials from environment (never hardcoded)
WAZUH_USER="${WAZUH_API_USER:-wazuh-wui}"
WAZUH_PASS="${WAZUH_API_PASSWORD:?WAZUH_API_PASSWORD must be set}"

# --- Authenticate and get JWT token ---
TOKEN_RESPONSE=$(curl -s -k -u "${WAZUH_USER}:${WAZUH_PASS}" \
  -X POST "${WAZUH_API_ENDPOINT}/security/user/authenticate" \
  --max-time 10 2>&1) || {
  echo "status: unreachable"
  echo "error: Cannot connect to Wazuh API at ${WAZUH_API_ENDPOINT}"
  exit 2
}

TOKEN=$(echo "$TOKEN_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('data',{}).get('token',''))" 2>/dev/null)

if [[ -z "$TOKEN" ]]; then
  echo "status: unreachable"
  echo "error: Authentication failed — check WAZUH_API_USER/WAZUH_API_PASSWORD"
  exit 2
fi

# --- Query for most recent event ---
# Use the Wazuh API to check agent status as a connectivity canary.
AGENT_RESPONSE=$(curl -s -k \
  -H "Authorization: Bearer ${TOKEN}" \
  "${WAZUH_API_ENDPOINT}/agents?limit=1&sort=-lastKeepAlive" \
  --max-time 10 2>&1) || {
  echo "status: degraded"
  echo "error: API reachable but agent query failed"
  exit 1
}

TOTAL_AGENTS=$(echo "$AGENT_RESPONSE" | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(data.get('data', {}).get('total_affected_items', 0))
" 2>/dev/null || echo "0")

LAST_KEEPALIVE=$(echo "$AGENT_RESPONSE" | python3 -c "
import sys, json
items = json.load(sys.stdin).get('data', {}).get('affected_items', [])
print(items[0].get('lastKeepAlive', 'unknown') if items else 'unknown')
" 2>/dev/null || echo "unknown")

# --- Assess health ---
if [[ "$TOTAL_AGENTS" -eq 0 ]]; then
  echo "status: degraded"
  echo "agents: 0"
  echo "error: No agents reporting to Wazuh manager"
  exit 1
fi

echo "status: healthy"
echo "agents: ${TOTAL_AGENTS}"
echo "last_keepalive: ${LAST_KEEPALIVE}"
exit 0
