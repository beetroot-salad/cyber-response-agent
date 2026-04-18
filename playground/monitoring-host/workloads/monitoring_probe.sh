#!/bin/bash
# Realistic monitoring probe: one SSH attempt against target-endpoint using a
# fixed monitoring-pattern username. No retry. Simulates a single health-check
# tool (Nagios, Zabbix, etc.) running on a cron.
#
# Invocation:
#   monitoring_probe.sh <username>
#
# The username is REQUIRED — fail loud if missing. Cron installs one entry per
# monitoring tool (see Dockerfile), each invoking this script with its own
# stable username. Rotating usernames from a single source would violate the
# archetype's "one tool = one identity" shape and break repeats-clustering in
# the ticket-context subagent.
#
# Trigger shape (on target-endpoint's sshd, which is what Wazuh monitors):
#   - srcip: monitoring-host's fixed IP (172.22.0.10)
#   - srcuser: $1 (must be listed in approved-monitoring-sources anchor)
#   - attempt_count: 1
#   - successful_login_after: false (user doesn't exist on target-endpoint)

set -u

if [ "$#" -ne 1 ] || [ -z "${1:-}" ]; then
    echo "usage: $0 <username>" >&2
    echo "  <username> must be listed in approved-monitoring-sources anchor" >&2
    exit 2
fi

USER="$1"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

echo "[$TIMESTAMP] monitoring_probe[$USER]: ssh ${USER}@target-endpoint (single attempt)"

ssh -4 \
    -o BatchMode=yes \
    -o ConnectTimeout=2 \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    "${USER}@target-endpoint" true 2>/dev/null || true

echo "[$TIMESTAMP] monitoring_probe[$USER]: done"
