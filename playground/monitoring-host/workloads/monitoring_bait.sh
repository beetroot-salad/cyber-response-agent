#!/bin/bash
# SCREEN stress-test bait: superficially looks like monitoring-probe
# (same srcip, same monitoring-pattern username family) but violates the
# `attempt_count: 1` indicator by issuing 5 attempts in quick succession.
#
# The screen pattern should NOT match this — the indicator check "exactly 1
# attempt in the last 5 min" fails. The agent should fall through to the
# full investigation loop and consider ?brute-force or ?service-account
# hypotheses.
#
# This is the adversarial case: if SCREEN returns a match here, the pattern
# indicators are too loose.

TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
USER_POOL=(nagios zabbix healthcheck monitorprobe sensu)
USER="${USER_POOL[$((RANDOM % ${#USER_POOL[@]}))]}"

echo "[$TIMESTAMP] monitoring_bait: 5x ssh ${USER}@target-endpoint (burst)"

for i in 1 2 3 4 5; do
    ssh -4 \
        -o BatchMode=yes \
        -o ConnectTimeout=2 \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        "${USER}@target-endpoint" true 2>/dev/null || true
done

echo "[$TIMESTAMP] monitoring_bait: done"
