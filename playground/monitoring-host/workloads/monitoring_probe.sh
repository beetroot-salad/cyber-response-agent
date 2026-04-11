#!/bin/bash
# Realistic monitoring probe: one SSH attempt per tick against target-endpoint
# using a monitoring-pattern username. No retry. Simulates a health-check job.
#
# Trigger shape (on target-endpoint's sshd, which is what Wazuh monitors):
#   - srcip: monitoring-host's fixed IP (172.22.0.10)
#   - srcuser: nagios | zabbix | healthcheck | monitorprobe | sensu
#   - attempt_count: 1
#   - successful_login_after: false (user doesn't exist on target-endpoint)
#
# This matches the monitoring-probe screen indicators in
# soc-agent/knowledge/signatures/wazuh-rule-5710/playbook.md.

TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
USER_POOL=(nagios zabbix healthcheck monitorprobe sensu)
USER="${USER_POOL[$((RANDOM % ${#USER_POOL[@]}))]}"

echo "[$TIMESTAMP] monitoring_probe: ssh ${USER}@target-endpoint (single attempt)"

ssh -4 \
    -o BatchMode=yes \
    -o ConnectTimeout=2 \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    "${USER}@target-endpoint" true 2>/dev/null || true

echo "[$TIMESTAMP] monitoring_probe: done"
