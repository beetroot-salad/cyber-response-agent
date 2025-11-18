#!/bin/bash
set -e

echo "========================================="
echo "Starting Target Endpoint Container"
echo "========================================="

# Start cron for workload scripts
echo "[+] Starting cron..."
service cron start

if service cron status > /dev/null 2>&1; then
    echo "    ✓ cron is running"
else
    echo "    ✗ cron failed to start"
    exit 1
fi

# Create initial activity marker
echo "[+] Creating initial activity marker..."
echo "Target endpoint started at $(date)" > /var/log/endpoint-startup.log

echo ""
echo "========================================="
echo "Target Endpoint Ready!"
echo "========================================="
echo "Monitoring:  Falco (eBPF - external container)"
echo "Cron:        ✓ Running (workload scripts scheduled)"
echo "Workload:    /var/log/workload.log"
echo "========================================="
echo ""

# Execute CMD (typically tail -f /dev/null to keep container running)
exec "$@"
