#!/bin/bash
set -e

echo "========================================="
echo "Starting Monitoring Host Container"
echo "========================================="

echo "[+] Starting cron..."
service cron start
if service cron status > /dev/null 2>&1; then
    echo "    ✓ cron is running"
else
    echo "    ✗ cron failed to start"
    exit 1
fi

echo ""
echo "Monitoring Host Ready"
echo "  Cron: ✓ monitoring_probe every 10 min → target-endpoint"
echo "  Bait: manual trigger via docker exec"
echo "========================================="
echo ""

exec "$@"
