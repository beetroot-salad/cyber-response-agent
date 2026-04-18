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

# Enroll and start elastic-agent (in background). Token is written by the
# fleet-setup one-shot to the fleet-shared volume.
echo "[+] Enrolling elastic-agent..."
TOKEN_FILE=/fleet-shared/enrollment-token
(
    for i in $(seq 1 60); do
        [ -s "$TOKEN_FILE" ] && break
        sleep 5
    done
    if [ ! -s "$TOKEN_FILE" ]; then
        echo "    ✗ elastic-agent: enrollment token not available after 5min"
        exit 1
    fi
    TOKEN=$(cat "$TOKEN_FILE")
    # Self-managed sentinel in the persistent /var/lib/elastic-agent volume.
    SENTINEL=/var/lib/elastic-agent/.enrolled
    if [ ! -f "$SENTINEL" ]; then
        echo "    (first run — enrolling)"
        /usr/bin/elastic-agent enroll \
            --url=http://fleet-server:8220 \
            --enrollment-token="$TOKEN" \
            --force --insecure >/var/log/elastic-agent-enroll.log 2>&1 || true
        touch "$SENTINEL"
    else
        echo "    (already enrolled — reusing persisted state)"
    fi
    nohup /usr/bin/elastic-agent run >/var/log/elastic-agent.log 2>&1 &
    echo "    ✓ elastic-agent running (PID $!)"
) &

echo ""
echo "Monitoring Host Ready"
echo "  Cron: ✓ nagios (5m) + zabbix (10m) + healthcheck (15m) → target-endpoint"
echo "  Bait: manual trigger via docker exec"
echo "========================================="
echo ""

exec "$@"
