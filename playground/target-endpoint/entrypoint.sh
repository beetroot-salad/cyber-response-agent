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

# Start rsyslog so SSH logs go to /var/log/auth.log
echo "[+] Starting rsyslog..."
rsyslogd
if [ $? -eq 0 ]; then
    echo "    ✓ rsyslog is running"
else
    echo "    ✗ rsyslog failed to start"
fi

# Start dnsmasq (local DNS resolver with query logging)
echo "[+] Starting dnsmasq..."
# Capture Docker's embedded DNS (127.0.0.11) before overwriting resolv.conf
# so dnsmasq can forward to it for container name resolution (e.g., wazuh.manager)
DOCKER_DNS=$(grep nameserver /etc/resolv.conf | head -1 | awk '{print $2}')
if [ -n "$DOCKER_DNS" ] && [ "$DOCKER_DNS" != "127.0.0.1" ]; then
    # Prepend Docker DNS as primary upstream (for internal names)
    sed -i "1i server=${DOCKER_DNS}" /etc/dnsmasq.conf
    echo "    Using Docker DNS upstream: $DOCKER_DNS"
fi
# Point local resolution to dnsmasq
echo "nameserver 127.0.0.1" > /etc/resolv.conf
dnsmasq
if [ $? -eq 0 ]; then
    echo "    ✓ dnsmasq is running (DNS queries logged via syslog)"
else
    echo "    ✗ dnsmasq failed to start"
    # Fallback to external DNS so container still works
    echo "nameserver 8.8.8.8" > /etc/resolv.conf
fi

# Start openssh-server for SSH alert generation
echo "[+] Starting sshd..."
/usr/sbin/sshd
if [ $? -eq 0 ]; then
    echo "    ✓ sshd is running"
else
    echo "    ✗ sshd failed to start"
fi

# Persist Wazuh agent state across container recreates
# /var/ossec-state is a named volume; on first run it's empty.
# We seed it from the image defaults, then symlink the live paths to it.
echo "[+] Setting up persistent Wazuh agent state..."
STATE_DIR=/var/ossec-state
mkdir -p "$STATE_DIR"

# client.keys — agent identity / enrollment
if [ ! -f "$STATE_DIR/client.keys" ]; then
    echo "    First run: creating empty client.keys (agent will auto-enroll)"
    : > "$STATE_DIR/client.keys"
fi
chown wazuh:wazuh "$STATE_DIR/client.keys"
chmod 640 "$STATE_DIR/client.keys"
ln -sf "$STATE_DIR/client.keys" /var/ossec/etc/client.keys

# queue/ — syscheck FIM DB, rids anti-replay counters, agent buffers
if [ ! -d "$STATE_DIR/queue" ]; then
    echo "    First run: seeding queue/ from image defaults"
    cp -a /var/ossec/queue "$STATE_DIR/queue"
fi
chown -R wazuh:wazuh "$STATE_DIR/queue"
rm -rf /var/ossec/queue
ln -s "$STATE_DIR/queue" /var/ossec/queue

# Start Wazuh agent
echo "[+] Starting wazuh-agent..."
/var/ossec/bin/wazuh-control start
if [ $? -eq 0 ]; then
    echo "    ✓ wazuh-agent is running"
else
    echo "    ✗ wazuh-agent failed to start"
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
echo "SSH:         ✓ Running (port 22)"
echo "DNS:         ✓ dnsmasq logging queries"
echo "Syscheck:    ✓ FIM every 5 min, realtime on /etc"
echo "Wazuh Agent: ✓ Running (manager: wazuh.manager)"
echo "Workload:    /var/log/workload.log"
echo ""
echo "Workload schedule:"
echo "  Every 5m:  benign_activity.sh, dns_activity.sh"
echo "  Every 10m: fim_activity.sh"
echo "  Every 15m: suspicious_patterns.sh"
echo "========================================="
echo ""

# Execute CMD (typically tail -f /dev/null to keep container running)
exec "$@"
