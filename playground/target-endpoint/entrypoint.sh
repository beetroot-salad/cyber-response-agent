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
echo "[+] Setting up persistent Wazuh agent state..."
STATE_DIR=/var/ossec-state
mkdir -p "$STATE_DIR"

# client.keys — agent identity / enrollment
# We can't symlink: wazuh-agentd writes via atomic-replace (write-temp +
# rename), which clobbers the symlink with a regular file. Instead we
# *copy* the persistent file in on startup, and run a background sync that
# copies the live file back to the persistent location whenever it changes.
if [ -s "$STATE_DIR/client.keys" ]; then
    echo "    Restoring client.keys from persistent state"
    cp "$STATE_DIR/client.keys" /var/ossec/etc/client.keys
else
    echo "    First run: empty client.keys (agent will auto-enroll)"
    : > /var/ossec/etc/client.keys
    : > "$STATE_DIR/client.keys"
fi
chown wazuh:wazuh /var/ossec/etc/client.keys "$STATE_DIR/client.keys"
chmod 640 /var/ossec/etc/client.keys "$STATE_DIR/client.keys"

# Background sync: every 30s, copy live client.keys to persistent location
# if it has changed. This catches the post-enrollment write.
(
    LAST_HASH=""
    while true; do
        sleep 30
        if [ -s /var/ossec/etc/client.keys ]; then
            HASH=$(md5sum /var/ossec/etc/client.keys 2>/dev/null | awk '{print $1}')
            if [ "$HASH" != "$LAST_HASH" ]; then
                cp -p /var/ossec/etc/client.keys "$STATE_DIR/client.keys.tmp" 2>/dev/null \
                    && mv "$STATE_DIR/client.keys.tmp" "$STATE_DIR/client.keys" \
                    && LAST_HASH="$HASH"
            fi
        fi
    done
) &
echo "    Started client.keys sync watcher (PID $!)"

# queue/ — syscheck FIM DB, rids anti-replay counters, agent buffers
# Symlink is safe here because wazuh-syscheckd writes individual files
# inside the directory rather than replacing the directory itself.
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

# Enroll and start elastic-agent (in background). Token is written by the
# fleet-setup one-shot to the fleet-shared volume.
echo "[+] Enrolling elastic-agent..."
TOKEN_FILE=/fleet-shared/enrollment-token
(
    # Wait for the token to appear (fleet-setup may still be running).
    for i in $(seq 1 60); do
        [ -s "$TOKEN_FILE" ] && break
        sleep 5
    done
    if [ ! -s "$TOKEN_FILE" ]; then
        echo "    ✗ elastic-agent: enrollment token not available after 5min"
        exit 1
    fi
    TOKEN=$(cat "$TOKEN_FILE")
    # Self-managed sentinel — /var/lib/elastic-agent is a persistent named
    # volume. On container recreate we skip re-enrollment so the agent.id
    # stays stable and no stale duplicates pile up in Fleet.
    # `|| true` on enroll: enroll exits non-zero from a spurious daemon-reload
    # step; server-side registration succeeds before that.
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
