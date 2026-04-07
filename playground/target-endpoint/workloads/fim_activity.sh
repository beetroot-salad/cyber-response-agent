#!/bin/bash
# File Integrity Monitoring workload — generates both benign and suspicious file changes
# in directories monitored by Wazuh syscheck (/etc, /usr/bin, /usr/sbin, /bin, /sbin).
#
# Runs every 10 minutes via cron.
# Benign activity runs every cycle; suspicious patterns trigger with 30% probability.
#
# Expected Wazuh rules triggered:
#   550 — Integrity checksum changed
#   553 — File deleted from the system
#   554 — File added to the system

TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
echo "[$TIMESTAMP] Starting FIM activity cycle"

# ============================================
# Benign FIM Activity (every cycle)
# ============================================

# Simulate config management / routine admin changes
# These should trigger FIM alerts but be identifiable as benign

# 1. Rotate a test logrotate config (common admin task)
cat > /etc/logrotate.d/workload-test <<EOF
/var/log/workload.log {
    rotate 7
    daily
    compress
    missingok
    notifempty
    # Updated: $TIMESTAMP
}
EOF

# 2. Update MOTD (message of the day) — routine on managed systems
echo "System managed by automation. Last update: $TIMESTAMP" > /etc/motd

# 3. Touch a cron file (simulates cron job management)
echo "# Maintenance window marker: $TIMESTAMP" > /etc/cron.d/maintenance-marker
chmod 0644 /etc/cron.d/maintenance-marker

echo "[$TIMESTAMP] Benign FIM activity completed"

# ============================================
# Suspicious FIM Activity (30% probability)
# ============================================

RANDOM_NUM=$((RANDOM % 10))

if [ $RANDOM_NUM -lt 3 ]; then
    echo "[$TIMESTAMP] Triggering suspicious FIM pattern"

    PATTERN=$((RANDOM % 5))

    case $PATTERN in
        0)
            # Pattern: Hidden file in /etc (persistence indicator)
            echo "[$TIMESTAMP] FIM Pattern: Hidden file in /etc"
            echo "suspicious config" > /etc/.hidden_config_$(date +%s)
            # Cleanup after 30 min
            find /etc -name ".hidden_config_*" -mmin +30 -delete 2>/dev/null || true
            ;;

        1)
            # Pattern: Modified system binary (backdoor indicator)
            # We copy a legitimate binary, modify the copy — simulates a tampered binary
            echo "[$TIMESTAMP] FIM Pattern: Binary modification in /usr/local/bin"
            cp /usr/bin/whoami /usr/local/bin/whoami_test_$(date +%s) 2>/dev/null || true
            # Cleanup
            find /usr/local/bin -name "whoami_test_*" -mmin +30 -delete 2>/dev/null || true
            ;;

        2)
            # Pattern: SSH config modification (lateral movement prep)
            echo "[$TIMESTAMP] FIM Pattern: SSH config change"
            # Add and immediately remove a suspicious config line
            cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
            echo "# TestMark $(date +%s)" >> /etc/ssh/sshd_config
            sleep 2
            mv /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
            ;;

        3)
            # Pattern: New setuid binary (privilege escalation indicator)
            echo "[$TIMESTAMP] FIM Pattern: Setuid binary creation attempt"
            cp /bin/ls /tmp/escalate_test_$(date +%s) 2>/dev/null || true
            chmod 4755 /tmp/escalate_test_$(date +%s) 2>/dev/null || true
            # Cleanup
            find /tmp -name "escalate_test_*" -mmin +30 -delete 2>/dev/null || true
            ;;

        4)
            # Pattern: Crontab modification (persistence via scheduled task)
            echo "[$TIMESTAMP] FIM Pattern: Suspicious cron entry"
            echo "*/30 * * * * root curl -s http://10.0.0.99/health > /dev/null 2>&1 # test-$(date +%s)" > /etc/cron.d/suspicious-job
            chmod 0644 /etc/cron.d/suspicious-job
            # Remove after 5 min
            sleep 300 && rm -f /etc/cron.d/suspicious-job 2>/dev/null &
            ;;
    esac

    echo "[$TIMESTAMP] Suspicious FIM pattern $PATTERN triggered"
else
    echo "[$TIMESTAMP] No suspicious FIM pattern this cycle"
fi

echo "[$TIMESTAMP] FIM activity cycle completed"
