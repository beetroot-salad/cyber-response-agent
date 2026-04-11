#!/bin/bash
# Simulates suspicious but controlled activity for testing detection rules
# Runs every 15 minutes via cron
# These patterns are designed to trigger alerts but are safe/controlled
#
# Patterns are grouped by detection domain:
#   0-2: Process execution anomalies (Falco rules 100001, 100002, 100009)
#   3-4: Credential access (Falco rule 100006, Wazuh auth rules)
#   5-6: Network reconnaissance (Falco rules 100005, 100008)
#   7-8: File-based indicators (Falco rules 100003, 100007)
#
# 5710 (SSH invalid user) traffic is generated from the monitoring-host
# container, not from target-endpoint's own loopback. See
# playground/monitoring-host/workloads/ for the realistic probe + the
# multi-attempt bait variant.

TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

echo "[$TIMESTAMP] Starting suspicious pattern check"

# Random chance to trigger suspicious behavior (30% probability)
RANDOM_NUM=$((RANDOM % 10))

if [ $RANDOM_NUM -lt 3 ]; then
    echo "[$TIMESTAMP] Triggering suspicious pattern (test scenario)"

    PATTERN=$((RANDOM % 9))

    case $PATTERN in
        0)
            # Process: Suspicious shell spawned by non-shell parent
            # Targets Falco rule: "Terminal shell in container" / suspicious shell spawn
            # → Wazuh 100001 (Suspicious shell spawned)
            echo "[$TIMESTAMP] Pattern: Suspicious process chain"
            # Run recon commands through sh -c (suspicious parent-child)
            sh -c "whoami > /tmp/user_check_$(date +%s).txt"
            sh -c "id > /tmp/id_check_$(date +%s).txt"
            sh -c "uname -a > /tmp/system_info_$(date +%s).txt"
            # Enumerate network config (post-exploitation recon pattern)
            sh -c "cat /proc/net/tcp > /dev/null 2>&1"
            sh -c "cat /proc/net/arp > /dev/null 2>&1"
            ;;

        1)
            # Process: Base64-encoded command execution
            # → Wazuh 100002 (Encoded command execution)
            echo "[$TIMESTAMP] Pattern: Encoded command execution"
            # Encode benign commands in base64 (common evasion technique)
            echo "d2hvYW1p" | base64 -d | sh 2>/dev/null || true
            echo "aWQgLXVu" | base64 -d | sh 2>/dev/null || true
            ENCODED=$(echo "hostname" | base64)
            echo "$ENCODED" | base64 -d | sh > /dev/null 2>&1 || true
            ;;

        2)
            # Process: Execution from /tmp (staging directory abuse)
            # → Wazuh 100009 (Execution from temp directory)
            echo "[$TIMESTAMP] Pattern: Execution from /tmp"
            # Create and execute a script from /tmp (dropper pattern)
            SCRIPT="/tmp/health_check_$(date +%s).sh"
            echo '#!/bin/bash' > "$SCRIPT"
            echo 'echo "system check: $(date)"' >> "$SCRIPT"
            echo 'ps aux | head -5' >> "$SCRIPT"
            chmod +x "$SCRIPT"
            "$SCRIPT" > /dev/null 2>&1 || true
            rm -f "$SCRIPT"
            ;;

        3)
            # Credential: Sensitive file access
            # → Wazuh 100006 (Sensitive file access)
            # → Wazuh 100037 (Critical file accessed)
            echo "[$TIMESTAMP] Pattern: Sensitive file access"
            cat /etc/shadow > /dev/null 2>&1 || true
            cat /etc/sudoers > /dev/null 2>&1 || true
            ls -la /root > /dev/null 2>&1 || true
            # Read SSH host keys (credential harvesting indicator)
            cat /etc/ssh/ssh_host_rsa_key > /dev/null 2>&1 || true
            ;;

        4)
            # Credential: Failed authentication attempts (brute force)
            # → Wazuh 100004 (Multiple failed auth)
            # → Wazuh built-in SSH/sudo auth rules
            echo "[$TIMESTAMP] Pattern: Failed authentication attempts"
            echo "wrong_password" | sudo -S ls /root 2>/dev/null || true
            sleep 1
            echo "wrong_password" | sudo -S ls /root 2>/dev/null || true
            sleep 1
            echo "wrong_password" | sudo -S ls /root 2>/dev/null || true
            ;;

        5)
            # Network: Port scanning (reconnaissance)
            # → Wazuh 100005 (Network scanning)
            echo "[$TIMESTAMP] Pattern: Network scanning"
            nc -zv localhost 22 2>/dev/null || true
            nc -zv localhost 80 2>/dev/null || true
            nc -zv localhost 443 2>/dev/null || true
            nc -zv localhost 3306 2>/dev/null || true
            nc -zv localhost 5432 2>/dev/null || true
            nc -zv localhost 8080 2>/dev/null || true
            ;;

        6)
            # Network: Connections to suspicious ports (C2 indicators)
            # → Wazuh 100008 (Unusual network connection)
            echo "[$TIMESTAMP] Pattern: Suspicious network connections"
            nc -zv -w 1 localhost 4444 2>/dev/null || true
            nc -zv -w 1 localhost 1337 2>/dev/null || true
            nc -zv -w 1 localhost 9001 2>/dev/null || true
            nc -zv -w 1 localhost 5555 2>/dev/null || true
            ;;

        7)
            # File: Suspicious files in /tmp (staging)
            # → Wazuh 100003 (Suspicious files in /tmp)
            echo "[$TIMESTAMP] Pattern: Suspicious file creation"
            touch /tmp/test_payload_$(date +%s).sh
            touch /tmp/test_sample_$(date +%s).bin
            echo "#!/bin/bash" > /tmp/test_script_$(date +%s).sh
            ;;

        8)
            # File: System file modification attempts
            # → Wazuh 100007 (System file modification)
            echo "[$TIMESTAMP] Pattern: System file modification attempt"
            echo "test" > /etc/test_file_$(date +%s).txt 2>/dev/null || true
            ;;
    esac

    echo "[$TIMESTAMP] Pattern $PATTERN triggered"

else
    echo "[$TIMESTAMP] No suspicious pattern triggered this cycle (random chance)"
fi

# Cleanup old test files (older than 2 hours)
find /tmp -name "user_check_*.txt" -mmin +120 -delete 2>/dev/null || true
find /tmp -name "id_check_*.txt" -mmin +120 -delete 2>/dev/null || true
find /tmp -name "system_info_*.txt" -mmin +120 -delete 2>/dev/null || true
find /tmp -name "test_payload_*.sh" -mmin +120 -delete 2>/dev/null || true
find /tmp -name "test_sample_*.bin" -mmin +120 -delete 2>/dev/null || true
find /tmp -name "test_script_*.sh" -mmin +120 -delete 2>/dev/null || true
find /tmp -name "health_check_*.sh" -mmin +120 -delete 2>/dev/null || true

echo "[$TIMESTAMP] Suspicious pattern check completed"
