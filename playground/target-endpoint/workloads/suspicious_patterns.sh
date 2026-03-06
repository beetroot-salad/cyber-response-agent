#!/bin/bash
# Simulates suspicious but controlled activity for testing detection rules
# Runs every 15 minutes via cron
# These patterns are designed to trigger alerts but are safe/controlled

TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

echo "[$TIMESTAMP] Starting suspicious pattern check"

# Random chance to trigger suspicious behavior (30% probability)
RANDOM_NUM=$((RANDOM % 10))

if [ $RANDOM_NUM -lt 3 ]; then
    echo "[$TIMESTAMP] Triggering suspicious pattern (test scenario)"

    # Choose a random suspicious pattern (0-6, skipping dangerous external URL pattern)
    PATTERN=$((RANDOM % 7))

    case $PATTERN in
        0)
            # Pattern: Unusual process execution chain
            echo "[$TIMESTAMP] Pattern: Suspicious process chain"
            sh -c "whoami > /tmp/user_check_$(date +%s).txt"
            sh -c "id > /tmp/id_check_$(date +%s).txt"
            sh -c "uname -a > /tmp/system_info_$(date +%s).txt"
            ;;

        1)
            # Pattern: Multiple failed authentication attempts
            echo "[$TIMESTAMP] Pattern: Failed authentication attempts"
            echo "wrong_password" | sudo -S ls /root 2>/dev/null || true
            sleep 1
            echo "wrong_password" | sudo -S ls /root 2>/dev/null || true
            sleep 1
            echo "wrong_password" | sudo -S ls /root 2>/dev/null || true
            ;;

        2)
            # Pattern: Network scanning (safe, localhost only)
            echo "[$TIMESTAMP] Pattern: Network scanning"
            nc -zv localhost 22 2>/dev/null || true
            nc -zv localhost 80 2>/dev/null || true
            nc -zv localhost 443 2>/dev/null || true
            nc -zv localhost 3306 2>/dev/null || true
            nc -zv localhost 5432 2>/dev/null || true
            ;;

        3)
            # Pattern: Suspicious file creation
            echo "[$TIMESTAMP] Pattern: Suspicious file operation"
            # Create files with suspicious names
            touch /tmp/payload_$(date +%s).sh
            touch /tmp/malware_$(date +%s).exe
            echo "#!/bin/bash" > /tmp/backdoor_$(date +%s).sh
            ;;

        4)
            # Pattern: Reading sensitive files
            echo "[$TIMESTAMP] Pattern: Sensitive file access"
            cat /etc/shadow > /dev/null 2>&1 || true
            cat /etc/sudoers > /dev/null 2>&1 || true
            ls -la /root > /dev/null 2>&1 || true
            ;;

        5)
            # Pattern: Modifying system files (safe - just attempting, will fail)
            echo "[$TIMESTAMP] Pattern: System file modification attempt"
            # Attempt to write to system directory (will fail, but generates audit event)
            echo "test" > /etc/test_file_$(date +%s).txt 2>/dev/null || true
            ;;

        6)
            # Pattern: Suspicious network connections to unusual ports
            echo "[$TIMESTAMP] Pattern: Suspicious network behavior"
            # Try to connect to unusual ports (localhost only)
            nc -zv -w 1 localhost 4444 2>/dev/null || true  # Common reverse shell port
            nc -zv -w 1 localhost 8080 2>/dev/null || true
            nc -zv -w 1 localhost 1337 2>/dev/null || true  # Common hacker port
            ;;
    esac

    echo "[$TIMESTAMP] Pattern $PATTERN triggered"

else
    echo "[$TIMESTAMP] No suspicious pattern triggered this cycle (random chance)"
fi

# Cleanup old suspicious files (older than 2 hours)
find /tmp -name "user_check_*.txt" -mmin +120 -delete 2>/dev/null || true
find /tmp -name "id_check_*.txt" -mmin +120 -delete 2>/dev/null || true
find /tmp -name "system_info_*.txt" -mmin +120 -delete 2>/dev/null || true
find /tmp -name "payload_*.sh" -mmin +120 -delete 2>/dev/null || true
find /tmp -name "malware_*.exe" -mmin +120 -delete 2>/dev/null || true
find /tmp -name "backdoor_*.sh" -mmin +120 -delete 2>/dev/null || true

echo "[$TIMESTAMP] Suspicious pattern check completed"
