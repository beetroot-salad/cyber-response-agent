#!/bin/bash
# DNS stress scenario for soc-agent eval on rule 100110 (high-entropy subdomain).
#
# Fires ~11 high-entropy A-record DNS queries to three fake parent domains
# over ~100 seconds. All queries resolve successfully (via dnsmasq wildcard
# address synthesis) so none of the co-fire rules trip:
#
#   - 100112 (TXT queries)            — NOT fired: only A queries
#   - 100113 (8 NXDOMAIN in 120s)     — NOT fired: wildcard resolves everything
#   - 100115 (known-bad string match) — NOT fired: no malware-c2|callback.evil|beacon.*.cc
#   - 100116 (15 queries in 60s)      — NOT fired: ~11 queries over ~100s
#
# Staying out of the co-fire envelope forces the investigation agent into the
# 4-starter-hypothesis characterization loop (cdn / analytics / dga / tunneling)
# rather than short-circuiting to the co-fired-malicious-pattern archetype.
#
# The three parents are shaped to seed different starter hypotheses:
#
#   edge.eventloop-cdn.net     4 queries, 12-char hex subdomain    -> ?cdn-or-cloud-service vs ?dga-malware
#   beacon.trackpixel-io.com   4 queries, 14-char base32 subdomain -> ?analytics-or-tracking vs ?dns-tunneling
#   api.ghostnebula.net        3 queries, 16-char mixed-alnum      -> ?dga-malware (pure unknown)
#
# Usage: docker exec target-endpoint /opt/workloads/dns_stress.sh

set -u

TS=$(date '+%Y-%m-%d %H:%M:%S')
echo "[$TS] DNS stress scenario starting"

PARENTS=(edge.eventloop-cdn.net beacon.trackpixel-io.com api.ghostnebula.net)

# Install dnsmasq wildcard address records so all subdomains of these parents
# resolve to a fixed RFC1918 address. Idempotent: only append if not present.
NEEDS_RELOAD=0
for p in "${PARENTS[@]}"; do
    if ! grep -q "^address=/$p/" /etc/dnsmasq.conf; then
        echo "address=/$p/10.0.0.1" >> /etc/dnsmasq.conf
        NEEDS_RELOAD=1
    fi
done

if [ "$NEEDS_RELOAD" = "1" ]; then
    echo "[$TS] Reloading dnsmasq config"
    killall -HUP dnsmasq
    sleep 1
fi

# Generate query labels.
gen() { tr -dc "$1" < /dev/urandom | head -c "$2"; }

queries=()
for _ in 1 2 3 4; do queries+=("$(gen 'a-f0-9' 12).edge.eventloop-cdn.net"); done
for _ in 1 2 3 4; do queries+=("$(gen 'a-z2-7' 14).beacon.trackpixel-io.com"); done
for _ in 1 2 3;   do queries+=("$(gen 'a-zA-Z0-9' 16).api.ghostnebula.net"); done

# Shuffle so the three clusters are interleaved (not sequentially grouped).
readarray -t shuffled < <(printf '%s\n' "${queries[@]}" | shuf)

echo "[$TS] Firing ${#shuffled[@]} queries with 5-11s jitter"

for q in "${shuffled[@]}"; do
    # @127.0.0.1 ensures we hit the local dnsmasq that wazuh is decoding.
    reply=$(dig +short +timeout=2 +tries=1 "$q" @127.0.0.1 2>/dev/null | head -n1)
    echo "  q=$q  reply=${reply:-<empty>}"
    sleep "$(awk 'BEGIN{srand(); print 5+rand()*6}')"
done

END_TS=$(date '+%Y-%m-%d %H:%M:%S')
echo "[$END_TS] DNS stress scenario complete"