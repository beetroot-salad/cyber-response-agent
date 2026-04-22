#!/bin/sh
# Pick the interface Zeek listens on at container start. In order of preference:
#   1. a soc-playground compose bridge (br-*, UP) — this is where inter-container
#      traffic flows; the playground's primary telemetry target.
#   2. eth0 — captures VPS ↔ public traffic only; useful but narrower.
# Bridge names are docker-assigned (br-<12-hex>) and change on network recreate,
# so we can't hardcode them. This script resolves at startup.
#
# Uses the Zeek_AF_Packet plugin (built into the LTS image). AF_PACKET avoids
# libpcap's "Promiscuous mode not supported on the 'any' device" limitation.
# `-C` ignores TCP checksums — Hetzner's NIC does checksum offloading, so Zeek
# would otherwise discard most packets as "invalid checksum".
set -eu

IFACE="$(ip -br link show type bridge up 2>/dev/null | awk '/^br-/ {print $1; exit}')"
: "${IFACE:=eth0}"

# Zeek writes logs to CWD. Drop them in the volume-backed logs dir so host-side
# log shippers (future batch) can mount it.
mkdir -p /usr/local/zeek/logs
cd /usr/local/zeek/logs

echo "zeek: capturing on ${IFACE} via af_packet; logs -> /usr/local/zeek/logs"
exec zeek -C -i "af_packet::${IFACE}" /usr/local/zeek/share/zeek/site/local.zeek
