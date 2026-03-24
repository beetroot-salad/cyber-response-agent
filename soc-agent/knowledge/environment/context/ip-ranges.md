---
tags: [network, ip-classification]
---

# IP Ranges

## Standard Private Ranges (Internal)

| CIDR | Range | Typical Use |
|------|-------|-------------|
| 10.0.0.0/8 | 10.0.0.0 – 10.255.255.255 | Large enterprise networks |
| 172.16.0.0/12 | 172.16.0.0 – 172.31.255.255 | Medium networks, cloud VPCs |
| 192.168.0.0/16 | 192.168.0.0 – 192.168.255.255 | Small networks, home labs |

## Special Ranges

| CIDR | Meaning |
|------|---------|
| 127.0.0.0/8 | Loopback (localhost) |
| 169.254.0.0/16 | Link-local (APIPA / unconfigured DHCP) |
| 100.64.0.0/10 | Carrier-grade NAT |

## Org-Specific Subnets

<!-- Example — replace with actual org subnets
| Subnet | Purpose | Notes |
|--------|---------|-------|
| 10.0.1.0/24 | Monitoring | Nagios, Zabbix hosts |
| 10.0.2.0/24 | Application servers | Production web tier |
| 10.10.0.0/16 | VPN clients | Remote access pool |
-->

## NAT Gateways

When source IP is a NAT gateway, single-IP attribution is unreliable.
Check for additional discriminators (username, session ID).

<!-- Example — replace with actual NAT/proxy IPs
| IP | Type | Aggregates |
|----|------|------------|
| 10.0.0.1 | NAT gateway | All outbound from 10.0.0.0/24 |
-->

## Risk Implications

| Source | Initial Risk | Notes |
|--------|--------------|-------|
| Internal (RFC1918) | Lower | But compromised hosts exist — don't assume safe |
| External | Higher | Requires more scrutiny |
| NAT gateway | Uncertain | Multiple sources collapsed into one IP |
| Loopback | Very low | Local process communication |
