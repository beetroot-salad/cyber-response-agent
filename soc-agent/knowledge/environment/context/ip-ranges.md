---
tags: [network, classification]
---

# IP Ranges

Classification heuristics for source/destination IPs. Consult when an alert
carries an IP and you need to answer "is this internal?", "is this a known
monitoring host?", "is this a DMZ subnet?" — without having to query CMDB.

## Classification Logic

1. Match against known **host-specific** entries (most specific first) — these
   are individual hosts with a known purpose (monitoring, jump box, CI runner).
2. Match against known **subnet** entries — purpose-segmented ranges (monitoring
   VLAN, production tier, DMZ).
3. Fall through to **RFC1918 / RFC4193** classification — any private range is
   "internal, purpose unknown". Public IPs are "external".

Host-specific and subnet entries only apply when the IP is on a known network
the agent has visibility into. A 10.0.0.0/8 IP from an alert on a cloud tenant
you don't control is just "private address space" — not "our internal network".

## Template — Real Org Conventions

<!-- Example — replace with actual org network map
| Range / Host | Classification | Notes |
|---|---|---|
| 10.1.0.0/16 | internal production | Prod VPC, west region |
| 10.2.0.0/16 | internal corp | Corporate WAN |
| 10.1.10.0/24 | internal monitoring subnet | Prometheus + Grafana + probes |
| 10.1.10.5 | internal monitoring host | nagios-primary |
| 10.1.10.6 | internal monitoring host | zabbix-primary |
| 192.168.99.0/24 | internal dmz | External-facing services |
-->

## Playground Deployment

The `cyber-response-agent_devcontainer` compose project uses a single bridge
network (`response-network`, `172.22.0.0/16`). Host assignments are stable
across recreates for services that pin `ipv4_address`; everything else gets
auto-assigned within the same /16.

| Range / Host | Classification | Notes |
|---|---|---|
| 172.22.0.0/16 | internal | Entire compose network — no public routing |
| 172.22.0.10 | **internal monitoring host** | `monitoring-host` container — runs scheduled SSH health-check probes against `target-endpoint`. Stable IP (pinned in `.devcontainer/docker-compose.yml`). Expected behavior: single-attempt SSH to target-endpoint every ~10 min using monitoring-pattern usernames (nagios, zabbix, healthcheck, monitorprobe, sensu). Manually-triggered multi-attempt variants exist for adversarial evaluation scenarios (see `playground/monitoring-host/workloads/monitoring_bait.sh`) — those should NOT match the monitoring-probe screen pattern. |
| ::1 | loopback | Same-host traffic, almost always a workload misconfiguration or a test trigger |

**How to use this in investigations:** when the source `srcip` on a 5710 alert
matches `172.22.0.10`, the source-reputation lead should classify it as an
internal monitoring host. That alone does NOT justify a SCREEN match — the
monitoring-probe screen pattern also requires `attempt_count: 1` and
`successful_login_after: false`. A single probe per tick → monitoring-probe.
A burst from the same host → not monitoring-probe, fall through to full loop.
