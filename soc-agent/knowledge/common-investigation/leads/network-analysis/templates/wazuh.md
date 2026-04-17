---
lead: network-analysis
vendor: wazuh
tags: [network, wazuh_alerts, profile]
entity_fields:
  ip: data.srcip
  dst_ip: data.dstip
  host: agent.name
  port: data.dstport
indexes: [wazuh-alerts-*]
---

# Wazuh Query Template: network-analysis

## Availability Caveat

Wazuh only sees network telemetry that a decoder has parsed from an
ingested log source. **Before trusting any result from this template,
confirm network data is actually flowing** — check
`environment/data-sources/network-events.md` and run the health
check below. An empty result may mean "no network activity" or "no
network logs ingested"; those are very different conclusions.

Common Wazuh rule groups that carry network data (availability
depends on what the manager is ingesting):

| Rule group           | Source                                       |
|----------------------|----------------------------------------------|
| `firewall`           | Generic firewall logs                        |
| `iptables`           | Linux iptables/nftables                      |
| `pf`                 | OpenBSD/FreeBSD packet filter                |
| `suricata` / `ids`   | Suricata IDS/IPS                             |
| `ossec,syscheck`     | Not network — do not use                     |

## Entity Field Mapping

| Entity type | Wazuh field   | Notes                                       |
|-------------|---------------|---------------------------------------------|
| ip          | data.srcip    | Source IP of the connection                 |
| dst_ip      | data.dstip    | Destination IP                              |
| host        | agent.name    | Host that collected the event (see field-quirks.md) |
| port        | data.dstport  | Destination port; source port is data.srcport |

Not every decoder populates every field. For firewall logs specifically,
`data.action`, `data.protocol`, `data.srcport`, `data.dstport`,
`data.bytes` are the common extracted fields — but coverage varies by
log format. When a field is missing, fall back to raw-log search
(`full_log:"<literal>"`) rather than assuming the event didn't occur.

## Health Check (run first)

Before querying by entity, confirm network events are present at all:

```bash
python3 scripts/tools/wazuh_cli.py query \
  --query 'rule.groups:(firewall OR iptables OR pf OR suricata)' \
  --window 1h --limit 5
```

Zero hits across a 1h window with non-zero overall alert volume is a
strong signal that this deployment does not ingest network logs —
do not proceed; report the gap and escalate to the main agent.

## Base Query

```
rule.groups:(firewall OR iptables OR suricata) AND {entity_field}:{entity_value}
```

Narrow the rule-group set to whichever groups the health check
confirmed are live.

## Example Invocations

Outbound connections from a host, last 2 hours:
```bash
python3 scripts/tools/wazuh_cli.py query \
  --query 'rule.groups:(firewall OR iptables) AND data.srcip:10.0.0.5' \
  --start 2026-04-17T10:00:00Z --window 2h
```

Connections to a specific destination IP (possible C2 peer):
```bash
python3 scripts/tools/wazuh_cli.py query \
  --query 'rule.groups:(firewall OR iptables OR suricata) AND data.dstip:203.0.113.42' \
  --start 2026-04-17T08:00:00Z --end 2026-04-17T12:00:00Z
```

Traffic on a specific destination port (non-standard service use):
```bash
python3 scripts/tools/wazuh_cli.py query \
  --query 'rule.groups:firewall AND data.dstport:"4444"' \
  --window 24h
```

Suricata IDS hits for a host (signature-based network alerts):
```bash
python3 scripts/tools/wazuh_cli.py query \
  --query 'rule.groups:suricata AND agent.name:web-server-01' \
  --window 24h
```

## Baseline (Shift Query)

Grade rate/volume claims by re-running the same query against a
prior window of equal duration — shift `--start` back 7 days,
keep `--window` identical.

Current window (observed):
```bash
python3 scripts/tools/wazuh_cli.py query \
  --query 'rule.groups:(firewall OR iptables) AND data.srcip:10.0.0.5 AND data.dstip:203.0.113.42' \
  --start 2026-04-17T10:00:00Z --window 2h
```

Baseline window (same pair, 7 days earlier, same duration):
```bash
python3 scripts/tools/wazuh_cli.py query \
  --query 'rule.groups:(firewall OR iptables) AND data.srcip:10.0.0.5 AND data.dstip:203.0.113.42' \
  --start 2026-04-10T10:00:00Z --window 2h
```

For beaconing cadence, pull raw events (`--raw`) from both windows
and compare inter-connection interval distributions. A 7-day shift
captures weekly seasonality (business-hour vs off-hour traffic);
widen to 30d only if the 7d baseline is too sparse to be
meaningful. If the entity is a short-lived host or container,
substitute "peer host in the same role" — a same-host 7d baseline
is meaningless when the host didn't exist then.

## Customization Notes

- To filter accept vs drop on firewall logs: add `AND data.action:drop`
  (or `accept`). Action vocabularies vary by firewall vendor — check
  a sample event before assuming.
- To scope to external destinations only (rough filter): combine with
  a negated RFC1918 match, e.g. `AND NOT data.dstip:(10.0.0.0/8 OR
  172.16.0.0/12 OR 192.168.0.0/16)`. Lucene CIDR support depends on
  index mapping; if this errors, fall back to prefix matches.
- For raw JSON (programmatic parsing of inter-arrival times, byte
  sums): add `--raw`.
