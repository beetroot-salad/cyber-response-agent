# Investigation: real-04-low-dns

## ORIENT

**Alert:** Wazuh rule 100110 — DNS query to domain with high-entropy subdomain (possible DGA/tunneling)  
**Timestamp:** 2026-05-07T14:26:48Z  
**Host:** `target-endpoint` (agent 002, IP 172.22.0.13)  
**Process:** `dnsmasq` — the local DNS resolver forwarded a query from `127.0.0.1`  
**Domain:** `c3Zjp9MCHnfKREE5.api.ghostnebula.net` (type A)  
**firedtimes:** 15 — alert fired 15 times (repeated queries)

**Behavior flagged:** A local process on `target-endpoint` sent repeated A-record queries for a high-entropy subdomain under `ghostnebula.net` through the local dnsmasq resolver. The subdomain prefix `c3Zjp9MCHnfKREE5` matches DGA or DNS-tunneling character distributions.

**Triage question:** Is this C2 beaconing / DNS tunneling from a compromised or malicious process, or is it a known benign tool's telemetry/health check? Disposition turns on: (1) which process is sending the queries, (2) query cadence and volume pattern, (3) domain reputation and prior org exposure.

```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|endpoint|endpoint:linux|target-endpoint|agent_id=002;agent_ip=172.22.0.13
v-002|endpoint|endpoint:dns-name|c3Zjp9MCHnfKREE5.api.ghostnebula.net|parent_domain=ghostnebula.net
v-003|process|process:system|dnsmasq[28]|role=local-dns-forwarder

:E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-001|queried_dns|v-001|v-002|2026-05-07T14:26:48Z|siem-event:wazuh|query_type=A;srcip=127.0.0.1;firedtimes=15;rule=100110
e-002|runs_on|v-003|v-001|2026-05-07T14:26:48Z|siem-event:wazuh|via=dnsmasq
```

## PLAN (loop 1)

Two competing explanations for repeated high-entropy subdomain queries:

- **?c2-dns-tunneling**: a malicious or compromised process on `target-endpoint` is using DNS as a C2/data-exfiltration channel. Prediction: queries are periodic/regular, no legitimate process with a known purpose would generate this subdomain, domain is novel/low-reputation.
- **?benign-tool-telemetry**: a known tool (monitoring agent, SDK, heartbeat) resolves a constructed domain as part of its normal operation. Prediction: queries map to a recognized process, domain has prior org exposure, cadence matches tool polling interval.

Leads for loop 1 — parallel dispatch:
- **l-001**: Query history for `ghostnebula.net` across `target-endpoint` (volume, cadence, all subdomains seen) — distinguishes one-off vs. sustained pattern.
- **l-002**: Process context on `target-endpoint` — which process tree is generating DNS from 127.0.0.1 at this time; are there other suspicious processes.

```invlang
:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|preds|refuts|authz?|weight|status]
h-001|?c2-dns-tunneling|v-002|queried_dns|process|adversary-c2-client|p1:proposed_parent:"no recognized legitimate process generates this subdomain pattern";p2:proposed_edge:"queries are periodic and subdomain entropy is consistent across all fires"|r1[p1,p2]:"queries trace to a known benign process with documented domain-construction behavior"||null|active
h-002|?benign-tool-telemetry|v-002|queried_dns|process|monitoring-agent|p1:proposed_parent:"known monitoring/telemetry tool on target-endpoint queries ghostnebula.net as part of normal operation";p2:proposed_edge:"subdomain is deterministically constructed (e.g. host-id hash), cadence matches polling interval"|r1[p1,p2]:"no known tool accounts for this domain; domain is novel org-wide"||null|active

:L findings [id|loop|name|target|tests|system|template|query|window]
l-001|1|dns-query-history-ghostnebula|v-002|h-001,h-002|wazuh|dns-query-history|domain=ghostnebula.net host=target-endpoint|7d
l-002|1|process-context-target-endpoint|v-001|h-001,h-002|wazuh|recent-rule-fires|host=target-endpoint|1h
```

## GATHER (loop 1)

Dispatched l-001 and l-002 in parallel.

**l-001 result (gather_raw/0.json):** 9 total DNS queries to ghostnebula.net subdomains over 7d. 6 distinct high-entropy subdomains under `api.ghostnebula.net` (e.g. `7ARacKkP58qcgLUB`, `7vVB8tc36ZIZryVw`, `Pn0k7qQb3z8TIO6I`, etc.). First seen 2026-05-05T10:59:02Z. Pattern: two episodic bursts (6 queries on 2026-05-05, 3 on 2026-05-07). Only `target-endpoint` queried ghostnebula.net. 3 of 9 queries returned NXDOMAIN (rule 100101). Template authored: `wazuh.dns-query-history`.

**l-002 result (gather_raw/1a.json, 1b.json):** 256 events on target-endpoint in past 1h. **Rule 100110 (high-entropy DNS) fired 31 times in the past hour** — far exceeding the 9 ghostnebula.net queries from l-001 over 7 days, implying other high-entropy domains are also being queried. Rule 5710 (SSH invalid user): 27 events from known monitoring sources (nagios, zabbix). Rule 550 (FIM): 18 events. Rule 510 (rootcheck): 22 events. Rule 533 (port change): 8. Sources: 127.0.0.1 (167 events, local dnsmasq), 172.22.0.10 (27 events, monitoring). No privilege escalation, lateral movement, or unknown external source IPs observed.

## ANALYZE (loop 1)

Critical discrepancy: rule 100110 fired 31× in 1h, but only 9 ghostnebula.net queries exist over 7 days. Implies **multiple C2 domains** beyond ghostnebula.net — the querying process is rotating across domains. This is a stronger C2/tunneling signal than a single-domain pattern.

```invlang
:R attr_updates [resolved_by|target|key|value]
l-001|v-002|query_count_7d|9
l-001|v-002|distinct_subdomain_count|6
l-001|v-002|first_seen|2026-05-05T10:59:02Z
l-001|v-002|nxdomain_count|3
l-001|v-002|fleet_peers_querying|0
l-002|v-001|rule_100110_fires_1h|31
l-002|v-001|activity_level|moderate-baseline
l-002|v-001|src_diversity|127.0.0.1+172.22.0.10-only

:T resolutions
h-001  null → +    [l-001 p1,p2 + l-002 p2 moderate ⟂ 6 distinct high-entropy subdomains under ghostnebula.net; 31 rule-100110 fires implies multiple C2 domains; only target-endpoint affected; no benign process identified; NXDOMAIN pattern consistent with C2 check-in failures]
h-002  null → --   [l-001 r1 severe ⟂ no known monitoring/telemetry tool generates 6+ rotating high-entropy subdomains across multiple domains; fleet peers = 0 contradicts any shared tool; 31 fires/hour far exceeds reasonable telemetry polling]
```

Loop 2 needed: characterize all distinct domains queried under rule 100110 in past 1h to understand full C2 scope. This is load-bearing — 31 fires vs. 9 ghostnebula queries means other C2 domains exist, which changes scope and urgency of escalation.

## PLAN (loop 2)

Lead:
- **l-003**: All rule 100110 fires on target-endpoint in past 7d, with domain breakdown — identify all C2 domains, query volume per domain, temporal clustering.

```invlang
:L findings [id|loop|name|target|tests|system|template|query|window]
l-003|2|all-high-entropy-dns-domains|v-001|h-001|wazuh|recent-rule-fires|rule=100110 host=target-endpoint|7d
```

## GATHER (loop 2)

**l-003 result (gather_raw/2.json):** 2,112 rule-100110 events over 7 days. 636 unique queried domains across 29 parent domains. Key findings:

- **`exfil.example.net`** — 94 queries with two hex-encoded subdomains:
  - `686f73...0a.exfil.example.net` (47 queries) — decodes to `hostname=target-endpoint&uid=0\n` (running as root)
  - `757365...0a.exfil.example.net` (47 queries) — decodes to `username=admin&password=secret\n` (credential exfiltration)
- **`staging-cdn{1-20}.xyz`** — 20 domains × 62 queries each = 1,240 total; `heartbeat.` prefix, uniform cadence (C2 heartbeat over 20 rotating domains)
- **`dynamicupdate.net`** — ~500 unique subdomains, 1 query each (DGA-style C2 beaconing)
- **`eventloop-cdn.net`** — hex-prefix unique subdomains, 1 query each (additional tunneling channel)
- **`account-verify.club`, `free-download.xyz`, `secure-login.top`, `update-service.buzz`** — 42 queries each, abused TLDs
- **`ghostnebula.net`** — original alert domain (6 queries)
- **Temporal pattern**: activity spans 2026-04-30 through 2026-05-07 (8 days); peak 2026-05-07T06:00Z (200 queries/6h bucket); gaps on 2026-05-04T18:00Z and 2026-05-06 (possibly C2 server downtime)

## ANALYZE (loop 2)

```invlang
:V l-003.observations.vertices [id|type|class|ident|attrs?]
v-004|endpoint|endpoint:dns-name|exfil.example.net|channel=dns-exfil
v-005|endpoint|endpoint:dns-name|dynamicupdate.net|channel=dga-c2
v-006|endpoint|endpoint:dns-name|eventloop-cdn.net|channel=dns-tunnel
v-007|endpoint|endpoint:dns-name|staging-cdn1-20.xyz|channel=c2-heartbeat;domain_count=20

:E l-003.observations.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-003|queried_dns|v-001|v-004|2026-04-30T12:00:00Z..2026-05-07T14:26:48Z|siem-event:wazuh|count=94;exfil_uid=0;exfil_creds=admin:secret
e-004|queried_dns|v-001|v-005|2026-04-30T12:00:00Z..2026-05-07T14:26:48Z|siem-event:wazuh|unique_subdomains=~500
e-005|queried_dns|v-001|v-006|2026-04-30T12:00:00Z..2026-05-07T14:26:48Z|siem-event:wazuh|hex_prefix_subdomains=true
e-006|queried_dns|v-001|v-007|2026-04-30T12:00:00Z..2026-05-07T14:26:48Z|siem-event:wazuh|count=1240;cadence=uniform;parent_domain_count=20

:R attr_updates [resolved_by|target|key|value]
l-003|v-001|rule_100110_total_7d|2112
l-003|v-001|c2_parent_domains|29
l-003|v-001|exfil_uid|0
l-003|v-001|exfil_creds_observed|username=admin;password=secret
l-003|v-001|c2_active_since|2026-04-30T12:00:00Z
l-003|v-001|process_identified|false

:T resolutions
h-001  + → ++   [l-003 p1,p2 severe ⟂ 2112 rule-100110 events over 8 days; confirmed DNS exfiltration of root credentials via hex-encoded subdomains; 29 parent C2 domains; DGA-style beaconing; no benign process accounts for this pattern]
h-002  -- → --  [l-003 r1 severe ⟂ no telemetry/monitoring tool generates multi-channel C2 across 29 domains with hex-encoded credential exfiltration in subdomains]
```

h-001 is at `++`. h-002 is at `--`. Ceiling: responsible process not identified — srcip=127.0.0.1 narrows to a local process on target-endpoint but process name / PID unknown without host-level query. The credential exfiltration and root-uid signal are sufficient to escalate immediately without waiting for process attribution.

## REPORT

```invlang
:T conclude
termination.category   adversarial-confirmed
termination.rationale  "Active multi-channel DNS C2 with confirmed credential exfiltration as root. Cannot identify responsible process from SIEM alone; escalate for host-level containment."
disposition            escalate
confidence             high
matched_archetype      dns-c2-tunneling
ceiling_rationale      "Responsible process not identified — SIEM shows srcip=127.0.0.1 (local dnsmasq forwarder) but no process attribution; host-level EDR or memory forensics required."
summary                "target-endpoint has been conducting active DNS-based C2 and exfiltration for 8 days (2026-04-30 to 2026-05-07). Confirmed: (1) credential exfiltration via hex-encoded DNS subdomains to exfil.example.net — payloads include hostname=target-endpoint&uid=0 and username=admin&password=secret, confirming root-level compromise; (2) 2,112 high-entropy DNS queries across 29 parent C2 domains including DGA-style beaconing (dynamicupdate.net ~500 unique subdomains), 20-domain rotating heartbeat (staging-cdn{1-20}.xyz, 1,240 queries), and additional tunneling channels (eventloop-cdn.net, ghostnebula.net). Benign telemetry explanation fully refuted. Process responsible for the queries is not identified from available SIEM data. Escalate for immediate host isolation and forensic investigation."

:T conclude.surviving [hyp_id|final_weight]
h-001|++
```
