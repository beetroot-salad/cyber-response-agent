## CONTEXTUALIZE

**Alert:** 1777222124.21 — wazuh-rule-100110 (DNS query with high-entropy subdomain)
**Key observables:**
- srcip: 10.0.14.22 (corp-dev-22)
- dns_domain: x9p2qkz7m4lv8wnrt3fby0.cloudapp-cdn.example.net
- dns_subdomain_entropy: 3.94 (high — random-looking)
- dns_subdomain_length: 22 chars
- 5-min window: 412 NXDOMAIN, 387 distinct qnames, avg entropy 3.82
- timestamp: 2026-04-22T17:08:44.210+0000
**Playbook hypotheses:** ?dga-beaconing-process, ?legitimate-high-entropy-service, ?cdn-or-sharded-service, ?misconfigured-resolver
**Available leads:** per-process-dns-attribution, resolver-config-change-timeline, dns-reputation, baseline-qname-profile
**Archetype matches:**
- dga-beaconing — candidate — high per-label entropy (3.94) + large distinct-qname count in 5-min window (387) + high NXDOMAIN rate (412) match the DGA signature shape; attacker-controlled subset resolves while the rest miss.
- legitimate-cdn-sharding — candidate — some CDNs (cloudapp-cdn.example.net pattern) emit random-looking subdomains for cache sharding; resolved vs NXDOMAIN mix depends on backend state.
- misconfigured-local-resolver — candidate — systemd-resolved or stub-resolver config drift can turn previously-resolving names into NXDOMAIN across all processes on the host.
**Adversarial archetype:** dga-beaconing — the worst-case outcome; a compromised client process is iterating algorithmically-generated names to reach attacker infrastructure.
**Data environment:** reachable: host_query, wazuh, playground_ticket; degraded: elastic

```yaml
prologue:
  vertices:
  - id: v-001
    type: endpoint
    classification: internal-dev-workstation
    identifier: 10.0.14.22
    attributes:
      hostname: corp-dev-22
  - id: v-002
    type: domain
    classification: unclassified-domain
    identifier: x9p2qkz7m4lv8wnrt3fby0.cloudapp-cdn.example.net
    attributes:
      parent_zone: cloudapp-cdn.example.net
      label_entropy: 3.94
      label_length: 22
  edges:
  - id: e-001
    relation: emitted_queries
    source_vertex: v-001
    target_vertex: v-002
    when:
      timestamp: '2026-04-22T17:08:44.210Z'
    attributes:
      window_5min_nxdomain_count: 412
      window_5min_distinct_qnames: 387
      window_5min_avg_entropy: 3.82
    authority:
      kind: siem-event
      source: Wazuh (rule 100110) + dnsmasq decoder
```
