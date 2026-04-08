---
signature_id: wazuh-rule-100110
name: DNS query with high-entropy subdomain
severity: medium
data_sources:
  - dnsmasq
  - /var/log/syslog
created_at: 2026-04-08
updated_at: 2026-04-08
mitre:
  tactics: Command and Control, Exfiltration
  techniques: T1568.002, T1071.004, T1048.003
references:
  - https://attack.mitre.org/techniques/T1568/002/
related_signatures:
  - wazuh-rule-100112
  - wazuh-rule-100113
  - wazuh-rule-100115
  - wazuh-rule-100116
base_rate:
  benign_pct: null
  sample_size: null
---

# Wazuh Rule 100110: DNS query with high-entropy subdomain

## Signature Logic

Custom rule 100110 fires when a DNS query is observed (via the local dnsmasq
resolver, decoded into the `dnsmasq-query` decoder) and the queried
`dns_domain` contains a leading label of 12 or more alphanumeric characters
followed by a parent domain. The intent is to flag domain-generation-algorithm
(DGA) and DNS-tunneling patterns where data or pseudo-random labels appear in
the subdomain.

The rule is intentionally broad — it does **not** compute true entropy, only
match a length/character pattern. See
`playground/config/wazuh_cluster/rules/dns_rules.xml`.

This is a stress-test signature: the underlying detection is inherently
ambiguous. Many legitimate services (CDNs, cloud providers, analytics
platforms, PWAs) emit DNS queries that match this shape, and attackers
deliberately blend into that noise. Resolving these alerts requires domain
knowledge that the rule cannot encode.

## Alert Fields

| Field | JSON Path | Description | Example |
|-------|-----------|-------------|---------|
| Query type | `data.dns_query_type` | DNS record type | `A`, `AAAA`, `TXT` |
| Domain | `data.dns_domain` | Queried FQDN | `xk3j2aab8f9q.example.com` |
| Source IP | `data.srcip` | Querying client (as seen by dnsmasq) | `127.0.0.1` |
| Agent | `agent.name` | Host running dnsmasq | `target-endpoint` |

> **Note:** Because dnsmasq runs locally on the endpoint, `data.srcip` is
> almost always `127.0.0.1`. The querying *process* is not visible from the
> dnsmasq log alone. Process attribution requires correlating with auditd,
> Falco, or similar host telemetry.

## Related Rules

| Rule ID | Description | Relationship |
|---------|-------------|--------------|
| 100100 | Base DNS query event | Parent rule (always fires first) |
| 100101 | DNS reply NXDOMAIN | Useful correlator for DGA |
| 100112 | TXT query | Often paired with tunneling cases |
| 100113 | NXDOMAIN burst (8 in 120s) | Strong DGA signal when correlated |
| 100115 | Known malicious domain pattern | Higher-confidence sibling |
| 100116 | High-volume DNS queries (15 in 60s) | Useful for beaconing/tunneling cases |

## Threat & Motivation

Attackers use high-entropy subdomains for two main reasons:

- **DGA C2 (T1568.002):** Malware iterates a list of algorithmically
  generated domains until it finds an active controller. Most queries return
  NXDOMAIN; one returns a valid IP.
- **DNS tunneling / exfiltration (T1071.004, T1048.003):** Data is encoded
  into the subdomain label of queries to a controlled domain, where the
  authoritative server decodes and reassembles it. Typically uses TXT,
  NULL, or A records.

**Blast radius if real:** Active C2 channel or ongoing data exfiltration. The
host issuing the query is presumed compromised.

## Known False Positives

Not yet characterized for this environment. The rule's design — a 12+ char
alphanumeric leading label — is known to overlap with several legitimate
patterns on the modern internet, but the specific patterns dominant in
this environment are unknown. Populate from real tickets as they accumulate.

> **Stress-test note:** Treat every benign-looking match as a hypothesis to
> validate, not a fact to assume. The single biggest failure mode for this
> signature is dismissing a real C2 query as "looks like a CDN".

## Risk Indicators

### Lower Risk
1. Parent domain (eTLD+1) belongs to a well-known CDN, cloud provider, or
   analytics platform
2. Query is for a common record type (A, AAAA) and resolved successfully
3. Source host has no other suspicious activity in the surrounding window
4. The same parent domain has been queried many times historically with
   varied subdomains (consistent CDN behaviour)

### Higher Risk
1. Parent domain is unknown or recently registered
2. Query is `TXT`, `NULL`, or another record type unusual for endpoint use
3. Burst of NXDOMAIN replies from the same host (rule 100113 also fired)
4. High volume of queries to varied subdomains under the same parent in a
   short window (rule 100116 also fired)
5. Subdomain label encodes recognizable structure (base32/base64/hex chunks,
   length/format consistent with data encoding)
6. Source host has correlated process, file, or network alerts
7. Parent domain is in a frequently-abused TLD (rule 100111 also fired)

## Field Notes

- dnsmasq's source IP field is essentially always `127.0.0.1` in this setup
  because the resolver runs locally on the endpoint. Source attribution
  must come from process-level telemetry, not the DNS event itself.
- Successful resolution does not imply benign — DGA controllers and
  tunneling endpoints both resolve normally.
- Subdomain entropy is approximated by length, not measured. A 12-char
  English word will match the rule. A 12-char base32 string will also match.
  The rule cannot tell them apart.
- Rule 100110 fires per query. Correlate with 100113 (NXDOMAIN burst) and
  100116 (volume) to recognize DGA and beaconing patterns.

## Impact

If real, this is C2 or active exfiltration. The originating host should be
treated as compromised pending investigation.

## Operational Notes

To be populated from real investigations.

## Tuning Guidance

The rule is intentionally broad. The right tuning lever is allowlisting
**parent domains** (eTLD+1) once they have been characterized as benign
high-entropy emitters in this environment, rather than relaxing the regex.
Allowlists belong in a Wazuh CDB list, not in the rule file.

## Detection Gaps

- No process attribution — the query log contains no PID or process name.
- No client identification — `srcip` is the local resolver, not the original
  client process.
- Real entropy is not measured; only label length is checked. Genuinely
  random short labels (≤11 chars) will not match.
- Encrypted DNS (DoH/DoT) bypasses the local resolver entirely and is
  invisible to this rule.
- Queries to subdomains shorter than 12 characters under controlled domains
  can still serve as tunneling channels and will not match.
- The rule's regex requires the parent domain to have **exactly two labels**
  after the high-entropy leading label (`<12+ chars>.<label>.<label>`).
  Single-label parents (e.g., `xk3j2aab8f9q.localhost`) and deeper parents
  (e.g., `xk3j2aab8f9q.foo.bar.example.com`) match differently and may be
  missed depending on label boundaries.
