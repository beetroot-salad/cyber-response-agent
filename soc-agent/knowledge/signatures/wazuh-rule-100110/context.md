---
signature_id: wazuh-rule-100110
name: DNS query with high-entropy subdomain
severity: medium
data_sources:
  - network-events
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

Custom Wazuh rule. The fundamental detected activity: **a DNS query was
issued whose leading label is at least 12 alphanumeric characters long.**

The activity is observed via the local dnsmasq resolver on the endpoint,
which logs every query through syslog. A custom Wazuh decoder
(`dnsmasq-query`) parses the syslog line into `dns_query_type`,
`dns_domain`, and `srcip` fields. Rule 100100 catches every parsed query;
rule 100110 narrows to queries whose `dns_domain` matches a regex
requiring 12+ alphanumerics in the leftmost label followed by a parent
domain. See `playground/config/wazuh_cluster/rules/dns_rules.xml`.

The rule does **not** compute Shannon entropy or any real randomness
measure — only label length. A 12-character English word matches the same
as a 12-character base32 blob.

This is a deliberate stress-test signature: the rule is broad and
ambiguous by design. Many legitimate services emit DNS queries that match
this shape. Resolving these alerts requires domain knowledge the rule
cannot encode.

## Related Rules

| Rule ID | Description | Relationship |
|---------|-------------|--------------|
| 100100 | Base DNS query event | Parent rule (always fires first via `if_sid`) |
| 100101 | DNS reply NXDOMAIN | Useful correlator for DGA |
| 100112 | TXT query | Often paired with tunneling cases |
| 100113 | NXDOMAIN burst (8 in 120s) | Strong DGA signal when correlated |
| 100115 | Known malicious domain pattern | Higher-confidence sibling |
| 100116 | High-volume DNS queries (15 in 60s) | Useful for beaconing/tunneling cases |

## Threat & Motivation

**What the activity is.** A process on the endpoint called the resolver
(directly or via libc) for a domain name with a long leading label. At
the OS level this is a `connect()` to the resolver socket and a DNS
packet on the wire. dnsmasq is the local intercept that lets us see it
without taking a pcap.

**Why an attacker would do this.** Two main use cases:

- **DGA C2 (T1568.002):** Malware embeds a domain-generation algorithm.
  At runtime it generates many candidate domains, queries each one, and
  uses whichever resolves to find its current C2 controller. Most queries
  return NXDOMAIN; one resolves and becomes the live channel. Defenders
  who block known C2 domains can't keep up because the domains rotate.
- **DNS tunneling / exfiltration (T1071.004, T1048.003):** The attacker
  controls an authoritative server for some domain. The malware encodes
  data into DNS query labels (typically base32 because of DNS character
  restrictions) and queries them as subdomains of the controlled parent.
  The auth server logs the queries and reassembles the data. Often uses
  TXT or NULL records for two-way traffic.

**Concrete attacker scenarios:**
- Commodity malware (Conficker, Necurs, Sality) calling home via DGA
- Cobalt Strike or Sliver implants tunnelling over DNS in network-egress
  -restricted environments
- Slow exfiltration of credentials or files via base32-encoded subdomain
  labels to an attacker domain

**Legitimate reasons this fires.** A lot of the modern internet looks
like this. All of these are real and common:

- CDN cache keys and edge routing — CloudFront, Akamai, Fastly, Cloudflare
  all use long opaque hostnames
- Cloud services using opaque shard/region identifiers — AWS S3,
  GoogleUserContent, Azure CDN
- Browser anti-DNS-rebinding random subdomains
- Email tracking / link shortener / abuse-prevention domains
- Analytics, advertising, anti-fraud, and bot-detection telemetry
- Service workers and PWA cache lookups

**Blast radius if real.** Active C2 channel or ongoing data exfiltration.
The host issuing the query is presumed compromised.

## Risk Indicators

The risk on this signature comes from **two orthogonal axes**:

### Axis 1 — Reputation of the parent domain

Is the eTLD+1 a recognizable, established service in this environment, or
something unknown?

- Parent matches a known CDN / cloud / analytics provider allowlist
  (lower risk)
- Parent has been queried many times historically from this environment
  with varied subdomains (lower risk — established footprint)
- Parent is unknown / never queried before / recently registered (higher
  risk)
- Parent is in a frequently-abused TLD (.xyz, .top, .tk, .ml, ...; higher
  risk; rule 100111 fires when this is true)

### Axis 2 — Pattern shape and co-firing rules

Does the alert sit alone, or is it part of a recognizable C2/tunneling
pattern?

- Single isolated query, normal record type (A/AAAA), resolves
  successfully (lower risk in isolation; ambiguous without parent
  reputation)
- Burst of NXDOMAIN replies from the same host (rule 100113 co-fires;
  classic DGA probing signature)
- High volume of queries to varied subdomains under the same parent in a
  short window (rule 100116 co-fires; beaconing or tunneling)
- TXT or NULL record queries (rule 100112 co-fires; tunneling-favoured
  record types)
- Subdomain label is structured (base32/base64/hex chunks, fixed format
  across queries; possible encoded data)

A high-reputation parent + isolated normal-shape query is the low-risk
quadrant. An unknown/new parent + co-firing volume/NXDOMAIN/TXT rules is
the high-risk quadrant.

> **Stress-test note:** Treat every benign-looking match as a hypothesis
> to validate, not a fact to assume. The single biggest failure mode for
> this signature is dismissing a real C2 query as "looks like a CDN."
> Reputation classification is not a guarantee — domain-fronting and
> compromised legit services exist. Sanction must come from outside the
> SIEM (allowlist, threat-intel feed, etc.).

## Detection Gaps

- No process attribution — the query log contains no PID or process name.
- No client identification — `srcip` is the local resolver, not the
  originating client process.
- Real entropy is not measured; only label length. A 12-char English word
  matches; a 12-char base32 blob matches; an 11-char base32 blob doesn't.
- Encrypted DNS (DoH/DoT) bypasses the local resolver entirely and is
  invisible to this rule.
- Queries to subdomains shorter than 12 characters under controlled
  domains can still serve as tunneling channels and will not match.
- The regex requires the parent domain to have **exactly two labels**
  after the high-entropy leading label (`<12+ chars>.<label>.<label>`).
  Single-label parents (e.g., `xk3j2aab8f9q.localhost`) and deeper parents
  (e.g., `xk3j2aab8f9q.foo.bar.example.com`) match differently and may be
  missed depending on label boundaries.
