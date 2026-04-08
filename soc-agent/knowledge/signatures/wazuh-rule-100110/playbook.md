---
signature_id: wazuh-rule-100110
last_updated: 2026-04-08
total_investigations: 0
resolution_rate: null
---

# Investigation Playbook: DNS query with high-entropy subdomain (100110)

> **Stress test:** This signature is inherently ambiguous. Many legitimate
> services produce DNS queries that match the rule's pattern. The
> investigation goal is **not** to "prove benign" — it is to determine
> whether the query fits a known legitimate pattern *for this environment*
> or whether it could plausibly be C2 or tunneling. When in doubt, escalate.

## Hypothesis Catalog

### ?cdn-or-cloud-service
A legitimate CDN, cloud provider, or hosted service that uses high-entropy
subdomain labels as part of normal operation (cache keys, region routing,
TLS SNI hashes, anti-cache pinning).

**Typical profile:** Parent domain (eTLD+1) belongs to a recognizable
provider (e.g., `cloudfront.net`, `akamaiedge.net`, `azureedge.net`,
`s3.amazonaws.com`, `googleusercontent.com`); query type is A/AAAA;
historically many queries to this parent with varied subdomains; resolution
succeeds.

### ?analytics-or-tracking
A web analytics, telemetry, advertising, or anti-fraud platform that
generates per-event or per-session subdomains.

**Typical profile:** Parent domain belongs to a known analytics/ads/tracking
provider; A or AAAA queries; resolves successfully; bursty pattern that
correlates with user web activity windows.

### ?dga-malware
Domain-generation-algorithm malware probing for an active C2 controller.

**Typical profile:** Many queries to varied high-entropy domains across one
or more parents with no prior history in the environment. NXDOMAIN bursts
(rule 100113 co-firing) are a strong but **not required** signal — a DGA
that has already located its active controller will produce mostly
successful resolutions to a small set of domains, so absence of NXDOMAIN
bursts does not refute this hypothesis on its own. Subdomain shape varies
by family: some are uniformly random alphanumerics, others (e.g., Suppobox,
Matsnu) concatenate dictionary words or syllables and look pronounceable.

### ?dns-tunneling
Data encoded into DNS query labels to a controlled authoritative server,
used for C2 or exfiltration.

**Typical profile:** Subdomain label is long and structured (base32/base64/hex
chunks, fixed length, predictable format); high query volume to the same
parent under varying subdomains; may use TXT or NULL record types
(rule 100112 co-fires); queries resolve (no NXDOMAIN bursts).

---

## Lead List

### parent-domain-classification
**Query:** Extract eTLD+1 from `data.dns_domain` and classify it. Is the
parent a known CDN, cloud provider, analytics platform, or other
recognizable service? Has it been queried before from this environment?

**Discriminates:** Benign-provider hypotheses vs adversary hypotheses.

| Hypothesis | Prediction |
|------------|------------|
| ?cdn-or-cloud-service | Parent matches known CDN/cloud allowlist |
| ?analytics-or-tracking | Parent matches known analytics/ads/tracking provider |
| ?dga-malware | Parent unknown, recently registered, or absent from historical queries |
| ?dns-tunneling | Parent unknown or low-reputation; may be a controlled lookalike |

### query-history-for-parent
**Query:** All DNS queries from this environment to the same eTLD+1 in the
last 7-30 days. How many distinct subdomains? What query types? What
reply distribution (success vs NXDOMAIN)?

**Discriminates:** Established behaviour vs new/anomalous activity.

| Hypothesis | Prediction |
|------------|------------|
| ?cdn-or-cloud-service | Long history, many subdomains, mostly successful resolutions |
| ?analytics-or-tracking | Long history, many subdomains, mostly successful resolutions |
| ?dga-malware | No history for the parent(s); may show NXDOMAIN bursts (probing phase) or steady successful resolutions to a small set (post-rendezvous) |
| ?dns-tunneling | No history or sudden volume increase under the same parent |

### nxdomain-and-volume-correlation
**Query:** Did rule 100113 (NXDOMAIN burst) or 100116 (high-volume queries)
fire from the same agent in the surrounding window (±5 min)?

**Discriminates:** DGA / tunneling vs benign provider noise.

| Hypothesis | Prediction |
|------------|------------|
| ?cdn-or-cloud-service | No co-firing |
| ?analytics-or-tracking | No co-firing, possibly some volume |
| ?dga-malware | Rule 100113 co-fires (NXDOMAIN burst is the canonical DGA signal) |
| ?dns-tunneling | Rule 100116 co-fires; possibly 100112 if TXT records used |

### subdomain-shape
**Query:** Inspect the leading label of `data.dns_domain`. Is it a
recognizable English word, a hash-like alphanumeric blob, base32/base64
encoded, or hex? What is its length and character distribution?

**Discriminates:** Encoded data vs random vs human-meaningful.

| Hypothesis | Prediction |
|------------|------------|
| ?cdn-or-cloud-service | Hash-like, fixed length matching the provider's pattern |
| ?analytics-or-tracking | Hash-like or short token, typical of session/event IDs |
| ?dga-malware | Family-dependent: random alphanumerics, dictionary-word concatenation, or syllable concatenation; length usually consistent within a family |
| ?dns-tunneling | Long, dense, base32/base64/hex chunks; often fixed format across queries |

### host-context
**Query:** Other alerts from the same agent in the last 24h, especially
process events (100001+), file changes (550), or auth anomalies (5710+).

**Discriminates:** Whether the DNS event is isolated or part of a chain.

| Hypothesis | Prediction |
|------------|------------|
| ?cdn-or-cloud-service | Clean host context |
| ?analytics-or-tracking | Clean host context |
| ?dga-malware | May correlate with process, file, or persistence alerts |
| ?dns-tunneling | May correlate with process or network alerts |

---

## Start With

**`parent-domain-classification`** — the eTLD+1 is the strongest single
signal. Most CDN/cloud parents are recognizable, and an unknown parent is
the first indicator that the alert deserves real investigation rather than
fast-path resolution.

Follow with `query-history-for-parent` to confirm whether the parent has an
established footprint in this environment, then `nxdomain-and-volume-correlation`
to look for DGA/tunneling co-signals, and `subdomain-shape` to characterize
the label.

---

## Auto-Close Criteria

All must be true:
1. Exactly one hypothesis remains with `++` support
2. Both adversary hypotheses (DGA, tunneling) have `--` refutation
3. A matching precedent exists in `precedents/`
4. No co-firing of rules 100112, 100113, 100115, or 100116 in the surrounding window
5. `confidence` is `high`

> **Note:** Given how broad this rule is, the bar for auto-close is
> deliberately high. When the parent domain is unknown or unrecognized,
> escalate rather than guess.

> **DGA vs DNS-tunneling discrimination is not required for escalation.**
> Both are escalation outcomes — the agent does not need to pick between
> them. If evidence supports either, escalate with both listed as active
> threat hypotheses and let the human investigator (with WHOIS, threat
> intel, and host forensics) make the final call.

## Escalation Criteria

Escalate immediately if ANY:
- Parent domain (eTLD+1) is not recognizable as a known provider and is not
  established in environment history
- Rule 100113 (NXDOMAIN burst) co-fired from the same agent in the
  surrounding window
- Rule 100112 (TXT query) or 100115 (known malicious pattern) co-fired
- Rule 100116 (high-volume queries) co-fired and the queries are spread
  across distinct subdomains under one parent
- Subdomain label is structured in a way consistent with encoded data
  (base32/base64/hex blocks, fixed format)
- Correlated non-DNS alerts on the same host in the surrounding window
- A field a lead depends on (`dns_domain`, `dns_query_type`, etc.) is
  missing from the alert and cannot be retrieved — do not guess
- No hypothesis reaches `++` after pursuing all leads

## Scope

Investigation covers the alerting query, other DNS events to the same eTLD+1
from the same agent in a ±15 minute window (and the broader 7-30 day history
for that parent), and other alerts from the same agent in the last 24 hours.
Do not expand beyond the originating host without escalating.
