---
signature_id: wazuh-rule-100110
last_updated: 2026-04-09
total_investigations: 0
resolution_rate: null
---

# Investigation Playbook: DNS query with high-entropy subdomain (100110)

This playbook is **steering, not procedure**. The investigation
methodology lives in the `investigate` skill.

> **Stress test:** This signature is inherently ambiguous. Many
> legitimate services produce DNS queries that match the rule's
> pattern. The investigation goal is **not** to "prove benign" — it
> is to determine whether the query fits a known legitimate pattern
> *for this environment* or whether it could plausibly be C2 or
> tunneling. When in doubt, escalate.

The archetype catalog under `archetypes/` is partial: only the
escalation archetype `co-fired-malicious-pattern` is authored so
far. The remaining common patterns are listed as starter hypotheses.

## Field shortcuts

| Field | Purpose |
|---|---|
| `data.dns_domain` | The full queried domain — extract the eTLD+1 for parent classification |
| `data.dns_query_type` | Query type (A, AAAA, TXT, NULL) — encoded-data hypotheses prefer TXT and NULL |

## Archetypes

| Archetype | One-line description | File |
|---|---|---|
| `co-fired-malicious-pattern` | High-entropy query alongside 100112/100113/100115/100116 co-firing — escalation outcome | `archetypes/co-fired-malicious-pattern.md` |

## Starter hypotheses

The remaining common patterns. Note that the benign-shape stories
share many primitives with each other and with the adversary
stories; discrimination requires more than pattern matching.

### ?cdn-or-cloud-service
A legitimate CDN, cloud provider, or hosted service that uses
high-entropy subdomain labels for cache keys, region routing, TLS
SNI hashes, or anti-cache pinning. Parent domain (eTLD+1) belongs
to a recognizable provider (`cloudfront.net`, `akamaiedge.net`,
`azureedge.net`, `s3.amazonaws.com`, `googleusercontent.com`);
query type is A/AAAA; historically many queries to this parent
with varied subdomains; resolution succeeds.

### ?analytics-or-tracking
A web analytics, telemetry, advertising, or anti-fraud platform
that generates per-event or per-session subdomains. Parent domain
belongs to a known analytics/ads/tracking provider; A/AAAA queries;
resolves successfully; bursty pattern correlating with user web
activity windows.

### ?dga-malware
Domain-generation-algorithm malware probing for an active C2
controller. Many queries to varied high-entropy domains across one
or more parents with no prior history in the environment. NXDOMAIN
bursts are a strong signal but not required — a DGA that has
already located its active controller will produce mostly
successful resolutions to a small set of domains.

### ?dns-tunneling
Data encoded into DNS query labels to a controlled authoritative
server, used for C2 or exfiltration. Subdomain label is long and
structured (base32/base64/hex chunks, fixed length, predictable
format); high query volume to the same parent under varying
subdomains; may use TXT or NULL record types.

## Starter lead order

1. **`parent-domain-classification`** — extract the eTLD+1 from
   `data.dns_domain` and classify it. Is the parent a known CDN,
   cloud provider, analytics platform, or other recognizable
   service? Has it been queried before from this environment? The
   eTLD+1 is the strongest single signal.
2. **`query-history-for-parent`** — all DNS queries from this
   environment to the same eTLD+1 in the last 7-30 days. How many
   distinct subdomains? What query types? What reply distribution
   (success vs NXDOMAIN)?
3. **`subdomain-shape`** — inspect the leading label of
   `data.dns_domain`. Recognizable English word, hash-like
   alphanumeric, base32/base64 encoded, or hex? What is its length
   and character distribution?

> **Co-firing of 100112/100113/100115/100116** is handled by the
> ticket-context subagent at CONTEXTUALIZE — its findings are
> already in the investigation context. If any of those rules
> co-fired from the same agent, the `co-fired-malicious-pattern`
> archetype matches and the alert escalates regardless of the other
> leads.

## Signature quirks

- **DGA vs DNS-tunneling discrimination is not required.** Both
  are escalation outcomes — the agent does not need to pick between
  them. If the evidence supports either, escalate with both listed
  as active threat hypotheses and let the human investigator (with
  WHOIS, threat intel, and host forensics) make the final call.
- **An unknown parent domain is the first escalation signal.**
  When the parent (eTLD+1) is not recognizable as a known provider
  and is not established in environment history, escalate rather
  than characterize further. The bar for benign resolution is high
  precisely because this rule is broad.
- **Encoded subdomain shape is suspicious regardless of parent.**
  A base32/base64/hex-shaped label under a known CDN parent is
  *more* suspicious than under an unknown parent, because it
  suggests domain fronting. The shape and the parent classification
  compose: known parent + encoded shape escalates.

## Scope

Standard for this signature: the alerting query, other DNS events
to the same eTLD+1 from the same agent in a ±15 minute window (and
the broader 7-30 day history for that parent), and other alerts
from the same agent in the last 24 hours (provided by
ticket-context at CONTEXTUALIZE — don't re-query). Anything beyond
this requires escalation per the skill's stay-in-scope rule.
