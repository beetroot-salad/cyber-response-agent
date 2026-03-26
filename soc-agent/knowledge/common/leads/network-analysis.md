---
name: network-analysis
data_tags: [network-events]
---

## Goal

Characterize network activity for a given entity — connections made
or received, traffic patterns, and communication targets.

## What to Characterize

- **Connection direction**: Inbound (entity received connection) vs
  outbound (entity initiated connection). Note both.
- **Communication targets**: Which IPs/domains/ports were contacted?
  Classify each as internal, external-known, or external-unknown.
- **Protocol and port**: Standard service ports vs unusual ports.
  Common C2 ports (443, 8080, 8443) used with non-standard protocols
  are suspicious.
- **Volume and timing**: Data volume transferred, connection duration,
  and timing pattern (single connection vs periodic beaconing vs burst).
- **DNS queries**: Domain names resolved by the entity. Note DGA-like
  patterns, newly registered domains, or known-malicious domains.
- **Temporal relationship to alert**: Network activity immediately
  before, during, or after the alerting event.

## Common Pitfalls

- Encrypted traffic (TLS) hides content. You can characterize
  connections (target, timing, volume) but not payload.
- CDNs and shared hosting mean an IP may serve thousands of domains.
  A connection to a Cloudflare IP tells you little without the SNI/domain.
- NAT and proxies obscure the true source or destination. Check if
  either endpoint is a known proxy.
- DNS-over-HTTPS bypasses standard DNS logging. Absence of DNS
  queries doesn't mean no domain resolution occurred.
