---
name: network-analysis
data_tags: [network-events]
baseline: optional       # Binary observations (connection to known-bad IP, DNS for newly-registered domain) are self-interpreting; volume/rate claims (beaconing frequency, bytes exfiltrated) require a shift-query comparison.
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
- Not every deployment ingests network telemetry into the SIEM.
  Check `environment/data-sources/network-events.md` before assuming
  flow data, firewall logs, or DNS logs are queryable — the absence
  of events may mean "not logged here," not "did not happen."

## Baseline

- **When needed:** Claims about rate, volume, or beaconing cadence
  ("30 MB exfiltrated," "connects every 60s," "10× normal outbound
  to this peer") are only interpretable against a baseline. Binary
  observations — connection to a known-bad IP, DNS for a newly
  registered domain, use of a non-standard port for a standard
  service — do not require one.
- **Shift query:** Re-run the same entity-scoped query against a
  prior window of equal duration, typically `--start` shifted `7d`
  earlier with identical `--window`. For beaconing cadence, compare
  inter-connection intervals between the two windows; for volume,
  compare byte/packet sums. If the entity is a short-lived host or
  container, substitute "peer host in the same role" for the shift
  — a same-host 7d baseline is meaningless when the host didn't
  exist then.
- **Interpretation:** Prefer σ-framing — `>3σ above this entity's
  7-day mean outbound bytes`, `beacon interval variance <5%
  (unusually regular)`, `first-ever connection to this /24` — over
  absolute thresholds. A `0 → N` jump (first contact, new peer,
  new port) is stronger evidence than `N → 10N` at the same
  absolute count; call it out explicitly.
