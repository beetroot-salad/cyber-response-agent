---
name: source-reputation
data_tags: [asset-state, threat-intel]
---

## Goal

Determine the identity and reputation of a source entity (IP, hostname,
or domain). Is it a known internal asset, a known external service,
or unrecognized?

## What to Characterize

- **Internal/external classification**: RFC1918 or org-specific range?
  See environment/context/ip-ranges.md.
- **Asset identity**: If internal, what system is it? Query asset
  inventory for hostname, owner, purpose, criticality.
- **Historical alert activity**: Other alerts from this source across
  all rules in the last 7-30 days. Pattern of benign noise vs.
  attack indicators.
- **Threat intelligence**: If external, check reputation services
  for known-malicious, known-scanner, known-cloud-provider, etc.
- **First-seen / last-seen**: Is this a new source or one with
  established history in the environment?

## Common Pitfalls

- IP reputation services have false positives — a "malicious" tag
  may be stale or based on shared hosting. Cross-reference with
  other evidence.
- Internal IPs are not inherently safe. A compromised internal host
  has a clean reputation history.
- Cloud provider IPs (AWS, GCP, Azure) host both legitimate services
  and attacker infrastructure. The IP range alone is not diagnostic.
- Dynamic IPs (DHCP, VPN pools) may have changed assignment since
  the event. Check the timestamp.
