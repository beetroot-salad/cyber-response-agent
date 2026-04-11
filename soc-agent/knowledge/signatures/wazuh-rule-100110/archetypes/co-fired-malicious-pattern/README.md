---
archetype: co-fired-malicious-pattern
signature_id: wazuh-rule-100110
required_anchors: []
---

# Co-Fired Malicious DNS Pattern

## Story

A high-entropy DNS query alert co-fired with one or more rules from
the malicious-DNS rule cluster:

- **100112** — suspicious TXT record query
- **100113** — NXDOMAIN burst (the canonical DGA signal)
- **100115** — known malicious DNS pattern
- **100116** — high-volume DNS queries from a single source

The combination of a high-entropy subdomain *and* one of these
correlated signals is the strongest available evidence that the
queries are adversarial — either DGA probing for an active C2
controller or DNS tunneling carrying encoded payloads. A single
high-entropy query in isolation is ambiguous (many CDNs and analytics
providers produce similar shapes), but the same query alongside an
NXDOMAIN burst or a high-volume cluster from the same agent is
unambiguously worth a human's attention.

This archetype is the composition rule for this signature: it
escalates whenever the co-firing condition holds, regardless of how
the primary query would otherwise be characterized.

This archetype always escalates. There is no trust anchor that
confirms co-fired malicious DNS patterns as legitimate — penetration
tests should be coordinated in advance through change tickets, in
which case the matched archetype would be a coordinated-test variant
(not yet defined). The agent does not need to discriminate DGA from
DNS tunneling here; both are escalation outcomes, and the human
investigator (with WHOIS, threat intel, and host forensics) is
better positioned to make the final call.

What takes an alert *out* of this archetype is the absence of any
co-fired rule. A high-entropy query with no co-firing falls back to
the starter hypotheses (CDN/cloud, analytics, DGA, tunneling) and
should be characterized further before escalating.

## Precedents

None yet.
