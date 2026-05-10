---
name: container-runtime-integrity-gap
description: No deployed system provides container image or runtime-process integrity data for internal RFC 1918 hosts; don't plan leads requiring it — escalate instead.
source_finding_ids:
  - livetest-5710/2
created_at: 2026-05-10T00:00:00Z
---

When the alert source is an internal RFC 1918 address hosting a container or internal service, you have no system that can verify:

- Whether the container's entrypoint or image was tampered (supply-chain compromise)
- Runtime process provenance inside the container
- Whether the observed behavior is the legitimate service or an attacker inheriting its identity

The available systems (SIEM for auth/network events, host-query for the monitored endpoint) characterize traffic *originating from* the source — they do not inspect the source container's internals. External enrichment (threat-intel, geolocation) is also silent on private RFC 1918 ranges.

**Do not plan a lead** for "verify container image integrity" or "inspect process tree on internal service host" — there is no backing data source. Planning such a lead wastes budget and produces no result.

**What to do instead:** if source-host legitimacy is the deciding factor for a benign disposition and no system can resolve it, record the gap explicitly in the investigation and escalate. A resolved-benign conclusion requires either confirming host integrity through an available system or a matched precedent that already established the source as a known-good, uncompromised host.
