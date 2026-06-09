---
alert_rule_ids:
  - rule-v2-cross-tier-ssh-pivot
  - v2-cross-tier-ssh-pivot
entities: []
relevance_criteria: Alert source IP needs to be mapped to a workstation hostname for CMDB authorization checks
mutable: true
status: live
recorded_at: 41a8e2063b9e
source_observation_ids:
  - live-crosstier-pivot/1
---

The CMDB in this environment indexes hosts by name, not IP address. The alert envelope for v2-cross-tier-ssh-pivot exposes the source IP (e.g. 172.18.0.11) but does not populate host.name for EQL sequence matches. An IP-based CMDB query returns no match even when the host is fully registered and authorized — that result means "lookup by IP is unsupported," not "host is absent." A spurious "not found" from a direct IP query must not be interpreted as absence of registration.

The correct resolution path is to recover the workstation hostname from the Elastic ancestor events before querying the CMDB. The projected telemetry records the mapping (e.g. 172.18.0.11 → dev-ws-4); that reverse-lookup must be performed via the SIEM event stream, not via the CMDB directly.
