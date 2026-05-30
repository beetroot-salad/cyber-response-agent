---
techniques: [T1078]
alert_rule_ids: [rule-v2-falco-suspicious-network-tool]
applies_to: [container-uid-namespace-isolation]
mutable: false
recorded_at: e8e5c01b9664
source_observation_ids: [20260530T133146Z-noise-alert-suspnet/0]
relevance_criteria: story assigns a named account to a UID from a container event and builds an insider-threat or privilege narrative on that identity
---

A story that claims a specific named account is behind activity inside a container must ground the UID-to-account mapping in the container's local passwd, not in a host-side or identity-system lookup. Reading `uid=1003` from a Falco alert and confirming via the IAM system that `dba.ivy` carries that UID on the host does not establish who owns UID 1003 inside the container.

If the container's `/etc/passwd` maps UID 1003 to a `nologin` service account, the insider-threat framing collapses and the investigation resolves to benign monitoring. The story's conviction and bypass logic must be built on the container-local mapping, and the story writer should verify it before committing to a specific identity claim.
