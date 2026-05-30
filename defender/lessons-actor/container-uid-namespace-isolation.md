---
subject: container-uid-namespace-isolation
alert_rule_ids: [rule-v2-falco-suspicious-network-tool]
mutable: true
status: live
recorded_at: e8e5c01b9664
source_observation_ids: [20260530T133146Z-noise-alert-suspnet/0]
relevance_criteria: story attributes a named account identity to a numeric UID appearing in a container alert
---

UID-to-account bindings are namespace-local: each container carries its own `/etc/passwd`, and the same numeric UID can resolve to entirely different accounts — or no account at all — inside the container versus on the host. A UID that maps to a privileged database account on the host may map to a `nologin` service account, or be unassigned, inside the container where the alert fired.

The identity system and any host-side passwd lookup only reflect the host's namespace. Correlating them to a containerized process requires reading the container's own `/etc/passwd` (e.g. via `docker exec cat /etc/passwd` or an equivalent overlay-fs read), not the host's.
