---
subject: container-uid-namespace-isolation
alert_rule_ids: [rule-v2-falco-suspicious-network-tool]
entities:
  - {type: process, class: nc}
relevance_criteria: Alert fired inside a container and carries a numeric UID; UID-to-account binding is namespace-local
mutable: true
status: live
recorded_at: e8e5c01b9664
source_observation_ids: [20260530T133146Z-noise-alert-suspnet/0, live-falco-nettool-1/0]
---

UID-to-account bindings are namespace-local in this deployment: each container carries its own `/etc/passwd`, and the same numeric UID can resolve to entirely different accounts — or to no account at all — inside the container versus on the host. A UID that maps to a privileged database account on the host may map to a `nologin` service account, or be unassigned, inside the container where the alert fired.

The identity system and any host-side passwd lookup reflect only the host's namespace. Grounding a containerized process's UID to a named account requires reading that container's own `/etc/passwd` (e.g. `docker exec cat /etc/passwd` or an equivalent overlay-fs read). In multi-container deployments the same numeric UID maps to different named accounts across containers, so resolving the UID against any container other than the exact one that fired the alert yields a different identity than the one behind the alert.
