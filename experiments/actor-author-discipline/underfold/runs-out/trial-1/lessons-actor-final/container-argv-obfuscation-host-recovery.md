---
name: container-argv-obfuscation-host-recovery
techniques: [T1027, T1059.004]
alert_rule_ids: []
defender_lead_tags: [wazuh.docker-exec-events]
actor_type: [external, internal]
applies_to: [container-side-execve-omits-argv]
mutable: false
recorded_at: 07000057bcde
source_observation_ids: [uf-P2/0]
relevance_criteria: payload hidden inside sh -c argument as base64 blob expecting container-side audit to omit it
---

Encoding a payload as a base64 argument to `sh -c` inside a container does not hide the content from the defender. The container-side `audit.execve` record omits argv, but the host-side `docker exec` syscall entry carries the full argument vector including the base64 blob. The defender recovers the payload from the host record without inspecting the container audit stream at all.

This pattern fails because the two audit surfaces disagree: the container sees only the program path, while the host-side event carries the args the caller passed. Tradecraft that relies on the container-side omission overlooks the host-side fork, which is the authoritative record for attribution.
