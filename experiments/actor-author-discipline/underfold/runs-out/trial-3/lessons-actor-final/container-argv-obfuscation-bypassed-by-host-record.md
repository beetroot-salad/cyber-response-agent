---
name: container-argv-obfuscation-bypassed-by-host-record
techniques: ["T1027", "T1059.004"]

alert_rule_ids: []
defender_lead_tags: ["wazuh.docker-exec-events"]

actor_type: [external, internal]
applies_to: ["container-side-execve-omits-argv"]

mutable: false

recorded_at: 120300ec954c
source_observation_ids: ["uf-P2/0"]

relevance_criteria: staging a payload as an encoded argument to sh -c inside a container, expecting container-side audit to omit the script body
---

Encoding a payload as a base64 argument to `sh -c` inside a container does not hide the argument from the defender. The host-side `docker exec` syscall record carries the full argv — including the encoded blob — regardless of what the container's own audit daemon captures. Container-side execve omission is irrelevant when the host-side record survives.

The attack surface for argv obfuscation inside a container is narrower than it appears: the container's audit gap is real, but it is upstream of the host-side event that already holds the args. Any cover story built on container-internal audit silence is invalid for this deployment.

Meaningful argv obfuscation would require the host-side docker exec event to also lose the argument — for example, by staging the payload through a mechanism that does not route through `docker exec` at all.
