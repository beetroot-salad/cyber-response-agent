---
actor_type: [external, internal]
subject: falco-shell-in-container
relevance_criteria: actor spawns an interactive shell inside any container in this deployment
recorded_at: synth-probe-amb-01
status: live
source_observation_ids: [synth-probe-amb-01/0]
---

Falco's `Terminal shell in container` rule fires on any interactive shell process whose parent is a container runtime, with a deployment-local suppression list that allows shells inside containers tagged `image.name ~ ^cra-dev-.*$`. Any shell spawn outside that image-name window surfaces as a Falco alert tagged `WARNING` and routed to the Wazuh pipeline within ~2 seconds. The control is image-name keyed, not user-keyed — running as root inside a non-allowlisted container does not bypass the rule.
