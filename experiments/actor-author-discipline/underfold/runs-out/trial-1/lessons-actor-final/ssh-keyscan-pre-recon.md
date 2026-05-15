---
name: ssh-keyscan-pre-recon
techniques: [T1592.002, T1595.001]
alert_rule_ids: [5701]
defender_lead_tags: [wazuh.auth-events-by-srcip]
actor_type: [external, internal]
applies_to: [wazuh-rule-5701-banner-fetch, asset-graph-cross-window-stitching]
mutable: false
recorded_at: 07000057bcde
source_observation_ids: [uf-P3/0]
relevance_criteria: SSH banner fingerprinting run from the same source IP that later executes a spray, linking recon to the spray case via asset graph
---

Running `ssh-keyscan` or any banner-fetching probe from the same source IP intended for a subsequent spray collapses recon and attack into one triage case. Wazuh rule 5701 fires on the probe; the asset graph associates that event with the spray source IP at triage time, so the defender sees the full pre-stage footprint when triaging the spray alert.

Separating the recon source IP from the spray source IP is necessary to avoid this stitching. A banner fetch from a different host than the spray origin does not surface in the spray triage context — but sharing the origin IP makes the two phases inseparable from the defender's view.
