---
name: asset-graph-cross-window-stitching
subject: asset-graph-cross-window-stitching
alert_rule_ids: [5701, 5712]
defender_lead_tags: [wazuh.auth-events-by-srcip]
actor_type: [external, internal]
mutable: true
status: live
recorded_at: 07000057bcde
source_observation_ids: [uf-P3/0]
relevance_criteria: the deployment's asset graph associates pre-recon events with the same source IP as a subsequent spray, surfacing the recon during triage of the spray alert
---

The deployment correlates events across time windows using the source IP as an asset-graph key. When a triage analyst pulls the alert for a spray campaign, the graph surfaces earlier events from the same source — including SSH banner fetches (rule 5701) that predate the spray by any interval.

A recon probe and the subsequent spray from the same source IP are effectively merged into one case at triage time. The defender sees both events even if the actor treated them as separate operational steps.
