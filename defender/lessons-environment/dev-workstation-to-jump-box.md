---
subject: dev-workstation-to-jump-box
alert_rule_ids:
  - rule-v2-cross-tier-ssh-pivot
  - v2-cross-tier-ssh-pivot
entities: []
relevance_criteria: Alert fired on a workstation-tier-to-prod-tier SSH sequence where the prod-tier target is a jump box
mutable: true
status: live
recorded_at: 41a8e2063b9e
source_observation_ids:
  - live-crosstier-pivot/0
---

At least one dev-tier workstation (dev-ws-1, and by the CMDB trust-topology pattern likely the broader dev-ws-* fleet) holds an authorized SSH trust edge to jump-box-1, which the EQL rule classifies as a prod-tier host (jump-box-* pattern). The CMDB trust-topology section of the l-002 investigation result records: `dev-ws-1: trust_edges_out = [jump-box-1]`. This is the authoritative grounding record; confirm the same trust edge for the specific workstation involved by querying the CMDB by hostname (not IP — the CMDB indexes by name).

The EQL rule v2-cross-tier-ssh-pivot fires deterministically on every such ordinary, policy-compliant two-hop developer session: engineer authenticates to their workstation, then opens an SSH connection to jump-box-1, producing exactly the sequence the rule matches. The rule carries no identity allowlist and no frequency gate, so it fires on each occurrence regardless of whether the actor is authorized. This means FP alerts on this rule are structurally expected for any dev-ws-* host with a trust edge to jump-box-*.
