---
techniques: [T1078, T1021.004]
alert_rule_ids: [rule-v2-sshd-success-after-failures]
applies_to: [dev-ws-1-cmdb-trust-profile]
mutable: false
recorded_at: ccbe7d71a2d8
source_observation_ids: [live-sshd-success-1/0]
relevance_criteria: story relies on the source host being partially-trusted or unclassified to leave an authorization contract open for investigation
---

A bypass argument that depends on the source host being ambiguously trusted can invert when the CMDB resolves the actual identity. If the actual host carries a declared trust edge to the destination, the defender closes the authorization contract as "authorized" and routes to benign — which is the opposite of the story's intended outcome. The misprediction is not just a narrative inaccuracy; it changes the defender's disposition.

Before framing bypass around "known internal but not fully trusted," verify the actual CMDB profile for the specific source IP. A developer workstation with an explicit trust relationship provides stronger legitimizing signal than a contractor workstation, and the authorization outcome depends on which one is actually present. Stories that need an open authorization contract require a source host that does not have a declared trust edge to the target.
