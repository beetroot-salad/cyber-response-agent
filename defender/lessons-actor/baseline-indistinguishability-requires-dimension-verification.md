---
techniques: [T1021.004, T1036]
alert_rule_ids: [rule-v2-cross-tier-ssh-pivot]
applies_to: [cross-tier-ssh-session-duration-baseline, cross-tier-ssh-auth-method]
mutable: false
recorded_at: 6b2e54cc15f2
source_observation_ids: [live-cross-tier-pivot-3/0, live-cross-tier-pivot-3/1]
relevance_criteria: bypass argument claims a session, credential, or behavior is indistinguishable from an established baseline without verifying observable dimensions
---

"Indistinguishable from the baseline" is a claim, not a defense. It can only be sustained if every observable dimension of the story — session duration, auth method, source IP, command shape — has been independently verified against what the actual deployment emits. Two separate failures on the same encounter: the session was 57ms (not the claimed 147s), and the auth method was password (not RSA-CERT). Both dimensions were observable in the same telemetry source.

The failure mode is assuming the baseline matches the story's mechanism requirements rather than querying what the environment actually produces. Before writing the bypass argument, enumerate each field the defender will see in auth telemetry and confirm the story value matches the deployment value. A single unverified dimension can collapse the bypass independently of all other cover.
