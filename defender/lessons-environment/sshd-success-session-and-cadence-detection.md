---
subject: sshd-success-session-and-cadence-detection
alert_rule_ids: [rule-v2-sshd-success-after-failures]
entities:
  - {type: compute, class: bastion}
relevance_criteria: Alert fired on sshd success-after-failures; the primary discriminators are inter-failure interval and post-success session duration
mutable: true
status: live
recorded_at: ccbe7d71a2d8
source_observation_ids: [live-sshd-success-1/1]
---

For the sshd success-after-failures alert, two timing signals are the primary discriminators, independent of failure count and username consistency: inter-failure interval and post-success session duration. In the observed case the intervals were 2–4 seconds and the post-success session was 54ms — both read as automated. A sub-100ms session is treated as a credential-check or immediate-exit pattern rather than a human login.

Failure count at the threshold floor and same-username consistency are checked but are not the basis for the automated classification; the anomaly determination comes from the timing dimensions.
