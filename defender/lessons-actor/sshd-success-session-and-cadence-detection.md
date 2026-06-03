---
subject: sshd-success-session-and-cadence-detection
alert_rule_ids: [rule-v2-sshd-success-after-failures]
defender_lead_tags: [wazuh.auth-events-by-host, wazuh.auth-events-by-srcip]
mutable: true
status: live
recorded_at: ccbe7d71a2d8
source_observation_ids: [live-sshd-success-1/1]
relevance_criteria: story crafts a failure-then-success SSH pattern and claims it reads as a human typo event
---

The defender keys on two signals independent of failure count and username consistency: inter-failure interval and session duration. Actual data showed 2–4 second inter-failure intervals and a 54ms post-success session — both flagged as automated. The sub-100ms session is treated as a credential-check or immediate-exit pattern, not a human login.

Failure count at the threshold floor and same-username consistency are insufficient discrimination — these dimensions are checked but are not the primary basis for the automated classification. The anomaly flag comes from timing.
