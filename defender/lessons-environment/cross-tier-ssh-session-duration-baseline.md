---
subject: cross-tier-ssh-session-duration-baseline
alert_rule_ids: [rule-v2-cross-tier-ssh-pivot]
entities:
  - {type: compute, class: bastion}
  - {type: socket, class: tcp-endpoint}
relevance_criteria: Alert fired on a cross-tier SSH pivot; observed session duration is recorded in logs-system.auth-* for the host pair
mutable: true
status: live
recorded_at: 6b2e54cc15f2
source_observation_ids: [live-cross-tier-pivot-3/0]
---

Cross-tier SSH sessions in this deployment for the pivot alert context run on the order of ~57ms — the duration of a connectivity check or a near-empty automation run, not a multi-minute hardening playbook. The session-duration signal is recorded in `logs-system.auth-*` for the relevant host pair and is the authoritative grounding for what "normal" looks like.

The baseline here is sub-second, so a multi-minute session is anomalous against it rather than indistinguishable from it. Session duration for the host pair is observable in the auth telemetry, so the actual baseline can be read directly rather than assumed to be a long playbook run.
