---
subject: cross-tier-ssh-session-duration-baseline
alert_rule_ids: [rule-v2-cross-tier-ssh-pivot]
defender_lead_tags: [elastic.auth-events-by-host]
mutable: true
status: live
recorded_at: 6b2e54cc15f2
source_observation_ids: [live-cross-tier-pivot-3/0]
relevance_criteria: story builds a session-duration bypass for a cross-tier SSH pivot by claiming the session is indistinguishable from a playbook run
---

Actual SSH sessions in this deployment for the cross-tier pivot alert context are ~57ms — a connectivity check or near-empty automation run, not a multi-minute hardening playbook. The oracle projected a 147-second session duration to match a story that inserted malicious tasks after legitimate playbook tasks; the real environment produced a sub-second session.

A bypass argument framing session duration as "indistinguishable from the baseline playbook run" requires that the actual baseline IS a multi-minute run. Verify observed session durations in `logs-system.auth-*` for the relevant host pair before committing to a duration-based cover argument.
