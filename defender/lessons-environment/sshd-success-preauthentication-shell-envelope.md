---
subject: sshd-success-preauthentication-shell-envelope
alert_rule_ids: [rule-v2-sshd-success-after-failures]
entities:
  - {type: compute, class: bastion}
relevance_criteria: Alert fired on sshd success-after-failures; the lead set targets authentication telemetry, not in-session shell activity
mutable: true
status: live
recorded_at: 0756c74a19ce
source_observation_ids: [port259-smoke/1]
---

For the sshd success-after-failures alert, the investigative lead set targets authentication telemetry: inter-failure intervals, session duration, source IP, and account consistency. Process-execution and file-access events from an interactive shell session in the same window are not part of the queried lead set for this alert class.

The grounding here is the shape of the standard investigation for this rule — it is an auth-telemetry envelope. In-session shell activity (file reads, directory traversal, history inspection) is outside the dimensions this encounter class examines.
