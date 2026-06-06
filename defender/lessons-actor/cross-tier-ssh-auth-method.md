---
subject: cross-tier-ssh-auth-method
alert_rule_ids: [rule-v2-cross-tier-ssh-pivot]
defender_lead_tags: [elastic.auth-events-by-host]
mutable: true
status: live
recorded_at: 6b2e54cc15f2
source_observation_ids: [live-cross-tier-pivot-3/1]
relevance_criteria: story claims cross-tier SSH pivot auth method is indistinguishable from the baseline playbook, or builds bypass around cert/key-based auth
---

This deployment's cross-tier SSH sessions use password authentication on both legs. An SSH-agent-forwarding mechanism that requires publickey/RSA-CERT will produce a different `auth_method` field than the baseline, making it immediately distinguishable rather than hidden.

The sshd logs include auth method as a native field. Bypass arguments that claim auth method matches the baseline must verify the actual method the environment's sshd emits — not assume cert-based auth because the story mechanism requires it.
