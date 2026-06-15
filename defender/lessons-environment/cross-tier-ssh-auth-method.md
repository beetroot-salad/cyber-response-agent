---
subject: cross-tier-ssh-auth-method
alert_rule_ids: [rule-v2-cross-tier-ssh-pivot]
entities:
  - {type: compute, class: bastion}
  - {type: socket, class: tcp-endpoint}
relevance_criteria: Alert fired on a cross-tier SSH pivot; the sshd auth_method field is observable and recorded per leg
mutable: true
status: live
recorded_at: 6b2e54cc15f2
source_observation_ids: [live-cross-tier-pivot-3/1]
---

This deployment's cross-tier SSH sessions use password authentication on both legs. The sshd logs carry `auth_method` as a native field, so the authentication mechanism is directly observable per session rather than inferred.

Because the standing baseline is password auth, a session using publickey or RSA-CERT (for example SSH-agent forwarding) emits a different `auth_method` value than the baseline and is distinguishable on that field alone — the observed auth method is grounded in the sshd event, not assumed from the connection topology.
