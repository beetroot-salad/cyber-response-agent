---
subject: svc-monitoring-non-interactive-invocation
alert_rule_ids: [rule-v2-falco-suspicious-network-tool]
defender_lead_tags: [elastic.process-events-by-container]
mutable: true
status: live
recorded_at: e8e5c01b9664
source_observation_ids: [20260530T161715Z-noise-alert-suspnet/1]
relevance_criteria: story relies on svc.monitoring account shell or invocation mode for persistence or payload delivery
---

The svc.monitoring health-check is invoked non-interactively: `tty=0`, cmdline `bash <health-check-script>`. The account's login shell is `/usr/sbin/nologin`. Non-interactive bash invocations do not source `.bashrc`, `.bash_profile`, or `.profile` regardless of the account's configured shell.

The health-check loop runs on an automated schedule. There is no interactive session that would trigger shell initialization files under normal operation.
