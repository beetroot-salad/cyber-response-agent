---
subject: svc-monitoring-non-interactive-invocation
alert_rule_ids: [rule-v2-falco-suspicious-network-tool]
entities:
  - {type: process, class: nc}
relevance_criteria: Alert fired on a container network tool; the svc.monitoring health-check runs non-interactively on canary-1
mutable: true
status: live
recorded_at: e8e5c01b9664
source_observation_ids: [20260530T161715Z-noise-alert-suspnet/1]
---

The svc.monitoring health-check is invoked non-interactively on an automated schedule: the process runs with `tty=0` and cmdline `bash <health-check-script>`, and the account's configured login shell is `/usr/sbin/nologin`. Non-interactive bash invocations do not source `.bashrc`, `.bash_profile`, or `.profile` regardless of the account's configured shell.

There is no interactive session for this account under normal operation that would trigger shell-initialization files; the health-check loop runs unattended on its schedule.
