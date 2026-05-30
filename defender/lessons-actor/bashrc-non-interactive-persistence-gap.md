---
techniques: [T1546.004]
alert_rule_ids: [rule-v2-falco-suspicious-network-tool]
applies_to: [svc-monitoring-non-interactive-invocation]
mutable: false
recorded_at: e8e5c01b9664
source_observation_ids: [20260530T161715Z-noise-alert-suspnet/1]
relevance_criteria: story uses .bashrc modification as a persistence mechanism under a service account that runs automated or health-check workloads
---

`.bashrc` modification as a persistence mechanism only fires when a bash shell is started interactively. Automated health-check scripts, cronjobs, and service invocations with `tty=0` run non-interactive shells and do not source `.bashrc` under any circumstance, regardless of the account's configured login shell.

For a service account whose only normal execution path is a non-interactive automated script, `.bashrc` persistence buys re-entry only if the attacker establishes their own interactive `exec` session — not from the automated loop the story frames as the delivery vehicle. The persistence mechanism must match the actual invocation mode of the vehicle it piggybacks on.
