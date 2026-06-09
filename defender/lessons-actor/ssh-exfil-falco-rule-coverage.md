---
techniques: [T1041, T1048, T1021.004]
alert_rule_ids: [rule-v2-falco-suspicious-network-tool]
applies_to: [falco-stdout-stdin-network-redirect-rule]
mutable: false
recorded_at: e8e5c01b9664
source_observation_ids: [20260530T161715Z-noise-alert-suspnet/2]
relevance_criteria: bypass claims SSH-based lateral movement or exfiltration avoids further Falco alerts because SSH is a normal administrative protocol in the environment
---

Normalcy of the SSH protocol does not imply normalcy of all SSH-related syscall patterns. Falco rules key on syscall-level behavior — STDOUT/STDIN redirection to a network socket, invocation of file-copy tools — not on the transport protocol name. SSH-tunneled exfiltration (piping file content over an SSH connection, running `scp`, using `rsync`) generates the same flagged syscalls regardless of the outer protocol.

Bypass budget must be distributed across all TTP steps that fire Falco rules, not just the initial probe that triggers the entry alert. When a cover argument claims that post-probe steps "generate no further Falco events," verify that claim against the deployment's active rule catalog for each TTP. Investing optimization in the entry probe while the exfiltration leg fires hundreds of alerts leaves the strongest detection signal untouched.
