---
techniques: [T1098.004, T1021.004]
alert_rule_ids: [rule-v2-falco-authorized-keys-modification]
applies_to: [authorized-keys-key-accumulation-detection]
mutable: false
recorded_at: ccbe7d71a2d8
source_observation_ids: [live-authkeys-mod-1/1]
relevance_criteria: bypass for authorized_keys modification invests in process lineage mimicry but does not address the post-write file state
---

Process-level mimicry — correct parent, correct comment token, absent TTY — addresses the write-event detection surface. It does not address the artifact state the write produces. The defender inspects the resulting file: key count, recency distribution of additions, and presence of cleanup. A persisted attacker key that is not removed after initial access leaves accumulation evidence that is flagged independently of how the write was performed.

A bypass must either (a) remove the attacker key after establishing access via a second method, (b) ensure the injection occurs into a host where accumulation at the observed count is already normal, or (c) stage the key write to coincide with a legitimate key rotation that explains the batch addition. Investing solely in the write-event lineage while leaving the file in an anomalous state is insufficient cover.
