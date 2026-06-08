---
techniques: [T1021.004, T1083, T1552.003]
alert_rule_ids: [rule-v2-sshd-success-after-failures]
applies_to: [sshd-success-preauthentication-shell-envelope]
mutable: false
recorded_at: 0756c74a19ce
source_observation_ids: [port259-smoke/1]
relevance_criteria: story's primary evasion work is concentrated on the sshd retry pattern rather than on the actor's own shell enumeration activity that precedes or follows authentication
---

The sshd retry loop is a detection-engine rule target: every field the defender checks is defined by the rule's trigger. Activity in the actor's own interactive shell session — directory traversal, credential file reads, bash history inspection — sits in a different telemetry envelope that the current lead set for this rule class does not query.

A story that inverts the primary and secondary surfaces — making the upstream shell enumeration the most visible artifact and keeping the authentication sequence minimal — stresses a genuine coverage gap. The sshd retry loop provides the triggering alert; the shell session provides the investigation surface. Defenders following the rule-standard lead sequence will analyze the authentication log and stop; the shell activity is never pulled.

To exploit this structurally: minimize the retry sequence to the threshold floor with clean timing, then invest cover in making the shell-session activity look routine (expected account, expected working directory, file access consistent with the account's job function). The investigator's attention is anchored to the authentication window; the enumeration that precedes it is outside the queried envelope.
