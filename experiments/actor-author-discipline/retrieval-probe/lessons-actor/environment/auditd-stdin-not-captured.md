---
actor_type: [external, internal]
subject: auditd-stdin-not-captured
relevance_criteria: actor story relies on stdin to an interactive process being unrecoverable from audit
recorded_at: synth-probe-amb-03
status: live
source_observation_ids: [synth-probe-amb-03/0]
---

`auditd` on this deployment records the execve syscall and its argv, but does not capture data written to a process's stdin after the fact. Interactive sessions where the actor types commands into an open shell, or pipes a payload via `echo ... | bash`, leave only the parent invocation in the audit trail (not the typed/piped content). The exception is the host-side `tmux` and `script` integrations: any session inside a tmux pane or wrapped under `script` is captured to a per-user transcript file under `/var/log/sessions/{user}/{ts}.cast`, which Wazuh tails with rule 100403.
