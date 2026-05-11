---
name: container-exec-missing-identity-lead
description: On container exec alerts, add a lead that anchors exec origin to an authorized identity before concluding benign.
source_finding_ids:
  - rerun-100001-envelope-split/0
created_at: 2026-05-11T00:00:00Z
---

When a syscall-level alert fires on a shell spawned inside a container (e.g., Falco "Terminal shell in container"), the syscall trace is identity-blind: a developer's automation script and an attacker with stolen SSH credentials produce the same runc footprint.

**Pitfall:** You built leads around frequency baseline and Falco context but never added a lead that answers *who issued the `docker exec`*. You concluded benign because the pattern was routine — but "routine pattern" and "authorized actor" are orthogonal. The investigation cannot refute an SSH-entry attacker story if it never queries for the initiating session.

**Check before concluding benign:**
- Is there a lead that correlates the exec timestamp to an approved identity context — SSH session user, CI/CD job ID, or developer automation schedule?
- If no such lead exists and the invocation origin is load-bearing for disposition, the investigation is incomplete. Either add the lead (if a data source covers it) or escalate with the gap named explicitly.
