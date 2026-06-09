---
name: ssh-pivot-upstream-credential-harvest-lead
description: Authorized SSH pivot cases need a pre-pivot source-host process lead; credential harvest is a distinct step from the sshd sequence.
source_finding_ids:
  - port259-smoke/1
created_at: 2026-06-08T00:00:00Z
---

You focused on the sshd event chain and landing-host post-auth behavior. The actor's own shell session on the source host — file traversal of co-worker home directories, reading `.bash_history` or credential-containing scripts — is a causally upstream step that produces separate process-execution and file-access evidence. Auth-log and sshd leads do not surface it.

When sshd timing alone is the discriminator (e.g., sub-human speed), the upstream harvest step is redundant. When timing is ambiguous or human-paced, source-host pre-pivot activity becomes the only remaining discriminator between an adversarial authorized pivot and a benign coincidence. Scoping the ceiling test narrowly to "initiating SSH client process identity" misses this earlier, distinct step.

**Check:** For any adversarial story where an authorized actor uses a co-worker's credentials to SSH, add a host-query or EDR process-execution lead scoped to the actor's own account on the source host, covering the window immediately preceding the sshd sequence. Look for file-traversal commands (`find`, `ls`, `cat`) targeting other users' home directories or files that contain credentials (`.bash_history`, deploy scripts, `.env` files). If that telemetry is unavailable, name it as a `ceiling_test` gap — do not omit it silently.
