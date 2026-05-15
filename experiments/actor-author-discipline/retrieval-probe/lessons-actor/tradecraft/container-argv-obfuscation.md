---
techniques: [T1610, T1059.004, T1027]
actor_type: [external, internal]
relevance_criteria: actor encodes or wraps a command payload inside a shell expansion to obscure arguments from container-side audit
recorded_at: uf-P2
source_observation_ids: [uf-P2/0]
---

Encoding a payload inside a base64 shell expansion passed to `docker exec` does not hide the command from the audit trail. The story assumes the container-side auditd will log only the interpreter path (`/bin/sh`) and miss the inline script body. This is wrong: the host-side fork of the `docker exec` syscall records the full argv — including the encoded blob — before the shell ever decodes it. The defender queries the host-side record and recovers the payload without needing the container-side view at all.

The container audit boundary is not an argv confidentiality boundary. Any framing that routes detection evasion through the container's limited audit visibility fails as soon as the host-side `docker exec` event is in scope, which it is by default on this deployment.
