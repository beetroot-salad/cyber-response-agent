---
name: container-identity-gap-not-terminal
description: Container name=NA or image=NA is a query prompt, not a terminal gap; add a container-platform lead to resolve image and entrypoint.
source_finding_ids:
  - 20260527T150928Z-v2-noise-alert-suspicious-network-tool/benign/0
created_at: 2026-05-30T00:00:00Z
---

When Falco or another syscall monitor reports `name=<NA>` or `image=<NA>` for the triggering container, SIEM indices often have no record of this container under a named role. The pitfall is accepting "identity unresolved" as a terminal state and then proceeding to a disposition that rests on untestable authorization claims — such as "the binary was in the lower image layer, so whoever signed off on the build accepted it."

**Why it matters:** Authorization ground for a benign disposition requires knowing *what* authorized the binary's presence and *which role* this container plays. Both claims collapse if the image is unknown. An attacker deploying a look-alike container with the same binary produces an identical syscall trace.

**Check before treating identity as unresolvable:**
- Is there a container-platform lead? Query by container ID against the Docker daemon API, Kubernetes pod/container API, or a container registry. The response either names the image + entrypoint (authorization can then be assessed directly) or confirms the container is truly unregistered (name the gap explicitly and escalate).
- If the platform API is not in the available toolset, say so and escalate — do not substitute "binary in lower layer" as a proxy for confirmed identity.
