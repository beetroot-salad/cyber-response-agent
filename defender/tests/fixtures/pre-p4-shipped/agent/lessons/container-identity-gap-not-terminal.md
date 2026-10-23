---
name: container-identity-gap-not-terminal
description: A container id with no name, or name=NA / image=NA, is a query prompt rather than a terminal gap; add a container-platform lead to resolve the name, image and entrypoint before any authorization claim rests on them.
telemetry_source: [falco, host-state]
attack_phase: [execution]
source_signature: [v2-falco-suspicious-network-tool]
frontier_nodes:
  - {type: compute, slot: ident}
observed_nodes:
  - {type: process, slot: attrs.container}
  - {type: compute, slot: attrs.container}
  - {type: compute, slot: attrs.container_id}
source_finding_ids:
  - 20260527T150928Z-v2-noise-alert-suspicious-network-tool/benign/0
created_at: 2026-05-30T00:00:00Z
---

When the record holds a container id and nothing else — a bare id in `attrs.container` or `attrs.container_id`, or a Falco or other syscall monitor reporting `name=<NA>` or `image=<NA>` for the triggering container — SIEM indices often have no record of this container under a named role. A resolved id is not a resolved identity: it names which container ran, and says nothing about what that container is for or who authorized it. The pitfall is accepting "identity unresolved" as a terminal state and then proceeding to a disposition that rests on untestable authorization claims — such as "the binary was in the lower image layer, so whoever signed off on the build accepted it."

**Why it matters:** Authorization ground for a benign disposition requires knowing *what* authorized the binary's presence and *which role* this container plays. Both claims collapse if the image is unknown. An attacker deploying a look-alike container with the same binary produces an identical syscall trace.

**Where the id and the name belong.** The bare id is an attribute, not an identity: keep it as `attrs.container_id` and leave the container's `ident` at `??` until a lead names it, or the open question disappears from every mechanism built to surface it. When a lead does resolve the name, it goes in that `ident`, not in an `attrs.*` cell on the container or on its host. And resolving it is not the end: an authorization contract discharged against the HOST answered a question about the host, so the lead that names the container owes a fresh contract naming the container.

**Check before treating identity as unresolvable:**
- Is there a container-platform lead? Query by container ID against the Docker daemon API, Kubernetes pod/container API, or a container registry. The response either names the image + entrypoint (authorization can then be assessed directly) or confirms the container is truly unregistered (name the gap explicitly and escalate).
- If the platform API is not in the available toolset, say so and escalate — do not substitute "binary in lower layer" as a proxy for confirmed identity.
