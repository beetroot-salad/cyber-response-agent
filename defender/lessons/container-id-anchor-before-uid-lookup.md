---
name: container-id-anchor-before-uid-lookup
description: Anchor uid/identity resolution to the alert's container_id before any passwd or host-state lookup; co-resident containers share uid numbers but map them to different accounts.
telemetry_source: [falco, host-state]
attack_phase: [execution]
source_signature: [v2-falco-suspicious-network-tool]
source_finding_ids:
  - 20260530T133146Z-noise-alert-suspnet/0
  - live-falco-nettool-1/1
created_at: 2026-05-30T13:31:46Z
---

You resolved a uid or container identity by querying a host identified from context fields (image name, service label, hostname hint, or the host running the SIEM agent) rather than from the container_id in the alert itself. The query returned a plausible result — but the same uid number can map to completely different usernames in different container images. If multiple containers are co-resident, you may have read the identity table of the wrong one.

This applies to both /etc/passwd lookups and host-state leads (process-table queries, user-session queries, or any lead that reports uid → username). Both are scoped to the container or host they target; if that target is inferred rather than confirmed from the alert's container_id, the result is unreliable.

**Check before any uid/username resolution:**
1. Take the `container_id` (or `container.id`) directly from the alert — treat it as an opaque identifier.
2. Confirm which running container holds that ID: `docker inspect <container_id>` (or the equivalent SIEM query that maps container_id → service/image). Do not infer from hostname, image-name patterns, or service labels alone.
3. Only then resolve uid → username using that container's identity context — whether from its passwd database or a host-state lead explicitly scoped to that container_id.

If the SIEM does not expose a container-id-to-service mapping and docker inspect is unavailable, record the uid numerically and mark the username as unconfirmed. Do not substitute an inferred hostname.
