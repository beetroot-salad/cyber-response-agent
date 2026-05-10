---
name: container-runtime-integrity-unreachable
description: do not plan leads requiring container image verification or runtime process inspection for internal source IPs unless a system providing that data is confirmed available — instead document this as an explicit observability gap
source_finding_ids:
  - livetest-5710/2
created_at: 2026-05-10T00:00:00Z
---

When the source of suspicious activity is an internal RFC 1918 host or container, you may be tempted to plan a lead that checks whether that container's image or entrypoint was tampered. This lead cannot be executed unless an EDR agent, container runtime API, or image registry inspector is available and scoped to the source host.

The SIEM (Wazuh) and host-query adapters cover the **destination** side and can characterize **traffic from** an IP, but neither can inspect what processes are running inside the source container or whether its entrypoint was modified.

**Recognize this gap at PREDICT time, not after a failed gather:**

1. Before placing a lead that targets source container integrity, confirm a system exists that can answer it (e.g., `host-query` scoped to that host, an EDR agent on the source, a container-registry diff tool).
2. If no such system is available, record this as an explicit observability ceiling in the `ceiling_rationale` field of the report.
3. Do not plan the lead speculatively and then discard it — that wastes gather budget and leaves the investigation without a documented gap.

For alerts where the source is an internal container and no container-inspection system is deployed, the relevant surface (container image/process integrity) is structurally dark. Note it once, route accordingly, and stop planning gather steps that require data you cannot obtain.
