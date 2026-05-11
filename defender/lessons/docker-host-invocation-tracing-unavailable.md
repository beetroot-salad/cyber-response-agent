---
name: docker-host-invocation-tracing-unavailable
description: SSH audit logs and Docker daemon audit trail are not integrated; don't plan leads requiring host-level exec invocation tracing.
source_finding_ids:
  - rerun-100001-envelope-split/2
created_at: 2026-05-11T00:00:00Z
---

When a container exec alert fires (e.g., Falco "Terminal shell in container"), the most discriminating question is: did `docker exec` originate from an SSH session (attacker entry point) or from approved automation running on the host?

**Pitfall:** You planned or implied a gather step that would answer this question (e.g., "correlate to SSH session user", "check Docker daemon invocation log"). Those data sources — syslog/auditd on the Docker host and the Docker daemon's audit trail — are not integrated into the available toolset. Leads that depend on them will produce no data.

**Stop:** Do not add "identify SSH session originating the exec" or "trace `docker exec` caller via host audit" as leads. These gather steps will return nothing.

**Instead:** If invocation origin is load-bearing for disposition (i.e., the investigation cannot distinguish attacker-SSH from authorized automation without it), name the gap explicitly in the report and escalate. Do not substitute frequency baseline as a proxy for identity confirmation.
