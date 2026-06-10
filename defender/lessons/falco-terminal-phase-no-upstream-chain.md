---
name: falco-terminal-phase-no-upstream-chain
description: A Falco terminal-execution lead set needs upstream cron-write and sensitive-read leads for the same container window — entity identity alone is insufficient.
telemetry_source: [falco, zeek]
attack_phase: [collection, persistence, exfiltration]
source_signature: [v2-falco-suspicious-network-tool]
source_finding_ids:
  - live-falco-nettool-e2e-1/2
created_at: 2026-06-06T00:00:00Z
---

You queried only what the Falco alert directly named. The alert fires at the *end* of an attack chain; collection and persistence phases — `/etc/cron.d/` writes, sensitive-file reads (`find`, `tar`), `/tmp/` archive creation, Zeek outbound connection records, and cron self-removal — all produce Falco events in the same container window that went unqueried.

When no upstream lead runs, disposition rests entirely on entity identity matching. A container whose legitimate cadence occasionally includes outbound tool calls would pass that check with no corroborating or refuting evidence from the collection and persistence phases.

**Check**: After anchoring to the alert's `container_id` and time window, scan for co-occurring Falco rules from adjacent attack phases: cron/scheduler writes (`write-below-etc`, `spawned-process-from-cron`), read-sensitive-file-untrusted, write-below-tmp, and Zeek `.connection` records. If any fire in the same window, add them as upstream corroboration leads before forming a disposition.
