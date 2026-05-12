---
case_id: rerun-100001-envelope-split
disposition: benign
confidence: high
---

Wazuh rule 100001 fired on `target-endpoint` (container `2427c46c4575`) when a `bash -c whoami` process was spawned via `runc` (docker exec pattern) as root with loginuid=-1 at 2026-04-19T08:28:29Z. Two leads resolved this. First, a Falco alert window query for the container showed 64 co-firing rule 100002 events — these are `sshd` doing `dup2` to wire its network socket to stdio, the normal SSH session mechanism, firing at a regular ~5-minute cadence that predates the focal alert; this is a known Falco false-positive pattern for containers running sshd, not an adversarial signal. Second, a 7-day historical baseline for rule 100001 showed 12 prior fires from `target-endpoint` container variants over the preceding week (3–6 per active day), confirming that `docker exec` invocations are a recurring routine pattern in this environment. Both adversarial indicators (novel first-time exec, escalation-grade co-fires) are absent; the event matches the routine container-exec archetype.
