---
techniques: [T1110.003]
actor_type: [external]
relevance_criteria: credential-spray campaign that uses a monitoring source IP as cover for high-volume auth attempts
recorded_at: synth-seed-02
source_observation_ids: [synth-seed-02/0]
---

A credential-spray pattern from a monitoring source IP burns the source-IP cover within minutes. Defenders typically baseline auth volume per source IP — a monitoring host that suddenly attempts dozens of accounts in a short window does not look like ambient health-check traffic; it looks like a compromised monitoring host. The technique is rapidly distinguishable from misconfiguration once the attempt count crosses the per-source baseline.

Stories that imagine spray-and-pray attempts hiding inside monitoring traffic are weaker than they appear. The cover only holds when each source IP issues at most one or two attempts per target per long window — the speed of a real spray defeats the framing.
