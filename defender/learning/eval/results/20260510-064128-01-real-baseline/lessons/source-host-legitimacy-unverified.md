---
name: source-host-legitimacy-unverified
description: Benign traffic pattern from an internal IP doesn't confirm the host is uncompromised; verify source host identity before closing.
source_finding_ids:
  - livetest-5710/1
created_at: 2026-05-10T00:00:00Z
---

You characterized traffic *from* an internal source IP and concluded the pattern matched legitimate automation (e.g., a monitoring probe). You did not issue any lead interrogating whether that source host itself is uncompromised.

**The gap:** A consistent, recognizable traffic pattern is also exactly what an attacker inherits when they compromise the service that produces it. If the actor has code execution inside the source container, observations from traffic-pattern and auth-history leads look identical whether the probe is legitimate or attacker-controlled.

**Check next time:** Before closing benign on an internal-source hypothesis, ask: does any issued lead establish source host identity — process provenance, image integrity, runtime behavior — or only characterize traffic *from* that host? If source host legitimacy is untested, either cover it with a lead or explicitly record it as a ceiling constraint in the conclude block.
