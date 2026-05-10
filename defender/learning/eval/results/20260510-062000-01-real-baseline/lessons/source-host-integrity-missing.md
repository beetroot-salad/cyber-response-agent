---
name: source-host-integrity-missing
description: Classifying a source IP as known automation without issuing a lead to verify the source host's own integrity leaves supply-chain or lateral-movement compromise untested.
source_finding_ids:
  - livetest-5710/1
created_at: 2026-05-10T06:07:46Z
---

You characterized traffic *from* an internal IP and concluded the source is a legitimate monitoring probe — but you never interrogated the source host itself. An attacker who inherits an existing automated service's credentials and behavior produces observations identical to legitimate automation. The traffic pattern, username set, and timing all match; only the source host's runtime state differs.

Check: before closing a benign verdict on internally-sourced traffic, ask whether there is a lead that tests the source endpoint's integrity (process list, image hash, recent config change) — not just its traffic pattern. If no such system is available, record this explicitly as an unresolvable uncertainty and escalate rather than resolving benign.

The gap survives even when the specific attacker story is incoherent: "source host could be compromised" is always a live hypothesis until positively refuted by a lead that reaches the source host directly.
