---
name: fixture-a-session-interactivity
description: On a jump-host login, tell an interactive person from a script by whether a terminal was allocated and how long the session lasted.
telemetry_source: [fixture-sensor]
attack_phase: [execution]
source_signature: [fixture-signature]
observed_nodes:
  - {type: session, slot: class}
  - {type: compute, class: bastion, slot: class}
source_finding_ids:
  - fixture-run/benign/1
created_at: 2026-06-07T00:00:00Z
---

Made-up fixture lesson (#1503): its selectors are kept from a lab lesson so recall and ranking tests exercise the same shapes; its text is invented and teaches nothing real.
