---
name: fixture-i-pivot-credential-lead
description: A login that pivots through a host raises the question of how the credential reached that host; give it a lead.
telemetry_source: [fixture-sensor]
attack_phase: [execution]
source_signature: [fixture-signature]
frontier_nodes:
  - {type: credential, slot: class}
  - {type: process, slot: class}
source_finding_ids:
  - fixture-run/benign/1
created_at: 2026-06-07T00:00:00Z
---

Made-up fixture lesson (#1503): its selectors are kept from a lab lesson so recall and ranking tests exercise the same shapes; its text is invented and teaches nothing real.
