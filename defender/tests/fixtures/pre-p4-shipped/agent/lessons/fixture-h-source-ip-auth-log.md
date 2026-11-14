---
name: fixture-h-source-ip-auth-log
description: Check where a source address logged in on the receiving host, not only where it is enrolled.
telemetry_source: [fixture-sensor]
attack_phase: [execution]
source_signature: [fixture-signature]
frontier_nodes:
  - {type: compute, class: ip-only, slot: ident}
  - {type: compute, class: ip-only, slot: class}
frontier_edges:
  - {anchor_kind: approved-source-list}
source_finding_ids:
  - fixture-run/benign/1
created_at: 2026-06-07T00:00:00Z
---

Made-up fixture lesson (#1503): its selectors are kept from a lab lesson so recall and ranking tests exercise the same shapes; its text is invented and teaches nothing real.
