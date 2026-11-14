---
name: fixture-d-container-identity-gap
description: A container id with no resolved name or image is a question to ask the container platform, not a dead end.
telemetry_source: [fixture-sensor]
attack_phase: [execution]
source_signature: [fixture-signature]
frontier_nodes:
  - {type: compute, slot: ident}
observed_nodes:
  - {type: process, slot: attrs.container}
  - {type: compute, slot: attrs.container}
  - {type: compute, slot: attrs.container_id}
source_finding_ids:
  - fixture-run/benign/1
created_at: 2026-06-07T00:00:00Z
---

Made-up fixture lesson (#1503): its selectors are kept from a lab lesson so recall and ranking tests exercise the same shapes; its text is invented and teaches nothing real.
