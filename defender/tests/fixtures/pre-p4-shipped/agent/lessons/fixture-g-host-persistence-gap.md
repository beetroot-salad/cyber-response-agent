---
name: fixture-g-host-persistence-gap
description: A sensor that watches only containers sees no persistence written on a plain host; name that as a visibility gap, not a clean result.
telemetry_source: [fixture-sensor]
attack_phase: [execution]
source_signature: [fixture-signature]
observed_nodes:
  - {type: compute, slot: attrs.kind}
  - {type: file, slot: class}
source_finding_ids:
  - fixture-run/benign/1
created_at: 2026-06-07T00:00:00Z
---

Made-up fixture lesson (#1503): its selectors are kept from a lab lesson so recall and ranking tests exercise the same shapes; its text is invented and teaches nothing real.
