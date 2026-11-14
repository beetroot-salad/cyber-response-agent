---
name: fixture-c-container-anchor-before-uid
description: Resolve a numeric user id inside the container it came from; two containers on one host can map the same number to different accounts.
telemetry_source: [fixture-sensor]
attack_phase: [execution]
source_signature: [fixture-signature]
observed_nodes:
  - {type: identity, slot: ident}
  - {type: process, slot: attrs.user}
source_finding_ids:
  - fixture-run/benign/1
created_at: 2026-06-07T00:00:00Z
---

Made-up fixture lesson (#1503): its selectors are kept from a lab lesson so recall and ranking tests exercise the same shapes; its text is invented and teaches nothing real.
