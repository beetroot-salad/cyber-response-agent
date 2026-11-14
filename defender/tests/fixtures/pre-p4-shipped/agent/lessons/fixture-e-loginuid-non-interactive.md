---
name: fixture-e-loginuid-non-interactive
description: An unset login id with no terminal means an automated, non-login process; it does not by itself say which tool started it.
telemetry_source: [fixture-sensor]
attack_phase: [execution]
source_signature: [fixture-signature]
observed_nodes:
  - {type: identity, slot: attrs.loginuid}
  - {type: process, slot: attrs.anomaly}
source_finding_ids:
  - fixture-run/benign/1
created_at: 2026-06-07T00:00:00Z
---

Made-up fixture lesson (#1503): its selectors are kept from a lab lesson so recall and ranking tests exercise the same shapes; its text is invented and teaches nothing real.
