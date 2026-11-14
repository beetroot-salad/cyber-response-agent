---
name: fixture-b-anomaly-needs-explanation
description: An unusual action is explained only by evidence that it was expected, not by the absence of evidence that it was malicious.
telemetry_source: [fixture-sensor]
attack_phase: [execution]
source_signature: [fixture-signature]
frontier_edges:
  - {anchor_kind: iam-policy}
  - {anchor_kind: approved-source-list}
source_finding_ids:
  - fixture-run/benign/1
created_at: 2026-06-07T00:00:00Z
---

Made-up fixture lesson (#1503): its selectors are kept from a lab lesson so recall and ranking tests exercise the same shapes; its text is invented and teaches nothing real.
