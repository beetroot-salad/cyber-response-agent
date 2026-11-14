---
name: fixture-owner-before-close
description: Made-up fixture lesson — look up the host's inventory owner before closing an alert on a host nobody claims.
telemetry_source: [cmdb]
attack_phase: [discovery]
source_signature: [fixture-unclaimed-host]
source_finding_ids:
  - fixture-run-1/1
created_at: 2026-10-01T00:00:00Z
---

Fixture content for tests (#1108 P4). It describes no real environment.

When an alert lands on a host and your hypothesis says the activity is routine, look up the
host's inventory owner first. An owner of record turns "routine" into a claim someone can
confirm; a host with no owner is a gap to record, not evidence of benign activity.
