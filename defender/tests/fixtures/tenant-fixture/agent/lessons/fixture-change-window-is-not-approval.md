---
name: fixture-change-window-is-not-approval
description: Made-up fixture lesson — a host inside its change window still needs a matching change record before activity is called sanctioned.
telemetry_source: [cmdb, change-mgmt]
attack_phase: [persistence]
source_signature: [fixture-window-edit]
source_finding_ids:
  - fixture-run-2/1
created_at: 2026-10-02T00:00:00Z
---

Fixture content for tests (#1108 P4). It describes no real environment.

A change window says when edits may happen, not that this edit was approved. Before closing
an alert as planned maintenance, find the change record whose scope names the host and the
action; a window with no matching record is an open question.
