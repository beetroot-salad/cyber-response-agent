---
name: authz-scope-discrepancy-needs-reconciliation-lead
description: When SIEM authz telemetry returns host scope wider than the provisioning oracle projects, spawn a reconciliation lead; an unexplained discrepancy is an unresolved model inconsistency, not a background credential-exposure note.
telemetry_source: [identity]
attack_phase: [lateral-movement]
source_signature: [v2-cross-tier-ssh-pivot]
source_finding_ids:
  - live-cross-tier-pivot-2/2
created_at: 2026-06-04T00:00:00Z
---

You queried the authorization oracle and noted that a service account's SIEM-returned access scope exceeded the provisioned scope. You logged this as "breadth is notable" or "standing credential exposure" and moved on.

That notation is not a reconciliation. When the oracle marks `access_authorized: false` for a host class but active access exists for that class in the telemetry, the investigation's authorization model is internally inconsistent. You cannot reliably close on "access was authorized" when the provisioning record contradicts what the SIEM shows.

**The check:** If SIEM-returned authorization scope contradicts the provisioned scope:

1. Spawn a lead targeting the provisioning or IAM system: when was the account last modified, what authorized the expanded scope, and whether the change has a ticket or approval record.
2. If the provisioning data source is unavailable, record it by name in `ceiling_test` ("IAM audit for svc.config-mgmt scope expansion not retrieved") — not a generic credential-exposure note.

The investigation's authorization claim depends on knowing the scope is current and matches intent. A discrepancy between the oracle's projection and live telemetry means the access model is unconfirmed, not that exposure is acceptable background context.
