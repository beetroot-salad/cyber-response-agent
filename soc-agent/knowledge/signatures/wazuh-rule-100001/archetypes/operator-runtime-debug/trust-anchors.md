---
archetype: operator-runtime-debug
signature_id: wazuh-rule-100001
required_anchors:
  - oncall-schedule
  - change-windows
---

# Operator Runtime Debug

Story: `story.md` (read that file for the observable shape).

## Trust Anchors

Both should be consulted. Either anchor confirming is sufficient for
the archetype to resolve cleanly; neither confirming → escalate.

### `oncall-schedule`

**Question:** was the user identified in `user.name` (or correlated via
session) on-call or otherwise authorized for prod-touch on this
workload at the alert time?

**Confirmation:** the anchor returns a named operator whose
authorization window includes the alert timestamp and whose scope
covers this workload's tier.

### `change-windows`

**Question:** is there an open or recently-closed change ticket whose
target includes this `container.id`, `container.name`, host, or
encompassing service?

**Confirmation:** the anchor returns a ticket whose window contains
the alert timestamp and whose scope covers the workload.

## Precedents

None yet — this archetype is provisional until the first ticket is
recorded and rooted here.
