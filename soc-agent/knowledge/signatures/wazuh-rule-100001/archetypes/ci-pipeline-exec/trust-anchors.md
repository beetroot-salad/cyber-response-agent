---
archetype: ci-pipeline-exec
signature_id: wazuh-rule-100001
required_anchors:
  - deploy-runs
---

# CI/CD Pipeline Exec

Story: `story.md` (read that file for the observable shape).

## Trust Anchors

### `deploy-runs`

**Question:** does the org's CI/CD run history show an active or
recently-completed job whose target includes this `container.id`,
`container.name`, or its host, with a window that contains the alert
timestamp?

**Confirmation:** the anchor returns a run ID whose target and time
window match the alert, and whose job type is consistent with the
observed cmdline (a migration job for a migration command, a smoke
test for a curl-shaped command, etc.). A run that targeted a
*different* workload at the same time is not a confirmation.

## Precedents

None yet.
