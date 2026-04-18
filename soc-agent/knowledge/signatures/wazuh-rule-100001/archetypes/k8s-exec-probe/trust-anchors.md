---
archetype: k8s-exec-probe
signature_id: wazuh-rule-100001
required_anchors:
  - workload-manifest
---

# Kubernetes Exec Probe

Story: `story.md` (read that file for the observable shape).

## Trust Anchors

### `workload-manifest`

**Question:** does the Kubernetes pod spec for this `container.name`
declare a liveness, readiness, or startup probe of `exec` type whose
command matches the observed `proc.cmdline`, with `periodSeconds`
matching the observed cadence?

**Confirmation:** the anchor returns a probe definition whose command
and period both match the observation. Mismatch on either the command
or the period is a refutation, not a confirmation — a probe that's
declared but runs a different command is more suspicious than no
declared probe at all.

## Precedents

None yet.
