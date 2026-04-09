---
tags: [trust-anchor, authorization, kubernetes]
provides: [workload-manifest]
---

# Workload Manifest

Retrieves the declared specification for a Kubernetes workload — used to confirm that observed activity (probes, container commands, security context) matches what the manifest declares.

## Question answered

For a given `container.name` (and namespace, if available), what does the Kubernetes pod spec declare? Specifically: what probes are configured, what commands do they run, what `periodSeconds` do they use, what is the security context?

## Available systems

<!-- Example
| System | Coverage | Access | Priority |
|--------|----------|--------|----------|
| Kubernetes API server | All clusters | kubectl or API | Primary (live state) |
| ArgoCD app definitions | GitOps-managed workloads | API | Authoritative for declared state |
-->

## Query

<!-- Example
`MCP: k8s.get_pod_spec(namespace, pod_name)`
Returns: full pod spec including containers, probes, volumes, security context
-->

## Confirmation shape

For probe-shaped alerts, a confirmation requires the manifest to declare an `exec` probe whose:

- Command matches the observed `proc.cmdline` (allowing for shell tokenization differences)
- `periodSeconds` matches the observed cadence

A probe declared with a *different* command than what was observed is a **refutation**, not just a non-confirmation — a probe whose runtime command silently differs from its declared command is more suspicious than no declared probe at all.

## Failure modes

- **Not a Kubernetes environment:** anchor returns "not applicable." Archetypes that depend on this anchor cannot match in non-K8s environments — they're inapplicable, not refuted. The agent should fall through to other archetypes.
- **API unavailable:** escalate.
- **Pod no longer exists:** the workload may have been recreated; try the most recent matching pod by label, otherwise escalate.
- **Manifest declares no probe matching the observation:** refutation, escalate.
