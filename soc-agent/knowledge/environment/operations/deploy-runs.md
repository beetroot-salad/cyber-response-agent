---
tags: [trust-anchor, authorization, ci-cd]
provides: [deploy-runs]
---

# CI/CD Deploy Runs

Confirms whether observed activity correlates with an active or recent CI/CD pipeline run.

## Question answered

Does the org's CI/CD run history show a job whose target includes the alerting workload, with a window that contains the alert timestamp?

## Available systems

<!-- Example
| System | Coverage | Access | Priority |
|--------|----------|--------|----------|
| GitHub Actions | Application repos | API or MCP | Primary |
| ArgoCD | Kubernetes GitOps deploys | API | Primary for k8s |
| Jenkins | Legacy pipelines | API | Secondary |
-->

## Query

<!-- Example
`MCP: ci.find_runs(target, at_timestamp, window=±10min)`
Returns: list of { run_id, workflow, target, started_at, finished_at, actor, status } or empty list
-->

## Confirmation shape

A confirmation returns at least one run whose:

- Target matches the alerting workload (image, deployment, namespace)
- Time window contains the alert timestamp
- Job type is consistent with the observed activity — a migration job for a migration command, a smoke test for a curl-shaped command

A pipeline run on a *different* workload at the same time is not a confirmation.

## Failure modes

- **Anchor unavailable:** escalate.
- **No runs in window:** refutation — escalate. CI-shaped activity without a recorded run is exactly the case this anchor exists to catch.
- **Run exists but target mismatch:** escalate with the closest run cited.
- **Job type mismatch with observed activity:** escalate with the run cited so the analyst can decide.
