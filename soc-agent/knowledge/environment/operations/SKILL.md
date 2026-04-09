---
name: operations
description: Queryable lookups in this org — primarily trust anchors that confirm whether an observed activity is sanctioned. Load when an investigation needs to consult an external authority instead of deriving legitimacy from telemetry alone.
---

# Operations

Concrete queryable operations the environment supports. Files here describe how to consult an external authority for a specific question — typically to confirm whether an observed activity is sanctioned.

## Trust anchors

Trust anchors are the pragmatic stopping points for legitimacy questions. When an investigation needs to confirm "is this action authorized" or "is this activity sanctioned," it consults a trust anchor instead of trying to derive legitimacy from telemetry alone.

Each anchor file describes:

- The question the anchor answers
- The org system that hosts the authoritative answer
- How to query it (API, MCP, manual lookup)
- The shape of a confirmation vs a refutation
- What to do on failure (timeout, ambiguous, unavailable → escalate by default)

Anchors are **socially** the stopping points, not epistemically. The agent's job is to consult and report the result, not to verify the anchor itself. Anchor compromise is detected by downstream auditors noticing patterns across many investigations, not by the agent inline.

## Files

- `oncall-schedule.md` — who has prod-touch authority right now
- `change-windows.md` — approved change tickets and maintenance windows
- `deploy-runs.md` — CI/CD pipeline run history
- `workload-manifest.md` — Kubernetes pod spec lookups (probes, containers, security context)
- `image-baseline.md` — established telemetry baselines for container images (pragmatic anchor — see file for epistemic notes)
