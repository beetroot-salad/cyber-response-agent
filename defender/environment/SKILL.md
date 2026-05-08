---
name: defender-environment
description: Visibility surface — which systems exist in this deployment, what each can answer, what each cannot, and when to reach for which. Loaded by the actor-reviewer learning loop (judge consumes it to route findings) and available to the defender for cross-system scoping.
---

# Defender environment (v4 — visibility only)

This directory describes the *visibility surface* of this deployment: which
systems are queryable, what each can answer, what each declares it cannot
answer, and when to reach for which.

It is intentionally narrow. It does **not** contain trust anchors,
classification heuristics, behavioral baselines, or cached resolutions —
those are derivable from the investigation corpus and belong to a future
self-learning loop, not to this directory. The boundary:

> v4 holds anything a human writes fresh after deploying a new system.
> The future cache loop holds anything that is the *result* of operating
> the system over time.

If the answer to "would we know this immediately on deploying a new
system?" is yes, it belongs here. If the answer is "only after the corpus
catches up," it does not.

## Files

One subdirectory per deployed system. Each `{system}/SKILL.md` follows the
same four-field shape:

- **available_queries** — the templates this system answers, with their
  measurement contracts. Source-of-truth for "is this query dispatchable
  as-is?"
- **gaps** — declared "this system cannot answer X here." Critical for
  distinguishing *we did not ask* from *we cannot ask*. Includes
  enrollment limits, schema absences, and known silent-failure modes.
- **read_guidance** — how to interpret results. Pitfalls, salted-output
  conventions, aggregation semantics, type-mismatch behaviors.
- **when_to_use** / **when_not_to_use** — scoping. When this system is
  the right reach, when another in this directory is better.

Currently described:

- `wazuh/` — primary SIEM (auth, FIM, syscall audit, rule-correlated alerts)
- `host-query/` — read-only endpoint introspection (point-in-time)

## Consumers

- **Judge** (actor-reviewer learning loop): reads this directory to route
  actor findings. A breaking-evidence query that names a template listed
  under `available_queries` is dispatchable. One that targets an entity
  listed under `gaps` is an observability finding, not a playbook gap.
  One that needs a system not described here at all is a tooling-gap
  finding (deployable in principle but no MCP / adapter exists yet).
- **Defender / gather**: cross-system scoping during PREDICT. When a
  measurement contract has multiple plausible source systems, the
  `when_to_use` fields disambiguate.

## What does not live here

- Classifications like "172.0.0.10 is a monitoring host" — cache,
  derivable from corpus, belongs to the self-learning loop.
- Trust anchors like "INC-8821 is a real ticket" — answered by querying
  the ticketing system, which is itself a `system/` entry once the
  ticket adapter ships.
- Active-control claims like "all images are cosign-signed at admission"
  — cached past resolutions of similar findings, surfaces in the
  self-learning loop.
- Accepted residuals at the org level ("Building 7 wifi has no host
  agent") — currently flagged as `gaps` on the relevant per-system page;
  if cross-system residuals accumulate, split into a top-level
  `residuals.md` later.
