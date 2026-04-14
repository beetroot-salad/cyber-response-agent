---
title: Tool discovery refactor: split data availability from tool mechanics
status: done
groups: phase-2
---

Landed as two separate entry points:
- `scripts/preflight.py` — checks live status of configured systems at run start.
- `soc-agent/skills/connect/` — onboarding skill for wiring new systems into `knowledge/environment/`.

The data-availability vs tool-mechanics split is realised through the 4-layer environment model documented in `docs/design-v3-tool-execution.md §10`: `environment/data-sources/` (abstract data tags the main agent consults), `environment/systems/` (vendor-specific query mechanics the lead subagents consult), `environment/context/` (classification heuristics), and `environment/operations/` (per-anchor grounding recipes).
