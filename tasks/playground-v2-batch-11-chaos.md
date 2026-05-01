---
title: Playground v2 batch 11 — chaos control plane
status: backlog
groups: playground-v2
---

Phase 4 driver for the chaos surface designed in `docs/playground-environment-v2.md` §Chaos model. Batch 9 (#125) shipped the CMDB overlay surface as a passive scaffold; batch 11 adds the controller that actually drives it, plus the other day-one chaos modes.

Picked up after the live-eval pass (`playground-v2-fire-signatures-batch10.md`) validates the happy path against the clean stack.

Scope:

- [ ] **Chaos controller service** — FastAPI on the VPS host, *outside* the response-network compose stack. Holds mutation state + revert procedures. Only component that knows the word "chaos"; downstream artifacts must be indistinguishable from organic environment behavior (`docs/playground-environment-v2.md` §Chaos concealment).
- [ ] **Day-one modes** (3):
  - Schema drift via Elasticsearch ingest-pipeline API
  - Data drops via pipeline filter stage
  - Stale CMDB via the existing overlay surface (`POST /admin/overlay/{name}` from #125)
- [ ] **Profile schema + seed + activation CLI.** Profile id, seed, mode set, duration. Per `docs/playground-environment-v2.md` §Reproducibility: profile + baseline schedule + attack scenario must reproduce the same shape across runs.
- [ ] **Eval-harness ledger** keyed by timestamp, written to a store the agent has no read path into. Scorer can cross-reference; agent cannot.
- [ ] **Concealment audit.** Grep the response-network surface for `chaos*`/`fault*`/`inject*` artifact names; ensure every mutation uses a realistic channel with a mundane cover story (parser change, agent backpressure, missed CMDB update).

Deferred to a later batch:
- toxiproxy-style service outages
- Threat-intel / change-mgmt chaos drivers (stubs from #125; no driver yet)
- Agent-side faults, clock skew
- MinIO-dependent modes

Exit criteria: each of the 3 day-one modes can be activated + reverted via the controller; an attack run from batch 10 executed under each profile produces telemetry that the agent cannot trivially attribute to chaos; profile id never leaks into agent-visible indices.
