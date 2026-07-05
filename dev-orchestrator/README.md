# Dev Workflow Orchestrator

A lightweight, single-developer service that orchestrates a Claude-Code-driven
development workflow and renders it as a Kanban board. Claude Code is the engine,
GitHub is the durable record, and the service is the thin orchestration + observation
layer that removes the repetitive manual hops.

Status: **core implemented, spec-first** (no app shell / UI yet). Name: TBD.
Slice 1 (transition engine) and slice 2 (worker + poll loops, `claimNext` CAS,
reconcile sweep) are implemented on Bun + `bun:sqlite`, with the executable
spec landing before each implementation (PR #524 → #525).

```bash
bun install && bun test    # full suite
bunx tsc --noEmit          # typecheck
```

## Contents

- [`design.md`](./design.md) — the full design: guiding principles, tech stack, state
  model, SQLite schema, state machine + transactions, and open decisions.
- [`src/`](./src) — `contract.ts` (event alphabet + CAS-guard `Expect` mixin),
  `engine.ts` (transactional transition engine), `worker.ts` / `poll.ts` (run
  execution + reconcile loops).
- [`test/`](./test) — the executable spec: one recording, fault-injecting
  `FakeEffects` (faults are data, not per-test mocks), deterministic async
  settlement, behavior-pinning assertions.
- [`mockups/board.html`](./mockups/board.html) — interactive board mockup (Cobalt Mono).
  Standalone HTML; open in a browser.
- [`mockups/palettes.html`](./mockups/palettes.html) — palette explorer used to pick the
  color direction.

## Pipeline

```
backlog → discuss → write_tests → write_code → review → done
```

Two human gates — **approve-tests** (after `write_tests`) and **approve-merge** (the
terminal gate of `review`); everything else is automated. Issue prioritization (the other
sense of "triage") is planning, not execution, and belongs on a separate view.

## Next

The service API + data flows are spec'd in [`design.md` §9](./design.md): one `/rpc`
command endpoint mirroring the `goto` event alphabet and the `getBoard` read model.
The in-process worker/poll loops behind them are implemented; remaining: choose the
app shell (Next.js vs. Hono+Vite — decision #4), scaffold the `/rpc` + board UI on
top of the engine, and relocate to its own repo.
