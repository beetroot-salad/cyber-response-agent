# Dev Workflow Orchestrator

A lightweight, single-developer service that orchestrates a Claude-Code-driven
development workflow and renders it as a Kanban board. Claude Code is the engine,
GitHub is the durable record, and the service is the thin orchestration + observation
layer that removes the repetitive manual hops.

Status: **design / pre-implementation**. Name: TBD.

## Contents

- [`design.md`](./design.md) — the full design: guiding principles, tech stack, state
  model, SQLite schema, state machine + transactions, and open decisions.
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

The service API + data flows are drafted in [`design.md` §9](./design.md): one `/rpc`
command endpoint mirroring the `goto` event alphabet, the `getBoard` read model, and the
in-process worker/poll loops that feed it. Remaining: choose the app shell (Next.js vs.
Hono+Vite — decision #4) and scaffold.
