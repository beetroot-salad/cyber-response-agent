# Dev Workflow Orchestrator

A lightweight, single-developer service that orchestrates a Claude-Code-driven
development workflow and renders it as a Kanban board. Claude Code is the engine,
GitHub is the durable record, and the service is the thin orchestration + observation
layer that removes the repetitive manual hops.

Status: **runnable, spec-first.** Name: `flowdeck` (working). Slices 1 (transition
engine), 2a (worker + poll loops, `claimNext` CAS, reconcile sweep), and 2b (the real
`Effects` subprocesses, on-disk migration, `/rpc` server, wired board, and `main` boot)
are implemented on Bun + `bun:sqlite`, each with its executable spec landing before the
implementation (PR #521→#525, #529→#531).

## Run

```bash
bun install
FLOWDECK_CONFIG=./flowdeck.config.json bun start   # board + /rpc on http://localhost:8765
bun test          # the gate — full suite
bunx tsc --noEmit # typecheck
```

`FLOWDECK_CONFIG` points at a JSON config (design §9.9 — `runRoot`, `repos[]`, `label`,
`pool`, `port`, `sessionHost`); without it, the §9.9 defaults apply (`~/.flowdeck`, no
repos). The one process runs the worker + poll loops, serves the board, and exposes
`POST /rpc` (`getBoard` / `getCard` / `dispatchEvent` / `createIssue`). There is no CI job
for this package yet — `bun test` + `bunx tsc --noEmit` is the local gate.

## Contents

- [`design.md`](./design.md) — the full design: guiding principles, tech stack, state
  model, SQLite schema, state machine + transactions, the service API (§9), and the
  slice-2b surface (§9.7.1 effects, §9.8 boot, §9.9 config, §10 test surface).
- [`src/`](./src) — `contract.ts` (types + effect seam), `engine.ts` (transactional
  transition engine), `worker.ts` / `poll.ts` (run + reconcile loops), `effects/*` (real
  `git` / `gh` / `claude` / session-host subprocesses), `server.ts` (`/rpc` + read model),
  `db.ts` / `config.ts` / `boot.ts` / `main.ts`, and `board/index.html` (the board wired
  to `/rpc`).
- [`test/`](./test) — the executable spec: one recording, fault-injecting `FakeEffects`
  (faults are data, not per-test mocks), driven against a real in-memory DB.
- [`mockups/board.html`](./mockups/board.html) — the original board mockup (Cobalt Mono).
- [`mockups/palettes.html`](./mockups/palettes.html) — palette explorer.

## Pipeline

```
backlog → discuss → write_tests → write_code → review → done
```

Two human gates — **approve-tests** (after `write_tests`) and **approve-merge** (the
terminal gate of `review`); everything else is automated. Issue prioritization (the other
sense of "triage") is planning, not execution, and belongs on a separate view.

## Next

The board's live `~/.claude` activity tail, the session-host `embedded-pty` / `tmux`
adapters, SSE `/events`, and `bun build --compile` packaging (design §9.3 / §9.6) are the
remaining follow-ups.
