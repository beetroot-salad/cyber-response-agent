# Dev Workflow Orchestrator — Design

> Status: **slice #1 + slice #2a shipped; slice #2b in spec-grade firm-up.** Name: `flowdeck`
> (working). Lives in the defender repo under `dev-orchestrator/` for now; relocate to the new
> project's own repo when scaffolded.
>
> - **Slice #1** — the V1 transition engine (`intake` / `applyEvent` / `claimNext` / `reconcile`)
>   against a recording `Effects` fake (Bun + `bun:sqlite` + `bun test`).
> - **Slice #2a** — the shell-agnostic loops the engine drives: the worker arc (`executeRun` /
>   `drainQueue`), the poll pass (`pollOnce`), `claimNext` as a pure CAS, and reconcile's worktree
>   sweep — still bound against the fake (§9.4).
> - **Slice #2b** *(this firm-up)* — the **runnable surface**: the real `Effects` as subprocesses
>   (`git worktree` / `claude -p` / `gh` / the session host), the on-disk `bun:sqlite` migration,
>   the `Bun.serve` + Hono `/rpc` server + read model, the board wired to live data, and the
>   `main` boot sequence. Spec'd in **§9.7.1 (effects), §9.8 (boot + layout), §9.9 (config),
>   §10 (test surface)**.
>
> Interactive UI mockups live in `mockups/` (board + palette explorer).

A lightweight, single-developer service that orchestrates a Claude-Code-driven
development workflow and renders it as a Kanban board:

```
discuss & design → write tests as spec → write code (ship + watch CI) → review (fix + file follow-ups + approve merge)
```

Claude Code is the engine. GitHub is the durable record. The service is the thin
orchestration + observation layer that removes repetitive manual hops.

---

## 1. Guiding principles

1. **GitHub Issues = system of record.** Anything a human should still see in six
   months — the work item, design discussion, follow-ups — lives in the issue. The
   issue *is* the working item; it gets commented on as stages run.
2. **SQLite = orchestration runtime only.** Job queue, current state, per-stage
   session pointers, transition history, transition idempotency. Nothing durable-to-a-human.
3. **`~/.claude` = system of record for session *content*.** Transcript, cost,
   tokens. We store a **pointer** (`session_id`) and read content back on demand —
   never duplicate it. For headless stages we **assign** `session_id` up front via
   `claude --session-id` (§2), so the pointer is known before the run starts.
4. **Don't rebuild what Claude / GitHub already give you.** The orchestrator stores
   only what it knows that Claude and GitHub don't.
5. **The transition map is code, not data.** Stage × trigger × what-runs is logic and
   lives in TypeScript. SQLite stores *instances* (cards, runs, events), not rules.
6. **Soft board, not gatekeeper.** Automation does the mechanical hops; the human
   keeps the two judgment calls. Nothing is ever blocked — a card can be dragged
   manually at any time.
7. **External binaries are injected.** `gh`, `claude`, and the **session host** (the
   terminal/editor that hosts interactive sessions — default VS Code) are wrapped behind
   thin interfaces with configurable paths/commands, passed in at construction (stubbable
   in tests, swappable). See §2's session-host adapter.
8. **Skills own the work; the orchestrator is dumb plumbing.** A stage skill runs its
   job end-to-end — including long-running concerns like watching CI — and reports one
   outcome. The orchestrator sequences runs and holds the human gates; it never reasons
   about CI, diffs, or test internals.

---

## 2. Tech stack

TypeScript end-to-end on **Bun** — logic, UI, tests, and bundle share one runtime with zero
native addons. The stack is chosen for *fast / lightweight / local*: everything is built-in
(sqlite, test runner, bundler, PTY) or a thin CLI wrapper, so a fresh clone runs on
`bun install` alone. `claude` is a subprocess (not the Agent SDK) — a real OS pid the worker
loop can pid-track, kill, and reap (§6.4).

| Concern | Choice | Notes |
|---|---|---|
| Runtime | **Bun** | one runtime for server + build + tests; no Node, no native addons |
| App / serving | **`Bun.serve` + Hono**, board bundled by **`bun build`** | one process serves `/rpc` + the static board (§9.1); no Next / Vite |
| Engine — headless stages | **`claude -p` subprocess** (write_tests / write_code / review) | injected spawn → real OS pid; `--session-id <uuid>` assigned up front; **not** the Agent SDK (no dep) |
| Engine — interactive discuss | **configurable session host** (default VS Code; **`Bun.Terminal`** backs the built-in `embedded-pty`) | injected launcher `exec`s a per-host command; the board owns the pty only for `embedded-pty` |
| Data | **`bun:sqlite`** (built-in, synchronous), WAL, on-disk in the run dir | open `{ strict: true }` for bare-key named binding; raw SQL, no Drizzle |
| Tests | **`bun test`** | slice #1's suite already runs here |
| GitHub | injected **`gh` CLI** | intake + drift by **polling** (§9.4); no inbound webhooks (skills self-report; CI is watched inside `write_code`) |

### Why build our own board (not GitHub Projects)

GitHub Projects is free on private + public repos, but it's hosted SaaS: **you cannot
add a card button that runs `claude --resume` on your machine.** Its only extension
points are cosmetic fields and server-side automation. The "launch a Claude session
from the card" requirement is what justifies a custom UI — a **local button that `exec`s
`code <worktree>` / `claude` / `gh` on your machine**, which a hosted board fundamentally
can't do.

### UI seam — what the board owns vs. what it points at

`gh` + `claude` are the bedrock; the board is a thin control surface over them, never a
replacement for either. It owns only orchestration state (which lives nowhere else) and
launches/links everything that has a canonical home.

**Owns (independent — nothing else has it):**
- The board grid — cards + `(stage, status)` (the SQLite state) — and the action
  affordances (`approve` / `skip` / `advance` / `retry` / `cancel` / `move` /
  `start_discuss`), including the launcher that `exec`s local tools. These are **UI
  gestures, not machine events**: every forward/lateral one lowers to a single primitive,
  `goto(target)` (plus `cancel` / `archive`) — the board is soft, so the transition layer
  never distinguishes advance from skip from approve (§6.2, §9.2).
- **Intake + issue creation.** It **discovers `gh` issues into `backlog` by default** (the
  poller, filtered by the tracking label — §7.9); a **"new issue" form runs
  `gh issue create`** under the hood, so a UI-authored issue lands as a card the same way.
- A read-only **activity line** per in-flight headless run (last step / elapsed / cost),
  tailed by `session_id` — glanceable without leaving the board.

**Points at (never re-implements):**
- **Interactive Claude sessions → a configurable session host (default: VS Code).** The
  service is local, so `start_discuss` / resume `exec`s the host's launch command — for
  VS Code, open `<worktree>` and seed a `claude` session in the **integrated terminal**.
  That dissolves the terminal-vs-VS-Code tension: the integrated terminal *is* a full shell
  *inside* your workbench, so "run claude in a terminal" and "keep VS Code as my working
  interface" are the same choice — with fewer hops than an embedded browser terminal, which
  would strand claude's shell away from where you edit. (Point it at your own workbench —
  see "Session host is configurable" below.)
- **Diffs / PRs / CI / review → GitHub** (link out; no diff viewer — GitHub stays the review interface).
- **Transcript / cost / tokens → `~/.claude`**, read on demand by `session_id`.
- **Issue body / design / follow-ups → GitHub**, linked.

**Consequence — a detached host isn't parented by the board.** VS Code (the default) runs
the session out-of-process, so there's no board-owned pid and no exit for the loop to await
(unlike headless runs, which the worker spawns, pid-tracks, and awaits — §6.4, §9.4; the `embedded-pty` host is the exception —
the board owns that one). Two follow-ons: (1) session-id capture is by pre-generated
`--session-id` or reading the newest `~/.claude` file (below); (2) the discuss run's
lifecycle is resolved by a **board action** — "Done — proceed" (`run_succeeded`) or
"Discard" (`cancel`) on the card — not by detecting a terminal exit. An unresolved discuss
just rests in `running` (it holds no worker slot and burns no tokens while idle) until you
resolve it or a dwell-timeout nags.

**Session host is configurable — VS Code is just the default adapter.** Launching is an
injected effect (§1.7) confined to the effect layer (§6.4.1), so the board depends on a thin
`SessionHost`, not on `code` — and generalizing touches no state machine, schema, or gate.
Its whole contract is *"open an interactive `claude` session rooted at worktree `P`,
optionally resuming `S`"*, with a capability-degradation model — a baseline any terminal
supports, richer hosts opting into more:

| Capability | Needs | Fallback if absent |
|---|---|---|
| **Open** in a cwd | exec a command with `{cwd}` | — (baseline; every terminal has it) |
| **Capture session-id** | pass a generated `--session-id` | read newest `~/.claude` file after launch |
| **Report completion** | a wrapper that pings the board on exit | the card's Done / Discard button |

Only *Open* is required, so "connect any terminal" is a one-line command template — no
per-terminal code:

```toml
[session_host]
kind = "vscode"          # default; or "command" | "tmux" | "embedded-pty"
# kind = "command": placeholders filled per launch
command = "wezterm start --cwd {cwd} -- claude {resume} --session-id {sid}"
session_id = "prearranged"    # board generates {sid}; else "watch-claude-dir"
reports_completion = false    # false → resolve via the card's Done/Discard button
```

Swap `command` for `alacritty`/`kitty`/`tmux`/`gnome-terminal`/iTerm and you're done. Ship
`vscode` (default) + `command` (covers all terminals) + optional `tmux`/`embedded-pty` — an
injected interface with a few adapters, not a plugin framework. Each user points it at their
own workbench, which *strengthens* "minimize transitions": everyone gets a one-surface home.

**VS Code adapter — the folder-open task.** `code {cwd}` only *opens the folder*; the VS Code
CLI can't run a command in the integrated terminal. So the adapter writes a task with
`"runOptions": { "runOn": "folderOpen" }` that runs `claude {resume} --session-id {sid}`,
then `exec code <workspace>` → VS Code auto-runs it in a terminal panel on open. Two gotchas:
(1) **Workspace Trust** must be granted for the tree and `task.allowAutomaticTasks` allowed —
a one-time per-tree consent (folder-open tasks are gated as an attack surface); if the task
"silently doesn't run," it's almost always trust. (2) To avoid mutating the repo's tracked
`.vscode/`, carry the task in a **generated `.code-workspace` file** in the run dir *outside*
the repo, not in-tree. The task string can also carry the completion ping and `--session-id`,
so `vscode` satisfies all three capabilities; if trust is a hassle, degrade to `exec code
{cwd}` and type `claude` (one manual step).

Net: two surfaces you already live in — **your workbench** (VS Code / terminal / tmux: work +
shell + claude) and **GitHub** (review) — plus the board as a glance-and-dispatch third
surface. The board is a launcher and ledger, never a place you do the work.

### Session-id capture

- **Headless stages (`claude -p`):** we **assign** the id — generate a uuid, pass
  `claude --session-id <uuid>`, and store it on the run *before* the process starts. Known up
  front, so there's no post-hoc harvest and no race with `~/.claude` file mtimes.
- **Interactive discuss (VS Code / terminal):** same `--session-id` when the host can carry it
  (the baseline capability, §2 table); a bare terminal that can't falls back to reading the
  newest `~/.claude` session file right after launch.
- **Live view:** session content lives in `~/.claude`, so the board tails a running headless
  run's transcript by `session_id` for a "watch it work" pane — read on demand, never stored.

*(Verify `--session-id` against the installed CLI when wiring the real effect.)*

---

## 3. User journey (soft board)

Two human touchpoints + discuss-on-demand. The pipeline runs itself not because the
orchestrator reacts to a storm of GitHub webhooks, but because **each stage is a
self-contained, long-running skill** that owns its job end-to-end (including watching
CI) and reports one outcome. The orchestrator only *sequences* runs and holds the two
human gates.

| Stage | Advance mechanism |
|---|---|
| **backlog** | new issue lands here (intake — discovered by polling `gh`) |
| **discuss** | card opens a seeded `claude` session in VS Code; **"Done — proceed" advances to `write_tests`**, "Discard" parks in `discuss` (§2 UI seam) |
| **write_tests** | runs, then **waits for human approval** of the spec — soft gate #1 |
| **write_code** | auto once tests approved → the `write-code` skill plans, implements, ships a PR, and **watches CI to green itself** (see §3.2) |
| **review** | **auto once `write_code` succeeds** → `/code-review` fixes what it safely can inline, **files the rest as follow-up issues**, re-greens the PR if it pushed (§3.3); then **waits for human** to approve the merge — soft gate #2 |
| **done** | terminal |

Nothing enforces order; automation just performs the mechanical transitions so the
human only supplies judgment (approve-tests, approve-merge) and initiative (discuss).

> **No `triage` stage.** Issue *prioritization* — the other sense of "triage" — is planning,
> not execution, and belongs on a separate backlog/planning view, not in this pipeline. The
> old post-review "triage" gate was really the **merge approval**; it now lives as the
> terminal gate of `review` (§3.3, §6.3), so the board is one column shorter and still keeps
> both human gates.

### 3.1 Stage execution model

Stages are **long-running skills, not webhook reactions.** A stage run owns its whole
job and blocks until done — `write_code` may run for minutes while it watches CI. This
is what lets the orchestrator stay dumb: it sees only `queued → running →
succeeded | failed`, never CI internals.

A consequence worth taking: **the service needs no inbound endpoint.** The only thing
that would have required a webhook was CI, and that now lives inside the stage runs themselves (`write_code`, and `review` when it pushes fixes).
Intake (new issues) and drift (a PR you merged by hand) are just as well discovered by
**polling `gh`** on a timer. So the default is a purely local, poll-driven service — no
tunnel, no public URL, no webhook secret. (Webhooks remain an optional latency
optimization; see §7.)

### 3.2 The `write-code` skill contract

The stage formerly called "implement," renamed `write-code` (symmetric with
`write-tests`, and free of the overloaded word *implement*). It is the smartest
component and owns the plan→ship→green loop:

1. **Plan** — read the issue + the approved test spec (already committed on the branch by `write_tests`).
2. **Implement** — write code until the tests pass locally.
3. **Ship** — commit, push, `gh pr create`; the skill reports `pr_number` in its outcome — **on failure as well as success**, so a PR that opened but never greened stays linked to the card (persisted by T-FAIL, §6.5).
4. **Watch + repair** — `gh pr checks --watch`, which natively watches *all* checks, not
   just required ones (no per-suite bookkeeping; `--required` would narrow to required-only,
   but we deliberately watch everything, and exit code 8 means checks are still pending). On
   red: read the failures, fix, push, re-watch.
5. **Exit** — `succeeded` when green; **`failed` out to a human** when it can't get green.

Two properties are load-bearing:

- **The repair loop is bounded** — max attempts *or* a time/cost budget. An unbounded
  fix loop is a credit sink and holds a worker slot indefinitely. When the bound trips
  the run *fails*; the card lands in `write_code / failed` and you can `claude --resume`
  the exact session (its `session_id` is on the run).
- **It holds its worker slot for the whole CI watch.** The watch is token-cheap
  (blocked on a `gh` call, not generating), but the *slot* is occupied for minutes —
  fine per-card (one active run each); it just caps cross-card throughput. The headless
  worker-pool size defaults to a small N (1–2 for a single dev) and is configurable;
  `discuss` runs outside it (§6.3).

### 3.3 The `review` skill contract

`review` is `write_code`'s mirror: rather than writing code to pass a spec, it reads the
green PR, **applies the safe fixes inline** (`/code-review --fix`, `/simplify`) and files
the rest as follow-ups. Because it can mutate the branch it **reuses `write_code`'s
ship-and-watch tail** (§3.2, steps 3–5): if it pushed any commit it re-runs
`gh pr checks --watch` and only `succeeds` once the PR is green again — otherwise the
"PR is already green" invariant the merge gate relies on would be a lie. A review
that changes nothing short-circuits straight to `succeeded`. On success the card rests at
`review / awaiting_human` — the **merge gate** (§6.3), the second and final human touchpoint.

This needs **no new state-machine rows**: a review that can't re-green fails through the
existing generic `run_failed` edge (§6.3) into `review / failed`, retryable like any
other stage. Note the consequence for the gate model — `review` mutates the branch
*autonomously*, so the human still never approves the diff directly; the two gates stay
approve-tests and approve-merge (the latter now the terminal gate of `review` — §6.3).
Whether review fixes inline at all, and whether it must re-green before that gate, is an
open decision (§7).

---

## 4. State model — materialized, not derived

**Decision:** the card carries the authoritative *current* state as an explicit
`(stage, status)` pair. The `run` table is mechanism + append-only history, and is
**never** consulted to answer "what state is this card in now."

- *Stage* and *lifecycle status* are two orthogonal axes (pipeline position vs. what a
  job is doing) — modeled as two fields, which is standard.
- **Invariant: board column = `card.stage`, always.** A queued card sits in its target
  column with a "queued" badge.
- **Transitions are atomic:** enqueuing a stage is one transaction that inserts the
  `run` row *and* updates `card.(stage, status)`. No window where the two disagree →
  no split-brain.
- A partial unique index enforces **at most one in-flight run per card** (matches
  "one worktree per active card").

**Why materialize rather than derive-from-both:** deriving current state from
`card.stage` + latest `run.status` forces every live read to compute an
aggregate and reason about "which run is latest," and lets the two sources
contradict. Materializing gives one source of truth for *now* (the card), keeps the
`run` log for audit, and matches how operational systems work (Airflow `DagRun.state`
+ `TaskInstance.state`, GitHub Actions run/job status — each level stores its own
state; children are mechanism + history). Pure derive-from-the-log is event sourcing —
justified by replay/time-travel or distributed multi-writer needs, which a
single-writer local board doesn't have. Cost (writing two places transactionally) is
trivial: SQLite gives the transaction; the worker is the single writer.

---

## 5. SQLite schema

```sql
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- One row per work item. 1:1 with a GitHub issue. AUTHORITATIVE CURRENT STATE.
-- Everything durable — design, discussion, follow-ups — lives in the issue, not here.
CREATE TABLE card (
  id             TEXT PRIMARY KEY,              -- uuid: stable internal id, independent of repo/issue
  repo           TEXT NOT NULL,                 -- "owner/name" — needed for gh calls + worktree paths
  issue_number   INTEGER NOT NULL,              -- pointer to the working item (the issue gets commented)
  pr_number      INTEGER,                       -- pointer, set when write_code ships the PR
  stage          TEXT NOT NULL                  -- board column = this, always
                   CHECK (stage IN ('backlog','discuss','write_tests','write_code',
                                    'review','done')),
  status         TEXT NOT NULL DEFAULT 'idle'   -- lifecycle; flips atomically with stage (see §6)
                   CHECK (status IN ('idle','queued','running','awaiting_human','failed')),
  title          TEXT,                          -- denormalized from the issue so the board renders w/o a GH call
  worktree_path  TEXT,                          -- isolated worktree, one per active card
  created_at     TEXT NOT NULL,                 -- ISO-8601 UTC
  updated_at     TEXT NOT NULL,
  state_entered_at TEXT NOT NULL,               -- when the card entered its current (stage,status); dwell / gate-nag "stuck" signal
  archived_at    TEXT,                          -- drop off the board without deleting
  UNIQUE (repo, issue_number)                   -- can't double-track one issue
);

-- (card, stage, attempt) -> session. Doubles as JOB QUEUE and append-only HISTORY.
-- Stores POINTERS + orchestration state only — never transcript/cost/logs
-- (read those from ~/.claude via session_id).
CREATE TABLE run (
  id           TEXT PRIMARY KEY,
  card_id      TEXT NOT NULL REFERENCES card(id) ON DELETE CASCADE,
  stage        TEXT NOT NULL                    -- same domain as card.stage; only run-bearing stages
                 CHECK (stage IN ('discuss','write_tests','write_code','review')),
  attempt      INTEGER NOT NULL DEFAULT 1,
  status       TEXT NOT NULL DEFAULT 'queued'   -- generic run lifecycle (gates live on card.status, §6)
                 CHECK (status IN ('queued','running','succeeded','failed','cancelled')),
  trigger      TEXT NOT NULL                    -- why it ran (audit)
                 CHECK (trigger IN ('manual','auto','retry')),
  session_id   TEXT,                            -- JOIN KEY into ~/.claude; content stays there
  pid          INTEGER,                         -- OS pid of the stage subprocess; written by the worker loop
                                                -- post-spawn, NULL when finished. A best-effort KILL handle only
                                                -- (reap by pgroup+pidfile, never bare kill(pid), §6.4); RETAINED
                                                -- on 'cancelled' so the reaper can reach a swallowed-kill orphan.
  created_at   TEXT NOT NULL,
  started_at   TEXT,
  finished_at  TEXT
);
CREATE INDEX run_queue   ON run (status, created_at);    -- worker polls WHERE status='queued'
CREATE INDEX run_by_card ON run (card_id, created_at);   -- render a card's timeline
-- at most one in-flight run per card (== one worktree per active card)
CREATE UNIQUE INDEX one_active_run_per_card
  ON run (card_id) WHERE status IN ('queued','running');
-- one row per (card, stage, attempt): retry must bump `attempt` monotonically per
-- (card, stage) — never reset to 1 — so a re-entered stage can't collide with old history.
CREATE UNIQUE INDEX one_run_per_attempt ON run (card_id, stage, attempt);

-- No `event` table: events (issue.opened, approve, run_succeeded, …) are the transition
-- function's in-memory input alphabet (§6.2), not rows. Guarded CAS on current state +
-- natural-key intake dedup already give idempotency; `run` is the append-only history.
```

### Schema notes

- **`card.id` is a uuid**, but `UNIQUE(repo, issue_number)` stops double-tracking. The
  uuid is the surface key (URLs, FKs); `(repo, issue_number)` is the natural key.
- **"Current session" = latest `run` for the card** — no `session_id` column on `card`.
- **`run` is your (card, stage → id) mapping**, one-to-*many* over attempts, which is
  why it's a table (per-entry status/trigger/timestamps) not a list column.
- **No `event` table.** Events are the transition function's input alphabet (§6.2),
  dispatched in-memory. The idempotency a table would buy is already covered by guarded
  CAS on current state + natural-key intake dedup; `run` is the append-only history. Add
  one only when webhooks need delivery-id dedup or you want raw-payload replay.

### Deliberately NOT in SQLite

- The transition map → TypeScript code.
- Big logs → files on disk; `run` points via `session_id` / a log path if needed.
- Design, discussion, follow-up issues → GitHub.
- Session transcript / cost / tokens → `~/.claude`, read by `session_id`.
- Soft gates (approve-tests, approve-merge) → not stored; an `approve` is a UI action that runs
  the transition transaction directly (enqueue the next run, or set `done`). Its only
  trace is the resulting `(card, run)` state change.

---

## 6. State machine & transactions

### 6.1 The two machines

- **Run lifecycle** (generic, one per `run` row):
  `queued → running → succeeded | failed | cancelled`.
  The interactive discuss session is `running` while the human is in the VS Code session;
  it `succeeds` when they click **Done — proceed** on the card (§2). `write_code` is `running` for its whole
  plan→ship→watch-CI loop; CI going red is handled *inside* the run, not by the
  orchestrator.
- **Card progression** (domain): driven by *events*. On `run_succeeded` the transition
  function picks the next `(stage, status)` from which stage just finished. Gates
  (`awaiting_human`) live on `card.status`, never on the run.

### 6.2 Alphabet

**Card states** = `(stage, status)`.
`stage ∈ {backlog, discuss, write_tests, write_code, review, done}`.
`status ∈ {idle, queued, running, awaiting_human, failed}`.

**Events** — the transition function's input alphabet (in-memory messages dispatched to
`nextState`, *not* rows; there is no `event` table, §5). Because the board is **soft**
(§1.6 — any drag is legal), every forward/lateral human gesture collapses to *one*
primitive, **`goto(target)`**; the old named gestures (advance / skip / approve / retry /
start_discuss / move) are just `goto` specialized by target, resolved from `(from, target)`
in code — not distinct events.

UI-originated (arrive over the board's `/rpc` endpoint):

| Event | UI gestures that emit it | Meaning |
|---|---|---|
| `goto(target[, park])` | Start-discuss · Advance · Skip · drag-forward · Approve-tests · Approve-merge · Retry · Move | put the card at `target` stage. Code derives everything else: cancel any in-flight run first, **enqueue** a run iff `target` is run-bearing (else rest `idle` / at its gate), bump `attempt` on re-entry, and compute `trigger`. `park` forces `idle` even at a run-bearing target (the old `move`). |
| `cancel` | Cancel · Discard (discuss) | discard the in-flight run **and its worktree**, rest at the current stage/`idle`. Distinct from `goto(current)`/Retry, which **keeps** the tree. |
| `archive` | Archive | drop off the board (`archived_at`); cancels any in-flight run first. |

System-originated (dispatched in-process by the worker/poller — never over the wire):

| Event | Source | Meaning |
|---|---|---|
| `issue.opened` | github (poll) | new tracked issue → intake (guarded by a tracking label) |
| `run_succeeded(id)` / `run_failed(id)` | worker; for `discuss` it's the card's **Done — proceed** button (§2) | a run finished (CI-red inside `write_code` surfaces as `run_failed`). *(Mergeable to `run_finished(id, ok)`; kept split to mirror T-SUCCEED / T-FAIL, §6.5.)* |
| `pr.merged` | github (poll) | tracked PR merged (pipeline or by hand) → card done (drift) |
| `pr.closed` | github (poll) | tracked PR closed **without** merge → card `failed`, so the human can reopen / rework / archive (drift) |

**How one `goto` reads by position** (all computed, none enumerated):

| `goto(target)` from… | reads as | because |
|---|---|---|
| resting `*/idle`, target = next stage | **advance** | +1 step |
| any resting stage, target = a later stage | **skip** | +N steps — the board is soft |
| `write_tests / awaiting_human` → `write_code` | **approve-tests** | a forward `goto` *out of* a gate releases it |
| `review / awaiting_human` → `done` | **approve-merge** | target is terminal → no run |
| `*/failed` → same stage | **retry** | re-enter; `attempt+1` |
| `backlog/idle` → `discuss` | **start-discuss** | target `discuss` → interactive lane (§6.3) |
| any state → arbitrary stage, `park` | **move / park** | explicit rest, no run |

`run.trigger ∈ {manual, auto, retry}` is **computed from `(source, from-state)`**, not the
gesture: **`retry`** = `goto(current)` from `*/failed`; **`auto`** = a gate release (a
forward `goto` out of `*/awaiting_human`) or a system auto-chain (`write_code → review`,
`discuss → write_tests` on **Done — proceed**); **`manual`** = every other human `goto`
(the human named the target). *(Rename to `retry`/`chain`/`human` if that reads clearer.)*

### 6.3 Transition table

Happy path (▸ = automatic, ✋ = human `goto`/action):

| From `(stage/status)` | Event | Actions (atomic) | To `(stage/status)` |
|---|---|---|---|
| — | `issue.opened` (has label) | insert card | `backlog / idle` |
| `backlog / idle` | ✋`goto(discuss)` | insert run(discuss, manual, running); spawn seeded `claude` in the session host *(post-commit)* | `discuss / running` |
| `discuss / running` | ▸`run_succeeded` (Done — proceed) | auto-chain: enqueue write_tests | `write_tests / queued` |
| `write_tests / queued` | ▸ worker claim | run→running | `write_tests / running` |
| `write_tests / running` | ▸`run_succeeded` | — | `write_tests / awaiting_human` |
| `write_tests / awaiting_human` | ✋`goto(write_code)` *(approve-tests)* | enqueue write_code | `write_code / queued` |
| `write_code / queued` | ▸ worker claim | run→running | `write_code / running` |
| `write_code / running` | ▸`run_succeeded` | store `pr_number`; auto-chain: enqueue review | `review / queued` |
| `review / queued` | ▸ worker claim | run→running | `review / running` |
| `review / running` | ▸`run_succeeded` *(fixes pushed + follow-ups filed)* | — | `review / awaiting_human` |
| `review / awaiting_human` | ✋`goto(done)` *(approve-merge)* | (optionally merge PR) — **terminal, no run** | `done / idle` |

Cross-cutting — the whole block is now **six rows**, because one `goto` absorbs advance /
skip / approve / retry / move / start_discuss:

| From | Event | Actions (atomic) | To |
|---|---|---|---|
| any state | ✋`goto(target[, park])` | cancel any in-flight run *(post-commit)*; set `stage=target`; **enqueue** a run there (or rest `idle`/at the gate if `park` or a non-run target); `attempt+1` on re-entry; `trigger` per §6.2 | `target / {queued\|awaiting_human\|idle}` |
| `* / running` | `run_failed` | run→failed; store `session_id` + `pr_number` (shipped-but-unmerged PR stays linked; `claude --resume` works) | `* / failed` |
| `* / {queued,running}` | ✋`cancel` | run→cancelled; kill proc + **remove worktree** *(post-commit)* — a discard, not a pause | `* / idle` |
| `*` | ✋`archive` | cancel any in-flight run, then set `archived_at` | (hidden) |
| `* (pr_number set)` | `pr.merged` | cancel any in-flight run *(post-commit)*, then mark done | `done / idle` |
| `* (pr_number set)` | `pr.closed` (unmerged) | cancel any in-flight run *(post-commit)*; keep `pr_number` linked so the human can reopen / rework / archive | `* / failed` |

Notes:
- **`goto` *is* the soft board.** One primitive expresses advance, skip, approve, retry,
  move, and start-discuss; the transition fn reads `(from, target)` to decide run-vs-park,
  the `attempt` bump, and `trigger` (§6.2). "Any phase is skippable / a card drags anywhere"
  (§1.6) isn't extra machinery — it's the *default*, and the old named events were just
  `goto` with the target precomputed. A dep bump is `goto(write_code)` from `backlog`
  (skipping discuss + write_tests, and thereby dropping the approve-tests gate — no spec to
  approve).
- **The gates are positions, not events.** `write_tests/awaiting_human` and
  `review/awaiting_human` are resting states; a forward `goto` *out of* one **is** the
  approval (approve-tests enqueues `write_code`; approve-merge is terminal `done`, no run).
  The two human gates are unchanged — they're just no longer distinct verbs, which is why
  "not every approve enqueues" stops being a special case: the target stage decides.
- **`cancel` vs `goto(current)`/Retry.** Both stop the current run, but `cancel` **removes
  the worktree** (a discard) while `goto` back onto the same stage / Retry **keeps** it for
  `claude --resume` and reuse (§6.5 T-CANCEL vs T-FAIL). That worktree semantic — not the
  target — is why `cancel` survives as its own verb.
- **`discuss` bypasses the worker queue.** `goto(discuss)` is human-initiated and
  interactive, so it spawns straight to `running` in its own lane rather than queueing
  behind headless runs. Available from any resting `*/idle`, not just `backlog`. Whether
  re-discussing from a later stage parks the card in `discuss` (default) or opens an ad-hoc
  side session leaving `card.stage` untouched is open. *(Open decision — §7.12.)*
- **`discuss → write_tests` is resolved from the board, not process exit.** The session host
  doesn't parent the session (§2), so the discuss card carries **Done — proceed**
  (`run_succeeded` → auto-chain to `write_tests`) and **Discard** (`cancel` → parks in
  `discuss/idle`). Intent is an explicit click, never inferred from how a terminal closed.
  `write_tests` then **cold-starts from the issue** (§7.5); nothing carries from the session.
- **Auto-chains** (`write_code → review`; `discuss → write_tests` on Done — proceed) enqueue
  the next run inside the predecessor's `T-SUCCEED`, atomically (`trigger=auto`) — so
  `write_code` success alone drives the card to `review`; there is no separate CI event.
  `review` files its own follow-ups and finishes on its own merge gate — no `follow_ups` run.
- **Drift.** Polling `gh` surfaces `pr.merged`/`pr.closed` for a card with `pr_number` set:
  merged → `done` from wherever it sat (CAS on any non-`done` state, so re-observing next
  poll is a no-op); closed-unmerged → `failed`, `pr_number` kept linked to reopen / rework /
  archive. This is the "PR you merged by hand" case §3.1 motivates.
- Filed follow-up issues re-enter via `issue.opened` as fresh `backlog` cards.
- *(Future: capture a recurring `goto` sequence as a named per-card **recipe** — a stored
  `plan` the card auto-runs, e.g. `chore = goto(write_code) → goto(review)` — so
  dep-bump-shaped work runs the short path without per-card clicks.)*

### 6.4 Transaction rules

1. **State moves inside the transaction; side effects run after commit.** Spawning
   `claude`, killing a process, GH calls, worktree ops — none happen inside the write
   transaction. The committed row is the instruction; an effect layer reconciles the
   world from it. Keeps a slow subprocess out of the write-lock and makes every effect
   retryable.
2. **The queued `run` row is the outbox.** The worker polls `run WHERE status='queued'`
   and spawns. Nothing else enqueues work.
3. **Idempotency at every entry point:**
   - **every transition is a guarded CAS on the expected current state** — a stale or
     duplicate event (double-clicked `approve`, a re-polled issue) updates 0 rows and is
     a safe no-op. This is the backbone; the rest are special cases of it.
   - run completion — `WHERE id=? AND status='running'`; a duplicate `run_succeeded`
     updates 0 rows and aborts.
   - intake — `ON CONFLICT(repo, issue_number) DO NOTHING`; re-observing the same issue
     on the next poll is a no-op.
   - enqueue — the `one_active_run_per_card` partial unique index makes a double-enqueue
     throw; caught as "already in flight."
4. **Crash recovery = a startup reconciler over runs left `running`, split by kind.**
   The durable handle is `run.session_id`, not the pid. A **headless** run the restarted
   orchestrator can no longer harvest (it lost the child-process handle) is simply stale → `failed`,
   and is **retryable / `claude --resume`-able off its `session_id`** — no liveness probe
   needed to decide that. `run.pid` is kept *only* as a best-effort **kill handle** to reap
   an orphaned subprocess that outlived the crash and would otherwise burn credits — and
   because a bare pid can be reused after a reboot, reap by **process group + a run-dir
   pidfile** (or a recorded start-time check), never a bare `kill(pid)`. **Interactive
   `discuss` runs are exempt:** the board never parented them (§2), so a restart leaves them
   `running`, to be resolved by the card's Done/Discard button and re-attached with
   `claude --resume <session_id>` — reconciling them to `failed` would destroy a live design
   session. Then re-drive `queued` runs, purely from committed state. Finally, a **worktree
   sweep** (`listWorktrees` vs the cards): remove any tree whose card is gone or now
   `worktree_path IS NULL` (cancelled / archived / done), reaping what a swallowed post-commit
   teardown left on disk (§9.4). The orphaned-**process** counterpart — a swallowed `kill` on
   a cancelled run — is reaped the same way once the pgroup+pidfile handle is real (2b);
   `cancelRun` keeps the `pid` for it.
5. **`BEGIN IMMEDIATE` for claim/enqueue** so the worker and the poll loop can't race a
   card into two runs.

### 6.5 Key transactions (pseudo-SQL)

```sql
-- T-INTAKE: new issue discovered by polling gh (idempotent on the issue)
BEGIN IMMEDIATE;
  INSERT INTO card(id, repo, issue_number, stage, status, ...)
    VALUES (:uuid, :repo, :n, 'backlog', 'idle', ...)
    ON CONFLICT(repo, issue_number) DO NOTHING;   -- already tracked → 0 rows → return
COMMIT;

-- T-ENQUEUE: the core transition — any `goto(target)` that enqueues (advance / approve-tests / skip / retry).
-- Auto-chains (write_code→review; discuss→write_tests on "Done — proceed") run this same shape in T-SUCCEED.
BEGIN IMMEDIATE;
  -- Guarded CAS on the card's EXPECTED (stage,status) FIRST: a stale/duplicate event —
  -- a double-clicked approve, or an approve that arrives after the card was moved away —
  -- updates 0 rows, so we ROLLBACK and insert NO run. This is the §6.4.3 CAS backbone,
  -- not a special case; the caller passes the (stage,status) it believes the card is in.
  UPDATE card SET stage=:stage, status='queued', state_entered_at=:now, updated_at=:now
    WHERE id=:card AND stage=:expected_stage AND status=:expected_status;
  -- if 0 rows updated → ROLLBACK and return (do not enqueue)
  INSERT INTO run(id, card_id, stage, attempt, status, trigger, created_at)
    VALUES (:uuid, :card, :stage, :attempt, 'queued', :trigger, :now);
    -- partial unique index one_active_run_per_card also throws if one is already in flight
COMMIT;
-- (post-commit) nothing — the worker will pick the queued run up

-- T-CLAIM: worker starts a queued run
BEGIN IMMEDIATE;
  UPDATE run  SET status='running', started_at=:now WHERE id=:run AND status='queued';  -- CAS
  UPDATE card SET status='running', updated_at=:now WHERE id=:card;
COMMIT;
-- claimNext returns {run, card} here — it is PURE CAS, no post-commit effect. The worker
-- loop (§9.4) creates the worktree, spawns `claude -p`, writes the child pid, then awaits
-- exit and dispatches T-SUCCEED / T-FAIL. session_id is assigned up front via --session-id (§2).

-- T-SUCCEED: run finished ok → transition function sets the next card state
BEGIN IMMEDIATE;
  UPDATE run SET status='succeeded', finished_at=:now, session_id=:sid, pid=NULL
    WHERE id=:run AND status='running';           -- 0 rows → already handled → abort
  -- next state from the finished stage (map in code):
  --   discuss    → INSERT run(write_tests, auto, queued); (write_tests, queued)  [on "Done — proceed"; write_tests cold-starts from the issue (§7.5); abandon → (discuss, idle) via T-CANCEL]
  --   write_tests→ (write_tests, awaiting_human)
  --   write_code → INSERT run(review, auto, queued);      (review, queued) + pr_number=:pr
  --   review     → (review, awaiting_human)               [merge gate; review filed its own follow-ups]
  UPDATE card SET stage=:next_stage, status=:next_status,
                  pr_number=COALESCE(:pr, pr_number),
                  state_entered_at=:now, updated_at=:now
    WHERE id=:card;
COMMIT;

-- T-FAIL: run failed → card to (stage, failed). Capture pointers even on failure so the
-- card stays linked and resumable.
BEGIN IMMEDIATE;
  UPDATE run  SET status='failed', finished_at=:now, session_id=:sid, pid=NULL
    WHERE id=:run AND status='running';           -- 0 rows → already handled → abort
  UPDATE card SET status='failed',
                  pr_number=COALESCE(:pr, pr_number),   -- shipped-but-unmerged PR stays linked
                  state_entered_at=:now, updated_at=:now
    WHERE id=:card;
COMMIT;
-- (post-commit) kill the pid only if still alive; KEEP the worktree for `claude --resume` / retry.

-- T-CANCEL: same CAS shape over WHERE status IN ('queued','running').
-- (post-commit) kill the pid AND `git worktree remove` — a cancel discards, not pauses.
```

### 6.6 Worktree & branch lifecycle

One branch + one worktree per card (`card.worktree_path`; branch e.g. `flow/issue-<n>`).

- **Created lazily** by the first stage that needs a checkout (`write_tests` on the happy
  path, or `write_code` when the card **skipped** straight into it — §6.3) in its post-commit
  spawn; the branch name and `worktree_path` are written back onto the card. Any
  checkout-needing stage must be able to create it, not just `write_tests`.
- **Shared** across `write_tests → write_code → review`: they build on one branch (the
  approved tests are committed there, `write_code` pushes it, `review` fixes on it).
- **`discuss` needs no worktree** (read-only exploration); it opens at the repo's **main
  checkout root** unless the card already carries a `worktree_path`, and any tree it wants is
  throwaway.
- **`fail` keeps the worktree** so `claude --resume` and `retry` reuse the exact tree;
  **`cancel` removes it** (§6.5 T-FAIL vs T-CANCEL) — cancel is a discard.
- **Teardown** on `done` (after any merge) or `archive`: `git worktree remove`. The branch
  survives on the remote once `write_code` pushed it, so the local tree is disposable and
  rebuildable from the branch.

---

## 7. Open decisions

1. **Multi-repo now, or single-repo?** (`repo` column is included; drop it if it's one
   repo forever.)
2. **Resolved — cost tracking dropped.** `run.cost_usd` is removed from the schema (§5) and
   the read model (§9.3); the board links out to `~/.claude` by `session_id` for cost on
   demand. Dropped for simplicity — one fewer column, and no SDK `total_cost_usd` hook to
   chase now that headless stages run as `claude -p` (§2). *(was: derive-on-read vs cache.)*
3. **Resolved — session-id is assigned, not harvested.** Headless (`claude -p`) and any host
   that can carry `--session-id` get the id we generate up front (§2 capture); a bare terminal
   that can't falls back to the newest `~/.claude` file. *(Verify `--session-id` on the
   installed CLI when wiring the real effect.)*
4. **Resolved — app shell = Bun.** `Bun.serve` + Hono serve `/rpc` + the `bun build` board
   bundle in one process (§2, §9.1); Next.js / Vite dropped. *(was: Next.js vs. Hono+Vite.)*
5. **Resolved — the `discuss → write_tests` boundary.** Two independent choices, both
   settled: (1) **discussion-done is a manual "Done — proceed" click** (§2, §6.3), never
   inferred from session exit, an LLM judgement, or a design-doc mtime — inferring it would
   drag session-content reasoning into the orchestrator (against §1.8) just to save one
   press. (2) **`write_tests` always cold-starts from the issue** — a fresh headless run
   reads the issue (+ any design doc committed on the branch) and authors tests against the
   *stated* intent; it never `--resume`s the discuss session. This makes discuss's real
   deliverable **the design written into the issue** (§1.1): if a cold session can't author
   the tests, the design wasn't captured — a defect to surface, not paper over with warm
   context. Cold start also keeps `write_tests` a pure headless run (no interactive/headless
   fork). Warm `--resume` and a single discuss+write_tests session were both weighed and
   dropped. *(was "resolved — auto-advance on clean exit"; retracted, then re-resolved.)*
6. **Resolved — `review` + `follow_ups`:** one run — `review` applies fixes *and* files
   follow-up issues; the separate `follow_ups` stage is removed. *(was: two chained runs vs. one)*
7. **`review` fix policy:** apply the safe fixes inline (default, §3.3) or findings-only?
   And when review pushes fixes: **re-green the PR inside the run** (default — keeps the
   merge gate honest) or let the merge/CI catch red later?
8. **Merge-gate approve (`review / awaiting_human`):** auto-merge the PR, or mark done and
   leave the merge to you?
9. **Intake filter:** which issues become cards — all, or only those with a tracking
   label (e.g. `flow`)?
10. **Poll vs. webhooks** for intake/drift. Default: **poll** (`gh` on a timer) → a
    fully local service with no inbound endpoint. Webhooks are an optional latency
    optimization if the poll interval ever feels sluggish.
11. **`write-code` repair-loop bound:** cap by max attempts, or a time/cost budget?
12. **Interactive `discuss` lane:** bypass the concurrency-capped worker queue (default,
    so the terminal opens immediately) or share it?

---

## 8. Suggested next steps

1. Confirm the open decisions above.
2. Scaffold the TS repo (app shell + `bun:sqlite` + migration for §5).
3. Encode the transition map (§6.3) in code, with the atomic enqueue helper (§6.5) and
   the `nextState(stage)` function that §6.5's `T-SUCCEED` map describes.
4. Author the `write-code` skill (§3.2) — the missing engine piece.
5. Wire one end-to-end slice on a real issue: poll-discovered intake → approve-tests →
   `write_code` (ships PR + watches CI green) → review run → findings comment.

---

## 9. Service API & data flows

The service is **one Bun process**: it serves the board's static bundle (`bun build`),
exposes a single command endpoint for the browser (`Bun.serve` + Hono), and runs the worker
+ poll loops in-process. Everything except the browser hop is a plain function call — the
core (transition fn, SQLite via `bun:sqlite`, effect layer, worker, poller) never talks to
itself over a wire.

### 9.1 The one wire — `/rpc`

The board is browser JS, a different process from Node, so a click **must** cross a socket;
that hop is the only API. It is **command-shaped, not REST** — the UI's job is to emit the
§6.2 event alphabet, so the endpoint is a direct projection of the state machine (§1.5),
not a set of CRUD resources.

| Route | Kind | Purpose |
|---|---|---|
| `GET /*` | static | the board bundle (HTML/JS/CSS) — the "files at :8765" |
| `POST /rpc` | command/query | `{op, args}` → dispatch to an in-process function; the whole API |
| `GET /events` *(optional)* | SSE | push the read model on change; **omit until polling feels slow** (§9.5) |

Endpoint *count* is cosmetic — `/rpc` multiplexes every operation, exactly as tRPC / Next
server actions do under the hood. Whether it's hand-rolled JSON, tRPC, or server actions is
**decision #4** (the app-shell choice); the *shape* is fixed either way.

**2b resolves the shape: Hono + hand-rolled JSON `/rpc`, board served as a single static file.**
`Bun.serve({ fetch: app.fetch })` mounts one Hono app; `POST /rpc` reads `{op, args}`, dispatches
to an in-process handler, and returns JSON; `GET /*` serves the board. The board is **one
hand-authored file** (`src/board/index.html` — the wired-up `mockups/board.html`), returned as a
static asset — no `bun build` step in V1 (the board is vanilla JS with no imports, so there is
nothing to bundle; `bun build` stays available for when the board grows modules). SSE `/events`
stays omitted (§9.5). The whole server is ~one file (§9.8).

### 9.2 Operations behind `/rpc`

Four procedures — different shapes, so distinct functions, but all in-process on the server:

| `op` | Args | Does | Maps to |
|---|---|---|---|
| `getBoard` | — | read model for every non-archived card | one SELECT (§9.3) |
| `getCard` | `cardId` | one card + its append-only run timeline | SELECT card + run |
| `dispatchEvent` | `cardId, event` | run the guarded-CAS transition for a UI event | T-ENQUEUE / T-CANCEL / … (§6.5) |
| `createIssue` | `repo, title, body` | `gh issue create`, then intake the result as a card | T-INTAKE (§6.5) |

`dispatchEvent` is the **whole write surface**. Its `event` is the §6.2 UI alphabet — a
discriminated union `{type:'goto', target, park?} | {type:'cancel'} | {type:'archive'}` —
carrying the `(stage,status)` the caller believes the card is in (the CAS guard, §6.4.3). It
runs the transaction and returns the card's new `(stage, status)`; a stale or double-clicked
event updates 0 rows and returns the *unchanged* state — a safe no-op, never an error.

**The router is a thin, total projection of the engine — 2b binds the wire, not new logic.**
Only the UI events (`goto` / `cancel` / `archive`) cross `/rpc`; worker- and poll-events never
do (§9.4). So the router's whole job is decode → call → shape the reply, and its behavior is
**fully pinned by the engine's return contract** (§ contract.ts `ApplyResult`), which is why it is
the prime 2b test seam (§10, driven via `app.fetch`):

| Outcome from the engine | Wire response |
|---|---|
| `getBoard` / `getCard` | `200 { … }` (read model, §9.3) |
| `dispatchEvent` → `{ ok:true, card }` | `200 { ok:true, card }` |
| `dispatchEvent` → `{ ok:false, reason:'stale' }` | `200 { ok:false, reason:'stale' }` — **a no-op, not an error** |
| `createIssue` → `{ ok:true, card }` | `200 { ok:true, card }` |
| `InvalidEventError` (malformed target / event / issue#) | `400 { error }` |
| `AlreadyInFlightError` (can't-happen index breach) | `409 { error }` |
| unknown `op` / unparseable body | `400 { error }` |

The stale-vs-error split is load-bearing: a double-clicked approve or a poll re-observing a
resolved PR is a **200 no-op**, never a 4xx — the CAS backbone (§6.4.3) surfaced verbatim on the
wire. `dispatchEvent`'s `event` is decoded straight into the §6.2 `Event` union (the `expected_*`
CAS key rides along from the client's last-seen state); the router adds no state of its own.

### 9.3 The read model

`getBoard` returns what the board renders with **no** further GitHub / `~/.claude` call —
denormalized so a paint is one SELECT:

```jsonc
// per card
{
  id, repo, issue_number, pr_number, title,     // card columns (denormalized on purpose, §5)
  stage, status, state_entered_at,              // position + dwell / gate-nag signal
  latest_run: {                                 // the card's newest run row, or null
    id, stage, attempt, status, trigger,
    session_id,                                 // JOIN KEY into ~/.claude (cost/tokens on demand)
    activity: { last_step, elapsed }            // live-tailed by session_id, running runs only
  } | null
}
```

`title` / `stage` / `status` / `pr_number` are card columns, so the board paints with no
live `gh` call. `activity` is the only field read live, and only for a `running` headless
run — tailed from `~/.claude` by `session_id` (§2), never stored. Everything durable (diffs,
design, follow-ups) is a **link out**, not a payload.

**2b splits the read model into a pure DB projection + a best-effort overlay.** `readBoard(db)`
is one query pass over the DB — non-archived cards, each joined to its **newest** `run`
(`ORDER BY created_at, rowid DESC LIMIT 1`, the § read.ts `latestRun` rule, so ties under a
coarse clock don't reorder) — and returns everything **except** `activity`, which is `null`. This
projection is pure, deterministic, and the §10 test seam. The `activity` overlay is a separate,
**degradable** server-layer step: only for a card whose `latest_run.status === 'running'` and
carries a `session_id`, tail `~/.claude` for `{ last_step, elapsed }`; **any read miss → leave it
`null`** (the run still shows as running from `status`, just without the live step). The overlay
touches no DB and is never unit-tested against a fixed transcript — it is I/O that fails soft
(§10 "verified by running"), so a `~/.claude` layout change degrades the activity line, never the
board.

### 9.4 What feeds the state — the three loops

State changes come from three sources; only UI gestures cross the wire (§9.1). All three
callers reach the **same sync engine** in-process — `applyEvent` / `claimNext` / `reconcile`.
The engine stays pure and synchronous; **all async and all effects live in the loops**, so
each loop is unit-testable against the same recording `Effects` fake the transition engine
already uses (slice #1).

**1. UI → `/rpc`** — human gestures (`goto` / `cancel` / `archive`). `dispatchEvent` runs
`applyEvent`; side effects fire post-commit (§6.4.1), off the committed row.

**2. Worker loop — owns run execution.** The engine's `claimNext` is a **pure CAS**: one
`BEGIN IMMEDIATE` moves the oldest `queued` run + its card to `running` and returns
`{run, card}` — it spawns nothing and touches no worktree. The loop owns the rest of the arc,
so a worktree- or spawn-failure becomes an immediate `run_failed` (fast retry) instead of a
run stuck `running` until the next restart-reconcile:

```ts
const claimed = claimNext(db, fx);              // pure CAS, sync
if (!claimed || active >= POOL) return;         // outbox-poll + concurrency cap (§3.2)
const { run, card } = claimed;
try {
  const sid = fx.uuid();
  recordSession(db, run.id, sid);                // assign + persist BEFORE spawn → resumable on crash
  const path = fx.createWorktree(card);          // deterministic path → idempotent on retry
  recordWorktree(db, card.id, path);
  const { pid, done } = fx.spawnHeadless(run, { ...card, worktree_path: path }, sid);  // --session-id sid
  recordPid(db, run.id, pid);                    // ← run.pid is finally written (§6.4)
  const r = await done;                          // the run — minutes
  applyEvent(db, fx, card.id, r.ok
    ? { type: 'run_succeeded', run_id: run.id, session_id: r.session_id, pr_number: r.pr_number }
    : { type: 'run_failed',    run_id: run.id, session_id: r.session_id });
} catch {
  applyEvent(db, fx, card.id, { type: 'run_failed', run_id: run.id });
}
```

The pool is a small N (§3.2). `discuss` is **not** in it — it's spawned interactively in
`handleGoto`'s post-commit via `fx.spawnSession` (§6.5, decision #12) and resolves on the
card's Done/Discard button, never by an await.

**3. Poll loop — `gh` on a 30–60 s timer** (§3.1; 5000/hr REST budget, avoid `--search`).
`fx.gh.issueList` (filtered by the tracking label, §7.9) → `intake` each; `fx.gh.prStatus`
for any card carrying a `pr_number` → `pr_merged` / `pr_closed` drift. Every dispatch is
idempotent (guarded CAS + `ON CONFLICT` intake), so re-polling the same issue/PR is a no-op.
No inbound endpoint, no webhook.

**Reconcile — startup, now with a worktree sweep.** Runs once before the loops start:
headless runs left `running` → `failed` (`session_id` kept, resumable); `discuss` runs exempt
(the board never parented them, §6.4.4); `queued` runs left claimable. Slice #2 adds a
**filesystem sweep** — `fx.listWorktrees()`, and `removeWorktree` any tree whose card is gone
or now `worktree_path IS NULL` (cancelled / archived / done) — reaping the worktree a
swallowed post-commit teardown left on disk. (The orphaned-**process** half of that reap — a
swallowed `kill` — needs the pgroup+pidfile protocol and lands with the real effects;
`cancelRun` already retains the run's `pid`, so the reaper has its handle, §6.4.)

So the only traffic on `/rpc` is UI-sourced; worker- and poll-sourced events are plain calls
into one engine — three callers, one transition function.

### 9.5 Live updates — poll first

The board stays current by **re-`getBoard` on a timer** (1–2 s) — no push, matching the
service's own poll-don't-webhook stance (§3.1). Add `GET /events` (SSE) only if a human
notices lag on the activity tail; it needs no schema change (same read model, pushed instead
of pulled), so start without it.

### 9.6 Packaging — the exec-on-host boundary

The API is trivially containerizable; the **launcher isn't**. §2's whole justification — "a
local button that `exec`s `code <worktree>` / `claude` / `gh` on *your* machine" — needs the
developer's actual workstation, which a container isolates you from (worst on macOS, where
the VS Code host is a GUI app). The clean split: the **headless half** (web server + worker
+ poller + SQLite + headless `claude` / `gh`) containerizes fine; the **interactive session
host** (§2) wants host access. Default recommendation: **run the whole thing as a local host
process** (a `bunx` / systemd / launchd one-liner, or a single `bun build --compile` binary) —
it matches "the service is local" better than a container. If a container is still wanted, scope it to the headless half and keep the
session-host launcher on the host, or degrade the host to `command` / `tmux` (§2's
capability table). *(Open decision — folds into #4 / packaging.)*

### 9.7 The effect seam — what slice #2 makes real

Slice #1 shipped the engine against a recording `Effects` fake. Slice #2 (a) implements those
effects as real subprocesses and (b) extends the seam where the loops need it. The **engine
never widens — only the effect layer does**, so the pure-CAS core and its test suite are
untouched by the surface work.

| Method | Slice #1 | Slice #2 | Drives |
|---|---|---|---|
| `createWorktree(card)` | returns a path | path is a **pure fn of the card** (`<runroot>/wt/issue-<n>`) | idempotent retry — no orphan tree |
| `removeWorktree(card)` | recorded | `git worktree remove` | cancel / teardown / sweep |
| `listWorktrees()` | — | **new** — enumerate trees under the run root | reconcile sweep |
| `spawnHeadless(run, card, sessionId)` | `void`, no id | **`{ pid, done: Promise<RunResult> }`** — spawn `claude -p --session-id <sessionId>`, resolve on exit | worker-loop await |
| `spawnSession(card, resume?)` | recorded | open the session host (§2); `resume` now wired | interactive discuss |
| `kill(run)` | recorded | pgroup + pidfile reap | cancel / reconcile |
| `gh.issueCreate(…)` | returns `{issue_number}` | `gh issue create` | UI new-issue |
| `gh.issueList(…)` | — | **new** — `gh issue list --label <flow>` | poll → intake |
| `gh.prStatus(…)` | — | **new** — `gh pr view --json state` | poll → drift |
| `now()` / `uuid()` | fake clock / counter | wall clock / real uuid | timestamps / ids |

`RunResult = { ok, session_id?, pr_number? }`. `session_id` is **assigned** up front and
**persisted before the spawn**: the worker generates a uuid, writes it to the run row
(`recordSession`, an engine helper), and passes it as `claude --session-id <uuid>`. So it's
known before the run starts — no post-hoc harvest, no `~/.claude` mtime race — and, crucially,
a run orphaned by a crash *before* completion still carries its `session_id`, so `reconcile`
can `claude --resume` it (§6.4.4). `RunResult.session_id` is therefore **confirmatory** (the
completion `COALESCE`s onto the already-written id, never a second source of truth); `pr_number`
is **discovered** post-run via
`gh pr list --head flow/issue-<n>`; `ok` is subprocess exit `0` (and, if we run `claude -p`
with `--output-format json`, `is_error === false`). No `cost_usd` — dropped for simplicity
(§7.2). Populating these is 2b; the `RunResult` **shape** is what 2a's loops bind against, with
the value supplied by the fake — exactly the slice-1 pattern.

### 9.7.1 The real effects — concrete construction (slice 2b)

Every real effect is a **pure builder/parser + a thin imperative shell**. The builder (argv, a
path, a parsed struct) is a total function of its inputs and is the §10 unit seam; the shell is
the one `Bun.spawn` / `Bun.file` / `process.kill` line that runs it, verified by running (§10),
not mocked. This split is the whole reason the surface is testable without a live `git`/`gh`/
`claude`. Effects are constructed from config (§9.9): a `repoRoot(repo) → localCloneDir` map, the
`runRoot`, the tracking `label`, and the `sessionHost` adapter. *(Flags below verified against the
installed CLIs — `claude` 2.1.201, `gh` 2.x, `git` 2.47 — when this was authored; re-verify on
wiring.)*

**Worktrees — `git worktree`, path encodes the repo.** The path is a pure fn of the card:
`worktreePath(card, cfg) = <runRoot>/wt/<owner>__<name>/issue-<issue_number>`, branch
`flow/issue-<n>`. Encoding `<owner>__<name>` in the path is load-bearing: `removeWorktreePath`
and the sweep hold **only a path** (an orphan has no card, contract.ts), so the path itself must
recover the owning repo → its `repoRoot` for the `git -C` call.
- `createWorktree(card)` → derive the path; if it is already a registered worktree
  (`git -C <root> worktree list --porcelain` contains it) return it unchanged (idempotent retry,
  §9.7); else `git -C <root> worktree add -B flow/issue-<n> <path> <base>` (`base` = cfg per repo,
  default `origin/<default-branch>`). Called **only when `card.worktree_path` is null** (the worker
  guards it, worker.ts) so a *kept* tree (fail/retry, §6.6) is reused directly and never reset.
- `removeWorktree(card)` / `removeWorktreePath(path)` → `git -C <root> worktree remove --force
  <path>` then best-effort `git worktree prune`. `removeWorktree` has the card's repo; the
  path-only variant recovers `<owner>__<name>` from the path (above).
- `listWorktrees()` → **union over every configured repo** of `git -C <root> worktree list
  --porcelain`, take the `worktree <path>` lines, keep only paths under `<runRoot>/wt/` (drops each
  repo's own main checkout — §9.7 "under the run root"). The reconcile sweep matches these by value
  against `card.worktree_path` (engine.ts `sweepOrphanWorktrees`).

**Headless stage — `claude -p`, one process group.** `spawnHeadless(run, card, sessionId)`:
- argv `headlessArgv(run, card, sessionId, cfg)` = `["setsid", "claude", "-p",
  headlessPrompt(run, card), "--session-id", sessionId, "--output-format", "json",
  "--permission-mode", cfg.permissionMode, "--add-dir", card.worktree_path,
  …stageTuning(run.stage, cfg) → (--model? / --effort?)]` — per-phase model + effort (§9.9),
  each flag omitted when its resolved value is empty (the claude CLI's own default then applies).
  `setsid` makes the child a **session + group leader** (pgid == pid), so the reaper can
  `kill(-pid)` the whole tree (below) — the §6.4 "never a bare `kill(pid)`" rule.
- `headlessPrompt(run, card)` is a **per-stage template keyed by `run.stage`** — the "skills own
  the work" seam (§1.8): `write_tests` → run the write-tests skill against issue `#n`; `write_code`
  → write-code-from-spec; `review` → `/code-review --fix` + file follow-ups. Every headless stage
  **cold-starts from the issue** (§7.5) — the prompt names the repo + issue number, nothing carries
  from a session. Exact wording is impl-tunable; what's *fixed* is: keyed by stage, cold from the
  issue, one skill per stage.
- shell → `Bun.spawn(argv, { cwd: card.worktree_path, stdout: "pipe" })`; write a pidfile
  `<runRoot>/run/<run.id>.pid` = `{ pid, started_at }` (the §6.4 reuse-guard); return `{ pid,
  done }` where `done = subprocess.exited.then(code => parseRunResult(code, stdout, discoverPr()))`.
- `parseRunResult(exitCode, stdout, prNumber?)` (pure) → `{ ok: exitCode === 0 && json.is_error
  === false, session_id: json.session_id, pr_number }`. `session_id` is **confirmatory** (§9.7).
  `discoverPr()` (write_code / review only) = `gh pr list -R <repo> --head flow/issue-<n> --json
  number` → the first number, or `undefined`.

**Interactive discuss — the session host (§2).** `spawnSession(card, resume?)` dispatches on
`cfg.sessionHost.kind`, all reducible to a **pure command/doc builder** + one `exec`:
- `command` / `tmux` → `sessionHostArgv(cfg, card, { resume, sid })` fills the template's
  `{cwd,resume,sid}` placeholders → `Bun.spawn`.
- `vscode` (default) → `vscodeWorkspaceDoc(cfg, card, { resume, sid })` emits a `.code-workspace`
  JSON (written to `<runRoot>` — never in-tree, §2) carrying a `folderOpen` task that runs `claude
  {--resume S} --session-id <sid>`, then `exec code <workspace>`.
Both builders are §10 unit seams; the `exec` is the shell. `discuss` opens at `card.worktree_path
?? repoRoot` (§6.6) and resolves via the card's Done/Discard button, never a process await (§2).

**Reap — pgroup + pidfile.** `kill(run)`: read `<runRoot>/run/<run.id>.pid`; if the recorded
`started_at` still matches the live process (guard against a **reused** pid after reboot, §6.4),
`process.kill(-pid, "SIGTERM")`, then `SIGKILL` after a short grace; unlink the pidfile. A missing
pidfile or a start-time mismatch is a no-op (nothing of ours to reap). Mostly shell — the *decision*
(pgroup + pidfile + start-time guard, never bare `kill(pid)`) is what's fixed; verified by running.

**GitHub — `gh`, parse stdout.** All three are a `gh` call + a pure parser:
- `gh.issueCreate({repo,title,body})` → `gh issue create -R <repo> --title <t> [--body <b>]
  --label <cfg.label>`; **`gh issue create` has no `--json`** — it prints the new issue's URL, so
  `parseIssueNumberFromUrl(stdout)` (pure) takes the trailing `/issues/<n>` → `{ issue_number }`.
- `gh.issueList({repo,label})` → `gh issue list -R <repo> --label <label> --state open --json
  number,title` → `parseIssueList(json, repo)` (pure) → `IssueRef[]`.
- `gh.prStatus({repo,pr_number})` → `gh pr view <n> -R <repo> --json state` → `parsePrState(json)`
  (pure): `MERGED → "merged"`, `CLOSED → "closed"`, `OPEN → "open"`. The PR `state` already
  distinguishes merged from closed, so **no `mergedAt` field is needed** (grounding correction to
  the §9.7 table's `--json state`).

**Clock / ids.** `now()` = `new Date().toISOString()`; `uuid()` = `crypto.randomUUID()`. (In tests
the fake's stable clock + monotonic counter stand in, unchanged from slice 1.)

### 9.8 Boot sequence & module layout (slice 2b)

One `main.ts` wires the process; the order is a **hard invariant** (and a §10 seam):

```ts
export async function boot(cfg: Config, deps = { serve: Bun.serve }) {
  const db = openDb(cfg.runRoot);        // §9.9: bun:sqlite, WAL, foreign_keys=ON, migrate-if-fresh
  const fx = realEffects(cfg);           // §9.7.1
  reconcile(db, fx);                     // 1. crash-recovery + worktree sweep — ONCE, BEFORE any loop
  const worker = every(cfg.workerTickMs, () => drainQueue(db, fx, { pool: cfg.pool }));  // 2.
  const poll   = every(cfg.pollMs,       () => pollOnce(db, fx, { label: cfg.label }));  // 3.
  const server = deps.serve({ port: cfg.port, fetch: makeApp(db, fx, cfg).fetch });      // 4.
  return { db, worker, poll, server };
}
```

`reconcile` **must** run before the worker/poll/server start — a loop that claimed or a UI event
that dispatched while stale `running` rows were still un-recovered would race crash-recovery. `boot`
takes an injectable `serve` (and `every`, a self-rescheduling non-overlapping timer) so a test
asserts the **ordering** (`reconcile` before first `drainQueue`/`pollOnce`/`serve`) without opening
a socket — the boot-ordering seam (§10). `drainQueue`/`pollOnce` are already async and idempotent
(2a), so a tick that overlaps a slow prior tick is prevented by `every`'s non-overlap guard, not by
new engine logic.

**File layout** (all under `dev-orchestrator/src/`, thin — the engine is untouched):

| File | Holds |
|---|---|
| `db.ts` | `openDb(runRoot)` — open + `PRAGMA` + migrate `SCHEMA_SQL` if `user_version` is 0 (promotes test-support `schema.ts` to a real migration) |
| `effects/git.ts` · `claude.ts` · `gh.ts` · `session_host.ts` · `reap.ts` | the §9.7.1 builders + shells; `effects/index.ts` composes them into one `Effects` |
| `server.ts` | `makeApp(db, fx, cfg)` — the Hono app: `POST /rpc` router (§9.2 table) + `GET /*` static board; `readBoard`/`readCard` (§9.3) live here |
| `config.ts` | `Config` type + `loadConfig()` (TOML/env → object); config is injected everywhere, never re-read in the hot path |
| `board/index.html` | the wired-up `mockups/board.html` (fetches `/rpc`, §10-UI) |
| `main.ts` | `boot(loadConfig())` — the entrypoint |

### 9.9 Configuration

One config object, injected (never global). Defaults target *local, single-dev, single-repo* (open
decision #1), but the shape is multi-repo-ready (the `repo` list + path-encoded worktrees, §9.7.1):

```toml
run_root = "~/.flowdeck"      # sqlite db + wt/ worktrees + run/ pidfiles + *.code-workspace
label = "flow"                # §7.9 tracking label — intake filter + the new-issue create label
pool = 2                      # headless worker slots (§3.2); discuss runs outside it
poll_ms = 30000               # §9.4 gh poll cadence (30–60s; 5000/hr REST budget)
worker_tick_ms = 1000         # drainQueue cadence
port = 8765                   # board + /rpc
permission_mode = "auto"      # claude -p --permission-mode for headless stages

[defaults]                    # fallback claude tuning for any headless stage without an override
model = ""                    # optional claude --model; empty = CLI default
effort = ""                   # optional claude --effort <low|medium|high|xhigh|max>; empty = CLI default

[stages.write_tests]          # per-headless-stage overrides (write_tests / write_code / review;
model = "opus"                # discuss is interactive via the session host, so it takes no tuning)
effort = "high"

[[repo]]
name = "owner/name"           # gh -R + the card.repo value
root = "/abs/path/to/clone"   # local checkout the worktrees branch from
base = "origin/main"          # createWorktree base ref

[session_host]                # §2 capability table
kind = "vscode"               # | "command" | "tmux" | "embedded-pty"
# command = "wezterm start --cwd {cwd} -- claude {resume} --session-id {sid}"   # kind="command"
```

Deferred to later slices (not 2b): the `embedded-pty` host (`Bun.Terminal`), SSE `/events` (§9.5),
`bun build --compile` packaging (§9.6), and auto-merge at the merge gate (open decision #8) — 2b's
merge-gate approve marks `done` and leaves the actual merge to the human (the conservative default).

---

## 10. Slice 2b — the test surface

The 2b deliverable follows the same **spec-first** shape as 2a (write-tests → write-code): the
tests are the contract. But 2b is *surface* — I/O and a browser — so the seam between "pinned by a
test" and "verified by running" is drawn deliberately, and stated here so the write-tests phase
knows exactly what to bind. The rule: **anything that is a pure function of its inputs is unit-
tested against the real DB + the slice-1 `FakeEffects`; anything that is a subprocess/socket/GUI
launch is verified by running the app, never mocked into a green test.** Mocking a `Bun.spawn` only
tests the mock; the honest signal is a real boot (§9.8) driving a real `gh`/`git` flow.

**Unit-tested (the binding suite):**

| Seam | Entry point | What's pinned |
|---|---|---|
| RPC router | `makeApp(db, fx, cfg).fetch(Request)` | op dispatch; `dispatchEvent` decode → §6.2 `Event` (incl. the `expected_*` CAS key); the §9.2 response table — `stale → 200` no-op, `InvalidEventError → 400`, `AlreadyInFlightError → 409`, unknown op / bad body → 400; `createIssue → gh.issueCreate → intake`; `getBoard`/`getCard` shapes |
| Read model | `readBoard(db)` / `readCard(db, id)` | non-archived only; newest-run join (§ read.ts `latestRun` rule); `activity` is `null` in the pure projection; `getCard` returns the full run timeline |
| Effect builders | `worktreePath` · `worktreeAddArgv`/`removeArgv` · `headlessArgv`/`headlessPrompt` · `parseRunResult` · `parseIssueNumberFromUrl` · `parseIssueList` · `parsePrState` · `sessionHostArgv`/`vscodeWorkspaceDoc` | argv/path/doc built exactly; parsers total over real CLI output samples (incl. malformed / empty) and the `MERGED`/`CLOSED`/`OPEN` mapping; path→repo recovery for the sweep |
| Boot ordering | `boot(cfg, { serve: fake, every: fake })` | `reconcile` fires **before** the first `drainQueue`/`pollOnce`/`serve`; `pool`/`label`/`port` threaded through |
| Migration | `openDb(tmpDir)` | fresh dir → full §5 schema; re-open → no-op (idempotent `user_version` gate); WAL + FK pragmas set |

**Verified by running, not unit-tested** (§ "verify" — drive the real flow, observe): the
`Bun.spawn`/`setsid`/`exec` shells, real `git worktree` create/list/remove, real `gh` calls, the
`~/.claude` activity tail (§9.3, fails soft), the VS Code launch, and the board's live fetch/render
against a booted server. The impl PR's evidence is a **real end-to-end boot** on a scratch repo:
poll-discovered intake → a card advancing → a real worktree on disk → `/rpc` responses over curl →
the board painting them — the §8 step-5 "one end-to-end slice on a real issue", now executable.
