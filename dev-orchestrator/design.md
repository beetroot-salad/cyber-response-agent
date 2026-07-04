# Dev Workflow Orchestrator — Design

> Status: **design / pre-implementation**. Name: TBD. Lives in the defender repo under
> `dev-orchestrator/` for now; relocate to the new project's own repo when scaffolded.
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
   never duplicate it. For headless stages the Agent SDK hands us `session_id` +
   `total_cost_usd` directly.
4. **Don't rebuild what the SDK / GitHub already give you.** The orchestrator stores
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

TypeScript end-to-end, so logic + UI share one language and the Agent SDK is
first-class.

| Concern | Choice | Notes |
|---|---|---|
| App / serving | **Next.js** (API routes + React board), or leaner **Hono + Vite/React** | one deployable |
| Engine — automated stages | **Claude Agent SDK (TS)** | `query({ options: { resume: sessionId } })`; returns `session_id` + `total_cost_usd` in the result message |
| Engine — interactive discuss | **configurable session host** (default VS Code) | injected launcher `exec`s a per-host command (VS Code / any terminal / tmux); `claude` runs in that host's terminal — no embedded pty |
| Data | **SQLite** via `better-sqlite3` (+ Drizzle if typed queries wanted) | WAL mode |
| GitHub | injected `gh` CLI | intake + drift discovered by **polling**; no inbound webhooks (skills self-report; CI is watched inside `write_code`) |

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
  `start_discuss`), including the launcher that `exec`s local tools.
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
the session out-of-process, so there's no board-owned pid and no SDK callback (unlike headless
runs, which the worker spawns and pid-tracks — §6.4; the `embedded-pty` host is the exception —
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

- **Headless stages:** the SDK result message carries `session_id` — capture at
  completion.
- **Interactive discuss (VS Code / terminal):** the board isn't the process parent, so
  there's no SDK callback. If the CLI accepts a `--session-id` you generate, pass it in the
  launch command; otherwise read the newest session file in the project's `~/.claude` dir
  right after launch. *(Confirm against the installed CLI version before committing to this.)*
- **Live view:** because session content lives in `~/.claude`, the board can tail a
  headless run's transcript by `session_id` for a "watch it work" pane (or subscribe to
  the SDK's streamed events directly) — no need to store any of it.

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
-- (read those from the SDK result or ~/.claude via session_id).
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
  pid          INTEGER,                         -- OS pid of the stage subprocess; set post-spawn, NULL when finished
                                                -- (the startup reconciler liveness-checks this, §6.4)
  cost_usd     REAL,                            -- OPTIONAL cache of the SDK's total_cost_usd after completion
                                                -- (derive-on-read first; add this only if the board feels slow)
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
- Session transcript / cost / tokens → `~/.claude` (or the SDK result).
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
`nextState`, *not* rows; there is no `event` table, §5):

| Event | Source | Meaning |
|---|---|---|
| `issue.opened` | github (poll) | new tracked issue → intake (guarded by a tracking label) |
| `start_discuss` | ui | human opens the discuss session in VS Code |
| `advance` | ui | human moves a resting card to the next stage (e.g. discuss → write_tests) |
| `approve` | ui | human passes a soft gate (approve-tests, approve-merge) |
| `retry` | ui | re-run a failed stage |
| `cancel` | ui | stop a queued/running run |
| `move(target)` | ui | manual drag / park to an arbitrary stage |
| `skip` | ui | advance past the current stage to the next one and enqueue it — the dashboard "skip this phase" gesture (§6.3) |
| `archive` | ui | remove from board |
| `run_succeeded(id)` / `run_failed(id)` | system (worker); for `discuss` it's the card's **Done — proceed** button (§2) | a run finished (CI-red inside `write_code` surfaces as `run_failed`) |
| `pr.merged` | github (poll) | the tracked PR merged (by the pipeline or by hand) → card is done (drift) |
| `pr.closed` | github (poll) | the tracked PR closed **without** merge → work abandoned; card → `failed` so the human can reopen / rework / archive (drift) |

`run.trigger ∈ {manual, auto, retry}` records *why* a run row exists: **`manual`** =
human-started (`start_discuss`, `advance`, `skip`); **`auto`** = a gate release (`approve`)
or an auto-chain link (`write_code → review`, and `discuss → write_tests` on **Done —
proceed**); **`retry`** = re-run after a failure. The split is *who chose what
runs next*, not *who clicked*: `advance`/`skip` are `manual` because the human named the
target stage, whereas `approve` is `auto` because releasing the gate hands the "what runs
next" choice back to the transition map. (Rename to `human`/`chain`/`retry` if that reads
clearer.)

### 6.3 Transition table

Happy path (▸ = automatic, ✋ = human action):

| From `(stage/status)` | Event | Guard | Actions (atomic) | To `(stage/status)` |
|---|---|---|---|---|
| — | `issue.opened` | has tracking label | insert card | `backlog / idle` |
| `backlog / idle` | ✋`start_discuss` | | insert run(discuss, manual, running); exec `code` → seeded `claude` in VS Code *(post-commit)* | `discuss / running` |
| `discuss / running` | ▸`run_succeeded` (Done — proceed) | | enqueue write_tests | `write_tests / queued` |
| `discuss / idle` | ✋`advance` | | enqueue write_tests | `write_tests / queued` |
| `write_tests / queued` | ▸worker claim | | run→running | `write_tests / running` |
| `write_tests / running` | ▸`run_succeeded` | | — | `write_tests / awaiting_human` |
| `write_tests / awaiting_human` | ✋`approve` | | enqueue write_code | `write_code / queued` |
| `write_code / queued` | ▸worker claim | | run→running | `write_code / running` |
| `write_code / running` | ▸`run_succeeded` | | store `pr_number`; enqueue review | `review / queued` |
| `review / queued` | ▸worker claim | | run→running | `review / running` |
| `review / running` | ▸`run_succeeded` (fixes pushed + follow-ups filed) | | — | `review / awaiting_human` |
| `review / awaiting_human` | ✋`approve` (merge) | | (optionally merge PR) — **terminal, no run** | `done / idle` |

Cross-cutting (apply from most states):

| From | Event | Actions | To |
|---|---|---|---|
| `* / running` | `run_failed` | run→failed; store `session_id` + `pr_number` (shipped-but-unmerged PR stays linked; `claude --resume` works) | `* / failed` |
| `* / failed` | ✋`retry` | enqueue same stage, `attempt+1`, trigger=retry | `* / queued` |
| `* / {queued,running}` | ✋`cancel` | run→cancelled; kill proc + worktree *(post-commit)* | `* / idle` |
| `*` | ✋`move(t)` | cancel any in-flight run, then set stage=t, status=idle (park — no run) | `t / idle` |
| `* (work stage)` | ✋`skip` | cancel any in-flight run, then advance to the **next** stage and enqueue it (or land on its gate) — the dashboard "skip this phase" gesture | `<next> / {queued\|awaiting_human}` |
| `*` | ✋`archive` | cancel any in-flight run, then set `archived_at` | (hidden) |
| `* (pr_number set)` | `pr.merged` | cancel any in-flight run *(post-commit)*, then mark done | `done / idle` |
| `* (pr_number set)` | `pr.closed` (unmerged) | cancel any in-flight run *(post-commit)*; keep `pr_number` linked so the human can reopen / rework / archive | `* / failed` |

Notes:
- **`discuss` bypasses the worker queue.** It's human-initiated and interactive, so it
  spawns straight to `running` in its own lane rather than waiting behind headless runs
  in the concurrency-capped queue. *(Open decision.)*
- **`discuss → write_tests` is resolved from the board, not by process exit.** VS Code
  hosts the session and the board doesn't parent it (§2 UI seam), so the discuss card
  carries two actions: **"Done — proceed"** (`run_succeeded` → the chain rolls into
  `write_tests`) and **"Discard"** (`cancel` → the card parks in `discuss / idle`,
  re-openable via `start_discuss`). Intent is an explicit click, not inferred from how you
  closed a terminal — an exploratory poke never barrels into writing tests; a real design
  pass is one button. `write_tests` then **cold-starts from the issue** (§7.5), so discuss's
  deliverable is the converged design written into the issue (§1.1); nothing is carried
  forward from the session's context.
- **Forward-drag = the gate gesture.** Dragging a card forward past a gate emits
  `approve`/`advance`; any other drag is a `move` (park). One UI affordance, two
  meanings by direction.
- **Any phase is skippable from the dashboard** via `skip` (advance + enqueue the next
  stage) or `move` (park anywhere). A dep bump skips `discuss` and `write_tests` straight
  into `write_code`; skipping `write_tests` also drops the approve-tests gate for that
  card (no spec to approve). From `backlog`, `start_discuss` opens discussion while
  `skip`/`move` jumps straight into a work stage. *(Future enhancement: capture recurring
  skip patterns as named per-card **recipes** — a stored `plan` the card auto-runs, e.g.
  `chore = [write_code, review]` — so dep-bump-shaped work runs the short path without
  per-card clicks.)*
- **Auto-chains** (`write_code → review`, and `discuss → write_tests` on **Done — proceed**)
  enqueue the next run inside the predecessor's `T-SUCCEED`, atomically — so `write_code`
  success alone drives the card to `review`; there is no separate CI event. `review`
  files its own follow-ups and finishes on its own **merge gate** (`review / awaiting_human`) — no separate `follow_ups` run.
- **The merge `approve` (at `review / awaiting_human`) is terminal** — it runs no new run;
  it sets `done` (+ optional PR merge). Not every `approve` enqueues.
- Filed follow-up issues re-enter via `issue.opened` as fresh `backlog` cards.
- **Drift = a hand-merge.** Polling `gh` also surfaces `pr.merged` for a card whose
  `pr_number` is set; the card jumps to `done` from wherever it sat (CAS on any non-`done`
  state, so re-observing next poll is a no-op). This is the "PR you merged by hand" case
  §3.1 motivates.
- **`start_discuss` is on-demand from any resting `*/idle`,** not just `backlog`. Whether
  re-discussing from a later stage parks the card back in `discuss` (default — visible,
  reachable forward again via `move`) or opens an ad-hoc side session that leaves
  `card.stage` untouched is an open question.

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
   orchestrator can no longer harvest (it lost the SDK handle) is simply stale → `failed`,
   and is **retryable / `claude --resume`-able off its `session_id`** — no liveness probe
   needed to decide that. `run.pid` is kept *only* as a best-effort **kill handle** to reap
   an orphaned subprocess that outlived the crash and would otherwise burn credits — and
   because a bare pid can be reused after a reboot, reap by **process group + a run-dir
   pidfile** (or a recorded start-time check), never a bare `kill(pid)`. **Interactive
   `discuss` runs are exempt:** the board never parented them (§2), so a restart leaves them
   `running`, to be resolved by the card's Done/Discard button and re-attached with
   `claude --resume <session_id>` — reconciling them to `failed` would destroy a live design
   session. Then re-drive `queued` runs, purely from committed state.
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

-- T-ENQUEUE: the core transition (advance / tests-approve / skip / retry).
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
-- (post-commit) spawn claude (Agent SDK); write the child pid, then session_id, onto the run

-- T-SUCCEED: run finished ok → transition function sets the next card state
BEGIN IMMEDIATE;
  UPDATE run SET status='succeeded', finished_at=:now, session_id=:sid, cost_usd=:cost, pid=NULL
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
  UPDATE run  SET status='failed', finished_at=:now, session_id=:sid, cost_usd=:cost, pid=NULL
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
2. **Cost tracking:** derive-on-read only, or cache `run.cost_usd` on completion?
   (Lean: derive first, cache if the board feels slow.) Note the VS-Code-hosted `discuss` run has no
   SDK `total_cost_usd` hook — read it from `~/.claude` by `session_id`, or omit discuss
   from the rollup.
3. **Discuss session-id capture** for interactive sessions — verify the CLI's `--session-id`
   support: it unlocks the "prearranged" capability across *all* session hosts (§2);
   otherwise every host falls back to reading the newest `~/.claude` session file.
4. **Next.js vs. Hono+Vite** for the app shell.
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
2. Scaffold the TS repo (app shell + `better-sqlite3` + migration for §5).
3. Encode the transition map (§6.3) in code, with the atomic enqueue helper (§6.5) and
   the `nextState(stage)` function that §6.5's `T-SUCCEED` map describes.
4. Author the `write-code` skill (§3.2) — the missing engine piece.
5. Wire one end-to-end slice on a real issue: poll-discovered intake → approve-tests →
   `write_code` (ships PR + watches CI green) → review run → findings comment.
