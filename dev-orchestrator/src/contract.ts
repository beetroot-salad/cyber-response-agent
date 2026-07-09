// V1 transition-engine contract (types + errors + effect seam).
//
// This is the CONTRACT the test spec binds to — pure declarations, no engine logic.
// The engine implementation (intake / applyEvent / claimNext / reconcile) lives in
// `./engine` and is NOT yet written: the test suite imports those functions and is
// expected to fail to resolve that module until the implement phase lands it.

export type Stage = "backlog" | "discuss" | "write_tests" | "write_code" | "review" | "done";
export type Status = "idle" | "queued" | "running" | "awaiting_human" | "failed";

/** Stages that actually run a job (and therefore own `run` rows). */
export type RunStage = "discuss" | "write_tests" | "write_code" | "review";
export type RunStatus = "queued" | "running" | "succeeded" | "failed" | "cancelled";
export type Trigger = "manual" | "auto" | "retry";

/** bun:sqlite Database handle. */
export type DB = import("bun:sqlite").Database;

/** A card row — the authoritative current state (§4, §5). */
export interface CardState {
  id: string;
  repo: string;
  issue_number: number;
  pr_number: number | null;
  stage: Stage;
  status: Status;
  title: string | null;
  worktree_path: string | null;
  created_at: string;
  updated_at: string;
  state_entered_at: string;
  archived_at: string | null;
}

/** A run row — job queue + append-only attempt history (§5). */
export interface RunRow {
  id: string;
  card_id: string;
  stage: RunStage;
  attempt: number;
  status: RunStatus;
  trigger: Trigger;
  session_id: string | null;
  pid: number | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
}

/** The pair a `claimNext` CAS returns — the run it moved to `running` and its card.
 *  claimNext is a PURE CAS (§9.4): it enqueues no effect; the worker loop owns the arc. */
export interface ClaimedRun {
  run: RunRow;
  card: CardState;
}

/** What a finished headless run reports back (§9.7). `session_id` is confirmatory — it was
 *  assigned + persisted before the spawn (recordSession); `pr_number` is discovered post-run.
 *  No `cost_usd` (dropped, §7.2). */
export interface RunResult {
  ok: boolean;
  session_id?: string;
  pr_number?: number;
}

/** A GitHub issue the poller discovered (§9.4). */
export interface IssueRef {
  repo: string;
  issue_number: number;
  title: string;
}

/** The state of a PR the poller checks for drift (§9.4). */
export type PrState = "open" | "merged" | "closed";

/** One poll pass's applied-transition counts (stale/no-op transitions are NOT counted). */
export interface PollSummary {
  intook: number;
  merged: number;
  closed: number;
}

/** Every card-targeted event carries the (stage,status) the caller believes the card is
 *  in — the guarded-CAS key (§6.4.3). A 0-row match is a safe `stale` no-op. */
export interface Expect {
  expected_stage: Stage;
  expected_status: Status;
}

export type Event =
  // UI gestures — guarded by the expected (stage,status) CAS (double-click / stale protection).
  | ({ type: "goto"; target: Stage; park?: boolean } & Expect)
  | ({ type: "cancel" } & Expect)
  | ({ type: "archive" } & Expect)
  // Worker completion — guarded by run_id + status='running' (the run CAS is the idempotency key).
  | { type: "run_succeeded"; run_id: string; session_id?: string; pr_number?: number }
  | { type: "run_failed"; run_id: string; session_id?: string; pr_number?: number }
  // Poller drift — guarded by "this card, pr_number set, any non-done state".
  | { type: "pr_merged" }
  | { type: "pr_closed" };

/** Hybrid return contract: success or a routine no-op. A genuine invariant breach
 *  (double-enqueue) throws `AlreadyInFlightError`; a malformed event throws
 *  `InvalidEventError` — neither is an `ApplyResult`. */
export type ApplyResult = { ok: true; card: CardState } | { ok: false; reason: "stale" };

export interface IntakeInput {
  repo: string;
  issue_number: number;
  title: string;
}

export interface ReconcileSummary {
  failed_headless: number;
  left_discuss: number;
  redriven_queued: number;
  killed: number;
  swept: number; // worktrees reaped by the filesystem sweep (§9.4) — orphans no live card claims
}

/** Injected side-effect seam (principle 7). State commits in-txn; these run AFTER
 *  commit and are fire-and-reconcile: a throwing effect is recorded, never rolled back
 *  into committed state, and never changes a transition's return value. */
export interface Effects {
  createWorktree(card: CardState): string; // deterministic path (pure fn of the card); idempotent on retry
  removeWorktree(card: CardState): void; // card-driven teardown (cancel/archive/done/drift) — has repo context
  listWorktrees(): string[]; // every worktree path on disk under the run root — for the reconcile sweep
  // Reap a worktree by PATH alone. The reconcile sweep reaps orphans — on-disk trees no live card
  // claims — and an orphan has NO owning card, so the sweep holds only a path (never a phantom card).
  removeWorktreePath(path: string): void;
  // Spawn a headless `claude -p --session-id <sessionId>` (the id is assigned + persisted BEFORE
  // spawn, §9.7). Returns the child pid and a promise that resolves on exit. The worker awaits
  // `done` OUTSIDE any transaction; a rejected `done` is a failed run.
  spawnHeadless(run: RunRow, card: CardState, sessionId: string): { pid: number; done: Promise<RunResult> };
  spawnSession(card: CardState, resume?: string): void;
  kill(run: RunRow): void;
  gh: {
    issueCreate(input: { repo: string; title: string; body?: string }): { issue_number: number };
    issueList(input: { repo?: string; label?: string }): IssueRef[]; // poll → intake
    prStatus(input: { repo: string; pr_number: number }): PrState; // poll → drift
  };
  now(): string; // ISO-8601 UTC
  uuid(): string;
}

/** Thrown when a second in-flight run would violate `one_active_run_per_card` — a
 *  "can't happen" breach under single-writer + BEGIN IMMEDIATE (§6.4.3). */
export class AlreadyInFlightError extends Error {
  constructor(message = "a run is already in flight for this card") {
    super(message);
    this.name = "AlreadyInFlightError";
  }
}

/** Thrown on a structurally malformed event a correct caller can't produce
 *  (unknown target stage / event type, non-positive issue_number). */
export class InvalidEventError extends Error {
  constructor(message = "malformed event") {
    super(message);
    this.name = "InvalidEventError";
  }
}

// ===========================================================================
// Slice 2b — the runnable surface (§9.7.1 / §9.8 / §9.9 / §10).
//
// Pure DATA + collaborator types shared by the 2b spec. The engine (above) is
// UNTOUCHED by 2b; these describe the server read model, the injected config, and
// the boot seam that wire the shell-agnostic core (slice #1/#2a) to real I/O.
// ===========================================================================

/** Per-repo config (§9.9): the local clone the worktrees branch from. */
export interface RepoConfig {
  name: string; // "owner/name" — matches card.repo and the gh -R target
  root: string; // local clone dir for `git -C <root>`
  base: string; // createWorktree base ref, e.g. "origin/main"
}

export type SessionHostKind = "vscode" | "command" | "tmux" | "embedded-pty";

/** The §2 session-host adapter. `command` carries {cwd}{resume}{sid} placeholders. */
export interface SessionHostConfig {
  kind: SessionHostKind;
  command?: string; // required for kind="command"/"tmux"
}

/** Per-headless-stage claude tuning (§9.9). Both fields optional — an unset field falls back to
 *  `Config.defaults`, and an empty/unset value omits the flag (the CLI's own default applies). */
export interface StageTuning {
  model?: string; // claude --model; "" / unset = CLI default
  effort?: string; // claude --effort <low|medium|high|xhigh|max>; "" / unset = CLI default
}

/** The one injected config object (§9.9) — never global, never re-read in the hot path. */
export interface Config {
  runRoot: string; // sqlite db + wt/ worktrees + run/ pidfiles + *.code-workspace
  label: string; // §7.9 tracking label — intake filter + new-issue create label
  pool: number; // headless worker slots (§3.2); discuss runs outside it
  pollMs: number; // gh poll cadence (§9.4)
  workerTickMs: number; // drainQueue cadence
  port: number; // board + /rpc
  permissionMode: string; // claude -p --permission-mode for headless stages
  defaults: StageTuning; // fallback model + effort for any headless stage without a `stages` override
  stages: Partial<Record<RunStage, StageTuning>>; // per-stage model + effort (write_tests/write_code/review; discuss is interactive)
  repos: RepoConfig[];
  sessionHost: SessionHostConfig;
}

/** The live "watch it work" tail (§9.3) — only for a running headless run, else null. */
export interface RunActivity {
  last_step: string;
  elapsed: number;
}

/** A card's newest run, as the board renders it (§9.3). */
export interface BoardRun {
  id: string;
  stage: RunStage;
  attempt: number;
  status: RunStatus;
  trigger: Trigger;
  session_id: string | null;
  activity: RunActivity | null; // overlay; ALWAYS null in the pure DB projection (readBoard)
}

/** One board card — denormalized so a paint is one query, no live gh call (§9.3). */
export interface BoardCard {
  id: string;
  repo: string;
  issue_number: number;
  pr_number: number | null;
  title: string | null;
  stage: Stage;
  status: Status;
  state_entered_at: string;
  latest_run: BoardRun | null;
}

/** `getCard`: the card + its full append-only run timeline (§9.2). */
export interface CardDetail {
  card: CardState;
  runs: RunRow[];
}

/** The one wire handler shape (§9.1). Both a hand-rolled fetch and a Hono `app.fetch` satisfy it. */
export type FetchHandler = (req: Request) => Response | Promise<Response>;
export interface App {
  fetch: FetchHandler;
}

/** Injected boot collaborators (§9.8). main.ts defaults these to the real ones; the boot-ordering
 *  test injects recording fakes to pin that `reconcile` fires BEFORE any loop or the server. */
export interface BootDeps {
  openDb(runRoot: string): DB;
  effects(cfg: Config): Effects;
  reconcile(db: DB, fx: Effects): ReconcileSummary;
  drainQueue(db: DB, fx: Effects, opts: { pool: number }): Promise<void>;
  pollOnce(db: DB, fx: Effects, opts: { label?: string }): Promise<PollSummary>;
  makeApp(db: DB, fx: Effects, cfg: Config): App;
  serve(opts: { port: number; fetch: FetchHandler }): unknown;
  every(ms: number, fn: () => void | Promise<void>): unknown; // self-rescheduling, non-overlapping timer
}

/** What `boot` hands back — the live handles (§9.8). */
export interface BootHandle {
  db: DB;
  worker: unknown;
  poll: unknown;
  server: unknown;
}
