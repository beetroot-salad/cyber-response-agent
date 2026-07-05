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
  cost_usd: number | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
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
  | { type: "run_succeeded"; run_id: string; session_id?: string; cost_usd?: number; pr_number?: number }
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
}

/** Injected side-effect seam (principle 7). State commits in-txn; these run AFTER
 *  commit and are fire-and-reconcile: a throwing effect is recorded, never rolled back
 *  into committed state, and never changes a transition's return value. */
export interface Effects {
  createWorktree(card: CardState): string; // returns worktree_path
  removeWorktree(card: CardState): void;
  spawnHeadless(run: RunRow, card: CardState): void;
  spawnSession(card: CardState, resume?: string): void;
  kill(run: RunRow): void;
  gh: { issueCreate(input: { repo: string; title: string; body?: string }): { issue_number: number } };
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
