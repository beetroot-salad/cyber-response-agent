// V1 transition engine — the SQLite state machine (design.md §4–§6).
//
// The four entry points (intake / applyEvent / claimNext / reconcile) each move card+run
// state inside a single `BEGIN IMMEDIATE` transaction, then run side effects AFTER commit
// (fire-and-reconcile: a throwing effect is recorded by the caller's `fx` and swallowed
// here — it never rolls committed state back, never changes the return value; orphans it
// leaves behind are caught by `reconcile`). Every card-targeted transition is a guarded
// CAS: a 0-row match is a routine `stale` no-op. A genuine double-enqueue (the
// one_active_run_per_card index) is a can't-happen breach → `AlreadyInFlightError`.

import type {
  ApplyResult,
  CardState,
  DB,
  Effects,
  Event,
  IntakeInput,
  ReconcileSummary,
  RunRow,
  RunStage,
  Stage,
  Status,
  Trigger,
} from "./contract";
import { AlreadyInFlightError, InvalidEventError } from "./contract";

const STAGES: readonly Stage[] = ["backlog", "discuss", "write_tests", "write_code", "review", "done"];
const STAGE_INDEX: Record<Stage, number> = {
  backlog: 0,
  discuss: 1,
  write_tests: 2,
  write_code: 3,
  review: 4,
  done: 5,
};
const RUN_BEARING: readonly Stage[] = ["discuss", "write_tests", "write_code", "review"];

const STALE: ApplyResult = { ok: false, reason: "stale" };

function isStage(s: unknown): s is Stage {
  return typeof s === "string" && (STAGES as readonly string[]).includes(s);
}
function isRunBearing(s: Stage): s is RunStage {
  return (RUN_BEARING as readonly string[]).includes(s);
}

/** Run `fn` in a single `BEGIN IMMEDIATE` transaction and return its value. A throw
 *  (e.g. `AlreadyInFlightError`) rolls the whole thing back and propagates. */
function inTxn<T>(db: DB, fn: () => T): T {
  return db.transaction(fn).immediate();
}

/** Post-commit side effect: fire-and-reconcile. The caller's `fx` records the call (and
 *  the throw) before it reaches us; we swallow it so committed state and the return stand. */
function runEffect(f: () => void): void {
  try {
    f();
  } catch {
    /* recorded by fx; orphan caught by reconcile */
  }
}

function isUniqueViolation(err: unknown, needle: string): boolean {
  return err instanceof Error && /UNIQUE constraint failed/.test(err.message) && err.message.includes(needle);
}

function getCardRow(db: DB, id: string): CardState | undefined {
  return db.prepare("SELECT * FROM card WHERE id = ?").get(id) as CardState | undefined;
}
function getRunRow(db: DB, id: string): RunRow | undefined {
  return db.prepare("SELECT * FROM run WHERE id = ?").get(id) as RunRow | undefined;
}

/** The card's one in-flight (queued|running) run, if any. */
function inflightRun(db: DB, cardId: string): RunRow | undefined {
  return db
    .prepare("SELECT * FROM run WHERE card_id = ? AND status IN ('queued','running') ORDER BY created_at, rowid LIMIT 1")
    .get(cardId) as RunRow | undefined;
}

/** Monotonic per (card, stage): max prior attempt + 1, never reset to 1 on re-entry. */
function nextAttempt(db: DB, cardId: string, stage: RunStage): number {
  const row = db.prepare("SELECT MAX(attempt) AS m FROM run WHERE card_id = ? AND stage = ?").get(cardId, stage) as {
    m: number | null;
  };
  return (row.m ?? 0) + 1;
}

interface NewRun {
  cardId: string;
  stage: RunStage;
  attempt: number;
  status: "queued" | "running";
  trigger: Trigger;
  createdAt: string;
  startedAt: string | null;
}

/** Insert a run, translating the one_active_run_per_card index breach (a can't-happen under
 *  single-writer) into `AlreadyInFlightError`. Callers cancel any in-flight run first. */
function insertRun(db: DB, fx: Effects, r: NewRun): RunRow {
  const id = fx.uuid();
  try {
    db.prepare(
      `INSERT INTO run (id, card_id, stage, attempt, status, trigger, session_id, pid, cost_usd,
                        created_at, started_at, finished_at)
       VALUES (@id, @card_id, @stage, @attempt, @status, @trigger, NULL, NULL, NULL,
               @created_at, @started_at, NULL)`,
    ).run({
      id,
      card_id: r.cardId,
      stage: r.stage,
      attempt: r.attempt,
      status: r.status,
      trigger: r.trigger,
      created_at: r.createdAt,
      started_at: r.startedAt,
    });
  } catch (err) {
    if (isUniqueViolation(err, "one_active_run_per_card")) throw new AlreadyInFlightError();
    throw err;
  }
  return getRunRow(db, id) as RunRow;
}

function cancelRun(db: DB, runId: string, now: string): void {
  db.prepare("UPDATE run SET status = 'cancelled', finished_at = ? WHERE id = ?").run(now, runId);
}

/** `trigger` is computed from where the human motion starts, never stored on the event. */
function computeTrigger(from: { stage: Stage; status: Status }, target: Stage): Trigger {
  if (from.status === "failed" && target === from.stage) return "retry";
  if (from.status === "awaiting_human" && STAGE_INDEX[target] > STAGE_INDEX[from.stage]) return "auto";
  return "manual";
}

// ---------------------------------------------------------------------------
// intake — create a backlog/idle card from an issue ref (idempotent on repo+issue).
// ---------------------------------------------------------------------------

export function intake(db: DB, fx: Effects, input: IntakeInput): ApplyResult {
  if (!Number.isInteger(input.issue_number) || input.issue_number <= 0) {
    throw new InvalidEventError("issue_number must be a positive integer");
  }
  const plan = inTxn(db, () => {
    const existing = db
      .prepare("SELECT id FROM card WHERE repo = ? AND issue_number = ?")
      .get(input.repo, input.issue_number) as { id: string } | undefined;
    if (existing) return { kind: "stale" as const };
    const id = fx.uuid();
    const now = fx.now();
    try {
      db.prepare(
        `INSERT INTO card (id, repo, issue_number, pr_number, stage, status, title,
                           worktree_path, created_at, updated_at, state_entered_at, archived_at)
         VALUES (?, ?, ?, NULL, 'backlog', 'idle', ?, NULL, ?, ?, ?, NULL)`,
      ).run(id, input.repo, input.issue_number, input.title, now, now, now);
    } catch (err) {
      if (isUniqueViolation(err, "card")) return { kind: "stale" as const }; // lost a create race
      throw err;
    }
    return { kind: "ok" as const, id };
  });
  if (plan.kind === "stale") return STALE;
  return { ok: true, card: getCardRow(db, plan.id) as CardState };
}

// ---------------------------------------------------------------------------
// applyEvent — the transition dispatcher.
// ---------------------------------------------------------------------------

export function applyEvent(db: DB, fx: Effects, cardId: string, event: Event): ApplyResult {
  switch (event.type) {
    case "goto":
      if (!isStage(event.target)) throw new InvalidEventError(`unknown target stage: ${String(event.target)}`);
      return handleGoto(db, fx, cardId, event);
    case "cancel":
      return handleCancel(db, fx, cardId, event);
    case "archive":
      return handleArchive(db, fx, cardId, event);
    case "run_succeeded":
      return handleRunSucceeded(db, fx, event);
    case "run_failed":
      return handleRunFailed(db, fx, event);
    case "pr_merged":
      return handlePrMerged(db, fx, cardId);
    case "pr_closed":
      return handlePrClosed(db, fx, cardId);
    default:
      throw new InvalidEventError(`unknown event type: ${String((event as { type?: unknown }).type)}`);
  }
}

type GotoEvent = Extract<Event, { type: "goto" }>;
type CancelEvent = Extract<Event, { type: "cancel" }>;
type ArchiveEvent = Extract<Event, { type: "archive" }>;

function guardedCard(db: DB, cardId: string, expectedStage: Stage, expectedStatus: Status): CardState | undefined {
  return db
    .prepare("SELECT * FROM card WHERE id = ? AND stage = ? AND status = ? AND archived_at IS NULL")
    .get(cardId, expectedStage, expectedStatus) as CardState | undefined;
}

// goto: the whole soft board — advance / skip / approve / retry / start-discuss / move.
function handleGoto(db: DB, fx: Effects, cardId: string, event: GotoEvent): ApplyResult {
  const target = event.target;
  const plan = inTxn(db, () => {
    const card = guardedCard(db, cardId, event.expected_stage, event.expected_status);
    if (!card) return { kind: "stale" as const };
    const now = fx.now();

    // Cancel any in-flight run FIRST, in-txn, so the unique index never trips on the new
    // insert. goto's cancel-first KEEPS the worktree (only `cancel`/teardown removes it).
    const inflight = inflightRun(db, cardId);
    if (inflight) cancelRun(db, inflight.id, now);

    const park = event.park === true;
    let newStatus: Status;
    let spawnSession = false;
    let teardown = false;

    if (!isRunBearing(target) || park) {
      newStatus = "idle";
      if (target === "done") teardown = true; // §6.6 terminal teardown
    } else if (target === "discuss") {
      // Interactive lane: straight to running via spawnSession, never the worker queue.
      insertRun(db, fx, {
        cardId,
        stage: "discuss",
        attempt: nextAttempt(db, cardId, "discuss"),
        status: "running",
        trigger: computeTrigger(card, target),
        createdAt: now,
        startedAt: now,
      });
      newStatus = "running";
      spawnSession = true;
    } else {
      insertRun(db, fx, {
        cardId,
        stage: target,
        attempt: nextAttempt(db, cardId, target),
        status: "queued",
        trigger: computeTrigger(card, target),
        createdAt: now,
        startedAt: null,
      });
      newStatus = "queued"; // spawn + worktree happen at claim, not enqueue
    }

    const oldPath = card.worktree_path;
    db.prepare(
      "UPDATE card SET stage = ?, status = ?, worktree_path = ?, state_entered_at = ?, updated_at = ? WHERE id = ?",
    ).run(target, newStatus, teardown ? null : oldPath, now, now, cardId);

    return {
      kind: "ok" as const,
      killRun: inflight && inflight.pid != null ? inflight : null,
      spawnSession,
      teardownPath: teardown ? oldPath : null,
    };
  });
  if (plan.kind === "stale") return STALE;

  const card = getCardRow(db, cardId) as CardState;
  if (plan.killRun) runEffect(() => fx.kill(plan.killRun as RunRow));
  if (plan.spawnSession) runEffect(() => fx.spawnSession(card));
  if (plan.teardownPath != null) runEffect(() => fx.removeWorktree({ ...card, worktree_path: plan.teardownPath }));
  return { ok: true, card };
}

// cancel: discard the in-flight run AND remove its worktree; rest the card at idle.
function handleCancel(db: DB, fx: Effects, cardId: string, event: CancelEvent): ApplyResult {
  const plan = inTxn(db, () => {
    const card = guardedCard(db, cardId, event.expected_stage, event.expected_status);
    if (!card) return { kind: "stale" as const };
    const inflight = inflightRun(db, cardId);
    if (!inflight) return { kind: "stale" as const }; // nothing to discard
    const now = fx.now();
    cancelRun(db, inflight.id, now);
    const oldPath = card.worktree_path;
    db.prepare(
      "UPDATE card SET status = 'idle', worktree_path = NULL, state_entered_at = ?, updated_at = ? WHERE id = ?",
    ).run(now, now, cardId);
    return { kind: "ok" as const, killRun: inflight.pid != null ? inflight : null, teardownPath: oldPath };
  });
  if (plan.kind === "stale") return STALE;
  const card = getCardRow(db, cardId) as CardState;
  if (plan.killRun) runEffect(() => fx.kill(plan.killRun as RunRow));
  if (plan.teardownPath != null) runEffect(() => fx.removeWorktree({ ...card, worktree_path: plan.teardownPath }));
  return { ok: true, card };
}

// archive: cancel any in-flight run, tear down the tree, drop off the board.
function handleArchive(db: DB, fx: Effects, cardId: string, event: ArchiveEvent): ApplyResult {
  const plan = inTxn(db, () => {
    const card = guardedCard(db, cardId, event.expected_stage, event.expected_status);
    if (!card) return { kind: "stale" as const };
    const now = fx.now();
    const inflight = inflightRun(db, cardId);
    if (inflight) cancelRun(db, inflight.id, now);
    const oldPath = card.worktree_path;
    db.prepare(
      "UPDATE card SET status = 'idle', worktree_path = NULL, archived_at = ?, state_entered_at = ?, updated_at = ? WHERE id = ?",
    ).run(now, now, now, cardId);
    return { kind: "ok" as const, killRun: inflight && inflight.pid != null ? inflight : null, teardownPath: oldPath };
  });
  if (plan.kind === "stale") return STALE;
  const card = getCardRow(db, cardId) as CardState;
  if (plan.killRun) runEffect(() => fx.kill(plan.killRun as RunRow));
  if (plan.teardownPath != null) runEffect(() => fx.removeWorktree({ ...card, worktree_path: plan.teardownPath }));
  return { ok: true, card };
}

// run_succeeded: per-finished-stage next-state map, keyed by run_id + status='running'.
function handleRunSucceeded(db: DB, fx: Effects, event: Extract<Event, { type: "run_succeeded" }>): ApplyResult {
  const plan = inTxn(db, () => {
    const run = db.prepare("SELECT * FROM run WHERE id = ? AND status = 'running'").get(event.run_id) as
      | RunRow
      | undefined;
    if (!run) return { kind: "stale" as const };
    const card = getCardRow(db, run.card_id) as CardState;
    const now = fx.now();
    db.prepare(
      `UPDATE run SET status = 'succeeded', session_id = COALESCE(?, session_id),
                      cost_usd = COALESCE(?, cost_usd), finished_at = ? WHERE id = ?`,
    ).run(event.session_id ?? null, event.cost_usd ?? null, now, run.id);

    let stage: Stage = card.stage;
    let status: Status = card.status;
    let prNumber = card.pr_number;
    switch (run.stage) {
      case "discuss": // Done — proceed → auto-chain write_tests
        stage = "write_tests";
        status = "queued";
        insertRun(db, fx, {
          cardId: card.id,
          stage: "write_tests",
          attempt: nextAttempt(db, card.id, "write_tests"),
          status: "queued",
          trigger: "auto",
          createdAt: now,
          startedAt: null,
        });
        break;
      case "write_tests": // rest at the approve-tests gate
        stage = "write_tests";
        status = "awaiting_human";
        break;
      case "write_code": // capture the PR, auto-chain review
        prNumber = event.pr_number ?? card.pr_number;
        stage = "review";
        status = "queued";
        insertRun(db, fx, {
          cardId: card.id,
          stage: "review",
          attempt: nextAttempt(db, card.id, "review"),
          status: "queued",
          trigger: "auto",
          createdAt: now,
          startedAt: null,
        });
        break;
      case "review": // rest at the merge gate
        stage = "review";
        status = "awaiting_human";
        break;
    }
    db.prepare(
      "UPDATE card SET stage = ?, status = ?, pr_number = ?, state_entered_at = ?, updated_at = ? WHERE id = ?",
    ).run(stage, status, prNumber ?? null, now, now, card.id);
    return { kind: "ok" as const, cardId: card.id };
  });
  if (plan.kind === "stale") return STALE;
  return { ok: true, card: getCardRow(db, plan.cardId) as CardState };
}

// run_failed: card → */failed, pointers kept (session_id + pr_number), worktree KEPT.
function handleRunFailed(db: DB, fx: Effects, event: Extract<Event, { type: "run_failed" }>): ApplyResult {
  const plan = inTxn(db, () => {
    const run = db.prepare("SELECT * FROM run WHERE id = ? AND status = 'running'").get(event.run_id) as
      | RunRow
      | undefined;
    if (!run) return { kind: "stale" as const };
    const card = getCardRow(db, run.card_id) as CardState;
    const now = fx.now();
    db.prepare(
      "UPDATE run SET status = 'failed', session_id = COALESCE(?, session_id), finished_at = ? WHERE id = ?",
    ).run(event.session_id ?? null, now, run.id);
    const prNumber = event.pr_number ?? card.pr_number;
    db.prepare(
      "UPDATE card SET stage = ?, status = 'failed', pr_number = ?, state_entered_at = ?, updated_at = ? WHERE id = ?",
    ).run(run.stage, prNumber ?? null, now, now, card.id);
    return { kind: "ok" as const, cardId: card.id };
  });
  if (plan.kind === "stale") return STALE;
  return { ok: true, card: getCardRow(db, plan.cardId) as CardState };
}

// pr_merged: drift — a hand-merged PR drives the card to done from any non-done state.
function handlePrMerged(db: DB, fx: Effects, cardId: string): ApplyResult {
  const plan = inTxn(db, () => {
    const card = db
      .prepare("SELECT * FROM card WHERE id = ? AND pr_number IS NOT NULL AND stage != 'done' AND archived_at IS NULL")
      .get(cardId) as CardState | undefined;
    if (!card) return { kind: "stale" as const };
    const now = fx.now();
    const inflight = inflightRun(db, cardId);
    if (inflight) cancelRun(db, inflight.id, now);
    const oldPath = card.worktree_path;
    db.prepare(
      "UPDATE card SET stage = 'done', status = 'idle', worktree_path = NULL, state_entered_at = ?, updated_at = ? WHERE id = ?",
    ).run(now, now, cardId);
    return { kind: "ok" as const, killRun: inflight && inflight.pid != null ? inflight : null, teardownPath: oldPath };
  });
  if (plan.kind === "stale") return STALE;
  const card = getCardRow(db, cardId) as CardState;
  if (plan.killRun) runEffect(() => fx.kill(plan.killRun as RunRow));
  if (plan.teardownPath != null) runEffect(() => fx.removeWorktree({ ...card, worktree_path: plan.teardownPath }));
  return { ok: true, card };
}

// pr_closed: drift — a PR closed unmerged drives the card to failed, PR + tree KEPT.
function handlePrClosed(db: DB, fx: Effects, cardId: string): ApplyResult {
  const plan = inTxn(db, () => {
    const card = db
      .prepare("SELECT * FROM card WHERE id = ? AND pr_number IS NOT NULL AND stage != 'done' AND archived_at IS NULL")
      .get(cardId) as CardState | undefined;
    if (!card) return { kind: "stale" as const };
    const now = fx.now();
    const inflight = inflightRun(db, cardId);
    if (inflight) cancelRun(db, inflight.id, now);
    db.prepare("UPDATE card SET status = 'failed', state_entered_at = ?, updated_at = ? WHERE id = ?").run(
      now,
      now,
      cardId,
    );
    return { kind: "ok" as const, killRun: inflight && inflight.pid != null ? inflight : null };
  });
  if (plan.kind === "stale") return STALE;
  const card = getCardRow(db, cardId) as CardState;
  if (plan.killRun) runEffect(() => fx.kill(plan.killRun as RunRow));
  return { ok: true, card };
}

// ---------------------------------------------------------------------------
// claimNext — the worker pulls the oldest queued run to running, lazily creating the
// shared worktree and requesting the headless spawn. Effect failures are fire-and-reconcile.
// ---------------------------------------------------------------------------

export function claimNext(db: DB, fx: Effects): ApplyResult | null {
  const plan = inTxn(db, () => {
    const run = db
      .prepare("SELECT * FROM run WHERE status = 'queued' ORDER BY created_at, rowid LIMIT 1")
      .get() as RunRow | undefined;
    if (!run) return { kind: "none" as const };
    const card = getCardRow(db, run.card_id) as CardState;
    const now = fx.now();
    db.prepare("UPDATE run SET status = 'running', started_at = ? WHERE id = ? AND status = 'queued'").run(now, run.id);
    db.prepare("UPDATE card SET status = 'running', state_entered_at = ?, updated_at = ? WHERE id = ?").run(
      now,
      now,
      card.id,
    );
    return {
      kind: "ok" as const,
      runId: run.id,
      cardId: card.id,
      needsWorktree: run.stage !== "discuss" && card.worktree_path === null,
    };
  });
  if (plan.kind === "none") return null;

  let card = getCardRow(db, plan.cardId) as CardState;
  const run = getRunRow(db, plan.runId) as RunRow;
  if (plan.needsWorktree) {
    try {
      const path = fx.createWorktree(card);
      db.prepare("UPDATE card SET worktree_path = ?, updated_at = ? WHERE id = ?").run(path, fx.now(), card.id);
      card = getCardRow(db, plan.cardId) as CardState;
    } catch {
      // fire-and-reconcile: the run is committed running with no path; spawn is not reached.
      return { ok: true, card };
    }
  }
  runEffect(() => fx.spawnHeadless(run, card));
  return { ok: true, card };
}

// ---------------------------------------------------------------------------
// reconcile — startup crash recovery over runs left 'running'.
// ---------------------------------------------------------------------------

export function reconcile(db: DB, fx: Effects): ReconcileSummary {
  const summary: ReconcileSummary = { failed_headless: 0, left_discuss: 0, redriven_queued: 0, killed: 0 };
  const toKill: RunRow[] = [];

  inTxn(db, () => {
    const running = db.prepare("SELECT * FROM run WHERE status = 'running' ORDER BY created_at, rowid").all() as RunRow[];
    const now = fx.now();
    for (const run of running) {
      if (run.stage === "discuss") {
        // The board never parented an interactive discuss run — leave it running.
        summary.left_discuss += 1;
        continue;
      }
      // Orphaned headless run → failed (session_id + pr_number kept, resumable); reap the proc.
      db.prepare("UPDATE run SET status = 'failed', finished_at = ? WHERE id = ?").run(now, run.id);
      db.prepare("UPDATE card SET status = 'failed', state_entered_at = ?, updated_at = ? WHERE id = ?").run(
        now,
        now,
        run.card_id,
      );
      summary.failed_headless += 1;
      if (run.pid != null) toKill.push(run);
    }
    const queued = db.prepare("SELECT COUNT(*) AS n FROM run WHERE status = 'queued'").get() as { n: number };
    summary.redriven_queued = queued.n;
  });

  for (const run of toKill) {
    runEffect(() => fx.kill(run));
    summary.killed += 1;
  }
  return summary;
}
