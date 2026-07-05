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
  ClaimedRun,
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
function runEffect(f: () => void): boolean {
  try {
    f();
    return true;
  } catch {
    /* recorded by fx; orphan caught by reconcile */
    return false;
  }
}

/** True when `err` is a SQLite UNIQUE violation whose offending column list is EXACTLY
 *  `columns`. SQLite reports the `<table>.<col>[, …]` list, never the index name, so the match
 *  is on columns — and it must be exact: a loose substring on "run.card_id" would also swallow
 *  the three-column `one_run_per_attempt` breach ("run.card_id, run.stage, run.attempt"). */
function isUniqueViolation(err: unknown, columns: string): boolean {
  return err instanceof Error && err.message === `UNIQUE constraint failed: ${columns}`;
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
function insertRun(db: DB, fx: Effects, r: NewRun): void {
  const id = fx.uuid();
  try {
    db.prepare(
      `INSERT INTO run (id, card_id, stage, attempt, status, trigger, session_id, pid,
                        created_at, started_at, finished_at)
       VALUES (@id, @card_id, @stage, @attempt, @status, @trigger, NULL, NULL,
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
    if (isUniqueViolation(err, "run.card_id")) throw new AlreadyInFlightError();
    throw err;
  }
}

function cancelRun(db: DB, runId: string, now: string): void {
  db.prepare("UPDATE run SET status = 'cancelled', finished_at = ? WHERE id = ?").run(now, runId);
}

// ---------------------------------------------------------------------------
// Run-arc DB writes — the worker loop's own atomic writes (NOT injected Effects). Each is a
// single statement the worker fires OUTSIDE any transaction (§9.4), so nothing it does holds a
// lock across the awaited headless run.
// ---------------------------------------------------------------------------

/** Persist the assigned session_id onto a run BEFORE the headless spawn (FORK-G / §9.7), so a
 *  crash mid-run leaves a resumable `--session-id`; the completion's session_id is confirmatory. */
export function recordSession(db: DB, runId: string, sessionId: string): void {
  db.prepare("UPDATE run SET session_id = ? WHERE id = ?").run(sessionId, runId);
}

/** Persist the child pid onto a run after the spawn — the kill/reap handle (§6.4). */
export function recordPid(db: DB, runId: string, pid: number): void {
  db.prepare("UPDATE run SET pid = ? WHERE id = ?").run(pid, runId);
}

/** Write the lazily-created shared worktree path back onto the card (reused across the arc). */
export function recordWorktree(db: DB, cardId: string, path: string, now: string): void {
  db.prepare("UPDATE card SET worktree_path = ?, updated_at = ? WHERE id = ?").run(path, now, cardId);
}

/** `trigger` is computed from where the human motion starts, never stored on the event. */
function computeTrigger(from: { stage: Stage; status: Status }, target: Stage): Trigger {
  if (from.status === "failed" && target === from.stage) return "retry";
  // A gate release advances to the IMMEDIATE next stage → auto (§6.2 approve). A forward jump
  // PAST the next stage is a human-named skip (§6.2) → manual, so require exactly next-stage.
  if (from.status === "awaiting_human" && STAGE_INDEX[target] === STAGE_INDEX[from.stage] + 1) return "auto";
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
      if (isUniqueViolation(err, "card.repo, card.issue_number")) return { kind: "stale" as const }; // lost a create race
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
                      pid = NULL, finished_at = ? WHERE id = ?`,
    ).run(event.session_id ?? null, now, run.id);

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
      "UPDATE run SET status = 'failed', session_id = COALESCE(?, session_id), pid = NULL, finished_at = ? WHERE id = ?",
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
    // Idempotent across polls: a card already resting in */failed (this drift's own target)
    // must NOT re-fire — mirrors pr_merged self-absorbing into 'done'. Without `status !=
    // 'failed'` every re-poll of a still-closed PR re-runs the UPDATE and resets
    // state_entered_at, defeating the §5 dwell/gate-nag "stuck" clock.
    const card = db
      .prepare(
        "SELECT * FROM card WHERE id = ? AND pr_number IS NOT NULL AND stage != 'done' AND status != 'failed' AND archived_at IS NULL",
      )
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
// claimNext — a PURE CAS (§9.4): move the oldest queued run + its card to `running` and hand
// back the pair. It creates NO worktree and spawns NOTHING; the whole effect arc
// (createWorktree → spawnHeadless → recordPid → await → dispatch) is the worker loop's
// (`executeRun`, src/worker.ts), so the sync engine stays lock-free across the run.
// ---------------------------------------------------------------------------

export function claimNext(db: DB, fx: Effects): ClaimedRun | null {
  const runId = inTxn(db, () => {
    const run = db
      .prepare("SELECT * FROM run WHERE status = 'queued' ORDER BY created_at, rowid LIMIT 1")
      .get() as RunRow | undefined;
    if (!run) return null;
    const now = fx.now();
    db.prepare("UPDATE run SET status = 'running', started_at = ? WHERE id = ? AND status = 'queued'").run(now, run.id);
    db.prepare("UPDATE card SET status = 'running', state_entered_at = ?, updated_at = ? WHERE id = ?").run(
      now,
      now,
      run.card_id,
    );
    return run.id;
  });
  if (runId === null) return null;
  const run = getRunRow(db, runId) as RunRow;
  const card = getCardRow(db, run.card_id) as CardState;
  return { run, card };
}

// ---------------------------------------------------------------------------
// reconcile — startup crash recovery over runs left 'running'.
// ---------------------------------------------------------------------------

export function reconcile(db: DB, fx: Effects): ReconcileSummary {
  const summary: ReconcileSummary = { failed_headless: 0, left_discuss: 0, redriven_queued: 0, killed: 0, swept: 0 };
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
      db.prepare("UPDATE run SET status = 'failed', pid = NULL, finished_at = ? WHERE id = ?").run(now, run.id);
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
    if (runEffect(() => fx.kill(run))) summary.killed += 1; // count only reaps that actually fired
  }

  sweepOrphanWorktrees(db, fx, summary);
  return summary;
}

// ---------------------------------------------------------------------------
// Worktree sweep (§9.4, finding #2) — after crash-recovery, reap every on-disk worktree that no
// live card claims (an orphan a swallowed post-commit teardown left behind). Runs AFTER recovery
// commits, so a just-failed run's KEPT path counts as a live claim and is spared. An orphan is a
// listWorktrees() path equal to NO non-archived card's worktree_path — matched by path VALUE,
// never by parsing `issue-<n>`. `swept` counts only removals that actually fired.
// ---------------------------------------------------------------------------

function sweepOrphanWorktrees(db: DB, fx: Effects, summary: ReconcileSummary): void {
  let onDisk: string[];
  try {
    onDisk = fx.listWorktrees();
  } catch {
    return; // list blip — recovery already stands; leave swept at 0.
  }
  const claimed = new Set(
    (
      db
        .prepare("SELECT worktree_path FROM card WHERE archived_at IS NULL AND worktree_path IS NOT NULL")
        .all() as { worktree_path: string }[]
    ).map((r) => r.worktree_path),
  );
  for (const path of onDisk) {
    if (claimed.has(path)) continue;
    // An orphan has no owning card — the sweep holds only the path, so it reaps via the path-based
    // seam (`removeWorktreePath`) rather than casting a phantom card. `swept` counts only reaps that fired.
    if (runEffect(() => fx.removeWorktreePath(path))) summary.swept += 1;
  }
}
