// The per-run execution arc + the pool-capped drain loop (design §9.4).
//
// `claimNext` (engine) is a pure CAS — it moves the oldest queued run to `running` and hands back
// { run, card }. `executeRun` then owns the whole effect arc OUTSIDE any transaction: assign +
// persist a session id (FORK-G), lazily create the shared worktree, spawn the headless
// `claude -p`, record the pid, then await the subprocess and dispatch a run_succeeded /
// run_failed completion. Any throw BEFORE the await fails the run fast (never a stranded
// 'running' row). `drainQueue` runs the arc for up to `pool` claimed runs concurrently, refilling
// a freed slot until the queue drains (FORK-F).

import type { CardState, DB, Effects, Event, RunResult, RunRow } from "./contract";
import { applyEvent, claimNext, recordPid, recordSession, recordWorktree } from "./engine";

/** Drive one claimed run from spawn to completion (§9.4). Resolves once the completion event has
 *  been applied (or the run has been failed pre-await). */
export async function executeRun(db: DB, fx: Effects, run: RunRow, card: CardState): Promise<void> {
  let done: Promise<RunResult>;
  let spawnedPid: number | null = null;
  try {
    // FORK-G: assign + PERSIST the session id before the spawn, then hand the SAME id to the
    // subprocess (`--session-id`) — a crash mid-run leaves a resumable pointer; the completion's
    // session_id is confirmatory, not a second source.
    const sessionId = run.session_id ?? fx.uuid();
    recordSession(db, run.id, sessionId);

    // Lazily create the shared worktree — reuse the card's path across the
    // write_tests → write_code → review arc; only the arc's first run creates it.
    let arcCard = card;
    if (arcCard.worktree_path === null) {
      const path = fx.createWorktree(arcCard);
      recordWorktree(db, arcCard.id, path, fx.now());
      arcCard = { ...arcCard, worktree_path: path };
    }

    const spawn = fx.spawnHeadless(run, arcCard, sessionId);
    spawnedPid = spawn.pid;
    recordPid(db, run.id, spawn.pid);
    done = spawn.done;
  } catch {
    // Pre-await failure (createWorktree / spawnHeadless / recordPid). Fail fast → run_failed;
    // never leave the run stranded 'running'. FORK-C: if we already hold a spawned pid (a
    // post-spawn step threw), reap it first — the pid never reached the run row, so the startup
    // reconciler could not kill it, leaving an un-reapable orphan.
    const pid = spawnedPid;
    if (pid !== null) {
      try {
        fx.kill({ ...run, pid });
      } catch {
        /* best-effort reap; the startup reconciler backstops */
      }
    }
    applyEvent(db, fx, card.id, { type: "run_failed", run_id: run.id });
    return;
  }

  // Await the subprocess OUTSIDE any transaction — the DB stays free for other writers.
  let result: RunResult;
  try {
    result = await done;
  } catch {
    // The subprocess crashed (done rejected) → failed run; worktree KEPT for --resume.
    applyEvent(db, fx, card.id, { type: "run_failed", run_id: run.id });
    return;
  }

  const completion: Event = result.ok
    ? { type: "run_succeeded", run_id: run.id, session_id: result.session_id, pr_number: result.pr_number }
    : { type: "run_failed", run_id: run.id, session_id: result.session_id, pr_number: result.pr_number };
  applyEvent(db, fx, card.id, completion);
}

/** Drain the queued-run backlog with at most `pool` concurrent run arcs (FORK-F): each worker
 *  claims (pure CAS) → executes → repeats until `claimNext` returns null, so peak concurrency
 *  never exceeds `pool` and every queued run eventually runs. */
export async function drainQueue(db: DB, fx: Effects, opts: { pool: number }): Promise<void> {
  async function worker(): Promise<void> {
    for (;;) {
      const claimed = claimNext(db, fx);
      if (!claimed) return;
      await executeRun(db, fx, claimed.run, claimed.card);
    }
  }
  const workers: Promise<void>[] = [];
  for (let i = 0; i < opts.pool; i++) workers.push(worker());
  await Promise.all(workers);
}
