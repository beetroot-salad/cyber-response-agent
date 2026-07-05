// executeRun (§9.4, src/worker.ts) — the per-run execution arc the worker loop owns:
//   recordSession(uuid) → createWorktree → recordWorktree → spawnHeadless → recordPid
//   → await done → applyEvent(run_succeeded | run_failed).
// Any throw BEFORE the await → run_failed (fast retry, never a stranded 'running' run).
// drainQueue runs the arc for up to `pool` claimed runs concurrently.
//
// NOTE: `../src/worker` is the not-yet-written target — this file is RED (import fails) until
// the implement phase lands it. The assertions below are the spec it must satisfy.
import { describe, expect, it } from "bun:test";
import { executeRun, drainQueue } from "../src/worker";
import { applyEvent, intake } from "../src/engine";
import { createTestDb } from "./support/db";
import { seedCard, seedRun } from "./support/arrange";
import { getCard, getRun, latestRun } from "./support/read";
import { FakeEffects } from "./support/effects";
import { ev } from "./support/events";

/** Let pending microtasks/timers settle (drainQueue's loop, awaited `done`s). */
const flush = () => new Promise((r) => setTimeout(r, 0));

/** Seed the post-claim state: a running card + its running run, returned as a ClaimedRun. */
function runningRun(db: ReturnType<typeof createTestDb>, opts: { stage?: "write_tests" | "write_code" | "review"; worktree_path?: string | null; pr_number?: number | null } = {}) {
  const card = seedCard(db, {
    stage: opts.stage ?? "write_tests",
    status: "running",
    worktree_path: opts.worktree_path ?? null,
    pr_number: opts.pr_number ?? null,
  });
  const run = seedRun(db, card.id, { id: "run-x", stage: opts.stage ?? "write_tests", status: "running" });
  return { run, card };
}

describe("executeRun — the run arc", () => {
  it("done {ok:true} → run_succeeded; run.status=succeeded, pid nulled, worktree KEPT", async () => {
    const db = createTestDb();
    const fx = new FakeEffects();
    const { run, card } = runningRun(db, { stage: "write_tests" });

    const p = executeRun(db, fx, run, card);
    fx.succeedRun(run.id);
    await p;

    expect(getRun(db, run.id)?.status).toBe("succeeded");
    expect(getRun(db, run.id)?.pid).toBeNull();
    expect([getCard(db, card.id)?.stage, getCard(db, card.id)?.status]).toEqual(["write_tests", "awaiting_human"]);
    expect(fx.countOf("createWorktree")).toBe(1);
    expect(fx.countOf("removeWorktree")).toBe(0); // success keeps the tree
  });

  it("assigns + PERSISTS session_id BEFORE the spawn, and passes it to spawnHeadless (--session-id)", async () => {
    const db = createTestDb();
    const fx = new FakeEffects();
    const { run, card } = runningRun(db);

    const p = executeRun(db, fx, run, card); // runs synchronously up to `await done`
    const sid = getRun(db, run.id)?.session_id;
    expect(sid).not.toBeNull(); // written before the run finishes — resumable on a crash (§6.4.4)
    const spawnArgs = fx.callsTo("spawnHeadless")[0]?.args as { sessionId: string };
    expect(spawnArgs.sessionId).toBe(sid!); // the SAME id, handed to the subprocess

    fx.succeedRun(run.id, { session_id: sid! });
    await p;
    expect(getRun(db, run.id)?.session_id).toBe(sid!); // completion is confirmatory, not a 2nd source
  });

  it("records the child pid after spawn (the kill/reap handle, §6.4)", async () => {
    const db = createTestDb();
    const fx = new FakeEffects();
    const { run, card } = runningRun(db);

    const p = executeRun(db, fx, run, card);
    expect(getRun(db, run.id)?.pid).not.toBeNull(); // written pre-await
    fx.succeedRun(run.id);
    await p;
  });

  it("creates the worktree at a deterministic path and writes it back onto the card", async () => {
    const db = createTestDb();
    const fx = new FakeEffects();
    const { run, card } = runningRun(db, { worktree_path: null });

    const p = executeRun(db, fx, run, card);
    expect(getCard(db, card.id)?.worktree_path).toBe(`/wt/issue-${card.issue_number}`);
    fx.succeedRun(run.id);
    await p;
  });

  it("reuses an existing worktree (card already has a path) — no second createWorktree", async () => {
    const db = createTestDb();
    const fx = new FakeEffects();
    const { run, card } = runningRun(db, { stage: "write_code", worktree_path: "/wt/existing" });

    const p = executeRun(db, fx, run, card);
    expect(fx.countOf("createWorktree")).toBe(0);
    const spawnArgs = fx.callsTo("spawnHeadless")[0]?.args as { worktree_path: string };
    expect(spawnArgs.worktree_path).toBe("/wt/existing");
    fx.succeedRun(run.id);
    await p;
  });

  it("done {ok:false} → run_failed; card (stage, failed); worktree KEPT for --resume", async () => {
    const db = createTestDb();
    const fx = new FakeEffects();
    const { run, card } = runningRun(db, { stage: "write_code" });

    const p = executeRun(db, fx, run, card);
    fx.failRun(run.id, { session_id: "s-fail" });
    await p;

    expect(getRun(db, run.id)?.status).toBe("failed");
    expect([getCard(db, card.id)?.stage, getCard(db, card.id)?.status]).toEqual(["write_code", "failed"]);
    expect(fx.countOf("removeWorktree")).toBe(0);
  });

  it("done rejects (subprocess crash) → run_failed; worktree KEPT; pid nulled", async () => {
    const db = createTestDb();
    const fx = new FakeEffects();
    const { run, card } = runningRun(db, { stage: "write_code" });

    const p = executeRun(db, fx, run, card);
    fx.rejectRun(run.id);
    await p;

    expect(getRun(db, run.id)?.status).toBe("failed");
    expect(getRun(db, run.id)?.pid).toBeNull();
    expect([getCard(db, card.id)?.stage, getCard(db, card.id)?.status]).toEqual(["write_code", "failed"]);
    expect(fx.countOf("removeWorktree")).toBe(0);
  });

  it("createWorktree throws → immediate run_failed; NO spawn; worktree_path stays NULL", async () => {
    const db = createTestDb();
    const fx = new FakeEffects().failOn("createWorktree");
    const { run, card } = runningRun(db, { worktree_path: null });

    await executeRun(db, fx, run, card); // no await on `done` — the throw is pre-spawn

    expect(getRun(db, run.id)?.status).toBe("failed");
    expect(fx.countOf("spawnHeadless")).toBe(0);
    expect(getCard(db, card.id)?.worktree_path).toBeNull();
    expect([getCard(db, card.id)?.stage, getCard(db, card.id)?.status]).toEqual(["write_tests", "failed"]);
    // rejected: leave the run 'running' for the startup reconciler (strands it until a reboot)
  });

  it("spawnHeadless throws → run_failed; worktree KEPT (created before the throw); no pid", async () => {
    const db = createTestDb();
    const fx = new FakeEffects().failOn("spawnHeadless");
    const { run, card } = runningRun(db, { worktree_path: null });

    await executeRun(db, fx, run, card);

    expect(getRun(db, run.id)?.status).toBe("failed");
    expect(getRun(db, run.id)?.pid).toBeNull();
    expect(getCard(db, card.id)?.worktree_path).toBe(`/wt/issue-${card.issue_number}`); // created, kept
    expect(fx.countOf("removeWorktree")).toBe(0);
  });

  it("write_code done {ok:true, pr_number} → auto-chains a queued review run + captures the PR", async () => {
    const db = createTestDb();
    const fx = new FakeEffects();
    const { run, card } = runningRun(db, { stage: "write_code", worktree_path: "/wt/existing" });

    const p = executeRun(db, fx, run, card);
    fx.succeedRun(run.id, { pr_number: 99 });
    await p;

    expect([getCard(db, card.id)?.stage, getCard(db, card.id)?.status]).toEqual(["review", "queued"]);
    expect(getCard(db, card.id)?.pr_number).toBe(99);
    const chained = latestRun(db, card.id)!;
    expect([chained.stage, chained.status, chained.trigger]).toEqual(["review", "queued", "auto"]);
  });

  it("a completion that lands AFTER a cancel is a stale no-op (run no longer 'running')", async () => {
    const db = createTestDb();
    const fx = new FakeEffects();
    const { run, card } = runningRun(db, { stage: "write_tests", worktree_path: null });

    const p = executeRun(db, fx, run, card); // spawned, awaiting done
    applyEvent(db, fx, card.id, ev.cancel({ stage: "write_tests", status: "running" })); // drift/cancel wins
    fx.succeedRun(run.id); // the late success
    await p;

    expect(getRun(db, run.id)?.status).toBe("cancelled"); // NOT resurrected to succeeded
    expect([getCard(db, card.id)?.stage, getCard(db, card.id)?.status]).toEqual(["write_tests", "idle"]);
  });

  it("holds NO write lock while awaiting `done` — other engine writes commit meanwhile", async () => {
    const db = createTestDb();
    const fx = new FakeEffects();
    const { run, card } = runningRun(db);

    const p = executeRun(db, fx, run, card); // now parked at `await done`
    const created = intake(db, fx, { repo: "o/r", issue_number: 777, title: "meanwhile" });
    expect(created.ok).toBe(true); // the DB is not locked by the in-flight run

    fx.succeedRun(run.id);
    await p;
  });

  // recordPid / recordWorktree are the arc's own DB writes (not injected Effects), so a
  // disk-full/locked failure of them needs a DB-fault seam the 2a harness doesn't have yet.
  // Resolved intent (FORK-C): fail-fast → run_failed, and for recordPid kill the in-hand pid
  // before dispatching (executeRun still holds it) so no un-reapable orphan is left.
  it.todo("recordPid write failure → fx.kill the in-hand pid, then run_failed (needs a DB-fault seam)", () => {});
});

describe("drainQueue — the pool cap", () => {
  it("never exceeds `pool` concurrent spawns and drains all K queued runs", async () => {
    const db = createTestDb();
    const fx = new FakeEffects();
    const K = 5;
    const POOL = 2;
    for (let i = 1; i <= K; i++) {
      const c = seedCard(db, { issue_number: i, stage: "write_tests", status: "queued" });
      seedRun(db, c.id, { id: `r${i}`, stage: "write_tests", status: "queued" });
    }

    const p = drainQueue(db, fx, { pool: POOL });
    await flush();
    let peak = fx.inFlight().length;
    while (fx.inFlight().length > 0) {
      peak = Math.max(peak, fx.inFlight().length);
      fx.succeedRun(fx.inFlight()[0]!); // free a slot → drainQueue claims the next
      await flush();
    }
    await p;

    expect(peak).toBeLessThanOrEqual(POOL); // the cap held
    expect(fx.spawned().length).toBe(K); // every queued run ran
  });

  it("an empty queue resolves immediately with no spawns", async () => {
    const db = createTestDb();
    const fx = new FakeEffects();
    await drainQueue(db, fx, { pool: 2 });
    expect(fx.countOf("spawnHeadless")).toBe(0);
  });
});
