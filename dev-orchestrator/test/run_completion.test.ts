// run_succeeded / run_failed (T-SUCCEED / T-FAIL): the per-finished-stage next-state map,
// keyed by run_id + status='running'. Auto-chains for discuss/write_code; gates for
// write_tests/review. Pointers captured even on failure.
import { describe, expect, it } from "bun:test";
import { applyEvent } from "../src/engine";
import { createTestDb } from "./support/db";
import { seedCard, seedRun } from "./support/arrange";
import { getCard, getRuns, latestRun } from "./support/read";
import { FakeEffects } from "./support/effects";
import { ev } from "./support/events";
import { expectOk, expectStale } from "./support/assert";

function runRow(db: ReturnType<typeof createTestDb>, id: string) {
  return db.prepare("SELECT * FROM run WHERE id = ?").get(id) as { status: string; session_id: string | null; cost_usd: number | null; pid: number | null };
}

describe("run completion — auto-chains and gates", () => {
  it("discuss run_succeeded (Done — proceed) auto-chains write_tests (trigger=auto)", () => {
    const db = createTestDb();
    const fx = new FakeEffects();
    const card = seedCard(db, { stage: "discuss", status: "running" });
    seedRun(db, card.id, { id: "d", stage: "discuss", status: "running", trigger: "manual" });

    const now = expectOk(applyEvent(db, fx, card.id, ev.runSucceeded("d", { session_id: "s1" })));
    expect([now.stage, now.status]).toEqual(["write_tests", "queued"]);
    expect(runRow(db, "d").status).toBe("succeeded");

    const chained = latestRun(db, card.id)!;
    expect(chained.stage).toBe("write_tests");
    expect(chained.attempt).toBe(1);
    expect(chained.status).toBe("queued");
    expect(chained.trigger).toBe("auto");
  });

  it("write_tests run_succeeded rests at the approve-tests gate and does NOT auto-chain", () => {
    const db = createTestDb();
    const fx = new FakeEffects();
    const card = seedCard(db, { stage: "write_tests", status: "running" });
    seedRun(db, card.id, { id: "t", stage: "write_tests", status: "running" });

    const now = expectOk(applyEvent(db, fx, card.id, ev.runSucceeded("t")));
    expect([now.stage, now.status]).toEqual(["write_tests", "awaiting_human"]);
    expect(getRuns(db, card.id)).toHaveLength(1); // no write_code run enqueued
  });

  it("write_code run_succeeded stores pr_number and auto-chains review (trigger=auto)", () => {
    const db = createTestDb();
    const fx = new FakeEffects();
    const card = seedCard(db, { stage: "write_code", status: "running" });
    seedRun(db, card.id, { id: "c", stage: "write_code", status: "running" });

    const now = expectOk(
      applyEvent(db, fx, card.id, ev.runSucceeded("c", { pr_number: 42, session_id: "s", cost_usd: 0.5 })),
    );
    expect([now.stage, now.status]).toEqual(["review", "queued"]);
    expect(now.pr_number).toBe(42);

    const done = runRow(db, "c");
    expect(done.status).toBe("succeeded");
    expect(done.session_id).toBe("s");
    expect(done.cost_usd).toBe(0.5);
    expect(done.pid).toBeNull();

    const chained = latestRun(db, card.id)!;
    expect(chained.stage).toBe("review");
    expect(chained.trigger).toBe("auto");
    expect(chained.status).toBe("queued");
  });

  it("review run_succeeded rests at the merge gate and does NOT auto-chain", () => {
    const db = createTestDb();
    const fx = new FakeEffects();
    const card = seedCard(db, { stage: "review", status: "running", pr_number: 42 });
    seedRun(db, card.id, { id: "r", stage: "review", status: "running" });

    const now = expectOk(applyEvent(db, fx, card.id, ev.runSucceeded("r")));
    expect([now.stage, now.status]).toEqual(["review", "awaiting_human"]);
    expect(getRuns(db, card.id)).toHaveLength(1);
  });
});

describe("run completion — idempotency and ordering", () => {
  it("a duplicate run_succeeded is a stale no-op (run no longer running)", () => {
    const db = createTestDb();
    const fx = new FakeEffects();
    const card = seedCard(db, { stage: "write_code", status: "running" });
    seedRun(db, card.id, { id: "c", stage: "write_code", status: "running" });

    expectOk(applyEvent(db, fx, card.id, ev.runSucceeded("c", { pr_number: 42 })));
    const after = getCard(db, card.id);
    expectStale(applyEvent(db, fx, card.id, ev.runSucceeded("c", { pr_number: 42 })));
    expect(getCard(db, card.id)).toEqual(after); // second changes nothing
  });

  it("run_succeeded for a nonexistent run is a stale no-op", () => {
    const db = createTestDb();
    const fx = new FakeEffects();
    const card = seedCard(db, { stage: "discuss", status: "running" });
    seedRun(db, card.id, { id: "d", stage: "discuss", status: "running" });

    expectStale(applyEvent(db, fx, card.id, ev.runSucceeded("ghost")));
    expect(getCard(db, card.id)?.status).toBe("running"); // untouched
    expect(runRow(db, "d").status).toBe("running");
  });

  it("a belated run_succeeded for an already-cancelled run does not resurrect the card", () => {
    const db = createTestDb();
    const fx = new FakeEffects();
    // arrange the aftermath of a cancel: card resting, its run cancelled
    const card = seedCard(db, { stage: "write_tests", status: "idle" });
    seedRun(db, card.id, { id: "t", stage: "write_tests", status: "cancelled" });

    expectStale(applyEvent(db, fx, card.id, ev.runSucceeded("t")));
    expect([getCard(db, card.id)?.stage, getCard(db, card.id)?.status]).toEqual(["write_tests", "idle"]);
    expect(runRow(db, "t").status).toBe("cancelled");
  });
});

describe("run failure — pointers kept, worktree kept", () => {
  it("run_failed drives */failed, stores session_id + pr_number, and KEEPS the worktree", () => {
    const db = createTestDb();
    const fx = new FakeEffects();
    const card = seedCard(db, { stage: "write_code", status: "running", worktree_path: "/wt/x" });
    seedRun(db, card.id, { id: "c", stage: "write_code", status: "running", pid: 77 });

    const now = expectOk(applyEvent(db, fx, card.id, ev.runFailed("c", { session_id: "s", pr_number: 42 })));
    expect([now.stage, now.status]).toEqual(["write_code", "failed"]);
    expect(now.pr_number).toBe(42);
    expect(now.worktree_path).toBe("/wt/x");

    const failed = runRow(db, "c");
    expect(failed.status).toBe("failed");
    expect(failed.session_id).toBe("s");
    expect(fx.countOf("removeWorktree")).toBe(0); // failure keeps the tree for --resume
  });

  it("a later run_failed with no pr_number does not null a pr_number already set (COALESCE)", () => {
    const db = createTestDb();
    const fx = new FakeEffects();
    const card = seedCard(db, { stage: "review", status: "running", pr_number: 42 });
    seedRun(db, card.id, { id: "r", stage: "review", status: "running" });

    const now = expectOk(applyEvent(db, fx, card.id, ev.runFailed("r")));
    expect([now.stage, now.status]).toEqual(["review", "failed"]);
    expect(now.pr_number).toBe(42); // not nulled
  });
});
