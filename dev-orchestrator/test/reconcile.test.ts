// reconcile (§6.4.4): startup crash recovery over runs left 'running'. Headless runs are
// failed (and their orphans killed) but stay resumable; a running discuss run is exempt
// (the board never parented it); queued runs are left claimable.
import { describe, expect, it } from "vitest";
import { reconcile } from "../src/engine";
import { createTestDb } from "./support/db";
import { seedCard, seedRun } from "./support/arrange";
import { getCard } from "./support/read";
import { FakeEffects } from "./support/effects";

function runRow(db: ReturnType<typeof createTestDb>, id: string) {
  return db.prepare("SELECT * FROM run WHERE id = ?").get(id) as { status: string; session_id: string | null };
}

describe("reconcile", () => {
  it("fails an orphaned headless run, kills it, and keeps it resumable (session_id + pr_number)", () => {
    const db = createTestDb();
    const fx = new FakeEffects();
    const card = seedCard(db, { stage: "write_code", status: "running", pr_number: 42, worktree_path: "/wt/x" });
    seedRun(db, card.id, { id: "c", stage: "write_code", status: "running", pid: 77, session_id: "s" });

    const summary = reconcile(db, fx);
    expect(runRow(db, "c").status).toBe("failed");
    expect(runRow(db, "c").session_id).toBe("s"); // resumable
    expect([getCard(db, card.id)?.stage, getCard(db, card.id)?.status]).toEqual(["write_code", "failed"]);
    expect(getCard(db, card.id)?.pr_number).toBe(42);
    expect(getCard(db, card.id)?.worktree_path).toBe("/wt/x"); // failure keeps the tree
    expect(fx.countOf("kill")).toBe(1);
    expect(summary.failed_headless).toBe(1);
    expect(summary.killed).toBe(1);
  });

  it("leaves a running discuss run untouched (exempt — never board-parented)", () => {
    const db = createTestDb();
    const fx = new FakeEffects();
    const card = seedCard(db, { stage: "discuss", status: "running" });
    seedRun(db, card.id, { id: "d", stage: "discuss", status: "running" });

    const summary = reconcile(db, fx);
    expect(runRow(db, "d").status).toBe("running"); // left alone
    expect([getCard(db, card.id)?.stage, getCard(db, card.id)?.status]).toEqual(["discuss", "running"]);
    expect(fx.countOf("kill")).toBe(0);
    expect(summary.left_discuss).toBe(1);
    expect(summary.failed_headless).toBe(0);
  });

  it("leaves a queued run claimable", () => {
    const db = createTestDb();
    const fx = new FakeEffects();
    const card = seedCard(db, { stage: "write_tests", status: "queued" });
    seedRun(db, card.id, { id: "t", stage: "write_tests", status: "queued" });

    const summary = reconcile(db, fx);
    expect(runRow(db, "t").status).toBe("queued"); // untouched — the worker will claim it
    expect(summary.redriven_queued).toBe(1);
  });

  it("is idempotent — a second reconcile finds no orphans", () => {
    const db = createTestDb();
    const fx = new FakeEffects();
    const card = seedCard(db, { stage: "write_code", status: "running", worktree_path: "/wt/x" });
    seedRun(db, card.id, { id: "c", stage: "write_code", status: "running", pid: 77 });

    expect(reconcile(db, fx).failed_headless).toBe(1);
    expect(reconcile(db, fx).failed_headless).toBe(0); // already failed
  });

  it("fire-and-reconcile: a throwing kill does not corrupt the committed failed state", () => {
    const db = createTestDb();
    const fx = new FakeEffects().failOn("kill");
    const card = seedCard(db, { stage: "write_code", status: "running", worktree_path: "/wt/x" });
    seedRun(db, card.id, { id: "c", stage: "write_code", status: "running", pid: 77 });

    const summary = reconcile(db, fx);
    expect(runRow(db, "c").status).toBe("failed"); // committed regardless of the kill throw
    expect(fx.callsTo("kill")[0]?.threw).toBe(true);
    expect(summary.failed_headless).toBe(1);
  });
});
