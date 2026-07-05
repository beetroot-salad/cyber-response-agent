// reconcile (§6.4.4): startup crash recovery over runs left 'running'. Headless runs are
// failed (and their orphans killed) but stay resumable; a running discuss run is exempt
// (the board never parented it); queued runs are left claimable.
import { describe, expect, it } from "bun:test";
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

// The slice-2 addition: after crash-recovery, sweep the filesystem for worktrees no live card
// claims — reaping what a swallowed post-commit teardown left behind (§9.4, finding #2). An
// "orphan" = a listWorktrees() path that equals NO non-archived card's worktree_path (matched
// by path VALUE, never by parsing issue-<n>). swept counts only removals that actually fired.
function sweptPaths(fx: FakeEffects): string[] {
  return fx.callsTo("removeWorktreePath").map((c) => (c.args as { worktree_path: string }).worktree_path);
}

describe("reconcile — worktree sweep", () => {
  it("removes an orphan tree that no live card claims, and keeps the one that a live card holds", () => {
    const db = createTestDb();
    const fx = new FakeEffects().setWorktrees(["/wt/issue-1", "/wt/issue-99"]);
    seedCard(db, { issue_number: 1, stage: "write_code", status: "running", worktree_path: "/wt/issue-1" });

    const summary = reconcile(db, fx);
    expect(sweptPaths(fx)).toEqual(["/wt/issue-99"]); // the unclaimed one only
    expect(summary.swept).toBe(1);
    expect(fx.countOf("removeWorktree")).toBe(0); // the sweep reaps by PATH, never via the card-driven seam
  });

  it("reaps a leftover tree whose card already cleared its worktree_path (cancel/done aftermath)", () => {
    const db = createTestDb();
    const fx = new FakeEffects().setWorktrees(["/wt/issue-5"]);
    // the card cancelled/finished and nulled its path, but the tree lingered on disk
    seedCard(db, { issue_number: 5, stage: "write_tests", status: "idle", worktree_path: null });

    const summary = reconcile(db, fx);
    expect(sweptPaths(fx)).toEqual(["/wt/issue-5"]);
    expect(summary.swept).toBe(1);
  });

  it("empty listWorktrees → swept:0, no removeWorktreePath", () => {
    const db = createTestDb();
    const fx = new FakeEffects().setWorktrees([]);
    seedCard(db, { stage: "write_code", status: "running", worktree_path: "/wt/issue-1" });
    expect(reconcile(db, fx).swept).toBe(0);
    expect(fx.countOf("removeWorktreePath")).toBe(0);
  });

  it("a throwing removeWorktreePath does not abort the sweep; swept counts only removals that fired", () => {
    const db = createTestDb();
    const fx = new FakeEffects().setWorktrees(["/wt/issue-90", "/wt/issue-91"]).failOn("removeWorktreePath");
    const summary = reconcile(db, fx);
    expect(fx.countOf("removeWorktreePath")).toBe(2); // both orphans still attempted
    expect(summary.swept).toBe(0); // neither fired
  });

  it("listWorktrees throwing → swept:0, but crash-recovery still ran", () => {
    const db = createTestDb();
    const fx = new FakeEffects().failOn("listWorktrees");
    const card = seedCard(db, { stage: "write_code", status: "running", worktree_path: "/wt/x" });
    seedRun(db, card.id, { id: "c", stage: "write_code", status: "running", pid: 77 });

    const summary = reconcile(db, fx);
    expect(summary.swept).toBe(0);
    expect(summary.failed_headless).toBe(1); // recovery is independent of the sweep
    expect(runRow(db, "c").status).toBe("failed");
  });

  it("a just-failed headless run KEEPS its tree — recovery runs before the sweep, run_failed keeps the path", () => {
    const db = createTestDb();
    const fx = new FakeEffects().setWorktrees(["/wt/issue-9"]);
    const card = seedCard(db, { issue_number: 9, stage: "write_code", status: "running", worktree_path: "/wt/issue-9" });
    seedRun(db, card.id, { id: "c", stage: "write_code", status: "running", pid: 77 });

    const summary = reconcile(db, fx);
    expect(summary.failed_headless).toBe(1);
    expect(getCard(db, card.id)?.worktree_path).toBe("/wt/issue-9"); // failure keeps it
    expect(sweptPaths(fx)).toEqual([]); // …so the sweep still sees a live claim and spares it
    expect(summary.swept).toBe(0);
  });
});
