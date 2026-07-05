// claimNext (T-CLAIM): the worker pulls the oldest queued run to running, lazily creating
// the worktree and requesting the headless spawn. Effect failures are fire-and-reconcile.
import { describe, expect, it } from "bun:test";
import { claimNext } from "../src/engine";
import { createTestDb } from "./support/db";
import { seedCard, seedRun } from "./support/arrange";
import { getCard, latestRun } from "./support/read";
import { FakeEffects } from "./support/effects";
import { expectOk } from "./support/assert";

describe("claimNext", () => {
  it("claims a queued run to running, lazily creates the worktree, and requests the spawn", () => {
    const db = createTestDb();
    const fx = new FakeEffects();
    const card = seedCard(db, { stage: "write_tests", status: "queued", worktree_path: null });
    const run = seedRun(db, card.id, { stage: "write_tests", attempt: 1, status: "queued" });

    const now = expectOk(claimNext(db, fx));
    expect(now.id).toBe(card.id);
    expect(now.status).toBe("running");
    expect(latestRun(db, card.id)?.status).toBe("running");
    expect(latestRun(db, card.id)?.id).toBe(run.id);

    expect(fx.countOf("createWorktree")).toBe(1);
    expect(getCard(db, card.id)?.worktree_path).toBe("/wt/card"); // written back
    expect(fx.countOf("spawnHeadless")).toBe(1);
  });

  it("reuses an existing worktree across the shared branch (no second createWorktree)", () => {
    const db = createTestDb();
    const fx = new FakeEffects();
    const card = seedCard(db, { stage: "write_code", status: "queued", worktree_path: "/wt/existing" });
    seedRun(db, card.id, { stage: "write_code", attempt: 1, status: "queued" });

    expectOk(claimNext(db, fx));
    expect(fx.countOf("createWorktree")).toBe(0); // already have the shared tree
    expect(fx.countOf("spawnHeadless")).toBe(1);
    expect(getCard(db, card.id)?.worktree_path).toBe("/wt/existing");
  });

  it("returns null when nothing is queued", () => {
    const db = createTestDb();
    const fx = new FakeEffects();
    seedCard(db, { stage: "write_tests", status: "awaiting_human" }); // resting, no queued run
    expect(claimNext(db, fx)).toBeNull();
  });

  it("fire-and-reconcile: a throwing spawnHeadless leaves committed state intact and still returns ok", () => {
    const db = createTestDb();
    const fx = new FakeEffects().failOn("spawnHeadless");
    const card = seedCard(db, { stage: "write_code", status: "queued", worktree_path: null });
    seedRun(db, card.id, { stage: "write_code", attempt: 1, status: "queued" });

    const now = expectOk(claimNext(db, fx)); // commit is truth — the throw doesn't change the result
    expect(now.status).toBe("running");
    expect(latestRun(db, card.id)?.status).toBe("running"); // committed, to be caught by reconcile
    expect(fx.callsTo("spawnHeadless")[0]?.threw).toBe(true);
  });

  it("fire-and-reconcile: a throwing createWorktree leaves the run running with no path, spawn not reached", () => {
    const db = createTestDb();
    const fx = new FakeEffects().failOn("createWorktree");
    const card = seedCard(db, { stage: "write_tests", status: "queued", worktree_path: null });
    seedRun(db, card.id, { stage: "write_tests", attempt: 1, status: "queued" });

    const now = expectOk(claimNext(db, fx));
    expect(now.status).toBe("running");
    expect(getCard(db, card.id)?.worktree_path).toBeNull(); // path never captured
    expect(fx.callsTo("createWorktree")[0]?.threw).toBe(true);
    expect(fx.countOf("spawnHeadless")).toBe(0); // threw before the spawn
  });
});
