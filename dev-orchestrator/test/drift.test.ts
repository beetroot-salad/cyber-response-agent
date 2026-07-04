// Drift (pr_merged / pr_closed): the poller reconciles a PR resolved outside the pipeline.
// Guarded by "this card, pr_number set, any non-done state" — so re-observing is a no-op.
import { describe, expect, it } from "vitest";
import { applyEvent } from "../src/engine";
import { createTestDb } from "./support/db";
import { seedCard, seedRun } from "./support/arrange";
import { getCard, latestRun } from "./support/read";
import { FakeEffects } from "./support/effects";
import { ev } from "./support/events";
import { expectOk, expectStale } from "./support/assert";

describe("pr_merged (hand-merge → done)", () => {
  it("cancels any in-flight run, moves to done from any non-done state, and tears down the worktree", () => {
    const db = createTestDb();
    const fx = new FakeEffects();
    const card = seedCard(db, { stage: "review", status: "running", pr_number: 42, worktree_path: "/wt/x" });
    const run = seedRun(db, card.id, { id: "r", stage: "review", status: "running", pid: 88 });

    const now = expectOk(applyEvent(db, fx, card.id, ev.prMerged()));
    expect([now.stage, now.status]).toEqual(["done", "idle"]);
    expect(now.pr_number).toBe(42);
    expect(latestRun(db, card.id)?.status).toBe("cancelled");
    expect(latestRun(db, card.id)?.id).toBe(run.id);
    expect(fx.countOf("kill")).toBe(1);
    expect(fx.countOf("removeWorktree")).toBe(1); // done teardown (§6.6)
  });

  it("reaches done from a non-running state too (drift CAS is on any non-done)", () => {
    const db = createTestDb();
    const fx = new FakeEffects();
    const card = seedCard(db, { stage: "write_code", status: "failed", pr_number: 7 });

    const now = expectOk(applyEvent(db, fx, card.id, ev.prMerged()));
    expect([now.stage, now.status]).toEqual(["done", "idle"]);
  });

  it("re-observing pr_merged on an already-done card is a stale no-op", () => {
    const db = createTestDb();
    const fx = new FakeEffects();
    const card = seedCard(db, { stage: "done", status: "idle", pr_number: 42 });

    expectStale(applyEvent(db, fx, card.id, ev.prMerged()));
    expect(getCard(db, card.id)?.stage).toBe("done");
  });

  it("pr_merged on a card with no PR is a stale no-op (nothing to reconcile against)", () => {
    const db = createTestDb();
    const fx = new FakeEffects();
    const card = seedCard(db, { stage: "review", status: "awaiting_human", pr_number: null });

    expectStale(applyEvent(db, fx, card.id, ev.prMerged()));
    expect([getCard(db, card.id)?.stage, getCard(db, card.id)?.status]).toEqual(["review", "awaiting_human"]);
  });
});

describe("pr_closed (unmerged → failed)", () => {
  it("cancels any in-flight run, drives the card to failed, and KEEPS the PR linked + worktree", () => {
    const db = createTestDb();
    const fx = new FakeEffects();
    const card = seedCard(db, { stage: "review", status: "running", pr_number: 42, worktree_path: "/wt/x" });
    seedRun(db, card.id, { id: "r", stage: "review", status: "running", pid: 88 });

    const now = expectOk(applyEvent(db, fx, card.id, ev.prClosed()));
    expect([now.stage, now.status]).toEqual(["review", "failed"]);
    expect(now.pr_number).toBe(42); // kept for reopen / rework / archive
    expect(now.worktree_path).toBe("/wt/x");
    expect(latestRun(db, card.id)?.status).toBe("cancelled");
    expect(fx.countOf("removeWorktree")).toBe(0); // failed keeps the tree
  });

  it("pr_closed on a card with no PR is a stale no-op", () => {
    const db = createTestDb();
    const fx = new FakeEffects();
    const card = seedCard(db, { stage: "write_code", status: "running", pr_number: null });
    seedRun(db, card.id, { id: "c", stage: "write_code", status: "running" });

    expectStale(applyEvent(db, fx, card.id, ev.prClosed()));
    expect(getCard(db, card.id)?.status).toBe("running");
  });
});
