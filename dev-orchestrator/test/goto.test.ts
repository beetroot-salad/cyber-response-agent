// `goto` is the whole soft board — one primitive reading as advance / skip / approve /
// retry / start-discuss / move by (from, target). These pin the polymorphism.
import { describe, expect, it } from "vitest";
import { applyEvent, claimNext } from "../src/engine";
import { InvalidEventError } from "../src/contract";
import { createTestDb } from "./support/db";
import { seedCard, seedRun } from "./support/arrange";
import { getCard, getRuns, latestRun } from "./support/read";
import { FakeEffects } from "./support/effects";
import { ev } from "./support/events";
import { expectOk } from "./support/assert";

describe("goto polymorphism", () => {
  it("start-discuss: goto(discuss) spawns straight to running via spawnSession, bypassing the worker queue", () => {
    const db = createTestDb();
    const fx = new FakeEffects();
    const card = seedCard(db, { stage: "backlog", status: "idle" });

    const now = expectOk(applyEvent(db, fx, card.id, ev.goto(card, "discuss")));
    expect(now.stage).toBe("discuss");
    expect(now.status).toBe("running");

    const run = latestRun(db, card.id)!;
    expect(run.stage).toBe("discuss");
    expect(run.status).toBe("running");
    expect(run.attempt).toBe(1);
    expect(run.trigger).toBe("manual");

    expect(fx.countOf("spawnSession")).toBe(1);
    expect(fx.countOf("spawnHeadless")).toBe(0);
    expect(fx.countOf("createWorktree")).toBe(0); // discuss needs no worktree
    expect(claimNext(db, fx)).toBeNull(); // nothing was ever queued
  });

  it("approve-tests: forward goto out of write_tests/awaiting_human enqueues write_code with trigger=auto", () => {
    const db = createTestDb();
    const fx = new FakeEffects();
    const card = seedCard(db, { stage: "write_tests", status: "awaiting_human" });
    seedRun(db, card.id, { stage: "write_tests", attempt: 1, status: "succeeded" });

    const now = expectOk(applyEvent(db, fx, card.id, ev.goto(card, "write_code")));
    expect([now.stage, now.status]).toEqual(["write_code", "queued"]);

    const run = latestRun(db, card.id)!;
    expect(run.stage).toBe("write_code");
    expect(run.attempt).toBe(1); // per-stage counter, first write_code attempt
    expect(run.status).toBe("queued");
    expect(run.trigger).toBe("auto"); // gate release, NOT manual

    // spawn + worktree happen at claim, not enqueue
    expect(fx.countOf("createWorktree")).toBe(0);
    expect(fx.countOf("spawnHeadless")).toBe(0);
  });

  it("approve-merge: goto(done) from review/awaiting_human is terminal — no run, worktree torn down", () => {
    const db = createTestDb();
    const fx = new FakeEffects();
    const card = seedCard(db, {
      stage: "review",
      status: "awaiting_human",
      pr_number: 42,
      worktree_path: "/wt/x",
    });
    seedRun(db, card.id, { stage: "review", attempt: 1, status: "succeeded" });
    const runsBefore = getRuns(db, card.id).length;

    const now = expectOk(applyEvent(db, fx, card.id, ev.goto(card, "done")));
    expect([now.stage, now.status]).toEqual(["done", "idle"]);
    expect(getRuns(db, card.id)).toHaveLength(runsBefore); // no new run enqueued
    expect(fx.countOf("removeWorktree")).toBe(1); // teardown on done (§6.6)
  });

  it("skip: goto(write_code) from backlog enqueues one run and drops the approve-tests gate (no write_tests run)", () => {
    const db = createTestDb();
    const fx = new FakeEffects();
    const card = seedCard(db, { stage: "backlog", status: "idle" });

    const now = expectOk(applyEvent(db, fx, card.id, ev.goto(card, "write_code")));
    expect([now.stage, now.status]).toEqual(["write_code", "queued"]);

    const runs = getRuns(db, card.id);
    expect(runs).toHaveLength(1);
    expect(runs[0]?.stage).toBe("write_code");
    expect(runs[0]?.trigger).toBe("manual"); // human named the target
    expect(runs.filter((r) => r.stage === "write_tests")).toHaveLength(0);
  });

  it("retry: goto(current) from */failed bumps attempt, trigger=retry, and KEEPS the worktree", () => {
    const db = createTestDb();
    const fx = new FakeEffects();
    const card = seedCard(db, { stage: "write_code", status: "failed", worktree_path: "/wt/x" });
    seedRun(db, card.id, { stage: "write_code", attempt: 1, status: "failed" });

    const now = expectOk(applyEvent(db, fx, card.id, ev.goto(card, "write_code")));
    expect([now.stage, now.status]).toEqual(["write_code", "queued"]);

    const run = latestRun(db, card.id)!;
    expect(run.attempt).toBe(2);
    expect(run.trigger).toBe("retry");
    expect(getCard(db, card.id)?.worktree_path).toBe("/wt/x"); // reused, not recreated
    expect(fx.countOf("createWorktree")).toBe(0);
    expect(fx.countOf("removeWorktree")).toBe(0);
  });

  it("same-stage re-goto from a gate (not failed) is a manual re-run, not a retry", () => {
    const db = createTestDb();
    const fx = new FakeEffects();
    const card = seedCard(db, { stage: "review", status: "awaiting_human" });
    seedRun(db, card.id, { stage: "review", attempt: 1, status: "succeeded" });

    expectOk(applyEvent(db, fx, card.id, ev.goto(card, "review")));
    const run = latestRun(db, card.id)!;
    expect(run.attempt).toBe(2);
    expect(run.trigger).toBe("manual"); // retry is specifically goto(current) from */failed
  });

  it("park: goto(target, park) rests idle at a run-bearing stage with no run and no worktree", () => {
    const db = createTestDb();
    const fx = new FakeEffects();
    const card = seedCard(db, { stage: "backlog", status: "idle" });

    const now = expectOk(applyEvent(db, fx, card.id, ev.goto(card, "review", true)));
    expect([now.stage, now.status]).toEqual(["review", "idle"]);
    expect(getRuns(db, card.id)).toHaveLength(0);
    expect(fx.countOf("createWorktree")).toBe(0);
    expect(fx.countOf("spawnHeadless")).toBe(0);
  });

  it("backward goto cancels the in-flight run first (keeping the tree) and enqueues without AlreadyInFlightError", () => {
    const db = createTestDb();
    const fx = new FakeEffects();
    const card = seedCard(db, {
      stage: "review",
      status: "running",
      pr_number: 42,
      worktree_path: "/wt/x",
    });
    seedRun(db, card.id, { id: "wt", stage: "write_tests", attempt: 1, status: "succeeded" });
    const inflight = seedRun(db, card.id, { id: "rev", stage: "review", attempt: 1, status: "running", pid: 555 });

    const now = expectOk(applyEvent(db, fx, card.id, ev.goto(card, "write_tests")));
    expect([now.stage, now.status]).toEqual(["write_tests", "queued"]);

    // old run cancelled in-txn (so the unique index never trips), proc reaped, tree KEPT
    expect(getRuns(db, card.id).find((r) => r.id === inflight.id)?.status).toBe("cancelled");
    expect(fx.countOf("kill")).toBe(1);
    expect(fx.countOf("removeWorktree")).toBe(0);
    expect(getCard(db, card.id)?.worktree_path).toBe("/wt/x");

    const fresh = latestRun(db, card.id)!;
    expect(fresh.stage).toBe("write_tests");
    expect(fresh.attempt).toBe(2); // re-entry of a stage that already had attempt 1
    expect(fresh.trigger).toBe("manual");
  });

  it("throws InvalidEventError on an unknown target stage", () => {
    const db = createTestDb();
    const fx = new FakeEffects();
    const card = seedCard(db, { stage: "backlog", status: "idle" });
    expect(() =>
      applyEvent(db, fx, card.id, {
        type: "goto",
        target: "frobnicate" as never,
        expected_stage: "backlog",
        expected_status: "idle",
      }),
    ).toThrow(InvalidEventError);
  });
});
