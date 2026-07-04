// cancel (T-CANCEL) is a discard: it removes the worktree, unlike a fail/goto-cancel-first
// which keep it. archive drops the card off the board and tears the tree down.
import { describe, expect, it } from "vitest";
import { applyEvent } from "../src/engine";
import { createTestDb } from "./support/db";
import { seedCard, seedRun } from "./support/arrange";
import { getCard, latestRun, listBoard } from "./support/read";
import { FakeEffects } from "./support/effects";
import { ev } from "./support/events";
import { expectOk, expectStale } from "./support/assert";

describe("cancel", () => {
  it("discards the in-flight run and REMOVES the worktree, resting the card at idle", () => {
    const db = createTestDb();
    const fx = new FakeEffects();
    const card = seedCard(db, { stage: "write_code", status: "running", worktree_path: "/wt/x" });
    seedRun(db, card.id, { id: "c", stage: "write_code", status: "running", pid: 90 });

    const now = expectOk(applyEvent(db, fx, card.id, ev.cancel(card)));
    expect([now.stage, now.status]).toEqual(["write_code", "idle"]);
    expect(latestRun(db, card.id)?.status).toBe("cancelled");
    expect(fx.countOf("kill")).toBe(1);
    expect(fx.countOf("removeWorktree")).toBe(1); // the discard — contrast fail/retry
    expect(getCard(db, card.id)?.worktree_path).toBeNull();
  });

  it("cancel with nothing in-flight is a stale no-op", () => {
    const db = createTestDb();
    const fx = new FakeEffects();
    const card = seedCard(db, { stage: "write_code", status: "idle" });
    expectStale(applyEvent(db, fx, card.id, ev.cancel(card)));
    expect(fx.calls).toHaveLength(0);
  });
});

describe("archive", () => {
  it("cancels any in-flight run, tears down the worktree, and drops off the board (getCard still returns it)", () => {
    const db = createTestDb();
    const fx = new FakeEffects();
    const card = seedCard(db, { stage: "write_code", status: "running", worktree_path: "/wt/x" });
    seedRun(db, card.id, { id: "c", stage: "write_code", status: "running", pid: 90 });

    expectOk(applyEvent(db, fx, card.id, ev.archive(card)));
    expect(latestRun(db, card.id)?.status).toBe("cancelled");
    expect(fx.countOf("kill")).toBe(1);
    expect(fx.countOf("removeWorktree")).toBe(1);
    expect(getCard(db, card.id)?.archived_at).not.toBeNull();
    expect(listBoard(db)).toHaveLength(0); // off the board
    expect(getCard(db, card.id)).toBeDefined(); // but still retrievable
  });

  it("re-archiving an already-archived card is a stale no-op", () => {
    const db = createTestDb();
    const fx = new FakeEffects();
    const card = seedCard(db, { stage: "review", status: "idle", archived_at: "2026-01-01T00:00:05.000Z" });
    expectStale(applyEvent(db, fx, card.id, ev.archive(card)));
  });

  it("an ordinary event on an archived card is a stale no-op (archived cards are off the machine)", () => {
    const db = createTestDb();
    const fx = new FakeEffects();
    const card = seedCard(db, { stage: "write_code", status: "idle", archived_at: "2026-01-01T00:00:05.000Z" });
    expectStale(applyEvent(db, fx, card.id, ev.goto(card, "review")));
    expect(getCard(db, card.id)?.stage).toBe("write_code");
  });
});
