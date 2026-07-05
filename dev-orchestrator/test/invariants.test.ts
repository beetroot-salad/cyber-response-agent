// Cross-cutting invariants: attempt scoping, atomicity, the clock, and the malformed-event
// contract.
import { describe, expect, it } from "bun:test";
import { applyEvent } from "../src/engine";
import { InvalidEventError } from "../src/contract";
import { createTestDb } from "./support/db";
import { seedCard, seedRun } from "./support/arrange";
import { getCard, getRuns, latestRun } from "./support/read";
import { FakeEffects } from "./support/effects";
import { ev } from "./support/events";
import { expectOk, expectStale } from "./support/assert";

describe("attempt scoping", () => {
  it("attempt is monotonic per (card, stage): a third write_code run is attempt 3, never reset", () => {
    const db = createTestDb();
    const fx = new FakeEffects();
    const card = seedCard(db, { stage: "write_code", status: "failed", worktree_path: "/wt/x" });
    seedRun(db, card.id, { id: "a1", stage: "write_code", attempt: 1, status: "failed" });
    seedRun(db, card.id, { id: "a2", stage: "write_code", attempt: 2, status: "failed" });

    expectOk(applyEvent(db, fx, card.id, ev.goto(card, "write_code")));
    expect(latestRun(db, card.id)?.attempt).toBe(3);
  });

  it("attempt is per-stage, not a global card counter: the first write_code run is attempt 1 even after two write_tests attempts", () => {
    const db = createTestDb();
    const fx = new FakeEffects();
    const card = seedCard(db, { stage: "write_tests", status: "awaiting_human" });
    seedRun(db, card.id, { id: "t1", stage: "write_tests", attempt: 1, status: "succeeded" });
    seedRun(db, card.id, { id: "t2", stage: "write_tests", attempt: 2, status: "succeeded" });

    expectOk(applyEvent(db, fx, card.id, ev.goto(card, "write_code")));
    const wc = latestRun(db, card.id)!;
    expect(wc.stage).toBe("write_code");
    expect(wc.attempt).toBe(1); // NOT 3
  });
});

describe("atomicity of enqueue", () => {
  it("a stale goto inserts NO run — the run insert and card update commit together or not at all", () => {
    const db = createTestDb();
    const fx = new FakeEffects();
    const card = seedCard(db, { stage: "discuss", status: "idle" });

    // caller believes (backlog, idle) but the card is (discuss, idle) → CAS matches 0 rows
    expectStale(applyEvent(db, fx, card.id, ev.goto({ stage: "backlog", status: "idle" }, "write_tests")));
    expect(getRuns(db, card.id)).toHaveLength(0); // no orphan run
    expect(fx.calls).toHaveLength(0);
    expect([getCard(db, card.id)?.stage, getCard(db, card.id)?.status]).toEqual(["discuss", "idle"]);
  });

  it("at most one in-flight run per card holds through a normal enqueue", () => {
    const db = createTestDb();
    const fx = new FakeEffects();
    const card = seedCard(db, { stage: "backlog", status: "idle" });

    expectOk(applyEvent(db, fx, card.id, ev.goto(card, "write_code")));
    const active = getRuns(db, card.id).filter((r) => r.status === "queued" || r.status === "running");
    expect(active).toHaveLength(1);
  });

  // AlreadyInFlightError is the backstop for a genuine concurrent double-enqueue. The state
  // that triggers it (two in-flight runs mid-insert) is un-representable in a single
  // connection — the one_active_run_per_card index prevents the precondition from ever
  // existing — so the engine's translation of the raw index violation is a concurrency-only
  // path, verified with a two-writer harness in a later slice, not here.
  it.todo("throws AlreadyInFlightError when a concurrent insert races a second in-flight run", () => {
    // Deferred to a two-writer harness (see comment above); un-representable on one connection.
  });
});

describe("clock and malformed events", () => {
  it("state_entered_at advances to fx.now() on each transition", () => {
    const db = createTestDb();
    const fx = new FakeEffects();
    const card = seedCard(db, { stage: "backlog", status: "idle", state_entered_at: "2026-01-01T00:00:00.000Z" });

    fx.tick(); // wall clock advances between events
    expectOk(applyEvent(db, fx, card.id, ev.goto(card, "discuss")));
    expect(getCard(db, card.id)?.state_entered_at).toBe("2026-01-01T00:00:01.000Z");
  });

  it("throws InvalidEventError on an unknown event type", () => {
    const db = createTestDb();
    const fx = new FakeEffects();
    const card = seedCard(db, { stage: "backlog", status: "idle" });
    expect(() =>
      applyEvent(db, fx, card.id, { type: "nonsense", expected_stage: "backlog", expected_status: "idle" } as never),
    ).toThrow(InvalidEventError);
  });

  it("applyEvent on a nonexistent card is a stale no-op", () => {
    const db = createTestDb();
    const fx = new FakeEffects();
    expectStale(applyEvent(db, fx, "ghost", ev.goto({ stage: "backlog", status: "idle" }, "discuss")));
  });
});
