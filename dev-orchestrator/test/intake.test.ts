import { describe, expect, it } from "bun:test";
import { intake } from "../src/engine";
import { InvalidEventError } from "../src/contract";
import { createTestDb } from "./support/db";
import { FakeEffects } from "./support/effects";
import { listBoard } from "./support/read";
import { expectOk, expectStale } from "./support/assert";

describe("intake (T-INTAKE)", () => {
  it("creates a backlog/idle card from an issue ref", () => {
    const db = createTestDb();
    const fx = new FakeEffects();
    const card = expectOk(intake(db, fx, { repo: "o/r", issue_number: 7, title: "Fix bug" }));
    expect(card.stage).toBe("backlog");
    expect(card.status).toBe("idle");
    expect(card.repo).toBe("o/r");
    expect(card.issue_number).toBe(7);
    expect(card.title).toBe("Fix bug");
    expect(listBoard(db)).toHaveLength(1);
  });

  it("is idempotent on (repo, issue_number): re-intake is a stale no-op, first write wins", () => {
    const db = createTestDb();
    const fx = new FakeEffects();
    intake(db, fx, { repo: "o/r", issue_number: 7, title: "original" });
    expectStale(intake(db, fx, { repo: "o/r", issue_number: 7, title: "edited" }));
    const rows = db.prepare("SELECT * FROM card").all() as { title: string }[];
    expect(rows).toHaveLength(1);
    expect(rows[0]?.title).toBe("original");
  });

  it("trusts sparse content: an empty title is stored, not rejected", () => {
    const db = createTestDb();
    const fx = new FakeEffects();
    const card = expectOk(intake(db, fx, { repo: "o/r", issue_number: 7, title: "" }));
    expect(card.title).toBe("");
  });

  it("throws InvalidEventError on a non-positive issue_number (a can't-happen-from-gh bug)", () => {
    const db = createTestDb();
    const fx = new FakeEffects();
    expect(() => intake(db, fx, { repo: "o/r", issue_number: 0, title: "x" })).toThrow(InvalidEventError);
    expect(() => intake(db, fx, { repo: "o/r", issue_number: -3, title: "x" })).toThrow(InvalidEventError);
  });

  it("creates no worktree, run, or process — intake is pure state", () => {
    const db = createTestDb();
    const fx = new FakeEffects();
    intake(db, fx, { repo: "o/r", issue_number: 7, title: "t" });
    expect(fx.calls).toHaveLength(0);
    expect(db.prepare("SELECT count(*) AS n FROM run").get()).toEqual({ n: 0 });
  });
});
