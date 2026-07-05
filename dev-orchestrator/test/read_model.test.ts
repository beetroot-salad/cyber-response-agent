// Spec: the getBoard/getCard read model (§9.3). `readBoard` is a PURE DB projection — one pass over
// non-archived cards, each joined to its NEWEST run, with `activity` always null (the live tail is a
// separate degradable overlay, §9.3). `readCard` returns the card + its full append-only timeline.

import { beforeEach, describe, expect, it } from "bun:test";
import type { BoardCard, DB, RunRow } from "../src/contract";
import { readBoard, readCard } from "../src/server";
import { seedCard, seedRun } from "./support/arrange";
import { createTestDb } from "./support/db";

let db: DB;
beforeEach(() => {
  db = createTestDb();
});

describe("readBoard — the one-paint projection", () => {
  it("projects the card columns the board renders without a live gh call", () => {
    seedCard(db, { id: "c1", repo: "owner/repo", issue_number: 42, pr_number: 438, title: "a task", stage: "review", status: "awaiting_human" });
    const [card] = readBoard(db);
    expect(card).toMatchObject({
      id: "c1",
      repo: "owner/repo",
      issue_number: 42,
      pr_number: 438,
      title: "a task",
      stage: "review",
      status: "awaiting_human",
    });
    expect(card.state_entered_at).toBeString();
  });

  it("joins each card to its NEWEST run (§ read.ts latestRun rule)", () => {
    const c = seedCard(db, { stage: "write_code", status: "running" });
    seedRun(db, c.id, { id: "old", stage: "write_tests", status: "succeeded", created_at: "2026-01-01T00:00:01.000Z" });
    seedRun(db, c.id, { id: "new", stage: "write_code", status: "running", trigger: "auto", created_at: "2026-01-01T00:00:02.000Z" });
    const [card] = readBoard(db);
    expect(card.latest_run?.id).toBe("new");
    expect(card.latest_run).toMatchObject({ stage: "write_code", status: "running", trigger: "auto" });
  });

  it("activity is null in the pure projection — the live tail is a separate overlay", () => {
    const c = seedCard(db, { stage: "write_code", status: "running" });
    seedRun(db, c.id, { stage: "write_code", status: "running", session_id: "sess-1" });
    expect(readBoard(db)[0].latest_run?.activity).toBeNull();
  });

  it("a card with no runs → latest_run null", () => {
    seedCard(db, { stage: "backlog", status: "idle" });
    expect(readBoard(db)[0].latest_run).toBeNull();
  });

  it("excludes archived cards", () => {
    seedCard(db, { id: "live", stage: "backlog" });
    seedCard(db, { id: "gone", stage: "backlog", archived_at: "2026-01-01T00:00:09.000Z" });
    expect(readBoard(db).map((c: BoardCard) => c.id)).toEqual(["live"]);
  });
});

describe("readCard — one card + its full timeline", () => {
  it("returns the card and every run, oldest first", () => {
    const c = seedCard(db, { id: "c1", stage: "review" });
    seedRun(db, c.id, { id: "r1", stage: "write_tests", status: "succeeded", created_at: "2026-01-01T00:00:01.000Z" });
    seedRun(db, c.id, { id: "r2", stage: "write_code", status: "succeeded", created_at: "2026-01-01T00:00:02.000Z" });
    const detail = readCard(db, "c1");
    expect(detail?.card.id).toBe("c1");
    expect(detail?.runs.map((r: RunRow) => r.id)).toEqual(["r1", "r2"]);
  });

  it("unknown id → null (a genuine miss, not a stale no-op)", () => {
    expect(readCard(db, "nope")).toBeNull();
  });
});
