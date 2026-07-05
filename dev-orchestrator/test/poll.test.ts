// pollOnce (§9.4, src/poll.ts) — one poll pass: gh.issueList → intake each; then, for every
// existing card carrying a pr_number in a live (non-done) state, gh.prStatus → pr_merged /
// pr_closed drift. Returns { intook, merged, closed } counting only APPLIED transitions.
// Intake and drift are independent halves: a list-endpoint blip must not suppress drift.
//
// NOTE: `../src/poll` is the not-yet-written target — this file is RED (import fails) until the
// implement phase lands it. The assertions below are the spec it must satisfy.
import { describe, expect, it } from "bun:test";
import { pollOnce } from "../src/poll";
import { createTestDb } from "./support/db";
import { seedCard } from "./support/arrange";
import { getCard, listBoard } from "./support/read";
import { FakeEffects } from "./support/effects";

describe("pollOnce — intake", () => {
  it("empty issue list → {0,0,0}, nothing created", async () => {
    const db = createTestDb();
    const fx = new FakeEffects().setIssues([]);
    const summary = await pollOnce(db, fx, { label: "flow" });
    expect(summary).toEqual({ intook: 0, merged: 0, closed: 0 });
    expect(listBoard(db)).toHaveLength(0);
  });

  it("a new issue is intaken to a backlog/idle card (intook:1)", async () => {
    const db = createTestDb();
    const fx = new FakeEffects().setIssues([{ repo: "o/r", issue_number: 7, title: "a feature" }]);
    const summary = await pollOnce(db, fx, { label: "flow" });
    expect(summary.intook).toBe(1);
    const card = listBoard(db)[0]!;
    expect([card.repo, card.issue_number, card.stage, card.status]).toEqual(["o/r", 7, "backlog", "idle"]);
  });

  it("re-polling the SAME issue is idempotent (intook:0 the second pass)", async () => {
    const db = createTestDb();
    const fx = new FakeEffects().setIssues([{ repo: "o/r", issue_number: 7, title: "a feature" }]);
    expect((await pollOnce(db, fx, { label: "flow" })).intook).toBe(1);
    expect((await pollOnce(db, fx, { label: "flow" })).intook).toBe(0); // ON CONFLICT DO NOTHING
    expect(listBoard(db)).toHaveLength(1);
  });

  it("a malformed issue mid-batch is skipped; the rest of the batch still intakes (SB-H)", async () => {
    const db = createTestDb();
    const fx = new FakeEffects().setIssues([
      { repo: "o/r", issue_number: 1, title: "good" },
      { repo: "o/r", issue_number: 0, title: "bad — non-positive" },
      { repo: "o/r", issue_number: 2, title: "good" },
    ]);
    const summary = await pollOnce(db, fx, { label: "flow" });
    expect(summary.intook).toBe(2); // the InvalidEventError for #0 is swallowed per-item
    expect(listBoard(db).map((c) => c.issue_number).sort()).toEqual([1, 2]);
    // rejected: abort the whole pass on one malformed row (one bad issue must not blind the poller)
  });
});

describe("pollOnce — drift", () => {
  function withOpenPr(db: ReturnType<typeof createTestDb>, pr_number: number) {
    return seedCard(db, { stage: "review", status: "awaiting_human", pr_number, worktree_path: "/wt/x" });
  }

  it("a merged PR drives the card to done and removes its worktree (merged:1)", async () => {
    const db = createTestDb();
    const fx = new FakeEffects().setIssues([]).setPrState(50, "merged");
    const card = withOpenPr(db, 50);
    const summary = await pollOnce(db, fx, {});
    expect(summary.merged).toBe(1);
    expect([getCard(db, card.id)?.stage, getCard(db, card.id)?.status]).toEqual(["done", "idle"]);
    expect(getCard(db, card.id)?.worktree_path).toBeNull();
    expect(fx.countOf("removeWorktree")).toBe(1);
  });

  it("a closed-unmerged PR drives the card to failed, KEEPING the PR + tree (closed:1)", async () => {
    const db = createTestDb();
    const fx = new FakeEffects().setIssues([]).setPrState(51, "closed");
    const card = withOpenPr(db, 51);
    const summary = await pollOnce(db, fx, {});
    expect(summary.closed).toBe(1);
    expect(getCard(db, card.id)?.status).toBe("failed");
    expect(getCard(db, card.id)?.pr_number).toBe(51); // kept
    expect(getCard(db, card.id)?.worktree_path).toBe("/wt/x"); // kept
  });

  it("an open PR causes no drift and no count", async () => {
    const db = createTestDb();
    const fx = new FakeEffects().setIssues([]).setPrState(52, "open");
    const card = withOpenPr(db, 52);
    const summary = await pollOnce(db, fx, {});
    expect(summary).toEqual({ intook: 0, merged: 0, closed: 0 });
    expect([getCard(db, card.id)?.stage, getCard(db, card.id)?.status]).toEqual(["review", "awaiting_human"]);
  });

  it("re-polling a still-closed PR is idempotent — the card stays failed, closed NOT re-counted", async () => {
    const db = createTestDb();
    const fx = new FakeEffects().setIssues([]).setPrState(53, "closed");
    withOpenPr(db, 53);
    expect((await pollOnce(db, fx, {})).closed).toBe(1);
    expect((await pollOnce(db, fx, {})).closed).toBe(0); // pr_closed guard: status != 'failed' → stale
  });

  it("only cards with a pr_number in a non-done state are checked (no prStatus for a bare backlog card)", async () => {
    const db = createTestDb();
    const fx = new FakeEffects().setIssues([]);
    seedCard(db, { stage: "backlog", status: "idle", pr_number: null }); // no PR → not eligible
    seedCard(db, { stage: "done", status: "idle", pr_number: 60 }); // done → not eligible
    await pollOnce(db, fx, {});
    expect(fx.countOf("gh.prStatus")).toBe(0);
  });

  it("a card intaken THIS pass (fresh, no pr_number) is skipped by the drift scan", async () => {
    const db = createTestDb();
    const fx = new FakeEffects().setIssues([{ repo: "o/r", issue_number: 8, title: "fresh" }]);
    const summary = await pollOnce(db, fx, { label: "flow" });
    expect(summary.intook).toBe(1);
    expect(fx.countOf("gh.prStatus")).toBe(0); // the new backlog card has no PR to drift on
  });
});

describe("pollOnce — robustness (independent halves)", () => {
  it("gh.issueList throwing is swallowed, and drift STILL runs over existing cards (SB-I)", async () => {
    const db = createTestDb();
    const fx = new FakeEffects().failOn("gh.issueList").setPrState(70, "merged");
    const card = seedCard(db, { stage: "review", status: "awaiting_human", pr_number: 70, worktree_path: "/wt/x" });
    const summary = await pollOnce(db, fx, { label: "flow" });
    expect(summary.intook).toBe(0); // list threw
    expect(summary.merged).toBe(1); // but drift is a separate half
    expect(getCard(db, card.id)?.stage).toBe("done");
  });

  it("a gh.prStatus throw is swallowed — the pass resolves and the un-checked card is left intact", async () => {
    const db = createTestDb();
    const fx = new FakeEffects().setIssues([]).failOn("gh.prStatus");
    const card = seedCard(db, { stage: "review", status: "awaiting_human", pr_number: 80, worktree_path: "/wt/x" });
    const summary = await pollOnce(db, fx, {}); // must not reject
    expect(summary).toEqual({ intook: 0, merged: 0, closed: 0 });
    expect([getCard(db, card.id)?.stage, getCard(db, card.id)?.status]).toEqual(["review", "awaiting_human"]);
    // The stronger claim — "one card's prStatus throw doesn't skip the OTHERS' drift" — needs a
    // per-call fault seam (failOn is a permanent set), so it is deferred with recordPid's it.todo.
  });
});
