// claimNext (post-migration, §9.4): a PURE CAS. It moves the oldest queued run + its card to
// `running` and returns { run, card } — it creates NO worktree and spawns NOTHING. The whole
// effect arc (createWorktree → spawnHeadless → recordPid → await → dispatch) moved to
// `executeRun` (see worker.test.ts), so the sync engine can stay lock-free during the run.
import { describe, expect, it } from "bun:test";
import { claimNext } from "../src/engine";
import { createTestDb } from "./support/db";
import { seedCard, seedRun } from "./support/arrange";
import { getCard, getRun } from "./support/read";
import { FakeEffects } from "./support/effects";
import { expectClaim } from "./support/assert";

describe("claimNext — pure CAS", () => {
  it("moves the oldest queued run + card to running and returns { run, card }", () => {
    const db = createTestDb();
    const fx = new FakeEffects();
    const card = seedCard(db, { stage: "write_tests", status: "queued", worktree_path: null });
    const run = seedRun(db, card.id, { stage: "write_tests", attempt: 1, status: "queued" });

    const claimed = expectClaim(claimNext(db, fx));
    expect(claimed.run.id).toBe(run.id);
    expect(claimed.run.status).toBe("running");
    expect(claimed.card.id).toBe(card.id);
    expect(claimed.card.status).toBe("running");
    expect(getRun(db, run.id)?.status).toBe("running");
    expect(getCard(db, card.id)?.status).toBe("running");
  });

  it("fires NO effects — no createWorktree, no spawnHeadless (the loop owns those)", () => {
    const db = createTestDb();
    const fx = new FakeEffects();
    const card = seedCard(db, { stage: "write_tests", status: "queued", worktree_path: null });
    seedRun(db, card.id, { stage: "write_tests", attempt: 1, status: "queued" });

    claimNext(db, fx);
    expect(fx.countOf("createWorktree")).toBe(0);
    expect(fx.countOf("spawnHeadless")).toBe(0);
    expect(fx.calls).toHaveLength(0); // the CAS touches no effect seam at all
    expect(getCard(db, card.id)?.worktree_path).toBeNull(); // claimNext never sets a path
  });

  it("returns null when nothing is queued", () => {
    const db = createTestDb();
    const fx = new FakeEffects();
    seedCard(db, { stage: "write_tests", status: "awaiting_human" }); // resting, no queued run
    expect(claimNext(db, fx)).toBeNull();
  });

  it("claims the OLDEST queued run first (FIFO — created_at is the PRIMARY key, rowid the tiebreak)", () => {
    const db = createTestDb();
    const fx = new FakeEffects();
    const a = seedCard(db, { issue_number: 1, stage: "write_tests", status: "queued" });
    const b = seedCard(db, { issue_number: 2, stage: "write_tests", status: "queued" });
    // Make created_at and rowid DISAGREE: the newer run is inserted FIRST (lower rowid). A correct
    // `ORDER BY created_at, rowid` claims the earlier-created run despite its higher rowid; a LIFO
    // regression (`created_at DESC`) — or one that drops created_at and orders by rowid alone —
    // would claim r-newer instead and fail here.
    seedRun(db, a.id, { id: "r-newer", stage: "write_tests", status: "queued", created_at: "2026-01-01T00:00:05.000Z" });
    const older = seedRun(db, b.id, { id: "r-older", stage: "write_tests", status: "queued", created_at: "2026-01-01T00:00:01.000Z" });

    expect(expectClaim(claimNext(db, fx)).run.id).toBe(older.id); // earliest created_at wins
  });

  it("never claims a running discuss run — discuss is never 'queued' (spawnSession'd interactively)", () => {
    const db = createTestDb();
    const fx = new FakeEffects();
    const card = seedCard(db, { stage: "discuss", status: "running" });
    seedRun(db, card.id, { id: "d", stage: "discuss", status: "running" });
    expect(claimNext(db, fx)).toBeNull(); // nothing queued to claim
  });

  it("does not re-claim a run it already moved to running (a second claim of a drained queue → null)", () => {
    const db = createTestDb();
    const fx = new FakeEffects();
    const card = seedCard(db, { stage: "write_code", status: "queued" });
    seedRun(db, card.id, { stage: "write_code", attempt: 1, status: "queued" });

    expectClaim(claimNext(db, fx)); // claims it
    expect(claimNext(db, fx)).toBeNull(); // now running, not re-claimable
  });
});
