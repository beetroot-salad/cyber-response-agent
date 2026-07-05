// End-to-end: the pipeline drives itself through the automated hops, stopping only at the two
// human gates. Now interleaves claimNext (pure CAS) + executeRun (the run arc) — the two halves
// the "loop owns the await" split created. Pins the shared-worktree-once invariant and the
// spawn accounting across the full walk. RED until src/worker.ts (executeRun) lands.
import { describe, expect, it } from "bun:test";
import { applyEvent, claimNext, intake } from "../src/engine";
import { executeRun } from "../src/worker";
import { createTestDb } from "./support/db";
import { getCard, latestRun } from "./support/read";
import { FakeEffects } from "./support/effects";
import { ev } from "./support/events";
import { expectClaim, expectOk } from "./support/assert";

/** Claim the next queued run and execute its arc to a successful completion. */
async function runNext(
  db: ReturnType<typeof createTestDb>,
  fx: FakeEffects,
  extra: { pr_number?: number; session_id?: string } = {},
): Promise<void> {
  const { run, card } = expectClaim(claimNext(db, fx));
  const p = executeRun(db, fx, run, card);
  fx.succeedRun(run.id, extra);
  await p;
}

describe("happy path — intake to done", () => {
  it("walks backlog → discuss → write_tests → (gate) → write_code → review → (gate) → done", async () => {
    const db = createTestDb();
    const fx = new FakeEffects();

    const created = expectOk(intake(db, fx, { repo: "o/r", issue_number: 1, title: "a feature" }));
    const id = created.id;
    const card = () => getCard(db, id)!;

    // discuss is interactive: goto → running via spawnSession; "Done — proceed" (an applyEvent,
    // NOT executeRun — the board never parented it) auto-chains write_tests.
    expectOk(applyEvent(db, fx, id, ev.goto(card(), "discuss")));
    expectOk(applyEvent(db, fx, id, ev.runSucceeded(latestRun(db, id)!.id)));
    expect([card().stage, card().status]).toEqual(["write_tests", "queued"]);

    // write_tests runs (creates the shared worktree), then rests at the approve-tests gate
    await runNext(db, fx);
    expect([card().stage, card().status]).toEqual(["write_tests", "awaiting_human"]);

    // approve-tests → write_code auto-chains review on success, carrying the PR (worktree reused)
    expectOk(applyEvent(db, fx, id, ev.goto(card(), "write_code")));
    await runNext(db, fx, { pr_number: 99 });
    expect([card().stage, card().status]).toEqual(["review", "queued"]);
    expect(card().pr_number).toBe(99);

    // review runs (worktree reused), then rests at the merge gate
    await runNext(db, fx);
    expect([card().stage, card().status]).toEqual(["review", "awaiting_human"]);

    // approve-merge → done (terminal), tearing down the tree
    const done = expectOk(applyEvent(db, fx, id, ev.goto(card(), "done")));
    expect([done.stage, done.status]).toEqual(["done", "idle"]);

    // one worktree shared across write_tests→write_code→review; discuss made none
    expect(fx.countOf("createWorktree")).toBe(1);
    expect(fx.countOf("removeWorktree")).toBe(1); // torn down at done
    expect(fx.countOf("spawnSession")).toBe(1); // discuss only
    expect(fx.countOf("spawnHeadless")).toBe(3); // write_tests, write_code, review
  });
});
