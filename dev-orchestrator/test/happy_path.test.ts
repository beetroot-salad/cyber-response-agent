// End-to-end: the pipeline drives itself through the automated hops, stopping only at the
// two human gates. Pins the shared-worktree-once invariant and the spawn accounting.
import { describe, expect, it } from "bun:test";
import { applyEvent, claimNext, intake } from "../src/engine";
import { createTestDb } from "./support/db";
import { getCard, latestRun } from "./support/read";
import { FakeEffects } from "./support/effects";
import { ev } from "./support/events";
import { expectOk } from "./support/assert";

describe("happy path — intake to done", () => {
  it("walks backlog → discuss → write_tests → (gate) → write_code → review → (gate) → done", () => {
    const db = createTestDb();
    const fx = new FakeEffects();

    const created = expectOk(intake(db, fx, { repo: "o/r", issue_number: 1, title: "a feature" }));
    const id = created.id;
    const card = () => getCard(db, id)!;

    // discuss (interactive, straight to running) → Done — proceed auto-chains write_tests
    expectOk(applyEvent(db, fx, id, ev.goto(card(), "discuss")));
    expectOk(applyEvent(db, fx, id, ev.runSucceeded(latestRun(db, id)!.id)));
    expect([card().stage, card().status]).toEqual(["write_tests", "queued"]);

    // write_tests runs, then rests at the approve-tests gate
    expectOk(claimNext(db, fx)); // creates the shared worktree
    expectOk(applyEvent(db, fx, id, ev.runSucceeded(latestRun(db, id)!.id)));
    expect([card().stage, card().status]).toEqual(["write_tests", "awaiting_human"]);

    // approve-tests → write_code auto-chains review on success, carrying the PR
    expectOk(applyEvent(db, fx, id, ev.goto(card(), "write_code")));
    expectOk(claimNext(db, fx)); // reuses the worktree
    expectOk(applyEvent(db, fx, id, ev.runSucceeded(latestRun(db, id)!.id, { pr_number: 99 })));
    expect([card().stage, card().status]).toEqual(["review", "queued"]);
    expect(card().pr_number).toBe(99);

    // review runs, then rests at the merge gate
    expectOk(claimNext(db, fx)); // reuses the worktree
    expectOk(applyEvent(db, fx, id, ev.runSucceeded(latestRun(db, id)!.id)));
    expect([card().stage, card().status]).toEqual(["review", "awaiting_human"]);

    // approve-merge → done (terminal)
    const done = expectOk(applyEvent(db, fx, id, ev.goto(card(), "done")));
    expect([done.stage, done.status]).toEqual(["done", "idle"]);

    // one worktree shared across write_tests→write_code→review; discuss made none
    expect(fx.countOf("createWorktree")).toBe(1);
    expect(fx.countOf("removeWorktree")).toBe(1); // torn down at done
    expect(fx.countOf("spawnSession")).toBe(1); // discuss only
    expect(fx.countOf("spawnHeadless")).toBe(3); // write_tests, write_code, review
  });
});
