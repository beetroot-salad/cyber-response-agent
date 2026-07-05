// Spec: the /rpc router (§9.1, §9.2). The only wire in the system; its whole job is decode → call
// the engine → shape the reply. Driven end-to-end via `app.fetch(Request)` against a REAL in-memory
// DB + the slice-1 FakeEffects — no socket. The response table (§9.2) is the contract: a stale CAS
// is a 200 no-op (never a 4xx), a malformed event is 400, the can't-happen breach is 409.

import { beforeEach, describe, expect, it } from "bun:test";
import type { App, DB } from "../src/contract";
import { makeApp } from "../src/server";
import { fakeConfig } from "./support/config";
import { seedCard, seedRun } from "./support/arrange";
import { createTestDb } from "./support/db";
import { FakeEffects } from "./support/effects";
import { getCard, latestRun, listBoard } from "./support/read";

let db: DB;
let fx: FakeEffects;
let app: App;
beforeEach(() => {
  db = createTestDb();
  fx = new FakeEffects();
  app = makeApp(db, fx, fakeConfig());
});

async function rpc(op: string, args?: unknown): Promise<{ status: number; body: any }> {
  const res = await app.fetch(
    new Request("http://localhost/rpc", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ op, args }),
    }),
  );
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : null };
}

describe("queries", () => {
  it("getBoard → 200, the read model for every non-archived card", async () => {
    seedCard(db, { id: "c1", stage: "backlog" });
    const { status, body } = await rpc("getBoard");
    expect(status).toBe(200);
    expect(body.map((c: { id: string }) => c.id)).toEqual(["c1"]);
  });

  it("getCard → 200 { card, runs }", async () => {
    const c = seedCard(db, { id: "c1", stage: "review" });
    seedRun(db, c.id, { id: "r1", stage: "write_code", status: "succeeded" });
    const { status, body } = await rpc("getCard", { cardId: "c1" });
    expect(status).toBe(200);
    expect(body.card.id).toBe("c1");
    expect(body.runs.map((r: { id: string }) => r.id)).toEqual(["r1"]);
  });

  it("getCard unknown id → 404 (a genuine miss)", async () => {
    const { status } = await rpc("getCard", { cardId: "nope" });
    expect(status).toBe(404);
  });
});

describe("dispatchEvent — the whole write surface", () => {
  it("approve-tests: a forward goto out of the gate → 200, enqueues write_code", async () => {
    const c = seedCard(db, { id: "c1", stage: "write_tests", status: "awaiting_human" });
    const { status, body } = await rpc("dispatchEvent", {
      cardId: "c1",
      event: { type: "goto", target: "write_code", expected_stage: "write_tests", expected_status: "awaiting_human" },
    });
    expect(status).toBe(200);
    expect(body).toEqual({ ok: true, card: expect.objectContaining({ stage: "write_code", status: "queued" }) });
    expect(latestRun(db, c.id)).toMatchObject({ stage: "write_code", status: "queued" });
  });

  it("a stale CAS (wrong expected state) → 200 { ok:false, reason:'stale' } — a no-op, NOT a 4xx", async () => {
    seedCard(db, { id: "c1", stage: "write_tests", status: "awaiting_human" });
    const { status, body } = await rpc("dispatchEvent", {
      cardId: "c1",
      event: { type: "goto", target: "write_code", expected_stage: "backlog", expected_status: "idle" },
    });
    expect(status).toBe(200);
    expect(body).toEqual({ ok: false, reason: "stale" });
    expect(getCard(db, "c1")).toMatchObject({ stage: "write_tests", status: "awaiting_human" }); // unchanged
  });

  it("cancel: discards the in-flight run + tree → 200, card rests idle", async () => {
    const c = seedCard(db, { id: "c1", stage: "write_code", status: "running", worktree_path: "/run/wt/owner__repo/issue-1" });
    seedRun(db, c.id, { stage: "write_code", status: "running", pid: 4242 });
    const { status, body } = await rpc("dispatchEvent", {
      cardId: "c1",
      event: { type: "cancel", expected_stage: "write_code", expected_status: "running" },
    });
    expect(status).toBe(200);
    expect(body.ok).toBe(true);
    expect(getCard(db, "c1")).toMatchObject({ status: "idle", worktree_path: null });
  });

  it("archive: drops the card off the board → 200, gone from getBoard", async () => {
    seedCard(db, { id: "c1", stage: "backlog", status: "idle" });
    const { status } = await rpc("dispatchEvent", {
      cardId: "c1",
      event: { type: "archive", expected_stage: "backlog", expected_status: "idle" },
    });
    expect(status).toBe(200);
    expect(listBoard(db)).toHaveLength(0);
  });

  it("a malformed event (unknown target) → 400", async () => {
    seedCard(db, { id: "c1", stage: "backlog", status: "idle" });
    const { status } = await rpc("dispatchEvent", {
      cardId: "c1",
      event: { type: "goto", target: "nowhere", expected_stage: "backlog", expected_status: "idle" },
    });
    expect(status).toBe(400);
  });

  it.todo("maps AlreadyInFlightError → 409 (defensive; needs a forced double-enqueue seam)", () => {});
});

describe("createIssue — gh issue create, then intake the result", () => {
  it("creates the issue and lands it as a backlog card → 200 { ok:true, card }", async () => {
    const { status, body } = await rpc("createIssue", { repo: "owner/repo", title: "new work", body: "why" });
    expect(status).toBe(200);
    expect(body.ok).toBe(true);
    expect(body.card).toMatchObject({ repo: "owner/repo", stage: "backlog", status: "idle", title: "new work" });
    expect(fx.countOf("gh.issueCreate")).toBe(1);
    // The fake stamps an incrementing issue number; the card carries it.
    expect(getCard(db, body.card.id)?.issue_number).toBe(body.card.issue_number);
  });
});

describe("router faults", () => {
  it("an unknown op → 400", async () => {
    expect((await rpc("frobnicate")).status).toBe(400);
  });

  it("an unparseable body → 400", async () => {
    const res = await app.fetch(
      new Request("http://localhost/rpc", { method: "POST", headers: { "content-type": "application/json" }, body: "{not json" }),
    );
    expect(res.status).toBe(400);
  });
});
