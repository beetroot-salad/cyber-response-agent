// Spec: the boot sequence (§9.8). The order is a HARD invariant: `reconcile` (crash-recovery +
// worktree sweep) MUST run once, BEFORE the worker/poll loops or the server start — a loop that
// claimed while stale `running` rows were un-recovered would race recovery. `boot` takes every
// collaborator injected, so this pins the ordering with zero real I/O (no subprocess, no socket).

import { describe, expect, it } from "bun:test";
import type { BootDeps, Config, Effects, PollHealth, PollSummary, ReconcileSummary } from "../src/contract";
import { boot } from "../src/boot";
import { createTestDb } from "./support/db";
import { FakeEffects } from "./support/effects";
import { fakeConfig } from "./support/config";

interface Recorded {
  order: string[];
  every: { ms: number; fn: () => void | Promise<void> }[];
  serve: { port: number } | null;
  drainOpts: { pool: number } | null;
  pollOpts: { label?: string } | null;
  health: PollHealth | null;
}

function recordingDeps(poll: PollSummary = { intook: 0, merged: 0, closed: 0, errors: 0 }): { deps: BootDeps; rec: Recorded } {
  const rec: Recorded = { order: [], every: [], serve: null, drainOpts: null, pollOpts: null, health: null };
  const deps: BootDeps = {
    openDb: () => {
      rec.order.push("openDb");
      return createTestDb();
    },
    effects: () => {
      rec.order.push("effects");
      return new FakeEffects();
    },
    reconcile: (): ReconcileSummary => {
      rec.order.push("reconcile");
      return { failed_headless: 0, left_discuss: 0, redriven_queued: 0, killed: 0, swept: 0 };
    },
    drainQueue: async (_db, _fx, opts) => {
      rec.order.push("drain");
      rec.drainOpts = opts;
    },
    pollOnce: async (_db, _fx, opts): Promise<PollSummary> => {
      rec.order.push("poll");
      rec.pollOpts = opts;
      return poll;
    },
    makeApp: (_db, _fx, _cfg, health) => {
      rec.order.push("makeApp");
      rec.health = health;
      return { fetch: () => new Response("ok") };
    },
    serve: (opts) => {
      rec.order.push("serve");
      rec.serve = { port: opts.port };
      return {};
    },
    every: (ms, fn) => {
      rec.order.push("every");
      rec.every.push({ ms, fn });
      return {};
    },
  };
  return { deps, rec };
}

describe("boot ordering — reconcile before any loop or the server", () => {
  it("reconciles once, before the first drain / poll / serve", () => {
    const { deps, rec } = recordingDeps();
    boot(fakeConfig(), deps);
    // reconcile has run; the loop bodies have NOT (they only fire when a timer ticks).
    expect(rec.order).toContain("reconcile");
    expect(rec.order).not.toContain("drain");
    expect(rec.order).not.toContain("poll");
    const iRec = rec.order.indexOf("reconcile");
    expect(rec.order.indexOf("serve")).toBeGreaterThan(iRec);
    expect(iRec).toBeGreaterThan(rec.order.indexOf("openDb"));
    expect(iRec).toBeGreaterThan(rec.order.indexOf("effects"));
  });

  it("registers the worker + poll timers with their configured cadences", () => {
    const { deps, rec } = recordingDeps();
    boot(fakeConfig({ workerTickMs: 500, pollMs: 45000 }), deps);
    expect(rec.every.map((e) => e.ms).sort((a, b) => a - b)).toEqual([500, 45000]);
  });

  it("serves on the configured port", () => {
    const { deps, rec } = recordingDeps();
    boot(fakeConfig({ port: 9999 }), deps);
    expect(rec.serve?.port).toBe(9999);
  });

  it("the worker timer drains at the pool cap; the poll timer polls the tracking label", async () => {
    const { deps, rec } = recordingDeps();
    boot(fakeConfig({ pool: 3, label: "flow", workerTickMs: 500, pollMs: 45000 }), deps);
    // Fire each registered timer body once and observe what it calls.
    for (const e of rec.every) await e.fn();
    expect(rec.drainOpts).toEqual({ pool: 3 });
    expect(rec.pollOpts).toEqual({ label: "flow" });
  });

  it("the poll timer feeds health into makeApp — ran flips true and errors surface", async () => {
    const { deps, rec } = recordingDeps({ intook: 0, merged: 0, closed: 0, errors: 2 });
    boot(fakeConfig({ label: "flow" }), deps);
    expect(rec.health).toEqual({ ran: false, errors: 0, at: null, okAt: null }); // makeApp sees the neutral start
    for (const e of rec.every) await e.fn(); // fire the timers (incl. the poll)
    expect(rec.health?.ran).toBe(true);
    expect(rec.health?.errors).toBe(2); // the SAME object makeApp holds now reflects the failing poll
    expect(rec.health?.okAt).toBeNull(); // errors>0 → last-ok NOT advanced
  });
});
