// boot (§9.8) — wire the process. The order is a HARD invariant: reconcile (crash-recovery +
// worktree sweep) runs ONCE, before the worker/poll loops or the server, so no loop claims against
// un-recovered `running` rows. Every collaborator is injected (BootDeps) so the ordering is a unit
// seam; main.ts supplies the real ones via realBootDeps().

import type { BootDeps, BootHandle, Config } from "./contract";
import { openDb } from "./db";
import { realEffects } from "./effects";
import { drainQueue } from "./worker";
import { pollOnce } from "./poll";
import { reconcile } from "./engine";
import { makeApp } from "./server";

/** A self-rescheduling, non-overlapping timer: a slow tick never stacks on the next (§9.8). */
export function every(ms: number, fn: () => void | Promise<void>): { stop(): void } {
  let stopped = false;
  let timer: ReturnType<typeof setTimeout>;
  const tick = async (): Promise<void> => {
    try {
      await fn();
    } catch {
      /* a loop body's own errors are swallowed — the engine + effects are idempotent (2a) */
    }
    if (!stopped) timer = setTimeout(tick, ms);
  };
  timer = setTimeout(tick, ms);
  return {
    stop() {
      stopped = true;
      clearTimeout(timer);
    },
  };
}

export function realBootDeps(): BootDeps {
  return {
    openDb,
    effects: realEffects,
    reconcile,
    drainQueue,
    pollOnce,
    makeApp,
    serve: (opts) => Bun.serve({ port: opts.port, fetch: opts.fetch }),
    every,
  };
}

export function boot(cfg: Config, deps: BootDeps = realBootDeps()): BootHandle {
  const db = deps.openDb(cfg.runRoot);
  const fx = deps.effects(cfg);
  deps.reconcile(db, fx); // 1. BEFORE any loop or the server (§9.8)
  const worker = deps.every(cfg.workerTickMs, () => deps.drainQueue(db, fx, { pool: cfg.pool })); // 2.
  // await the poll (non-overlap guard, §9.8) but discard its summary — `every` wants Promise<void>.
  const poll = deps.every(cfg.pollMs, async () => {
    await deps.pollOnce(db, fx, { label: cfg.label });
  }); // 3.
  const server = deps.serve({ port: cfg.port, fetch: deps.makeApp(db, fx, cfg).fetch }); // 4.
  return { db, worker, poll, server };
}
