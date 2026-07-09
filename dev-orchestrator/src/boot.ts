// boot (§9.8) — wire the process. The order is a HARD invariant: reconcile (crash-recovery +
// worktree sweep) runs ONCE, before the worker/poll loops or the server, so no loop claims against
// un-recovered `running` rows. Every collaborator is injected (BootDeps) so the ordering is a unit
// seam; main.ts supplies the real ones via realBootDeps().

import type { BootDeps, BootHandle, Config, PollHealth } from "./contract";
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
  // Board-visible poll health (§9.4) — mutated in place each pass; makeApp reads this same object so
  // getBoard reports the latest without re-plumbing. `ran:false` keeps a fresh boot neutral (not "failed").
  const health: PollHealth = { ran: false, errors: 0, at: null, okAt: null };
  // await the poll (non-overlap guard, §9.8); log the summary each pass so a healthy-but-empty poll is
  // observable — a silent no-op otherwise looks identical to a dead loop. `every` wants Promise<void>.
  const poll = deps.every(cfg.pollMs, async () => {
    const s = await deps.pollOnce(db, fx, { label: cfg.label });
    health.ran = true;
    health.at = fx.now();
    health.errors = s.errors;
    if (s.errors === 0) health.okAt = health.at;
    console.log(`poll: intook=${s.intook} merged=${s.merged} closed=${s.closed} errors=${s.errors}`);
  }); // 3.
  const server = deps.serve({ port: cfg.port, fetch: deps.makeApp(db, fx, cfg, health).fetch }); // 4.
  return { db, worker, poll, server };
}
