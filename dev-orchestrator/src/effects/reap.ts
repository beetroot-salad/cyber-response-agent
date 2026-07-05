// Process reaping (§6.4, §9.7.1): a pidfile per run + a pgroup kill guarded by a start-time reuse
// check. `spawnHeadless` runs the child under `setsid`, so its pgid == pid and killing `-pid` reaps
// the whole tree; NEVER a bare kill(pid) — a pid can be reused after a reboot, so the pidfile
// carries the process start-time and we refuse to kill a pid whose start-time no longer matches.

import { mkdirSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { Config, RunRow } from "../contract";

interface Pidfile {
  pid: number;
  started_at: string | null; // /proc start-time (jiffies) — the reuse guard; null when unreadable
}

export function pidfilePath(runRoot: string, runId: string): string {
  return join(runRoot, "run", `${runId}.pid`);
}

/** Read a process's kernel start-time (field 22 of /proc/<pid>/stat) — stable per live process,
 *  so a reused pid gets a different value. Returns null off Linux / when the process is gone. */
export function procStartTime(pid: number): string | null {
  try {
    const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
    // The comm field (field 2) is parenthesized and may contain spaces — split after the last ')'.
    const rest = stat.slice(stat.lastIndexOf(")") + 2).split(" ");
    return rest[19] ?? null; // field 22 overall = index 19 after the (pid, comm) pair
  } catch {
    return null;
  }
}

export function writePidfile(runRoot: string, runId: string, pid: number): void {
  mkdirSync(join(runRoot, "run"), { recursive: true });
  const pf: Pidfile = { pid, started_at: procStartTime(pid) };
  writeFileSync(pidfilePath(runRoot, runId), JSON.stringify(pf));
}

export function makeReap(cfg: Config) {
  return function kill(run: RunRow): void {
    const pf = pidfilePath(cfg.runRoot, run.id);
    let recorded: Pidfile | null = null;
    try {
      recorded = JSON.parse(readFileSync(pf, "utf8")) as Pidfile;
    } catch {
      recorded = null;
    }
    const pid = recorded?.pid ?? run.pid;
    if (pid == null) return; // nothing of ours to reap
    // Reuse guard: if we recorded a start-time and the live process no longer matches, it's a
    // DIFFERENT process on a recycled pid — leave it alone.
    if (recorded?.started_at != null && procStartTime(pid) !== recorded.started_at) {
      cleanup(pf);
      return;
    }
    try {
      process.kill(-pid, "SIGTERM"); // -pid = the whole process group (setsid leader)
    } catch {
      /* already gone */
    }
    cleanup(pf);
  };
}

function cleanup(pf: string): void {
  try {
    unlinkSync(pf);
  } catch {
    /* already gone */
  }
}
