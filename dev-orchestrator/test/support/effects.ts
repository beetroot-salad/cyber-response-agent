import type { CardState, Effects, RunRow } from "../../src/contract";

export interface RecordedCall {
  seam: string;
  args: unknown;
  threw: boolean;
}

/** A recording, fault-injecting `Effects` stub. Faults are DATA (`failOn`), never bespoke
 *  per-test mocks; the fake injects failures only — it never decides policy. `now()` is a
 *  stable clock advanced explicitly by `tick()` (so all timestamps within one transition
 *  match, and successive transitions can be distinguished). `uuid()` is monotonic. */
export class FakeEffects implements Effects {
  readonly calls: RecordedCall[] = [];
  private readonly failing = new Set<string>();
  private worktreePath = "/wt/card";
  private clockSec = 0;
  private uuidN = 0;
  private ghIssueN = 1000;

  /** Inject a fault: the named seam(s) throw when next invoked (still recorded). */
  failOn(...seams: string[]): this {
    for (const s of seams) this.failing.add(s);
    return this;
  }

  setWorktreePath(p: string): this {
    this.worktreePath = p;
    return this;
  }

  /** Advance the injected wall clock between transitions. */
  tick(seconds = 1): this {
    this.clockSec += seconds;
    return this;
  }

  callsTo(seam: string): RecordedCall[] {
    return this.calls.filter((c) => c.seam === seam);
  }

  countOf(seam: string): number {
    return this.callsTo(seam).length;
  }

  private record(seam: string, args: unknown): void {
    const threw = this.failing.has(seam);
    this.calls.push({ seam, args, threw });
    if (threw) throw new Error(`fake ${seam} failed (injected)`);
  }

  createWorktree(card: CardState): string {
    this.record("createWorktree", { cardId: card.id });
    return this.worktreePath;
  }

  removeWorktree(card: CardState): void {
    this.record("removeWorktree", { cardId: card.id, worktree_path: card.worktree_path });
  }

  spawnHeadless(run: RunRow, card: CardState): void {
    this.record("spawnHeadless", { runId: run.id, stage: run.stage, cardId: card.id });
  }

  spawnSession(card: CardState, resume?: string): void {
    this.record("spawnSession", { cardId: card.id, resume: resume ?? null });
  }

  kill(run: RunRow): void {
    this.record("kill", { runId: run.id, pid: run.pid });
  }

  gh = {
    issueCreate: (input: { repo: string; title: string; body?: string }): { issue_number: number } => {
      this.record("gh.issueCreate", input);
      return { issue_number: this.ghIssueN++ };
    },
  };

  now(): string {
    const s = String(this.clockSec).padStart(2, "0");
    return `2026-01-01T00:00:${s}.000Z`;
  }

  uuid(): string {
    this.uuidN += 1;
    return `id-${this.uuidN}`;
  }
}
