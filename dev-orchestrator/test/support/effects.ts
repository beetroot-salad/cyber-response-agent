import type { CardState, Effects, IssueRef, PrState, RunResult, RunRow } from "../../src/contract";

export interface RecordedCall {
  seam: string;
  args: unknown;
  threw: boolean;
}

interface Deferred {
  promise: Promise<RunResult>;
  resolve: (r: RunResult) => void;
  reject: (e: unknown) => void;
}

/** A recording, fault-injecting `Effects` stub. Faults are DATA (`failOn`), never bespoke
 *  per-test mocks; the fake injects failures only — it never decides policy. `now()` is a
 *  stable clock advanced explicitly by `tick()`; `uuid()` is monotonic.
 *
 *  Slice-2 additions: `spawnHeadless` returns `{ pid, done }` where `done` is a Promise the
 *  test resolves/rejects DETERMINISTICALLY via `succeedRun` / `failRun` / `rejectRun` — so an
 *  async run has no wall-clock timing. `inFlight()` exposes spawned-but-unsettled runs for the
 *  pool-cap assertion. `listWorktrees` / `gh.issueList` / `gh.prStatus` are data-configured. */
export class FakeEffects implements Effects {
  readonly calls: RecordedCall[] = [];
  private readonly failing = new Set<string>();
  private worktreePath: string | null = null;
  private clockSec = 0;
  private uuidN = 0;
  private ghIssueN = 1000;
  private nextPid = 5000;

  // spawnHeadless completion control: runId → its unsettled `done` deferred.
  private readonly pending = new Map<string, Deferred>();
  private readonly spawnOrder: string[] = [];

  // Poll-loop data sources (configured per test).
  private worktrees: string[] = [];
  private issues: IssueRef[] = [];
  private readonly prStates = new Map<number, PrState>();

  /** Inject a fault: the named seam(s) throw when next invoked (still recorded). */
  failOn(...seams: string[]): this {
    for (const s of seams) this.failing.add(s);
    return this;
  }

  /** Override createWorktree's return with a fixed path (default is a per-card deterministic path). */
  setWorktreePath(p: string): this {
    this.worktreePath = p;
    return this;
  }

  /** What `listWorktrees()` will report on disk (the reconcile sweep's input). */
  setWorktrees(paths: string[]): this {
    this.worktrees = [...paths];
    return this;
  }

  /** What `gh.issueList()` will return (the poll intake source). */
  setIssues(issues: IssueRef[]): this {
    this.issues = [...issues];
    return this;
  }

  /** What `gh.prStatus()` will return for a given pr_number (default "open"). */
  setPrState(pr_number: number, state: PrState): this {
    this.prStates.set(pr_number, state);
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

  // --- spawnHeadless completion control -------------------------------------

  /** Run ids spawned but not yet settled — i.e. currently in flight (for the pool cap). */
  inFlight(): string[] {
    return [...this.pending.keys()];
  }

  /** Every run id ever spawned, in spawn order (for "drains all K"). */
  spawned(): string[] {
    return [...this.spawnOrder];
  }

  /** Resolve a run's `done` as a success. */
  succeedRun(runId: string, extra: { session_id?: string; pr_number?: number } = {}): this {
    return this.settle(runId, { ok: true, ...extra });
  }

  /** Resolve a run's `done` as a clean failure (`{ ok: false }`). */
  failRun(runId: string, extra: { session_id?: string; pr_number?: number } = {}): this {
    return this.settle(runId, { ok: false, ...extra });
  }

  /** Reject a run's `done` (the subprocess crashed / the promise threw). */
  rejectRun(runId: string, err: unknown = new Error("run process crashed")): this {
    this.take(runId).reject(err);
    return this;
  }

  private settle(runId: string, result: RunResult): this {
    this.take(runId).resolve(result);
    return this;
  }

  private take(runId: string): Deferred {
    const d = this.pending.get(runId);
    if (!d) throw new Error(`no in-flight run '${runId}' to settle`);
    this.pending.delete(runId);
    return d;
  }

  private record(seam: string, args: unknown): void {
    const threw = this.failing.has(seam);
    this.calls.push({ seam, args, threw });
    if (threw) throw new Error(`fake ${seam} failed (injected)`);
  }

  // --- Effects --------------------------------------------------------------

  createWorktree(card: CardState): string {
    this.record("createWorktree", { cardId: card.id });
    // Deterministic path = pure fn of the card (§9.7), so a retry re-derives the SAME path.
    return this.worktreePath ?? `/wt/issue-${card.issue_number}`;
  }

  removeWorktree(card: CardState): void {
    this.record("removeWorktree", { cardId: card.id, worktree_path: card.worktree_path });
  }

  listWorktrees(): string[] {
    this.record("listWorktrees", {});
    return [...this.worktrees];
  }

  spawnHeadless(run: RunRow, card: CardState, sessionId: string): { pid: number; done: Promise<RunResult> } {
    this.record("spawnHeadless", {
      runId: run.id,
      stage: run.stage,
      cardId: card.id,
      sessionId,
      worktree_path: card.worktree_path,
    });
    const pid = this.nextPid++;
    let resolve!: (r: RunResult) => void;
    let reject!: (e: unknown) => void;
    const promise = new Promise<RunResult>((res, rej) => {
      resolve = res;
      reject = rej;
    });
    this.pending.set(run.id, { promise, resolve, reject });
    this.spawnOrder.push(run.id);
    return { pid, done: promise };
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
    issueList: (input: { repo?: string; label?: string }): IssueRef[] => {
      this.record("gh.issueList", input);
      return [...this.issues];
    },
    prStatus: (input: { repo: string; pr_number: number }): PrState => {
      this.record("gh.prStatus", input);
      return this.prStates.get(input.pr_number) ?? "open";
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
