// Arrange helpers: seed cards/runs DIRECTLY via SQL (never via the engine), so a test can
// start from any state without replaying the whole pipeline. Act via the engine; assert via
// read helpers. Arrangement independence keeps the suite a spec, not a mirror of the engine.

import type {
  CardState,
  DB,
  RunRow,
  RunStage,
  RunStatus,
  Stage,
  Status,
  Trigger,
} from "../../src/contract";
import { getCard } from "./read";

const T0 = "2026-01-01T00:00:00.000Z";
let seq = 0;

export interface SeedCard {
  id?: string;
  repo?: string;
  issue_number?: number;
  pr_number?: number | null;
  stage?: Stage;
  status?: Status;
  title?: string | null;
  worktree_path?: string | null;
  archived_at?: string | null;
  state_entered_at?: string;
}

export function seedCard(db: DB, opts: SeedCard = {}): CardState {
  seq += 1;
  const id = opts.id ?? `seed-card-${seq}`;
  db.prepare(
    `INSERT INTO card (id, repo, issue_number, pr_number, stage, status, title,
                       worktree_path, created_at, updated_at, state_entered_at, archived_at)
     VALUES (@id, @repo, @issue_number, @pr_number, @stage, @status, @title,
             @worktree_path, @created_at, @updated_at, @state_entered_at, @archived_at)`,
  ).run({
    id,
    repo: opts.repo ?? "owner/repo",
    issue_number: opts.issue_number ?? seq,
    pr_number: opts.pr_number ?? null,
    stage: opts.stage ?? "backlog",
    status: opts.status ?? "idle",
    title: opts.title ?? "a title",
    worktree_path: opts.worktree_path ?? null,
    created_at: T0,
    updated_at: T0,
    state_entered_at: opts.state_entered_at ?? T0,
    archived_at: opts.archived_at ?? null,
  });
  return getCard(db, id) as CardState;
}

export interface SeedRun {
  id?: string;
  stage?: RunStage;
  attempt?: number;
  status?: RunStatus;
  trigger?: Trigger;
  session_id?: string | null;
  pid?: number | null;
  cost_usd?: number | null;
  started_at?: string | null;
  finished_at?: string | null;
}

export function seedRun(db: DB, cardId: string, opts: SeedRun = {}): RunRow {
  seq += 1;
  const id = opts.id ?? `seed-run-${seq}`;
  db.prepare(
    `INSERT INTO run (id, card_id, stage, attempt, status, trigger, session_id, pid,
                      cost_usd, created_at, started_at, finished_at)
     VALUES (@id, @card_id, @stage, @attempt, @status, @trigger, @session_id, @pid,
             @cost_usd, @created_at, @started_at, @finished_at)`,
  ).run({
    id,
    card_id: cardId,
    stage: opts.stage ?? "write_tests",
    attempt: opts.attempt ?? 1,
    status: opts.status ?? "queued",
    trigger: opts.trigger ?? "manual",
    session_id: opts.session_id ?? null,
    pid: opts.pid ?? null,
    cost_usd: opts.cost_usd ?? null,
    created_at: T0,
    started_at: opts.started_at ?? null,
    finished_at: opts.finished_at ?? null,
  });
  return db.prepare("SELECT * FROM run WHERE id = ?").get(id) as RunRow;
}
