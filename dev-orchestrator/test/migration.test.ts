// Spec: openDb — the on-disk migration (§9.8). Promotes the test-support SCHEMA_SQL to a real
// `bun:sqlite` open: WAL + foreign_keys pragmas, and a `user_version`-gated migration that is
// idempotent (a second open of an existing db is a no-op that keeps the data). This is the one 2b
// unit test that touches the real filesystem — openDb is deterministic local-fs, not a subprocess.

import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openDb } from "../src/db";

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "flowdeck-mig-"));
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe("openDb — fresh directory", () => {
  it("creates the §5 schema (a card round-trips)", () => {
    const db = openDb(dir);
    db.prepare(
      `INSERT INTO card (id, repo, issue_number, stage, status, created_at, updated_at, state_entered_at)
       VALUES ('c1','owner/repo',1,'backlog','idle','t','t','t')`,
    ).run();
    expect((db.prepare("SELECT id FROM card").get() as { id: string }).id).toBe("c1");
    db.close();
  });

  it("sets WAL + foreign_keys + stamps user_version", () => {
    const db = openDb(dir);
    expect((db.prepare("PRAGMA journal_mode").get() as { journal_mode: string }).journal_mode).toBe("wal");
    expect((db.prepare("PRAGMA foreign_keys").get() as { foreign_keys: number }).foreign_keys).toBe(1);
    expect((db.prepare("PRAGMA user_version").get() as { user_version: number }).user_version).toBeGreaterThan(0);
    db.close();
  });
});

describe("openDb — re-open is idempotent", () => {
  it("keeps existing data and does not re-run the migration (no duplicate-table throw)", () => {
    const first = openDb(dir);
    first.prepare(
      `INSERT INTO card (id, repo, issue_number, stage, status, created_at, updated_at, state_entered_at)
       VALUES ('keep','owner/repo',1,'backlog','idle','t','t','t')`,
    ).run();
    first.close();

    const second = openDb(dir); // must NOT throw "table card already exists"
    expect((second.prepare("SELECT id FROM card").get() as { id: string }).id).toBe("keep");
    second.close();
  });
});
