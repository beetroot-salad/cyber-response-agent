// openDb — the on-disk bun:sqlite migration (§9.8). Opens (creating if absent)
// `<runRoot>/orchestrator.db`, sets WAL + foreign_keys, and applies the §5 schema exactly once
// under a `user_version` gate so a re-open of an existing db keeps its data and never re-runs the
// DDL. `strict: true` binds named params by bare key (`@id` ← { id }), matching the engine.

import { Database } from "bun:sqlite";
import { mkdirSync } from "node:fs";
import { join } from "node:path";
import type { DB } from "./contract";
import { SCHEMA_SQL } from "./schema";

const SCHEMA_VERSION = 1;

export function openDb(runRoot: string): DB {
  mkdirSync(runRoot, { recursive: true });
  const db = new Database(join(runRoot, "orchestrator.db"), { strict: true, create: true });
  db.exec("PRAGMA journal_mode = WAL");
  db.exec("PRAGMA foreign_keys = ON");
  const { user_version } = db.prepare("PRAGMA user_version").get() as { user_version: number };
  if (user_version < SCHEMA_VERSION) {
    db.exec(SCHEMA_SQL);
    db.exec(`PRAGMA user_version = ${SCHEMA_VERSION}`);
  }
  return db;
}
