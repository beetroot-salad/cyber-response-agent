import { Database } from "bun:sqlite";
import type { DB } from "../../src/contract";
import { SCHEMA_SQL } from "./schema";

/** A fresh in-memory DB with the §5 schema. WAL is a no-op on :memory:, but foreign
 *  keys must be enabled explicitly (the ON DELETE CASCADE from run→card relies on it). */
export function createTestDb(): DB {
  // `strict: true` binds named params by bare key (`@id` ← { id }), matching the
  // engine's better-sqlite3-style call sites; positional `?` binding is unaffected.
  const db = new Database(":memory:", { strict: true });
  db.exec("PRAGMA foreign_keys = ON");
  db.exec(SCHEMA_SQL);
  return db;
}
