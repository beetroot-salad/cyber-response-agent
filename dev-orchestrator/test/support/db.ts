import Database from "better-sqlite3";
import type { DB } from "../../src/contract";
import { SCHEMA_SQL } from "./schema";

/** A fresh in-memory DB with the §5 schema. WAL is a no-op on :memory:, but foreign
 *  keys must be enabled explicitly (the ON DELETE CASCADE from run→card relies on it). */
export function createTestDb(): DB {
  const db = new Database(":memory:");
  db.pragma("foreign_keys = ON");
  db.exec(SCHEMA_SQL);
  return db;
}
