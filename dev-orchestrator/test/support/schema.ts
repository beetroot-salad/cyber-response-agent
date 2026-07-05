// The §5 schema DDL, now single-sourced from the production migration (src/schema.ts). Re-exported
// here so the test harness (support/db.ts) and the real openDb (src/db.ts) can never drift.

export { SCHEMA_SQL } from "../../src/schema";
