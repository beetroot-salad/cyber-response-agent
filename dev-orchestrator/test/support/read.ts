import type { CardState, DB, RunRow } from "../../src/contract";

/** Read a card's authoritative current state. */
export function getCard(db: DB, id: string): CardState | undefined {
  return db.prepare("SELECT * FROM card WHERE id = ?").get(id) as CardState | undefined;
}

/** All of a card's runs, oldest first — the append-only timeline. Tie-break on `rowid`
 *  (SQLite's insertion order) not the string `id`: under the fake clock many runs share a
 *  `created_at`, and a lexical `id` sort ("id-N" vs "seed-run-N") would reorder them. */
export function getRuns(db: DB, cardId: string): RunRow[] {
  return db
    .prepare("SELECT * FROM run WHERE card_id = ? ORDER BY created_at, rowid")
    .all(cardId) as RunRow[];
}

/** A card's newest run (or undefined). */
export function latestRun(db: DB, cardId: string): RunRow | undefined {
  const runs = getRuns(db, cardId);
  return runs[runs.length - 1];
}

/** One run by id — for asserting the worker's writes (status / pid / session_id). */
export function getRun(db: DB, id: string): RunRow | undefined {
  return db.prepare("SELECT * FROM run WHERE id = ?").get(id) as RunRow | undefined;
}

/** The board read model: non-archived cards only (§9.3). */
export function listBoard(db: DB): CardState[] {
  return db.prepare("SELECT * FROM card WHERE archived_at IS NULL").all() as CardState[];
}
