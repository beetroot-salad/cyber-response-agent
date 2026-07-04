import type { CardState, DB, RunRow } from "../../src/contract";

/** Read a card's authoritative current state. */
export function getCard(db: DB, id: string): CardState | undefined {
  return db.prepare("SELECT * FROM card WHERE id = ?").get(id) as CardState | undefined;
}

/** All of a card's runs, oldest first — the append-only timeline. */
export function getRuns(db: DB, cardId: string): RunRow[] {
  return db
    .prepare("SELECT * FROM run WHERE card_id = ? ORDER BY created_at, id")
    .all(cardId) as RunRow[];
}

/** A card's newest run (or undefined). */
export function latestRun(db: DB, cardId: string): RunRow | undefined {
  const runs = getRuns(db, cardId);
  return runs[runs.length - 1];
}

/** The board read model: non-archived cards only (§9.3). */
export function listBoard(db: DB): CardState[] {
  return db.prepare("SELECT * FROM card WHERE archived_at IS NULL").all() as CardState[];
}
