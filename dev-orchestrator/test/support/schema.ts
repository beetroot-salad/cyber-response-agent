// The §5 SQLite schema, verbatim, as the test DB's DDL. Kept in test-support (not a
// production migration) so the deliverable stays a tests-only diff; the implement phase
// promotes this to a real migration.

export const SCHEMA_SQL = `
CREATE TABLE card (
  id             TEXT PRIMARY KEY,
  repo           TEXT NOT NULL,
  issue_number   INTEGER NOT NULL,
  pr_number      INTEGER,
  stage          TEXT NOT NULL
                   CHECK (stage IN ('backlog','discuss','write_tests','write_code','review','done')),
  status         TEXT NOT NULL DEFAULT 'idle'
                   CHECK (status IN ('idle','queued','running','awaiting_human','failed')),
  title          TEXT,
  worktree_path  TEXT,
  created_at     TEXT NOT NULL,
  updated_at     TEXT NOT NULL,
  state_entered_at TEXT NOT NULL,
  archived_at    TEXT,
  UNIQUE (repo, issue_number)
);

CREATE TABLE run (
  id           TEXT PRIMARY KEY,
  card_id      TEXT NOT NULL REFERENCES card(id) ON DELETE CASCADE,
  stage        TEXT NOT NULL
                 CHECK (stage IN ('discuss','write_tests','write_code','review')),
  attempt      INTEGER NOT NULL DEFAULT 1,
  status       TEXT NOT NULL DEFAULT 'queued'
                 CHECK (status IN ('queued','running','succeeded','failed','cancelled')),
  trigger      TEXT NOT NULL
                 CHECK (trigger IN ('manual','auto','retry')),
  session_id   TEXT,
  pid          INTEGER,
  cost_usd     REAL,
  created_at   TEXT NOT NULL,
  started_at   TEXT,
  finished_at  TEXT
);
CREATE INDEX run_queue   ON run (status, created_at);
CREATE INDEX run_by_card ON run (card_id, created_at);
CREATE UNIQUE INDEX one_active_run_per_card
  ON run (card_id) WHERE status IN ('queued','running');
CREATE UNIQUE INDEX one_run_per_attempt ON run (card_id, stage, attempt);
`;
