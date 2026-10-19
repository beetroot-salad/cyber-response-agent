"""Session schema, vocabulary, and refusal types."""
from __future__ import annotations
import sqlite3
from defender._run_id import CASE_ID_RE  # noqa: F401 — re-export; the rule lives with the id rules
from defender._store_errors import InvalidCaseId, StoreError  # noqa: F401 — re-exports
from defender.runtime.run_end import (  # noqa: F401 — re-exports
    TRUNCATED_BY_ABORTED,
    TRUNCATED_BY_BUDGET,
    TRUNCATED_BY_DEAD_END,
    TRUNCATED_BY_EXECUTED_QUERIES,
    TRUNCATED_BY_PROVIDER_DOWN,
    TRUNCATED_BY_REQUEST_LIMIT,
    TRUNCATED_BY_RETRY_EXHAUSTED,
    TRUNCATED_BY_SERVED_LEDGER,
    TRUNCATED_BY_STORE,
    TRUNCATED_BY_TIMED_OUT,
    TRUNCATED_BY_VALUES,
    normalized_truncated_by,
)



SCHEMA_VERSION = 2


PAYLOAD_ENSURE_ASCII = True


ROLES = ("send", "analysis", "actor")


#: The closed set `append`'s `reason` is validated against (a Python constant, not a SQL
#: CHECK). `append` refuses `fork`: `fork()` writes its own entry.
HEAD_MOVE_REASONS = ("fork", "fold")



_CONFIG_REQUIRED_FIELDS = ("models", "corpus", "prompts", "versions")




class StoreAppendError(StoreError):
    """An append was refused at the store's own boundary."""




class UnknownSchemaVersion(StoreError):
    """The store's `PRAGMA user_version` is not one the reader recognizes."""




class PayloadNotRepresentable(StoreError):
    """A payload value `dump_python` would silently coerce; refused at append."""




class PayloadSchemaSkew(StoreError):
    """A stored payload carries a field the installed adapter does not recognize."""




class CyclicParentChain(StoreError):
    """The `parent_id` chain loops; the walk refuses to follow it forever."""




class IncompleteConfig(Exception):
    """A config dict is missing one of the four required reproducibility fields."""




class UnknownReadRole(StoreError):
    """`hydrate` was asked for a role outside the closed `{send, analysis, actor}` set."""




class UnresolvablePathElement(StoreError):
    """A walked path names a message id no `message` row resolves (only reachable through
    direct file damage; the foreign key blocks it on every API write)."""




class IngestTailUnderflow(StoreError):
    """A live message list is shorter than the session's last recorded render length."""




DDL = """
CREATE TABLE IF NOT EXISTS config (
    sha256 TEXT PRIMARY KEY,
    body TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS session (
    session_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    parent_session_id TEXT REFERENCES session(session_id),
    agent_id TEXT,
    head_message_id INTEGER REFERENCES message(id),
    truncated_by TEXT,
    last_render_len INTEGER
) STRICT;

CREATE TABLE IF NOT EXISTS message (
    id INTEGER PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES session(session_id),
    agent_id TEXT NOT NULL,
    parent_id INTEGER REFERENCES message(id),
    seq INTEGER NOT NULL,
    synthesized INTEGER NOT NULL DEFAULT 0,
    kind TEXT NOT NULL,
    tool_name TEXT,
    run_step INTEGER,
    duration_ms REAL,
    wire_sha TEXT,
    UNIQUE (session_id, agent_id, synthesized, seq)
) STRICT;

CREATE TABLE IF NOT EXISTS message_payload (
    message_id INTEGER PRIMARY KEY REFERENCES message(id),
    payload TEXT NOT NULL,
    payload_sha TEXT NOT NULL
) STRICT;

-- fork_snapshot — what MAIN's run held when its `request`-th model response arrived, before
-- any of that response's tool calls ran (#1255 P2): the per-run counters the model can feel and
-- the model-readable files by length, hash or content. One row per tool-calling response,
-- keyed by the session that drove it and the framework's request count (a resumed session
-- starts its count at the branch point's, so the numbering runs on along the lineage). Host
-- bookkeeping: it lives here, beside the runs base, where no box mount reaches (P3). `body`
-- is `runtime/branch/_snapshot.py`'s JSON; a document's text is kept once per digest in
-- `fork_snapshot_blob`, since it rarely changes between two responses.
CREATE TABLE IF NOT EXISTS fork_snapshot (
    session_id TEXT NOT NULL REFERENCES session(session_id),
    request INTEGER NOT NULL,
    body TEXT NOT NULL,
    PRIMARY KEY (session_id, request)
) STRICT;

CREATE TABLE IF NOT EXISTS fork_snapshot_blob (
    sha256 TEXT PRIMARY KEY,
    body TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS session_head_log (
    id INTEGER PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES session(session_id),
    from_message_id INTEGER REFERENCES message(id),
    to_message_id INTEGER NOT NULL REFERENCES message(id),
    attached_to_message_id INTEGER REFERENCES message(id),
    reason TEXT NOT NULL
) STRICT;

-- gather_boundary — the danger-lens surface, scoped to each session's PATH from its
-- recorded head (#753 / FK16). `session_id` names the session whose conversation the row
-- is on, NOT the session that happens to own the row: a fork therefore sees the prefix it
-- inherited, because its defender genuinely holds those turns, and a folded session stops
-- seeing the turns the fold displaced, because they are reachable from nothing. Session
-- scoping falls out of that — no read can serve one session another's leads — so a caller
-- adding `WHERE session_id = ?` is CHOOSING a session, not repairing the view.
--
-- The walk is by rowid and `extract_lead_id` still runs only on `kind='response'` rows, so
-- the added cost is small next to the per-row Python extraction: measured 53.6 ms -> 66.5 ms
-- for a 2200-row session read out of a file also holding 20 gather legs. Two caveats C16's
-- number does NOT cover. The recursion itself is NOT narrowed — parents chain THROUGH
-- request rows, so every row on every path is visited whatever the outer predicate, and a
-- caller's `session_id` cannot be pushed into it. And a shared prefix is walked (and its
-- leads extracted) once per DESCENDANT on an unscoped read: N forks off an L-row prefix
-- cost N*L, not L. Both are bounded by the per-case file, which is one case's run.
--
-- `UNION` (not `UNION ALL`) is the recursion's cycle guard: a looped parent chain repeats
-- a (session, message, parent) triple and the duplicate is discarded, so a corrupted file
-- ends the walk instead of hanging the reader. The view therefore DEGRADES on a cycle
-- (each row in the ring, once) where `_walk_parents` FAILS CLOSED (`CyclicParentChain`) —
-- deliberate: a lens that hangs is worse than one that over-reports, and the reader that
-- projects the conversation is the one that must refuse.
--
-- A phantom `parent_id` — an id no `message` row resolves, reachable only by direct file
-- damage — is the SECOND asymmetry, and it runs the other way from the cycle one: the
-- recursion's `JOIN` simply finds nothing, so the walk stops early and the view silently
-- serves a TRUNCATED path, under-reporting leads. `_walk_parents` terminates there too,
-- but its read-side callers fail closed on it (`UnresolvablePathElement`). Stated here
-- because a lens that quietly drops rows is the failure a reader cannot see.
--
-- Dropped and rebuilt on every open rather than `IF NOT EXISTS`: a view holds no data,
-- and #753 redefined this one after #744 shipped it unscoped. `IF NOT EXISTS` would have
-- left a file created in between serving the old, unscoped definition forever, with the
-- reader given no signal — the exact trap the redefinition exists to disarm.
--
-- The rebuild is ONE transaction, not two statements. Every `open_store` runs this script,
-- and two of them race on a per-case file the moment concurrent gather legs each open their
-- own handle: unwrapped, both DROP, then both CREATE, and the loser dies on `view
-- gather_boundary already exists`. A concurrent reader querying the view inside the same
-- window gets `no such table: gather_boundary`. `BEGIN IMMEDIATE` closes both: the losing
-- opener waits out `busy_timeout` and then finds the view already correct, and no reader
-- can observe the gap between the DROP and the CREATE.
BEGIN IMMEDIATE;
DROP VIEW IF EXISTS gather_boundary;
CREATE VIEW gather_boundary AS
WITH RECURSIVE session_path(session_id, message_id, parent_id) AS (
    SELECT s.session_id, m.id, m.parent_id
    FROM session s
    JOIN message m ON m.id = s.head_message_id
    UNION
    SELECT sp.session_id, m.id, m.parent_id
    FROM session_path sp
    JOIN message m ON m.id = sp.parent_id
)
SELECT
    m.id AS message_id,
    sp.session_id AS session_id,
    m.kind AS kind,
    extract_lead_id(p.payload) AS lead_id
FROM session_path sp
JOIN message m ON m.id = sp.message_id
JOIN message_payload p ON p.message_id = m.id
WHERE m.kind = 'response';
COMMIT;
"""




#: How long an append blocks on another connection's lock. One constant for both
#: `sqlite3.connect(timeout=)` (seconds) and the `busy_timeout` pragma (milliseconds).
STORE_BUSY_TIMEOUT_MS = 30_000




#: Below the installed `ModelMessagesTypeAdapter.dump_python`'s own ceiling (bisected at
#: ~250 levels of dict nesting for a `ToolCallPart.args` payload), so the append-time refusal
#: fires before pydantic-core's uncaught `ValueError: Circular reference detected`.
_MAX_PAYLOAD_DEPTH = 200



_TOO_DEEP = object()




def _refuse_stale_version(conn: sqlite3.Connection) -> None:
    """Read `PRAGMA user_version` and refuse anything but `SCHEMA_VERSION`, before any DDL
    and before the WAL pragma — so a refused file is left byte-identical and no `-wal`/`-shm`
    sidecar is written beside it. There is no migration path."""
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    if version != SCHEMA_VERSION:
        raise UnknownSchemaVersion(f"store reports schema version {version}")




class LegacyRunLink(StoreError):
    """A run recorded before #1235: its run -> case link is still the file inside the run
    folder, and no link sits beside the folder. Refused, never read as "no session": which case
    the run belongs to is unknown, and the run can be re-run."""




#: The run -> case link's name inside the run folder before #1235 moved it beside the folder
#: (`RunPaths.session_pointer`). Only its presence is ever looked at.
_LEGACY_LINK_NAME = "session_store_pointer.json"
