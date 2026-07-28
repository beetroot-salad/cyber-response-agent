"""The per-case SQLite session store — #705's canonical, append-only message log.

One file per `case_id`, sibling of the runs base (never a child): `message` rows form a
parent-chain tree (never updated, never deleted), `message_payload` holds the verbatim
`ModelMessagesTypeAdapter` dump in its own table, and `hydrate()` is the ONE role-scoped
reader (`send` / `analysis` / `actor`) that walks the chain and projects it.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import math
import re
import sqlite3
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic_ai.messages import (
    ModelMessagesTypeAdapter,
    ModelRequest,
    ModelResponse,
    ToolCallPart,
    ToolReturnPart,
)

SCHEMA_VERSION = 2
PAYLOAD_ENSURE_ASCII = True
ROLES = ("send", "analysis", "actor")
POINTER_FILENAME = "session_store_pointer.json"
#: The closed set `append`'s `reason` keyword is validated against — a Python constant, not
#: a SQL CHECK (`reason_is_a_python_closed_set_not_a_sql_check`). `fork` has no legitimate
#: caller through `append` at all: `fork()` writes its own entry directly.
HEAD_MOVE_REASONS = ("fork", "fold")

CASE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")

_CONFIG_REQUIRED_FIELDS = ("models", "corpus", "prompts", "versions")


class StoreError(Exception):
    """Base for every failure this store raises on its own behalf.

    The driver catches THIS (alongside `sqlite3.Error`) to end a run through the handled
    `truncated_by` exit. A new store exception that does not inherit from it propagates
    out of the `ProcessHistory` hook and takes the whole `run.py` process down instead —
    which is what a `PayloadNotRepresentable` from one NaN in a tool result used to do.
    """


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
    """A walked path names a message id no `message` row resolves — a corrupted
    `parent_id` chain, reached only through direct file damage since the foreign key
    keeps a phantom id out of every write the store's own API can make."""


class IngestTailUnderflow(StoreError):
    """A live message list is shorter than the session's last recorded render length."""


class InvalidCaseId(ValueError):
    """A `case_id` does not conform to the store's slug shape; refused, not sanitized."""


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

CREATE TABLE IF NOT EXISTS session_head_log (
    id INTEGER PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES session(session_id),
    from_message_id INTEGER REFERENCES message(id),
    to_message_id INTEGER NOT NULL REFERENCES message(id),
    attached_to_message_id INTEGER REFERENCES message(id),
    reason TEXT NOT NULL
) STRICT;

CREATE VIEW IF NOT EXISTS gather_boundary AS
SELECT
    m.id AS message_id,
    m.session_id AS session_id,
    m.kind AS kind,
    extract_lead_id(p.payload) AS lead_id
FROM message m
JOIN message_payload p ON p.message_id = m.id
WHERE m.kind = 'response';
"""


# --------------------------------------------------------------------------
# gather_boundary's extraction — pure Python, registered as a SQL function so a
# malformed or pathologically deep `args` value can never abort the query (adv:PO2).
# --------------------------------------------------------------------------

def _first_wins_pairs(pairs: list[tuple[str, Any]]) -> dict:
    out: dict = {}
    for k, v in pairs:
        if k not in out:
            out[k] = v
    return out


def _lead_id_from_args(args: Any) -> str | None:
    if isinstance(args, str):
        try:
            args = json.loads(args, object_pairs_hook=_first_wins_pairs)
        except Exception:  # noqa: BLE001 — untrusted, possibly-hostile text
            return None
    if not isinstance(args, dict) or "lead_id" not in args:
        return None
    value = args["lead_id"]
    if isinstance(value, str):
        return value
    if isinstance(value, (dict, list)):
        try:
            return json.dumps(value, separators=(",", ":"))
        except Exception:  # noqa: BLE001 — untrusted content boundary
            return None
    return None


def _extract_lead_id(payload_text: str) -> str | None:
    try:
        payload = json.loads(payload_text, object_pairs_hook=_first_wins_pairs)
        parts = payload.get("parts") if isinstance(payload, dict) else None
        if not isinstance(parts, list):
            return None
        for part in parts:
            if not isinstance(part, dict) or part.get("part_kind") != "tool-call":
                continue
            lead_id = _lead_id_from_args(part.get("args"))
            if lead_id is not None:
                return lead_id
        return None
    except Exception:  # noqa: BLE001 — the whole point: never abort the query
        return None


def _bare_connect(path: Path) -> sqlite3.Connection:
    """A connection with no pragma and no function registered yet — so a stale-version
    refusal can fire before the WAL pragma rewrites the file's header (FK-G)."""
    return sqlite3.connect(str(path), timeout=30.0, isolation_level=None)


def _finish_connect(conn: sqlite3.Connection) -> None:
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA busy_timeout = 30000")
    conn.create_function("extract_lead_id", 1, _extract_lead_id)


# --------------------------------------------------------------------------
# the handle
# --------------------------------------------------------------------------

@dataclass
class StoreHandle:
    """One handle, ONE `sqlite3.Connection`, shared by the main agent's session and every
    concurrently-dispatched gather sub-agent's session.

    That is safe only because `append()`'s `BEGIN IMMEDIATE … COMMIT` block contains no
    `await`: pydantic_ai dispatches parallel `gather` calls as asyncio tasks on one
    thread, so without a suspension point inside the transaction two tasks cannot
    interleave halfway through one. **Adding any `await` inside that block reintroduces
    interleaved-transaction corruption** — give each session its own connection first.
    """

    path: Path
    connection: sqlite3.Connection
    case_id: str
    pending_stamps: dict = field(default_factory=dict, repr=False, compare=False)

    def new_session(self, agent_id: str) -> str:
        session_id = uuid.uuid4().hex
        self.connection.execute(
            "INSERT INTO session (session_id, case_id, parent_session_id, agent_id, "
            "head_message_id, truncated_by, last_render_len) "
            "VALUES (?, ?, NULL, ?, NULL, NULL, NULL)",
            (session_id, self.case_id, agent_id),
        )
        return session_id

    def fork(self, session_id: str, at_message_id: int) -> str:
        """Open a session branching from `session_id` at `at_message_id`.

        The branch point becomes the new session's `head_message_id` directly — no
        separate fallback column left to consult — and its own `session_head_log` entry,
        both inside one `BEGIN IMMEDIATE`: a fault between the two writes would leave a
        session with a head and no branch-point record, exactly the unreachable-lineage-
        without-a-record state the design forbids. `last_render_len` is set to the length
        of the inherited prefix so the first `ingest` does not re-append it (PR-24)."""
        new_id = uuid.uuid4().hex
        conn = self.connection
        conn.execute("BEGIN IMMEDIATE")
        committed = False
        try:
            row = conn.execute(
                "SELECT case_id, agent_id FROM session WHERE session_id = ?",
                (session_id,)).fetchone()
            case_id = row[0] if row else self.case_id
            agent_id = row[1] if row else None
            prefix_len = len(_walk_parents(conn, at_message_id))
            conn.execute(
                "INSERT INTO session (session_id, case_id, parent_session_id, agent_id, "
                "head_message_id, truncated_by, last_render_len) "
                "VALUES (?, ?, ?, ?, ?, NULL, ?)",
                (new_id, case_id, session_id, agent_id, at_message_id, prefix_len),
            )
            conn.execute(
                "INSERT INTO session_head_log (session_id, from_message_id, to_message_id, "
                "attached_to_message_id, reason) VALUES (?, NULL, ?, NULL, 'fork')",
                (new_id, at_message_id),
            )
            conn.execute("COMMIT")
            committed = True
        except BaseException:
            if not committed:
                with contextlib.suppress(sqlite3.Error):
                    conn.execute("ROLLBACK")
            raise
        return new_id

    def append(  # noqa: PLR0913 — the write primitive's full coordinate set
        self, session_id: str, messages: list, *, agent_id: str,
        parent_id: int | None = None, synthesized: bool = False, seq: int | None = None,
        run_step: int | None = None, duration_ms: float | None = None,
        wire_sha: str | None = None, reason: str | None = None,
    ) -> list[int]:
        messages = list(messages)
        _validate_reason(reason)
        if not messages:
            return []
        _validate_batch_shape(messages, seq=seq, duration_ms=duration_ms)

        conn = self.connection
        conn.execute("BEGIN IMMEDIATE")
        committed = False
        try:
            prev_head, first_parent, is_linear = _classify_move(
                conn, session_id, parent_id=parent_id, reason=reason, synthesized=synthesized)
            ids: list[int] = []
            pid = first_parent
            for m in messages:
                row_seq = seq if seq is not None else _next_seq(
                    conn, session_id, agent_id, synthesized)
                pid = _insert_message(
                    conn, m, session_id=session_id, agent_id=agent_id, parent_id=pid,
                    seq=row_seq, synthesized=synthesized, run_step=run_step,
                    duration_ms=duration_ms, wire_sha=wire_sha,
                )
                ids.append(pid)
            _move_head(conn, session_id, prev_head=prev_head, new_head=ids[-1],
                      attached_to=first_parent, is_linear=is_linear, reason=reason)
            conn.execute("COMMIT")
            committed = True
            conn.execute("SELECT 1")
        except BaseException:
            # Only roll back a transaction that is still open. Past COMMIT there is none,
            # and `ROLLBACK` with no active transaction itself raises
            # (sqlite3.OperationalError) — which would replace whatever actually brought
            # us here with an unrelated error, and get the run classified as a routine
            # "store" truncation even though the rows are already durable.
            if not committed:
                with contextlib.suppress(sqlite3.Error):
                    conn.execute("ROLLBACK")
            raise
        return ids

    def write_config(self, config: dict) -> str:
        missing = [f for f in _CONFIG_REQUIRED_FIELDS if f not in config]
        if missing:
            raise IncompleteConfig(f"missing required config field(s): {missing}")
        canonical = json.dumps(config, sort_keys=True, ensure_ascii=True)
        sha = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        self.connection.execute(
            "INSERT INTO config (sha256, body) VALUES (?, ?) "
            "ON CONFLICT(sha256) DO NOTHING", (sha, canonical))
        return sha

    def set_truncated_by(self, session_id: str, reason: str) -> None:
        self.connection.execute(
            "UPDATE session SET truncated_by = ? WHERE session_id = ?", (reason, session_id))

    def set_last_render_len(self, session_id: str, n: int) -> None:
        self.connection.execute(
            "UPDATE session SET last_render_len = ? WHERE session_id = ?", (n, session_id))

    def last_render_len(self, session_id: str) -> int | None:
        row = self.connection.execute(
            "SELECT last_render_len FROM session WHERE session_id = ?", (session_id,)
        ).fetchone()
        return row[0] if row else None

    def close(self) -> None:
        self.connection.close()


def _walk_parents(conn: sqlite3.Connection, tip: int) -> list[int]:
    """Tip-to-root row ids, refusing a cyclic chain. The one walk both the reader
    (`path_row_ids`) and the writer (`append`'s write-time cycle guard) go through, so a
    corrupted chain cannot stay invisible at write time and surface only later, at read
    time. Terminates cleanly (and returns a phantom id as the path's oldest element,
    rather than raising) when an id along the chain resolves no `message` row — the
    read-side callers (`hydrate`, `synthesized_flags`) are what fail closed on that."""
    ids: list[int] = []
    seen: set[int] = set()
    current: int | None = tip
    while current is not None:
        if current in seen:
            raise CyclicParentChain(f"cycle detected at message {current}")
        seen.add(current)
        ids.append(current)
        row = conn.execute(
            "SELECT parent_id FROM message WHERE id = ?", (current,)).fetchone()
        current = row[0] if row else None
    return ids


def _read_head(conn: sqlite3.Connection, session_id: str) -> int | None:
    """`session.head_message_id`, read raw — the implicit append parent and the anchor
    `path_row_ids` walks from. `None` for both a NULL head and a nonexistent session_id."""
    row = conn.execute(
        "SELECT head_message_id FROM session WHERE session_id = ?", (session_id,),
    ).fetchone()
    return row[0] if row is not None else None


def _session_has_rows(conn: sqlite3.Connection, session_id: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM message WHERE session_id = ? LIMIT 1", (session_id,)).fetchone()
    return row is not None


def _insert_message(  # noqa: PLR0913 — one row's full coordinate set, from append()
    conn: sqlite3.Connection, message: Any, *, session_id: str, agent_id: str,
    parent_id: int | None, seq: int, synthesized: bool, run_step: int | None,
    duration_ms: float | None, wire_sha: str | None,
) -> int:
    """One `message` row plus its `message_payload` row; returns the new row id.
    Caller owns the transaction."""
    kind = "request" if isinstance(message, ModelRequest) else "response"
    cur = conn.execute(
        "INSERT INTO message (session_id, agent_id, parent_id, seq, synthesized, "
        "kind, tool_name, run_step, duration_ms, wire_sha) "
        "VALUES (?,?,?,?,?,?,?,?,?,?)",
        (session_id, agent_id, parent_id, seq, int(synthesized), kind,
         _tool_name(message), run_step, duration_ms, wire_sha),
    )
    mid = cur.lastrowid
    if mid is None:
        raise StoreAppendError("INSERT produced no rowid")
    dumped = ModelMessagesTypeAdapter.dump_python([message], mode="json")[0]
    payload_text = json.dumps(dumped, ensure_ascii=PAYLOAD_ENSURE_ASCII)
    payload_sha = hashlib.sha256(payload_text.encode("utf-8")).hexdigest()
    conn.execute(
        "INSERT INTO message_payload (message_id, payload, payload_sha) VALUES (?,?,?)",
        (mid, payload_text, payload_sha),
    )
    return mid


def _validate_seq(seq: Any) -> None:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise StoreAppendError(f"seq must be a real int, got {seq!r}")


def _validate_duration_ms(duration_ms: Any) -> None:
    """`duration_ms` is bound straight into the INSERT, so it never meets
    `_find_nonrepresentable` — the isfinite discipline every other float in the row is
    held to. Without this check SQLite silently stores a NaN as SQL NULL (defeating the
    discipline two lines away) and an inf round-trips verbatim, later serializing to the
    bare token `Infinity`, which is not valid JSON for any strict downstream consumer."""
    if duration_ms is None:
        return
    if isinstance(duration_ms, bool) or not isinstance(duration_ms, (int, float)):
        raise PayloadNotRepresentable(
            f"duration_ms must be a real number, got {duration_ms!r}")
    if not math.isfinite(duration_ms):
        raise PayloadNotRepresentable(f"cannot store {duration_ms!r} as duration_ms")


def _validate_reason(reason: str | None) -> None:
    """Membership by exact match, whenever `reason` is not `None` — before the
    empty-batch short-circuit and before the move's linearity is classified (FK-C).
    `fork` is a member of the closed set but has no legitimate caller through `append`
    at all: `fork()` writes its own entry directly."""
    if reason is None:
        return
    if reason not in HEAD_MOVE_REASONS:
        raise StoreAppendError(
            f"reason must be one of {HEAD_MOVE_REASONS} or None, got {reason!r}")
    if reason == "fork":
        raise StoreAppendError("append cannot mint a fork entry; fork() writes its own")


def _validate_batch_shape(messages: list, *, seq: int | None, duration_ms: float | None) -> None:
    if seq is not None:
        _validate_seq(seq)
        if len(messages) != 1:
            raise StoreAppendError(
                "an explicit seq may only be given for a single-message append")
    _validate_duration_ms(duration_ms)
    for m in messages:
        bad = _find_nonrepresentable(m)
        if bad is _TOO_DEEP:
            raise PayloadNotRepresentable(
                f"payload nesting exceeds {_MAX_PAYLOAD_DEPTH} levels")
        if bad is not None:
            raise PayloadNotRepresentable(f"cannot store {bad!r} verbatim")


def _classify_move(
    conn: sqlite3.Connection, session_id: str, *, parent_id: int | None,
    reason: str | None, synthesized: bool,
) -> tuple[int | None, int | None, bool]:
    """Resolve the first row's parent, refuse the write-time hazards obligation 7 and
    P55 name, and classify the move as linear or not. Returns
    `(prev_head, first_parent, is_linear)`."""
    prev_head = _read_head(conn, session_id)
    first_parent = parent_id if parent_id is not None else prev_head
    if first_parent is None and _session_has_rows(conn, session_id):
        raise StoreAppendError(
            "append into a session that holds rows but has no recorded head is "
            "refused rather than silently orphaning them")
    if first_parent is not None:
        _walk_parents(conn, first_parent)  # write-time cycle guard (correction R3)
    is_linear = first_parent == prev_head
    if reason is not None:
        if is_linear and not synthesized:
            raise StoreAppendError(
                "a reason on a linear move is refused unless the caller mints a "
                "frontier row (synthesized=True)")
    elif not is_linear:
        raise StoreAppendError(
            "a non-linear append (its first row's parent is not the session's "
            "current head) requires an explicit reason from the closed set")
    return prev_head, first_parent, is_linear


def _move_head(  # noqa: PLR0913 — the log row's full coordinate set
    conn: sqlite3.Connection, session_id: str, *, prev_head: int | None, new_head: int,
    attached_to: int | None, is_linear: bool, reason: str | None,
) -> None:
    conn.execute(
        "UPDATE session SET head_message_id = ? WHERE session_id = ?",
        (new_head, session_id))
    if not is_linear or reason is not None:
        conn.execute(
            "INSERT INTO session_head_log (session_id, from_message_id, "
            "to_message_id, attached_to_message_id, reason) VALUES (?,?,?,?,?)",
            (session_id, prev_head, new_head, attached_to, reason))


def _next_seq(conn: sqlite3.Connection, session_id: str, agent_id: str, synthesized: bool) -> int:
    row = conn.execute(
        "SELECT COALESCE(MAX(seq), -1) + 1 FROM message "
        "WHERE session_id = ? AND agent_id = ? AND synthesized = ?",
        (session_id, agent_id, int(synthesized)),
    ).fetchone()
    return row[0]


def _tool_name(message: Any) -> str | None:
    """Every distinct tool named by the message, comma-joined in first-seen order.

    One response legitimately carries several tool calls — the `gather` tool's own
    docstring tells the model to "issue multiple gather calls in one turn to dispatch
    sibling leads in parallel". Returning only the first would make the `actor`
    projection disagree with `observe.write_trace`, which re-derives the same fact from
    `message.parts` and lists all of them. Single-tool messages are unaffected."""
    names: list[str] = []
    for part in getattr(message, "parts", []):
        if isinstance(part, (ToolCallPart, ToolReturnPart)) and part.tool_name not in names:
            names.append(part.tool_name)
    return ",".join(names) if names else None


def _is_nonrepresentable_leaf(obj: Any) -> bool:
    if isinstance(obj, float):
        return not math.isfinite(obj)
    return isinstance(obj, (bytes, bytearray, set))


def _children(obj: Any) -> Any:
    if isinstance(obj, dict):
        return obj.values()
    if isinstance(obj, (list, tuple)):
        return obj
    if hasattr(obj, "__dict__"):
        return vars(obj).values()
    return ()


#: Below the installed `ModelMessagesTypeAdapter.dump_python`'s own ceiling (bisected
#: empirically at ~250 levels of dict nesting for a `ToolCallPart.args` payload — well
#: under SQLite's ~1000-level JSON ceiling and under Python's default recursion limit),
#: so the append-time refusal fires before pydantic-core's own uncaught
#: `ValueError: Circular reference detected (depth exceeded)` would.
_MAX_PAYLOAD_DEPTH = 200

_TOO_DEEP = object()


def _find_nonrepresentable(obj: Any) -> Any:
    """Iterative, not recursive, and depth-capped: a deeply-nested tool-call `args` dict
    is attacker-influenced by construction (the model chooses its own tool-call shape),
    and both a Python-recursion-depth scan AND `dump_python` itself crash on one well
    before SQLite's own ~1000-level JSON ceiling — the same failure mode `extract_lead_id`
    (this module's SQL scalar function) was built to sidestep, re-found here in the
    append-time validator by re-probing PR5/adv:PO2 against the real implementation."""
    stack: list[tuple[Any, int]] = [(obj, 0)]
    while stack:
        current, depth = stack.pop()
        if depth > _MAX_PAYLOAD_DEPTH:
            return _TOO_DEEP
        if _is_nonrepresentable_leaf(current):
            return current
        stack.extend((child, depth + 1) for child in _children(current))
    return None


# --------------------------------------------------------------------------
# open / resolve
# --------------------------------------------------------------------------

def store_path_for(case_id: str, *, runs_base: Path) -> Path:
    if not isinstance(case_id, str) or not CASE_ID_RE.match(case_id):
        raise InvalidCaseId(repr(case_id))
    runs_base = Path(runs_base)
    return runs_base.parent / "sessions" / f"{case_id}.db"


def _refuse_stale_version(conn: sqlite3.Connection) -> None:
    """Read `PRAGMA user_version` and refuse anything but `SCHEMA_VERSION`, before any
    DDL and before the WAL pragma — so a refused file is left byte-identical and no
    `-wal`/`-shm` sidecar is ever written beside it (FK-G). No migration path is offered:
    D3 deletes the ALTER shim that used to silently re-shape a pre-existing store."""
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    if version != SCHEMA_VERSION:
        raise UnknownSchemaVersion(f"store reports schema version {version}")


def open_store(*, case_id: str, runs_base: Path) -> StoreHandle:
    path = store_path_for(case_id, runs_base=runs_base)
    path.parent.mkdir(parents=True, exist_ok=True)
    fresh = not path.exists()
    conn = _bare_connect(path)
    try:
        if not fresh:
            _refuse_stale_version(conn)
        _finish_connect(conn)
        conn.executescript(DDL)
        if fresh:
            conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
    except BaseException:
        conn.close()
        raise
    return StoreHandle(path=path, connection=conn, case_id=case_id)


def open_store_for_read(store_path: Path) -> StoreHandle:
    """Open an EXISTING store file for reading only — never creates one.

    `open_store` deliberately creates-if-missing (the writer's DDL is `IF NOT EXISTS`);
    a reader (the visualizer, run after the fact from just a `run_dir`) must fail closed
    instead of silently conjuring an empty database where a real one used to be. It is
    also the only opener that ever meets a file it did not create, so it refuses a stale
    version exactly as `open_store` does, at the same pre-DDL, pre-WAL point."""
    store_path = Path(store_path)
    if not store_path.is_file():
        raise FileNotFoundError(f"session store not found: {store_path}")
    conn = _bare_connect(store_path)
    try:
        _refuse_stale_version(conn)
        _finish_connect(conn)
    except BaseException:
        conn.close()
        raise
    return StoreHandle(path=store_path, connection=conn, case_id="")


def write_case_pointer(run_dir: Path, *, case_id: str, store_path: Path) -> None:
    run_dir = Path(run_dir)
    body = {"case_id": case_id, "store_path": str(store_path)}
    (run_dir / POINTER_FILENAME).write_text(json.dumps(body), encoding="utf-8")


def resolve_store_path(run_dir: Path) -> Path:
    data = json.loads((Path(run_dir) / POINTER_FILENAME).read_text(encoding="utf-8"))
    return Path(data["store_path"])


# --------------------------------------------------------------------------
# the path walk
# --------------------------------------------------------------------------

def path_row_ids(store: Any, session_id: str) -> list[int]:
    """The parent walk from the session's RECORDED head — never from the highest-id row
    it happens to own. A NULL head (no entry, or a session with rows but no head) reads
    as an empty path: there is no fallback left that re-derives a tip from insertion
    order."""
    conn = store.connection
    head = _read_head(conn, session_id)
    if head is None:
        return []
    ids = _walk_parents(conn, head)
    ids.reverse()
    return ids


# --------------------------------------------------------------------------
# the log readers
# --------------------------------------------------------------------------

def displaced_tip(store: Any, session_id: str) -> int | None:
    """The MOST RECENT fold's displaced tip — `None` for a session with no fold entry
    and for a session_id that does not exist."""
    row = store.connection.execute(
        "SELECT from_message_id FROM session_head_log WHERE session_id = ? "
        "AND reason = 'fold' ORDER BY id DESC LIMIT 1", (session_id,),
    ).fetchone()
    return row[0] if row is not None else None


def fold_history(store: Any, session_id: str) -> list[int | None]:
    """Every fold's displaced tip, in head-move order — `displaced_tip` is its last
    element. The ordered accessor a single "most recent" reader cannot provide: it is
    what makes the first fold's displaced tip reachable at all."""
    rows = store.connection.execute(
        "SELECT from_message_id FROM session_head_log WHERE session_id = ? "
        "AND reason = 'fold' AND from_message_id IS NOT NULL ORDER BY id", (session_id,),
    ).fetchall()
    return [r[0] for r in rows]


def branch_point(store: Any, session_id: str) -> int | None:
    """The session's branch point — a log row that is BOTH origin-less and fork-reasoned.
    Neither condition alone is sufficient: an origin-less row can be a fold of an empty
    path, and a fork-reasoned row can be smuggled in with a non-NULL origin by a caller
    that bypasses `append`'s own refusal."""
    row = store.connection.execute(
        "SELECT to_message_id FROM session_head_log WHERE session_id = ? "
        "AND reason = 'fork' AND from_message_id IS NULL ORDER BY id DESC LIMIT 1",
        (session_id,),
    ).fetchone()
    return row[0] if row is not None else None


# --------------------------------------------------------------------------
# the one role-scoped reader
# --------------------------------------------------------------------------

def _check_schema_version(store: Any) -> None:
    version = store.connection.execute("PRAGMA user_version").fetchone()[0]
    if version != SCHEMA_VERSION:
        raise UnknownSchemaVersion(f"store reports schema version {version}")


def _fetch_message_rows(conn: sqlite3.Connection, ids: list[int]) -> dict[int, dict]:
    placeholders = ",".join("?" * len(ids))
    rows = conn.execute(
        f"SELECT id, session_id, agent_id, seq, kind, synthesized, tool_name "
        f"FROM message WHERE id IN ({placeholders})", tuple(ids),
    ).fetchall()
    return {
        r[0]: {"session_id": r[1], "agent_id": r[2], "seq": r[3], "kind": r[4],
               "synthesized": r[5], "tool_name": r[6]}
        for r in rows
    }


def _fetch_payloads(conn: sqlite3.Connection, ids: list[int]) -> dict[int, str]:
    placeholders = ",".join("?" * len(ids))
    rows = conn.execute(
        f"SELECT message_id, payload FROM message_payload WHERE message_id IN ({placeholders})",
        tuple(ids),
    ).fetchall()
    return dict(rows)


def _message_from_payload(text: str) -> Any:
    return ModelMessagesTypeAdapter.validate_python([json.loads(text)])[0]


def _actor_row(row: dict) -> dict:
    return {
        "coord": f"{row['session_id']}/{row['agent_id']}#{row['seq']}",
        "agent_id": row["agent_id"],
        "kind": row["kind"],
        "tool_name": row["tool_name"],
    }


def _complete_prefix_len(messages: list) -> int:
    if not messages:
        return 0
    last = messages[-1]
    if isinstance(last, ModelResponse):
        calls = [p for p in last.parts if isinstance(p, ToolCallPart)]
        if calls:
            returned = {
                p.tool_call_id for m in messages for p in getattr(m, "parts", [])
                if isinstance(p, ToolReturnPart)
            }
            if any(c.tool_call_id not in returned for c in calls):
                return len(messages) - 1
    return len(messages)


def _require_resolved(ids: list[int], table: dict[int, Any]) -> None:
    """`_walk_parents` terminates cleanly on a phantom id instead of raising, so the read
    side is what fails closed: a dict lookup that would otherwise die on an uncaught
    `KeyError` raises the store's own, named error instead."""
    missing = [i for i in ids if i not in table]
    if missing:
        raise UnresolvablePathElement(
            f"path element(s) resolve no message row: {missing}")


def hydrate(store: Any, session_id: str, role: Any, *,
            requested_role_from_content: Any = None) -> list:
    _check_schema_version(store)
    if role not in ROLES:
        raise UnknownReadRole(repr(role))
    ids = path_row_ids(store, session_id)
    if not ids:
        return []
    if role == "actor":
        rows = _fetch_message_rows(store.connection, ids)
        _require_resolved(ids, rows)
        return [_actor_row(rows[i]) for i in ids]
    payloads = _fetch_payloads(store.connection, ids)
    _require_resolved(ids, payloads)
    messages = [_message_from_payload(payloads[i]) for i in ids]
    if role == "send":
        messages = messages[: _complete_prefix_len(messages)]
    return messages


def synthesized_flags(store: Any, session_id: str, role: Any) -> list[bool]:
    _check_schema_version(store)
    if role not in ROLES:
        raise UnknownReadRole(repr(role))
    ids = path_row_ids(store, session_id)
    if not ids:
        return []
    rows = _fetch_message_rows(store.connection, ids)
    _require_resolved(ids, rows)
    if role == "send":
        payloads = _fetch_payloads(store.connection, ids)
        _require_resolved(ids, payloads)
        messages = [_message_from_payload(payloads[i]) for i in ids]
        ids = ids[: _complete_prefix_len(messages)]
    return [bool(rows[i]["synthesized"]) for i in ids]


def ends_on_complete_pair(store: Any, session_id: str) -> bool:
    row = store.connection.execute(
        "SELECT truncated_by FROM session WHERE session_id = ?", (session_id,)).fetchone()
    return row is not None and row[0] is None


# --------------------------------------------------------------------------
# payload validation, standalone (skew detection)
# --------------------------------------------------------------------------

def _has_extra_keys(raw: Any, redumped: Any) -> bool:
    if isinstance(raw, dict):
        if not isinstance(redumped, dict):
            return True
        for k, v in raw.items():
            if k not in redumped:
                return True
            if _has_extra_keys(v, redumped[k]):
                return True
        return False
    if isinstance(raw, list):
        # Same verdict as the dict branch above: a type change or a dropped element IS
        # skew. Returning False here would report "no skew" for exactly the case
        # PayloadSchemaSkew exists to catch — an adapter that reshapes a list-typed
        # field (`parts`) on the round-trip instead of raising.
        if not isinstance(redumped, list) or len(raw) != len(redumped):
            return True
        return any(_has_extra_keys(a, b) for a, b in zip(raw, redumped, strict=True))
    return False


def load_payload(json_text: str) -> Any:
    raw = json.loads(json_text)
    message = ModelMessagesTypeAdapter.validate_python([raw])[0]
    redumped = ModelMessagesTypeAdapter.dump_python([message], mode="json")[0]
    if _has_extra_keys(raw, redumped):
        raise PayloadSchemaSkew(
            "payload carries a field the installed adapter does not recognize")
    return message
