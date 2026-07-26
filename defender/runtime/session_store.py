"""The per-case SQLite session store — #705's canonical, append-only message log.

One file per `case_id`, sibling of the runs base (never a child): `message` rows form a
parent-chain tree (never updated, never deleted), `message_payload` holds the verbatim
`ModelMessagesTypeAdapter` dump in its own table, and `hydrate()` is the ONE role-scoped
reader (`send` / `analysis` / `actor`) that walks the chain and projects it.
"""
from __future__ import annotations

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

SCHEMA_VERSION = 1
PAYLOAD_ENSURE_ASCII = True
ROLES = ("send", "analysis", "actor")
POINTER_FILENAME = "session_store_pointer.json"

CASE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")

_CONFIG_REQUIRED_FIELDS = ("models", "corpus", "prompts", "versions")


class StoreAppendError(Exception):
    """An append was refused at the store's own boundary."""


class UnknownSchemaVersion(Exception):
    """The store's `PRAGMA user_version` is not one the reader recognizes."""


class PayloadNotRepresentable(Exception):
    """A payload value `dump_python` would silently coerce; refused at append."""


class PayloadSchemaSkew(Exception):
    """A stored payload carries a field the installed adapter does not recognize."""


class CyclicParentChain(Exception):
    """The `parent_id` chain loops; the walk refuses to follow it forever."""


class IncompleteConfig(Exception):
    """A config dict is missing one of the four required reproducibility fields."""


class UnknownReadRole(Exception):
    """`hydrate` was asked for a role outside the closed `{send, analysis, actor}` set."""


class IngestTailUnderflow(Exception):
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


def _connect(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path), timeout=30.0, isolation_level=None)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA busy_timeout = 30000")
    conn.create_function("extract_lead_id", 1, _extract_lead_id)
    return conn


# --------------------------------------------------------------------------
# the handle
# --------------------------------------------------------------------------

@dataclass
class StoreHandle:
    path: Path
    connection: sqlite3.Connection
    case_id: str
    pending_stamps: dict = field(default_factory=dict, repr=False, compare=False)

    def new_session(self, agent_id: str) -> str:  # noqa: ARG002 — part of the contract
        session_id = uuid.uuid4().hex
        self.connection.execute(
            "INSERT INTO session (session_id, case_id, parent_session_id, truncated_by, "
            "last_render_len) VALUES (?, ?, NULL, NULL, NULL)",
            (session_id, self.case_id),
        )
        return session_id

    def fork(self, session_id: str, at_message_id: int) -> str:  # noqa: ARG002
        new_id = uuid.uuid4().hex
        row = self.connection.execute(
            "SELECT case_id FROM session WHERE session_id = ?", (session_id,)).fetchone()
        case_id = row[0] if row else self.case_id
        self.connection.execute(
            "INSERT INTO session (session_id, case_id, parent_session_id, truncated_by, "
            "last_render_len) VALUES (?, ?, ?, NULL, NULL)",
            (new_id, case_id, session_id),
        )
        return new_id

    def append(  # noqa: PLR0913 — the write primitive's full coordinate set
        self, session_id: str, messages: list, *, agent_id: str,
        parent_id: int | None = None, synthesized: bool = False, seq: int | None = None,
        run_step: int | None = None, duration_ms: float | None = None,
        wire_sha: str | None = None,
    ) -> list[int]:
        messages = list(messages)
        if not messages:
            return []
        if seq is not None:
            _validate_seq(seq)
            if len(messages) != 1:
                raise StoreAppendError(
                    "an explicit seq may only be given for a single-message append")
        for m in messages:
            bad = _find_nonrepresentable(m)
            if bad is _TOO_DEEP:
                raise PayloadNotRepresentable(
                    f"payload nesting exceeds {_MAX_PAYLOAD_DEPTH} levels")
            if bad is not None:
                raise PayloadNotRepresentable(f"cannot store {bad!r} verbatim")

        conn = self.connection
        conn.execute("BEGIN IMMEDIATE")
        try:
            ids: list[int] = []
            pid = parent_id if parent_id is not None else _session_tip(conn, session_id)
            for m in messages:
                kind = "request" if isinstance(m, ModelRequest) else "response"
                tool_name = _tool_name(m)
                row_seq = seq if seq is not None else _next_seq(
                    conn, session_id, agent_id, synthesized)
                cur = conn.execute(
                    "INSERT INTO message (session_id, agent_id, parent_id, seq, synthesized, "
                    "kind, tool_name, run_step, duration_ms, wire_sha) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (session_id, agent_id, pid, row_seq, int(synthesized), kind, tool_name,
                     run_step, duration_ms, wire_sha),
                )
                mid = cur.lastrowid
                if mid is None:
                    raise StoreAppendError("INSERT produced no rowid")
                dumped = ModelMessagesTypeAdapter.dump_python([m], mode="json")[0]
                payload_text = json.dumps(dumped, ensure_ascii=PAYLOAD_ENSURE_ASCII)
                payload_sha = hashlib.sha256(payload_text.encode("utf-8")).hexdigest()
                conn.execute(
                    "INSERT INTO message_payload (message_id, payload, payload_sha) "
                    "VALUES (?,?,?)",
                    (mid, payload_text, payload_sha),
                )
                ids.append(mid)
                pid = mid
            conn.execute("COMMIT")
            conn.execute("SELECT 1")
        except BaseException:
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


def _session_tip(conn: sqlite3.Connection, session_id: str) -> int | None:
    row = conn.execute(
        "SELECT id FROM message WHERE session_id = ? ORDER BY id DESC LIMIT 1",
        (session_id,),
    ).fetchone()
    return row[0] if row else None


def _validate_seq(seq: Any) -> None:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise StoreAppendError(f"seq must be a real int, got {seq!r}")


def _next_seq(conn: sqlite3.Connection, session_id: str, agent_id: str, synthesized: bool) -> int:
    row = conn.execute(
        "SELECT COALESCE(MAX(seq), -1) + 1 FROM message "
        "WHERE session_id = ? AND agent_id = ? AND synthesized = ?",
        (session_id, agent_id, int(synthesized)),
    ).fetchone()
    return row[0]


def _tool_name(message: Any) -> str | None:
    for part in getattr(message, "parts", []):
        if isinstance(part, (ToolCallPart, ToolReturnPart)):
            return part.tool_name
    return None


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


def open_store(*, case_id: str, runs_base: Path) -> StoreHandle:
    path = store_path_for(case_id, runs_base=runs_base)
    path.parent.mkdir(parents=True, exist_ok=True)
    fresh = not path.exists()
    conn = _connect(path)
    conn.executescript(DDL)
    if fresh:
        conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
    return StoreHandle(path=path, connection=conn, case_id=case_id)


def open_store_for_read(store_path: Path) -> StoreHandle:
    """Open an EXISTING store file for reading only — never creates one.

    `open_store` deliberately creates-if-missing (the writer's DDL is `IF NOT EXISTS`);
    a reader (the visualizer, run after the fact from just a `run_dir`) must fail closed
    instead of silently conjuring an empty database where a real one used to be."""
    store_path = Path(store_path)
    if not store_path.is_file():
        raise FileNotFoundError(f"session store not found: {store_path}")
    conn = _connect(store_path)
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
    conn = store.connection
    tip = conn.execute(
        "SELECT id FROM message WHERE session_id = ? ORDER BY id DESC LIMIT 1",
        (session_id,),
    ).fetchone()
    if tip is None:
        return []
    ids: list[int] = []
    seen: set[int] = set()
    current: int | None = tip[0]
    while current is not None:
        if current in seen:
            raise CyclicParentChain(f"cycle detected at message {current}")
        seen.add(current)
        ids.append(current)
        row = conn.execute(
            "SELECT parent_id FROM message WHERE id = ?", (current,)).fetchone()
        current = row[0] if row else None
    ids.reverse()
    return ids


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
        return [_actor_row(rows[i]) for i in ids]
    payloads = _fetch_payloads(store.connection, ids)
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
    if role == "send":
        payloads = _fetch_payloads(store.connection, ids)
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
        if not isinstance(redumped, list) or len(raw) != len(redumped):
            return False
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
