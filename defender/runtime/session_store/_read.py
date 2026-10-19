"""Role-scoped session projections."""
from __future__ import annotations
import sqlite3
from typing import Any
from pydantic_ai.messages import (
    ModelResponse,
    ToolCallPart,
    ToolReturnPart,
)
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

from ._payload import _message_from_payload
from ._schema import ROLES, UnknownReadRole, UnresolvablePathElement, _refuse_stale_version
from ._tree import _read_head, _walk_parents



# the path walk

def path_row_ids(store: Any, session_id: str) -> list[int]:
    """The parent walk from the session's recorded head, never from its highest-id row. A NULL
    head is an empty path."""
    conn = store.connection
    head = _read_head(conn, session_id)
    if head is None:
        return []
    ids = _walk_parents(conn, head)
    ids.reverse()
    return ids




# the log readers

def displaced_tip(store: Any, session_id: str) -> int | None:
    """The most recent fold's displaced tip, or `None` (no fold, or unknown session)."""
    row = store.connection.execute(
        "SELECT from_message_id FROM session_head_log WHERE session_id = ? "
        "AND reason = 'fold' ORDER BY id DESC LIMIT 1", (session_id,),
    ).fetchone()
    return row[0] if row is not None else None




def fold_history(store: Any, session_id: str) -> list[int | None]:
    """Every fold's displaced tip, in head-move order; `displaced_tip` is the last element."""
    rows = store.connection.execute(
        "SELECT from_message_id FROM session_head_log WHERE session_id = ? "
        "AND reason = 'fold' AND from_message_id IS NOT NULL ORDER BY id", (session_id,),
    ).fetchall()
    return [r[0] for r in rows]




def branch_point(store: Any, session_id: str) -> int | None:
    """The session's branch point: a log row that is both origin-less and fork-reasoned.
    Neither alone suffices (a fold of an empty path is origin-less; a caller bypassing
    `append` could write a fork row with an origin)."""
    row = store.connection.execute(
        "SELECT to_message_id FROM session_head_log WHERE session_id = ? "
        "AND reason = 'fork' AND from_message_id IS NULL ORDER BY id DESC LIMIT 1",
        (session_id,),
    ).fetchone()
    return row[0] if row is not None else None




def main_session_id(store: Any, *, agent_id: str = "main") -> str:
    """The root-of-lineage session for `agent_id`. Forks inherit `agent_id`, so ordering
    cannot pick the right one; raises unless exactly one root matches."""
    rows = store.connection.execute(
        "SELECT session_id FROM session WHERE agent_id = ? AND parent_session_id IS NULL",
        (agent_id,),
    ).fetchall()
    if len(rows) != 1:
        raise ValueError(
            f"expected exactly one root-of-lineage {agent_id!r} session; found {len(rows)}")
    return rows[0][0]




# the one role-scoped reader

def _check_schema_version(store: Any) -> None:
    """Re-check the schema version at read time against the handle in hand."""
    _refuse_stale_version(store.connection)




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




def _send_len(store: Any, session_id: str, ids: list[int], messages: list) -> int:
    """How much of a session's path a send-role read hands over: through the last complete
    pair (`_complete_prefix_len`), except that a session whose head is still its own fork
    point keeps that point whole. Since #1255 (D1) a branch is taken AT a response whose tool
    calls are unanswered, and the resumed run is handed that response so its framework runs
    the calls; anywhere else a trailing unanswered call is a turn that never finished."""
    if ids and branch_point(store, session_id) == ids[-1]:
        return len(messages)
    return _complete_prefix_len(messages)




def _require_resolved(ids: list[int], table: dict[int, Any]) -> None:
    """Fail closed on a phantom id (which `_walk_parents` returns rather than raising) with a
    named store error instead of a `KeyError`."""
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
        messages = messages[: _send_len(store, session_id, ids, messages)]
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
        ids = ids[: _send_len(store, session_id, ids, messages)]
    return [bool(rows[i]["synthesized"]) for i in ids]




def ends_on_complete_pair(store: Any, session_id: str) -> bool:
    row = store.connection.execute(
        "SELECT truncated_by FROM session WHERE session_id = ?", (session_id,)).fetchone()
    return row is not None and row[0] is None
