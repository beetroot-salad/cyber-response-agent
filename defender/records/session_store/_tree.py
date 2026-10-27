"""Session head and parent-chain traversal."""
from __future__ import annotations
import sqlite3
from defender.records._run_id import CASE_ID_RE  # noqa: F401 — re-export; the rule lives with the id rules
from defender.records._store_errors import InvalidCaseId, StoreError  # noqa: F401 — re-exports
from defender.records.run_end import (  # noqa: F401 — re-exports
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

from ._schema import CyclicParentChain



def _walk_parents(conn: sqlite3.Connection, tip: int) -> list[int]:
    """Tip-to-root row ids, refusing a cyclic chain. Shared by the reader (`path_row_ids`) and
    `append`'s write-time cycle guard. On a phantom id it returns it as the oldest element;
    `hydrate`/`synthesized_flags` fail closed on that.

    `gather_boundary`'s `WITH RECURSIVE` (in `DDL`) is a second, weaker implementation of this
    walk; a traversal change here must be made there too."""
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
