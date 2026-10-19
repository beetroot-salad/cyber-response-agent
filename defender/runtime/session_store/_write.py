"""Store connections and append-only writes."""
from __future__ import annotations
import contextlib
import hashlib
import json
import math
import sqlite3
import uuid
from dataclasses import field
from defender._model import model
from pathlib import Path
from typing import Any
from pydantic_ai.messages import (
    ModelMessagesTypeAdapter,
    ModelRequest,
)
from defender._io import guarded_mkdir
from defender._run_id import CASE_ID_RE  # noqa: F401 — re-export; the rule lives with the id rules
from defender.run_repository import SessionPaths
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

from ._payload import _extract_lead_id, _find_nonrepresentable, _tool_name
from ._read import _fetch_payloads, _require_resolved
from ._schema import DDL, HEAD_MOVE_REASONS, IncompleteConfig, PAYLOAD_ENSURE_ASCII, PayloadNotRepresentable, SCHEMA_VERSION, STORE_BUSY_TIMEOUT_MS, StoreAppendError, _CONFIG_REQUIRED_FIELDS, _MAX_PAYLOAD_DEPTH, _TOO_DEEP, _refuse_stale_version
from ._tree import _read_head, _walk_parents



def _bare_connect(path: Path) -> sqlite3.Connection:
    """A connection with no pragma and no function registered yet — so a stale-version
    refusal can fire before the WAL pragma rewrites the file's header."""
    return sqlite3.connect(str(path), timeout=STORE_BUSY_TIMEOUT_MS / 1000,
                           isolation_level=None)




def _finish_connect(conn: sqlite3.Connection) -> None:
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute(f"PRAGMA busy_timeout = {STORE_BUSY_TIMEOUT_MS}")
    conn.create_function("extract_lead_id", 1, _extract_lead_id)




# the handle

@model
class StoreHandle:
    """One `sqlite3.Connection` shared by the main agent's session and every concurrent
    gather sub-agent's session.

    Safe only because `append()`'s `BEGIN IMMEDIATE … COMMIT` block contains no `await`:
    parallel `gather` calls are asyncio tasks on one thread, so they cannot interleave within
    a transaction. Adding an `await` there would corrupt transactions; give each session its
    own connection first.
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

        The branch point becomes the new session's `head_message_id` and its own
        `session_head_log` entry, both inside one `BEGIN IMMEDIATE`: a fault between the two
        writes would leave a session with a head and no branch-point record.

        `last_render_len` is seeded to the send-role length of the inherited prefix: the whole
        prefix, since its tail is the fork point, which send-role reads keep even when it is a
        response whose tool calls are still unanswered (#1255 D1: the resumed run's framework
        runs those calls)."""
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
            prefix_ids = _walk_parents(conn, at_message_id)
            prefix_ids.reverse()
            prefix_payloads = _fetch_payloads(conn, prefix_ids)
            _require_resolved(prefix_ids, prefix_payloads)
            # The fork point is the child's head, so the whole prefix — a call-bearing
            # response at its tail included (#1255 D1) — is what the child is charged for:
            # `hydrate(role="send")` hands the same list back (`_send_len`).
            prefix_len = len(prefix_ids)
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
            prev_head, first_parent, _is_linear = _classify_move(
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
                      attached_to=first_parent, reason=reason)
            conn.execute("COMMIT")
            committed = True
            conn.execute("SELECT 1")
        except BaseException:
            # Past COMMIT there is no transaction, and `ROLLBACK` would raise an unrelated
            # error that masks the original even though the rows are durable.
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

    def write_fork_snapshot(self, session_id: str, request: int, body: str,
                            blobs: dict[str, str]) -> None:
        """Record one fork snapshot (the `fork_snapshot` DDL comment), with the texts it names
        by digest. One transaction, so a snapshot is never left naming a blob that is not
        there. A second write for the same response replaces the first."""
        conn = self.connection
        conn.execute("BEGIN IMMEDIATE")
        committed = False
        try:
            for sha, text in blobs.items():
                conn.execute("INSERT INTO fork_snapshot_blob (sha256, body) VALUES (?, ?) "
                             "ON CONFLICT(sha256) DO NOTHING", (sha, text))
            conn.execute(
                "INSERT INTO fork_snapshot (session_id, request, body) VALUES (?, ?, ?) "
                "ON CONFLICT(session_id, request) DO UPDATE SET body = excluded.body",
                (session_id, request, body))
            conn.execute("COMMIT")
            committed = True
        except BaseException:
            if not committed:
                with contextlib.suppress(sqlite3.Error):
                    conn.execute("ROLLBACK")
            raise

    def fork_snapshot(self, session_id: str, request: int) -> str | None:
        """The fork snapshot `session_id` recorded at its `request`-th response, or `None`."""
        row = self.connection.execute(
            "SELECT body FROM fork_snapshot WHERE session_id = ? AND request = ?",
            (session_id, request)).fetchone()
        return row[0] if row is not None else None

    def fork_snapshot_blob(self, sha256: str) -> str | None:
        row = self.connection.execute(
            "SELECT body FROM fork_snapshot_blob WHERE sha256 = ?", (sha256,)).fetchone()
        return row[0] if row is not None else None

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> StoreHandle:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()




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
    """`duration_ms` is bound directly into the INSERT and skips `_find_nonrepresentable`.
    Unchecked, SQLite stores NaN as NULL and inf round-trips to the invalid JSON `Infinity`.

    Not a pydantic strict-`float` check: that accepts `Decimal`/`Fraction` by coercion, while
    the original value is what gets bound, and sqlite3 would reject it mid-transaction with an
    error no caller handles."""
    if duration_ms is None:
        return
    if isinstance(duration_ms, bool) or not isinstance(duration_ms, (int, float)):
        raise PayloadNotRepresentable(
            f"duration_ms must be a real number, got {duration_ms!r}")
    if not math.isfinite(duration_ms):
        raise PayloadNotRepresentable(f"cannot store {duration_ms!r} as duration_ms")




def _validate_reason(reason: str | None) -> None:
    """Membership by exact match, whenever `reason` is not `None` — before the empty-batch
    short-circuit and before the move's linearity is classified."""
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
    """Resolve the first row's parent, refuse write-time hazards (orphaning rows, cycles, a
    non-linear move without a reason), and classify the move. Returns
    `(prev_head, first_parent, is_linear)`."""
    prev_head = _read_head(conn, session_id)
    first_parent = parent_id if parent_id is not None else prev_head
    if first_parent is None and _session_has_rows(conn, session_id):
        raise StoreAppendError(
            "append into a session that holds rows but has no recorded head is "
            "refused rather than silently orphaning them")
    if first_parent is not None:
        _walk_parents(conn, first_parent)  # write-time cycle guard
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




def _move_head(
    conn: sqlite3.Connection, session_id: str, *, prev_head: int | None, new_head: int,
    attached_to: int | None, reason: str | None,
) -> None:
    """`is_linear` is derived here (`attached_to == prev_head`) rather than passed, so it
    cannot disagree with the fields it comes from."""
    conn.execute(
        "UPDATE session SET head_message_id = ? WHERE session_id = ?",
        (new_head, session_id))
    is_linear = attached_to == prev_head
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




# open / resolve

def store_path_for(case_id: str, *, sessions: SessionPaths) -> Path:
    """The store for `case_id`, as the layout owner's `sessions` (a run's
    `RunPaths.session_paths()`) names it (#1105 fork S(b)). Raises `InvalidCaseId` for a
    malformed or non-case-stable id."""
    store, _root = sessions.store(case_id)
    return store




def open_store(*, case_id: str, sessions: SessionPaths) -> StoreHandle:
    """The store for `case_id`, created if missing. The layout owner (`sessions`, a run's
    `RunPaths.session_paths()`) hands over both the store's path and the root its directory
    is made under (#1105 fork S(b)): this module reads neither a runs base nor a trust root."""
    # The store's path and the root its directory is made under, from the owner's one
    # hand-out (the one `store_path_for`, which the resume door asks, reads too), asked once.
    path, root = sessions.store(case_id)
    guarded_mkdir(path.parent, base=root)
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
    """Open an existing store file for reading; never creates one, so a reader fails closed
    instead of conjuring an empty database. Refuses a stale version before DDL/WAL.

    Issues no DDL, so an older file may still carry an unscoped `gather_boundary` view with
    the same `SCHEMA_VERSION`; a reader of that view must rebuild it first."""
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
