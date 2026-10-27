"""Shared machinery for the #754 head-pointer + head-log spec suite — NO test scripts."""
from __future__ import annotations

from defender.tests.support.shared.contracts._spec1077 import fixture_run as _run_handle_1165

import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Any, NamedTuple

import pytest

pytest.importorskip("pydantic_ai")

from defender.tests.support.storage._session_store_705 import (  # noqa: E402
    DEFENDER,
    store_mod,
    user_request,
)


# the observation channel for the two new pieces of state

class LogRow(NamedTuple):
    """One `session_head_log` row as the file holds it.

    Six columns: `attached_to_message_id` is the FIRST inserted row's own
    `parent_id`, which is neither `from_message_id` (the DISPLACED head) nor
    `to_message_id` (the NEW head) — the misreading one of the three answering copies made
    and the reason the column exists.
    """

    id: int
    session_id: str
    from_message_id: int | None
    to_message_id: int
    attached_to_message_id: int | None
    reason: str


_LOG_COLUMNS = ("id, session_id, from_message_id, to_message_id, "
                "attached_to_message_id, reason")


def head_of(store: Any, session_id: str) -> int | None:
    """`session.head_message_id` for one session, read raw. `None` for SQL NULL AND for a
    session that does not exist — the caller distinguishes them by construction."""
    row = store.connection.execute(
        "SELECT head_message_id FROM session WHERE session_id = ?", (session_id,)).fetchone()
    return row[0] if row is not None else None


def log_rows(store: Any, session_id: str | None = None) -> list[LogRow]:
    """Every `session_head_log` row in `id` order, optionally scoped to one session."""
    if session_id is None:
        rows = store.connection.execute(
            f"SELECT {_LOG_COLUMNS} FROM session_head_log ORDER BY id").fetchall()
    else:
        rows = store.connection.execute(
            f"SELECT {_LOG_COLUMNS} FROM session_head_log WHERE session_id = ? ORDER BY id",
            (session_id,)).fetchall()
    return [LogRow(*r) for r in rows]


def message_ids(store: Any, session_id: str) -> list[int]:
    """Every `message` row id this session owns, in insertion order — the channel that
    still reads insertion order, so a test can say what head does NOT follow."""
    return [r[0] for r in store.connection.execute(
        "SELECT id FROM message WHERE session_id = ? ORDER BY id", (session_id,)).fetchall()]


def linear_turns(store: Any, session_id: str, n: int, *, agent_id: str = "main",
                 label: str = "turn") -> list[int]:
    """`n` ordinary turns: one single-message append each, no explicit parent, no reason.
    Every one is linear under the rule, so the log stays untouched and head advances once
    per call."""
    ids: list[int] = []
    for i in range(n):
        ids.extend(store.append(session_id, [user_request(f"{label}-{i}")], agent_id=agent_id))
    return ids


# a real, hand-built store file at the schema version this change refuses

#: The `session` table as #705 first shipped it — before `_migrate_session_columns`'
#: two ALTERs. B7 (executed) measured the shim growing exactly this table from five
#: columns to seven, with no version check and no error; D3 deletes the shim.
_V1_SESSION_PRE_MIGRATION = """
CREATE TABLE session (
    session_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    parent_session_id TEXT REFERENCES session(session_id),
    truncated_by TEXT,
    last_render_len INTEGER
) STRICT;
"""

#: The `session` table as #744 shipped it: seven columns, `fork_at_message_id` among them,
#: and no `head_message_id`.
_V1_SESSION_MIGRATED = """
CREATE TABLE session (
    session_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    parent_session_id TEXT REFERENCES session(session_id),
    agent_id TEXT,
    fork_at_message_id INTEGER REFERENCES message(id),
    truncated_by TEXT,
    last_render_len INTEGER
) STRICT;
"""

_V1_REST = """
CREATE TABLE config (
    sha256 TEXT PRIMARY KEY,
    body TEXT NOT NULL
) STRICT;

CREATE TABLE message (
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

CREATE TABLE message_payload (
    message_id INTEGER PRIMARY KEY REFERENCES message(id),
    payload TEXT NOT NULL,
    payload_sha TEXT NOT NULL
) STRICT;
"""


def legacy_v1_store_file(path: Path, *, migrated: bool = True) -> Path:
    """Write a real SQLite store file carrying the shape #705/#744 shipped, stamped
    `PRAGMA user_version = 1`."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.executescript(
        (_V1_SESSION_MIGRATED if migrated else _V1_SESSION_PRE_MIGRATION) + _V1_REST)
    conn.execute("PRAGMA user_version = 1")
    conn.commit()
    conn.close()
    return path


def file_shape(path: Path) -> dict:
    """The observable shape of a store file: its schema objects, the `session` columns, the
    journal mode and the stamped version — read through a throwaway connection that issues
    no DDL and no pragma WRITE of its own."""
    conn = sqlite3.connect(str(path))
    try:
        return {
            "objects": sorted(r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").fetchall()),
            "session_columns": [r[1] for r in conn.execute(
                "PRAGMA table_info(session)").fetchall()],
            "journal_mode": conn.execute("PRAGMA journal_mode").fetchone()[0].lower(),
            "user_version": conn.execute("PRAGMA user_version").fetchone()[0],
        }
    finally:
        conn.close()


def sidecars(path: Path) -> list[str]:
    """The `-wal` / `-shm` files sitting beside a store path. PR-12 (executed): a raise
    propagating out of `open_store` without the caller ever getting a handle to close
    LEAKS both until process exit, so their absence after a refusal is the observable
    half of "the gate closes the connection before re-raising"."""
    return [s for s in ("-wal", "-shm") if Path(str(path) + s).exists()]


# the one injected fault object, and the loose-class call helper

class NotSerializable:
    """A message object the REAL serializer refuses — B8's "an object dump_python rejects".

    It carries an empty `parts` so `append`'s `_tool_name` and its pre-transaction
    `_find_nonrepresentable` scan both pass it through untouched; the refusal then lands
    inside `BEGIN IMMEDIATE`, at `ModelMessagesTypeAdapter.dump_python`, AFTER any earlier
    message in the same batch has already been inserted. Nothing here names an exception
    class: the real primitive raises whatever it really raises.
    """

    parts: tuple = ()


def session_analysis(run_dir: Path) -> list[tuple[Any, str]]:
    """Resolve the run's OWN session — else the store's root-of-lineage main — and hydrate
    its path in both roles.

    This composition used to live in the deleted transcript renderer, which is why the tests
    that pin it read as being about a page. They are not: what they pin is
    `resolve_session_id` falling back to `main_session_id`, and that pick refusing zero or
    several roots rather than choosing one. `investigation/branch/_frontier.py` is the production
    caller that still depends on both.
    """
    ss = store_mod()
    with ss.open_store_for_read(ss.resolve_store_path(_run_handle_1165(Path(run_dir)))) as store:
        session_id = ss.resolve_session_id(_run_handle_1165(Path(run_dir))) or ss.main_session_id(store)
        messages = ss.hydrate(store, session_id, role="analysis")
        coords = ss.hydrate(store, session_id, role="actor")
        return list(zip(messages, [c["coord"] for c in coords], strict=True))


def raised_by(fn: Any, *args: Any, **kwargs: Any) -> BaseException | None:
    """Call `fn` and hand back the exception it raised, or `None` if it returned.

    For the cases where the spec deliberately leaves the exception CLASS unpinned — P2's
    STRICT type violation ("the test asserts the rollback, not the class") and the
    root-of-lineage refusal — so the assertion can be about the outcome without a
    `pytest.raises(Exception)` that would pass on any incidental programming error.
    """
    try:
        fn(*args, **kwargs)
    except Exception as exc:  # noqa: BLE001 — the class is the thing deliberately unpinned
        return exc
    return None


DELIBERATE = (AttributeError, NameError, TypeError, IndexError, KeyError)


# the cross-process read (C11/F6: the visualizer is the only one)

_READBACK = """
import json, sys
from defender.records import session_store as ss

store = ss.open_store_for_read(sys.argv[1])
out = {}
for session_id in sys.argv[2:]:
    head = store.connection.execute(
        "SELECT head_message_id FROM session WHERE session_id = ?", (session_id,)).fetchone()
    log = store.connection.execute(
        "SELECT id, session_id, from_message_id, to_message_id, attached_to_message_id, "
        "reason FROM session_head_log WHERE session_id = ? ORDER BY id", (session_id,)
    ).fetchall()
    out[session_id] = {
        "head": head[0] if head is not None else None,
        "path": ss.path_row_ids(store, session_id),
        "log": [list(r) for r in log],
    }
print(json.dumps(out))
"""


def fresh_process_readback(store_path: Path, *session_ids: str) -> dict:
    """Read head, path and log back out of the file in a REAL second interpreter.

    Not a second handle in this process: C11 established the store is reached from two
    processes and that the visualizer — a separate `python presentation/...` run — is
    the only cross-process reader, so "reads back identically from a second process" is
    tested as one.
    """
    env = {**os.environ, "PYTHONPATH": str(DEFENDER.parent)}
    proc = subprocess.run(
        [sys.executable, "-c", _READBACK, str(store_path), *session_ids],
        capture_output=True, text=True, env=env, check=False,
    )
    assert proc.returncode == 0, (
        f"the second process could not read the store back: {proc.stderr.strip()}")
    return json.loads(proc.stdout)
