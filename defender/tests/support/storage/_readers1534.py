"""#1534 reader machinery (no tests): plant a run's closing record, or a fault where it is read, through real primitives.

Production names are imported inside functions, so a missing one reds only the tests that use it. Faults are a
deleted file, a dropped table, a scalar column UPDATE, garbage bytes, a different schema version or a non-JSON pointer;
the structured columns are never encoded here."""
from __future__ import annotations

import sqlite3
import uuid
from pathlib import Path
from typing import Any

from defender.tests.storage.verdict_1534 import _spec1534 as V
from defender.tests.support.shared._locations_1210 import fixture_runs_base
from defender.tests.support.shared.contracts._spec1077 import fixture_run

#: Faults a reader meets at its slot, by the kind it must report. `NO_POINTER` is not a fault: it is `NeverClosed`.
NO_POINTER = "no-pointer"
KINDS_BY_FAULT = ("database-missing", "pointer-unreadable", "store-unreadable", "schema-version",
                  "recorded-before-1534", "row-invalid")
#: The two kinds every reader proves, and the one beside them that tells a missing database from a changed one.
TWO_KINDS = ("database-missing", "row-invalid")
#: The detail a fault carries must never reach a reader's outward slot: it names the database path.
DETAIL_MARK = "closing_record"


def valid_fields(disposition: str) -> dict[str, Any]:
    """Fields of a record the host could write for `disposition`: a close that stood (the design's invariant per outcome,
    so every member of `DISPOSITION_VALUES` is plantable)."""
    from defender.records import closing as C

    cause = {"unresolved": C.CAUSE_NOT_REVIEWED, "inconclusive": C.CAUSE_CEILING_EXAMINED}.get(
        disposition, C.CAUSE_STORY_SETTLED)
    return {"disposition": disposition, "cause": cause}


def ceiling_entry(note: str = "EDR execve logs for web-1 never came back", *, state: str | None = None,
                  ref: str | None = "l-001", cap: str | None = None) -> Any:
    from defender.records import closing as C

    return C.CeilingEntry(state=state or C.CEILING_STATES[0], ref=ref, cap=cap, note=note)


def baseline_entry(result: str = "no logins from this host in the prior 30 days", *, reasoning: str = "") -> Any:
    from defender.records import closing as C

    return C.BaselineEntry(
        lead="l-001", anchor_kind=C.ANCHOR_KINDS[0], grounding_kind=C.GROUNDING_KINDS[0], anchor_id="baseline-7",
        window_start="2026-10-01T00:00:00Z", window_end="2026-10-31T00:00:00Z", result=result, reasoning=reasoning)


def plant_run(run_dir: Path, fields: dict[str, Any] | None = None, *, fault: str | None = None,
              case_id: str | None = None, sessions_base: Path | None = None) -> Path | None:
    """`run_dir`'s session pointer, a real store behind it, and (when `fields` is not None) the run's closing record;
    then `fault` applied (`KINDS_BY_FAULT`), or `NO_POINTER` for a run that never opened a store. `fields=None` is a
    run with a pointer and a table but no row. Returns the database (None when no pointer or an unreadable one)."""
    from defender.records import SessionPaths
    from defender.records import session_store as ss

    run_dir = Path(run_dir)
    run = fixture_run(run_dir)
    if fault == NO_POINTER:
        return None
    if fault == "pointer-unreadable":
        run.observability.session_pointer.write("{not json")
        return None
    sessions = SessionPaths(fixture_runs_base(sessions_base or run_dir.parent))
    with ss.open_store(case_id=case_id or f"c1534-{uuid.uuid4().hex[:12]}", sessions=sessions) as store:
        store.new_session(agent_id="main")
        ss.write_case_pointer(run, case_id=store.case_id, store_path=store.path)
        if fields is not None:
            V.plant(store, V.a_record(run_dir.name, **fields))
        database = Path(store.path)
    break_database(database, run_dir.name, fault)
    return database


def break_database(database: Path, run_id: str, fault: str | None) -> None:
    """Apply `fault` to an existing database by a real primitive."""
    if fault is None:
        return
    if fault == "database-missing":
        for leftover in (database, Path(f"{database}-wal"), Path(f"{database}-shm")):
            leftover.unlink(missing_ok=True)
    elif fault == "recorded-before-1534":
        V.drop_table(database)
    elif fault == "row-invalid":
        V.corrupt(database, run_id, "disposition", "no-such-disposition")
    elif fault == "store-unreadable":
        database.write_bytes(b"this is not a database\n" * 64)
    elif fault == "schema-version":
        conn = sqlite3.connect(database, timeout=30)
        try:
            conn.execute("PRAGMA user_version = 99")
            conn.commit()
        finally:
            conn.close()
    else:
        raise AssertionError(f"no such fault: {fault}")


def names(kind: str, text: str) -> bool:
    """Does `text` carry `kind`'s fixed wording (`FAULT_WORDING[kind]`)?"""
    from defender.records import closing as C

    return C.FAULT_WORDING[kind] in text


def names_only(kind: str, text: str) -> bool:
    """`text` carries `kind`'s wording and no other kind's, so a reader cannot pass by naming a different fault."""
    from defender.records import closing as C

    others = [w for k, w in C.FAULT_WORDING.items() if k != kind and w not in C.FAULT_WORDING[kind]]
    return names(kind, text) and not any(w in text for w in others)


def fresh_case(label: str) -> str:
    """A case id of this test's own (a database no other test shares)."""
    return f"{label}-{uuid.uuid4().hex[:12]}"
