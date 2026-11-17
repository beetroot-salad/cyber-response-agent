"""The one lookup of a run's closing record, with three outcomes (#1534 V-LOOK).

`Record`, `NeverClosed`, or `CouldNotLook(kind, detail)`: no reader may turn a fault into an
absence. Each kind has fixed outward wording (`FAULT_WORDING`); `detail` names what was found
(paths included) and goes to the log only.

Routes, one per kind of holder, all ending in `read_database`: the run handle (`for_run`, the
database its host-written pointer recorded), the job lane (the database derived from the
pointer's case id, `job_lane`), and an episode's run view (roster -> arm run -> `for_run`)."""
from __future__ import annotations

import json
import os
import sqlite3
from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from defender._model import model
from defender.records._run_id import refuse_bad_case_id
from defender.records._store_errors import StoreError

from ._record import BaselineEntry, CeilingEntry, ClosingRecord

if TYPE_CHECKING:
    from defender.records._handle import Run


TABLE = "closing_record"

DATABASE_MISSING = "database-missing"
POINTER_UNREADABLE = "pointer-unreadable"
STORE_UNREADABLE = "store-unreadable"
SCHEMA_VERSION_KIND = "schema-version"
RECORDED_BEFORE_1534 = "recorded-before-1534"
LEGACY_LINK = "legacy-link"
ROSTER_GONE = "roster-gone"
ARM_REFUSED = "arm-refused"
ROW_INVALID = "row-invalid"
FAULT_KINDS: tuple[str, ...] = (
    DATABASE_MISSING, POINTER_UNREADABLE, STORE_UNREADABLE, SCHEMA_VERSION_KIND, RECORDED_BEFORE_1534,
    LEGACY_LINK, ROSTER_GONE, ARM_REFUSED, ROW_INVALID,
)
#: The worker's message for a job whose end says the close committed while the run has no
#: closing record. Not a lookup kind: the lookup's answer there is `NeverClosed`.
COMMITTED_WITHOUT_RECORD = "committed-without-record"

#: Each kind's fixed outward wording, and the worker's committed-but-no-row message. No reader
#: shows `detail`; these sentences name no path, case or run.
FAULT_WORDING: Mapping[str, str] = MappingProxyType({
    DATABASE_MISSING: "The run's closing record could not be read: its session database is no longer where "
                      "the run recorded it.",
    POINTER_UNREADABLE: "The run's closing record could not be read: the record of which session database "
                        "holds it is unreadable.",
    STORE_UNREADABLE: "The run's closing record could not be read: its session database could not be opened "
                      "or queried.",
    SCHEMA_VERSION_KIND: "The run's closing record could not be read: its session database is at a schema "
                         "version this code does not read.",
    RECORDED_BEFORE_1534: "The run's closing record could not be read: the run was recorded before closing "
                          "records were kept in its session database.",
    LEGACY_LINK: "The run's closing record could not be read: the run was recorded before #1235, and which "
                 "session database holds it is unknown.",
    ROSTER_GONE: "The run's closing record could not be read: the episode's arm roster is missing.",
    ARM_REFUSED: "The run's closing record could not be read: the episode's arm run was refused or is gone.",
    ROW_INVALID: "The run's closing record could not be read: its stored row is not a valid closing record.",
    COMMITTED_WITHOUT_RECORD: "The run reported a committed close, but no closing record exists for it.",
})


@model(frozen=True)
class Record:
    """The run's closing record."""

    record: ClosingRecord


@model(frozen=True)
class NeverClosed:
    """The run has no closing record: no pointer, or the database's table has no row for it."""


@model(frozen=True)
class CouldNotLook:
    """The lookup could not answer. `kind` is one of `FAULT_KINDS`; `detail` is for the log."""

    kind: str
    detail: str

    def __post_init__(self) -> None:
        if self.kind not in FAULT_KINDS:
            raise ValueError(f"{self.kind!r} is not a lookup fault kind {FAULT_KINDS}")

    @property
    def wording(self) -> str:
        """The kind's fixed outward wording."""
        return FAULT_WORDING[self.kind]


Lookup = Record | NeverClosed | CouldNotLook

_COLUMNS = ("disposition", "outcome", "cause", "failure_kind", "drafted_disposition", "ceiling_test",
            "runtime_evidence", "summary")


def fault(kind: str, detail: str, *, run_id: object = "") -> CouldNotLook:
    """A `CouldNotLook`. Not logged here: a CLI's log is its stderr, an outward slot, so each
    reader with a log of its own (the worker, the ticket leg, the run page) logs `detail`."""
    del run_id  # the route's own name for the run, kept at every call site for the readers' logs
    return CouldNotLook(kind=kind, detail=detail)


def for_run(run: Run) -> Lookup:
    """The run-handle route: the database the run's host-written pointer recorded."""
    run_id = str(run.id)
    pointer = run.observability.session_pointer
    try:
        read = pointer.read_result()
    except OSError as e:
        return fault(POINTER_UNREADABLE, f"the session pointer {pointer.path} cannot be read: {e!r}", run_id=run_id)
    if read.absent:
        # The pre-#1235 link is consulted only when no pointer sits beside the folder: it lives
        # in the box-writable folder, so it never outranks the host's pointer.
        from defender.records.session_store import _LEGACY_LINK_NAME

        if os.path.lexists(Path(run.run_dir) / _LEGACY_LINK_NAME):
            return fault(LEGACY_LINK, f"{run.run_dir} holds a pre-#1235 link and no pointer", run_id=run_id)
        return NeverClosed()
    if read.text is None:
        return fault(POINTER_UNREADABLE, f"the session pointer {pointer.path} cannot be read: {read.reason}",
                     run_id=run_id)
    database = _pointer_database(read.text)
    if isinstance(database, str):
        return fault(POINTER_UNREADABLE, f"the session pointer {pointer.path} {database}", run_id=run_id)
    return read_database(database, run_id)


def for_run_dir(run_dir: Path) -> Lookup:
    """`for_run` over the handle of the run folder `run_dir` under its runs folder: for a view or
    a scorer handed a folder rather than a `Run`."""
    from defender.records._lookup import run_of_folder

    return for_run(run_of_folder(Path(run_dir)))


def _pointer_database(text: str) -> Path | str:
    """The database a pointer's text names, or why it names none usable."""
    try:
        data = json.loads(text)
    except ValueError as e:
        return f"is not JSON ({e})"
    if not isinstance(data, dict):
        return "is not a JSON object"
    store_path = data.get("store_path")
    if not isinstance(store_path, str) or not store_path:
        return "names no store_path"
    try:
        refuse_bad_case_id(data.get("case_id"))
    except StoreError as e:
        return f"names no usable case id ({e})"
    return Path(store_path)


def read_database(database: Path, run_id: str) -> Lookup:
    """The row read every route ends in: `run_id`'s closing record in `database`."""
    from defender.records import session_store as ss

    database = Path(database)
    if not database.exists():
        return fault(DATABASE_MISSING, f"the session database {database} does not exist", run_id=run_id)
    try:
        with ss.open_store_for_read(database) as store:
            conn = store.connection
            if conn.execute("SELECT 1 FROM sqlite_master WHERE name = ?", (TABLE,)).fetchone() is None:
                return fault(RECORDED_BEFORE_1534, f"{database} has no {TABLE} table", run_id=run_id)
            row = conn.execute(
                f"SELECT {', '.join(_COLUMNS)} FROM {TABLE} WHERE run_id = ?", (run_id,)).fetchone()  # noqa: S608
    except ss.UnknownSchemaVersion as e:
        return fault(SCHEMA_VERSION_KIND, f"{database}: {e}", run_id=run_id)
    except FileNotFoundError as e:
        return fault(DATABASE_MISSING, f"{database}: {e!r}", run_id=run_id)
    except (OSError, sqlite3.Error, StoreError) as e:
        return fault(STORE_UNREADABLE, f"{database}: {e!r}", run_id=run_id)
    if row is None:
        return NeverClosed()
    try:
        return Record(record=_row_record(run_id, dict(zip(_COLUMNS, row, strict=True))))
    except (ValueError, TypeError) as e:
        return fault(ROW_INVALID, f"{database}: the row of {run_id} is not a valid record: {e}", run_id=run_id)


def _row_record(run_id: str, row: dict[str, Any]) -> ClosingRecord:
    ceiling = [CeilingEntry(**entry) for entry in _entries(row["ceiling_test"])]
    baselines = [BaselineEntry(**entry) for entry in _entries(row["runtime_evidence"])]
    return ClosingRecord(
        run_id=run_id, disposition=row["disposition"], outcome=row["outcome"], cause=row["cause"],
        failure_kind=row["failure_kind"], drafted_disposition=row["drafted_disposition"],
        ceiling_test=tuple(ceiling), runtime_evidence=tuple(baselines), summary=row["summary"])


def _entries(stored: object) -> list[dict[str, Any]]:
    """A structured column's entries: a JSON array of objects."""
    if not isinstance(stored, str):
        raise ValueError(f"a structured column holds {type(stored).__name__}, not JSON text")
    entries = json.loads(stored)
    if not isinstance(entries, list) or not all(isinstance(e, dict) for e in entries):
        raise ValueError("a structured column is not an array of objects")
    return entries


def encode_entries(entries: tuple[CeilingEntry, ...] | tuple[BaselineEntry, ...]) -> str:
    """A structured column's stored form (the inverse of the read)."""
    import dataclasses

    return json.dumps([dataclasses.asdict(e) for e in entries], ensure_ascii=False, sort_keys=True)
