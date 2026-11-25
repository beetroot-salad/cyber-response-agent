"""Run-to-session pointer records."""
from __future__ import annotations
import dataclasses
import json
import os
from pathlib import Path
from typing import Any

from defender import _io
from defender.records._run_id import CASE_ID_RE, refuse_bad_case_id  # noqa: F401 — re-export; the rule lives with the id rules
from defender.records import Run
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

from ._schema import LegacyRunLink, _LEGACY_LINK_NAME



def write_case_pointer(
    run: Run, *, case_id: str, store_path: Path, session_id: str | None = None,
) -> None:
    """Record which database holds this run's messages, and which session in it is the run's.

    `session_id` is needed for a resumed run: a sibling forks into the source's database, so
    the store's root session is the source run's. Omitted for a fresh run, where readers fall
    back to the root correctly.

    The database is recorded relative to the run's folder (#1546 design "Session pointer"), so a run moved whole with its
    tenant's sessions (a bundle unpacked under another root) still names its own; `run_store_path` reads it back.
    """
    recorded = os.path.relpath(os.path.abspath(store_path), os.path.abspath(run.run_dir))
    body: dict = {"case_id": case_id, "store_path": recorded, CLOSING_RECORD_MARKER: True}
    if session_id is not None:
        body["session_id"] = session_id
    run.observability.session_pointer.write(json.dumps(body))


#: The pointer's mark that its run keeps its closing record in its session database (#1534 r3.3 N1). Code before
#: #1534 never wrote it, so a run whose pointer lacks it was recorded before closing records were kept, whatever its
#: database holds now: one case's database holds runs of both eras, since re-runs and branch arms join it.
CLOSING_RECORD_MARKER = "closing_record"


class PointerUnreadable(StoreError):
    """A session pointer that does not parse, or names no usable case."""


@dataclasses.dataclass(frozen=True)
class CasePointer:
    """A session pointer, parsed. `recorded` is the path the writer recorded, relative to the run's folder: only
    `database` names the file. A reader that must agree with the job lane derives the database from `case_id` instead
    (`SessionPaths.session_db`)."""

    case_id: str
    recorded: str
    session_id: str | None
    keeps_closing_record: bool

    def database(self, run_dir: Path) -> Path:
        """The database this pointer names for the run folder `run_dir` (`run_store_path`)."""
        return run_store_path(run_dir, self.recorded)


def run_store_path(run_dir: Path, recorded: str) -> Path:
    """The one resolver of a pointer's recorded database: `recorded` joined to the run's folder, lexically (no walk
    through the box-writable run folder resolves a link in it)."""
    return Path(os.path.normpath(os.path.join(os.path.abspath(run_dir), recorded)))


def parse_case_pointer(text: str) -> CasePointer:
    """A pointer's text, parsed: shared by the closing lookup's two routes (the run handle, the job lane's held view)
    and the job lane's cost read. `PointerUnreadable` names why it is not a pointer."""
    # The project's one decode of a JSON artifact: it refuses nesting deep enough to raise `RecursionError`.
    data, unreadable = _io.load_json_artifact(text)
    if unreadable is not None:
        raise PointerUnreadable(f"is not JSON ({unreadable})")
    if not isinstance(data, dict):
        raise PointerUnreadable("is not a JSON object")
    store_path = data.get("store_path")
    if not isinstance(store_path, str) or not store_path:
        raise PointerUnreadable("names no store_path")
    try:
        refuse_bad_case_id(data.get("case_id"))
    except StoreError as e:
        raise PointerUnreadable(f"names no usable case id ({e})") from None
    session_id = data.get("session_id")
    if session_id is not None and not isinstance(session_id, str):
        raise PointerUnreadable("names no usable session")
    marker = data.get(CLOSING_RECORD_MARKER, False)
    if not isinstance(marker, bool):
        raise PointerUnreadable(f"has a {CLOSING_RECORD_MARKER!r} that is not true or false")
    return CasePointer(case_id=data["case_id"], recorded=store_path, session_id=session_id or None,
                       keeps_closing_record=marker)




def refuse_legacy_link(run_dir: Path) -> None:
    """`LegacyRunLink` when `run_dir` still holds the link it was recorded with before #1235.

    For a folder with no link beside it: a link beside the folder always wins, and a folder
    with neither (a hand-copied run) has no session."""
    run_dir = Path(run_dir)
    if os.path.lexists(run_dir / _LEGACY_LINK_NAME):
        raise LegacyRunLink(
            f"run {run_dir.name} was recorded before #1235: its run -> case link is still "
            f"inside the run folder ({_LEGACY_LINK_NAME}) and none sits beside it, so the case "
            "it belongs to is unknown. Runs recorded before #1235 are not read; re-run it.")




def _case_pointer(run: Run) -> Any:
    """The run -> case link beside `run_dir`, parsed. `FileNotFoundError` when there is none,
    `LegacyRunLink` when the run was recorded before #1235."""
    try:
        result = run.observability.session_pointer.read_result()
        if result.absent:
            raise FileNotFoundError(str(run.observability.session_pointer.path))
        if result.text is None:
            raise OSError(result.reason)
        text = result.text
    except FileNotFoundError:
        refuse_legacy_link(run.run_dir)
        raise
    return json.loads(text)




def resolve_store_path(run: Run) -> Path:
    """The database `run`'s pointer names, through the one run-relative resolver (`run_store_path`)."""
    data = _case_pointer(run)
    recorded = data.get("store_path") if isinstance(data, dict) else None
    if not isinstance(recorded, str) or not recorded:
        raise PointerUnreadable(f"the session pointer of run {run.run_dir.name} names no store_path")
    return run_store_path(run.run_dir, recorded)




def resolve_session_id(run: Run) -> str | None:
    """The session this run owns, or `None` when the pointer names none (a fresh run); the
    caller then falls back to `main_session_id`.
    """
    data = _case_pointer(run)
    session_id = data.get("session_id")
    return session_id if isinstance(session_id, str) and session_id else None
