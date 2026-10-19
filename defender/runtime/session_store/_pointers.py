"""Run-to-session pointer records."""
from __future__ import annotations
import json
import os
from pathlib import Path
from typing import Any
from defender.records._run_id import CASE_ID_RE  # noqa: F401 — re-export; the rule lives with the id rules
from defender.run_repository import Run
from defender.records._store_errors import InvalidCaseId, StoreError  # noqa: F401 — re-exports
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

from ._schema import LegacyRunLink, _LEGACY_LINK_NAME



def write_case_pointer(
    run: Run, *, case_id: str, store_path: Path, session_id: str | None = None,
) -> None:
    """Record which database holds this run's messages, and which session in it is the run's.

    `session_id` is needed for a resumed run: a sibling forks into the source's database, so
    the store's root session is the source run's. Omitted for a fresh run, where readers fall
    back to the root correctly.
    """
    body: dict = {"case_id": case_id, "store_path": str(store_path)}
    if session_id is not None:
        body["session_id"] = session_id
    run.observability.session_pointer.write(json.dumps(body))




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
    data = _case_pointer(run)
    return Path(data["store_path"])




def resolve_session_id(run: Run) -> str | None:
    """The session this run owns, or `None` when the pointer names none (a fresh run); the
    caller then falls back to `main_session_id`.
    """
    data = _case_pointer(run)
    session_id = data.get("session_id")
    return session_id if isinstance(session_id, str) and session_id else None
