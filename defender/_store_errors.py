"""The session store's error root and its case-id refusal — stdlib only.

Here rather than in `runtime/session_store.py` because the store's path owner
(`_run_paths.SessionPaths`) raises `InvalidCaseId`, and the owner must import with no
third-party package installed (the box entrypoint's closure); `session_store` pulls in
pydantic-ai. `session_store` re-exports both names, so every caller keeps its import.
"""
from __future__ import annotations


class StoreError(Exception):
    """Base for every failure this store raises on its own behalf.

    The driver catches THIS (alongside `sqlite3.Error`) to end a run through the handled
    `truncated_by` exit. A new store exception that does not inherit from it propagates out
    of the `ProcessHistory` hook and takes the whole `run.py` process down instead.
    """


class InvalidCaseId(StoreError, ValueError):
    """A `case_id` does not conform to the store's slug shape, or is not case-stable; refused,
    not sanitized. A `StoreError`, so the driver's store-setup handler ends the run through the
    handled exit; still a `ValueError`, as it always was, for callers that catch that."""
