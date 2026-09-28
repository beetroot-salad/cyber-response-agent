"""The session store's error root and its bad-case-id error — stdlib only.

Kept out of `runtime/session_store.py` (which pulls in pydantic-ai) because
`_run_paths.SessionPaths` raises `InvalidCaseId` and must import with no third-party package
installed. `session_store` re-exports both names.
"""
from __future__ import annotations


class StoreError(Exception):
    """Base for every failure this store raises on its own behalf.

    The driver catches this (alongside `sqlite3.Error`) to end a run through the handled
    `truncated_by` exit; a store exception outside it crashes the `run.py` process.
    """


class InvalidCaseId(StoreError, ValueError):
    """A `case_id` that is not a case-stable slug; refused, not sanitized. Also a `ValueError`
    for callers that catch that."""
