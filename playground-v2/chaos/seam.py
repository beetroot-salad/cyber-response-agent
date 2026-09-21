"""The exec seam's contract: a payload, or an exception. Never a status code.

Every call the controller makes into the stack (`cmdb_request`, `es_request`,
`read_container_file`) either returns what the backend answered or raises
one of these. There is no third outcome for a caller to interpret, so "the
backend was down" can never be mistaken for "nothing there", and an HTTP
error body can never be recorded as a success. `chaos/tests/_fakes.py`'s
fake seam honours the same contract, which is what lets the unit suite pin
the failure paths the real seam takes.
"""
from __future__ import annotations

from typing import Any, Optional


class SeamError(RuntimeError):
    """The stack did not answer, or answered with an error status."""

    def __init__(self, message: str, *, status: Optional[int] = None, payload: Any = None) -> None:
        super().__init__(message)
        self.status = status
        self.payload = payload


class SeamNotFound(SeamError):
    """HTTP 404 — the one error a caller may legitimately treat as 'absent'
    (a pipeline that does not exist yet is a valid before-state)."""
