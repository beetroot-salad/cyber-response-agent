"""The exec seam's contract: a payload, or an exception. Never a status code.

Every call the controller makes into the stack either returns what the
backend answered or raises one of these, so "backend down" can never be
mistaken for "nothing there", nor an error body for success. The test fake
honours the same contract.
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
