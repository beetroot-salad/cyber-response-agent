"""What a fetch or delivery fault means: `transient` (an outage that may pass by itself) or `lasting` (a retry changes
nothing). P3 folds git, forge, auth and OS faults into one `DeliveryRefused`; the fault it was raised from stays its
cause, and `classify` reads that chain. Drains use the split for the person ceiling; the fetch child reports it."""

from __future__ import annotations

import re
import subprocess

import httpx

from defender import _git
from defender._text import one_line
from defender.tenancy import RecordsUnreachable

from .forgejo import ForgeError

TRANSIENT, LASTING = "transient", "lasting"
#: What git says when it could not reach the remote at all (no answer, not a refusal).
_GIT_UNREACHABLE = re.compile(
    r"could not resolve host|failed to connect|connection refused|connection reset|"
    r"connection timed out|operation timed out|timed out after|operation too slow|"
    r"empty reply from server|network is unreachable|returned error: 5\d\d|"
    r"unexpected disconnect|early eof|recv failure|send failure",
    re.IGNORECASE,
)
#: The most of a forge's error body a reason carries.
_BODY_LIMIT = 400


def _chain(error: BaseException) -> list[BaseException]:
    seen: list[BaseException] = []
    at: BaseException | None = error
    while at is not None and all(at is not s for s in seen):
        seen.append(at)
        at = at.__cause__ or at.__context__
    return seen


def classify(error: BaseException) -> tuple[str, str]:
    """`(kind, one-line reason)` of a fault: `transient` or `lasting`."""
    reason = str(error)
    for fault in _chain(error):
        if isinstance(fault, httpx.HTTPStatusError) and any(isinstance(f, ForgeError) for f in _chain(error)):
            body = fault.response.text[:_BODY_LIMIT] if fault.response is not None else ""
            if body:
                reason = f"{reason}: {body}"
            break
    return _fault_kind(error), one_line(reason)


def _fault_kind(error: BaseException) -> str:
    for fault in _chain(error):
        if isinstance(fault, (httpx.TransportError, subprocess.TimeoutExpired, RecordsUnreachable)):
            return TRANSIENT
        if isinstance(fault, httpx.HTTPStatusError):
            status = fault.response.status_code if fault.response is not None else 0
            return TRANSIENT if status >= 500 else LASTING
        if isinstance(fault, _git.GitError):
            return TRANSIENT if _GIT_UNREACHABLE.search(fault.stderr) else LASTING
    return LASTING
