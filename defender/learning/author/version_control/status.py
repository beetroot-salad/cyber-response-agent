"""What a publish fault means (O-STALE), and the tenant's last publish outcome (O-SEE).

P3 folds git, forge, auth and OS faults into one `DeliveryRefused` (P4-C23); the fault it was
raised from stays its cause. `classify` reads that chain: an outage that may pass by itself
(the issuer or the forge unreachable or failing with a server error, a network call timing
out, the tenant lock busy) is `transient`; anything else needs a human (`operator`): a refused
login or token, `main` unprotected, a dirty or diverged clone, a commit refused on content.

Every publish trigger records its outcome in `<T>/publish-status.json`
(`tenancy._publish_status`): the refusal classified here, or the commit it published.
"""

from __future__ import annotations

import contextlib
import re
import subprocess
from collections.abc import Iterator

import httpx

from defender import _git
from defender._text import one_line
from defender.tenancy._publish_status import (
    OPERATOR,
    TRANSIENT,
    read_status,
    record_published,
    record_refusal,
)
from defender.tenancy._tenant import Tenant

from .forgejo import ForgeError
from .model import LockBusy

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
    """`(kind, one-line reason)` of a publish fault: `transient` or `operator` (module doc)."""
    reason = str(error)
    for fault in _chain(error):
        if isinstance(fault, httpx.HTTPStatusError) and any(
            isinstance(f, ForgeError) for f in _chain(error)
        ):
            body = fault.response.text[:_BODY_LIMIT] if fault.response is not None else ""
            if body:
                reason = f"{reason}: {body}"
            break
    return _fault_kind(error), one_line(reason)


def _fault_kind(error: BaseException) -> str:
    if isinstance(error, LockBusy):
        return TRANSIENT
    for fault in _chain(error):
        if isinstance(fault, (httpx.TransportError, subprocess.TimeoutExpired)):
            return TRANSIENT
        if isinstance(fault, httpx.HTTPStatusError):
            status = fault.response.status_code if fault.response is not None else 0
            return TRANSIENT if status >= 500 else OPERATOR
        if isinstance(fault, _git.GitError):
            return TRANSIENT if _GIT_UNREACHABLE.search(fault.stderr) else OPERATOR
    return OPERATOR


def record_refused(tenant: Tenant, error: BaseException, *, by: str) -> None:
    """A publish by `by` was refused (the lock busy is not a refusal, and is not recorded)."""
    if isinstance(error, LockBusy):
        return
    kind, reason = classify(error)
    record_refusal(tenant, kind=kind, reason=reason, by=by)


@contextlib.contextmanager
def recording(tenant: Tenant, *, by: str) -> Iterator[None]:
    """Record a refusal raised inside as `by`'s publish refusal, and re-raise it."""
    try:
        yield
    except Exception as refused:
        record_refused(tenant, refused, by=by)
        raise


__all__ = [
    "OPERATOR", "TRANSIENT", "classify", "read_status", "record_published",
    "record_refused", "recording",
]
