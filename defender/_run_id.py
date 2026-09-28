from __future__ import annotations

import datetime as _dt
import re
from collections.abc import Callable

from defender._store_errors import InvalidCaseId

RUN_ID_ALLOWED = "ASCII alphanumerics, '_', '.', '-', starting alphanumeric"


def is_valid_run_id(run_id: str) -> bool:
    return (
        bool(run_id)
        and run_id.isascii()
        and run_id[0].isalnum()
        and all(c.isalnum() or c in "_.-" for c in run_id)
    )


#: The shape a session store's case (lineage) id must have to name its `.db` file. Lives here
#: so `refuse_bad_case_id` needs no store import; `runtime.session_store` re-exports it.
CASE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")


CASE_STABLE_REQUIRED = "lower case only, so two ids cannot become one file"


def is_case_stable_id(run_id: str) -> bool:
    """Is this id the only spelling of itself a filesystem can produce?

    Asked where an id becomes a filename among siblings. On a case-insensitive filesystem
    (macOS) `Base` and `base` are one inode but two ids to every string compare, so a world
    named `Base` would pass distinctness checks and write into `base`'s immutable capture.
    Callers refuse rather than fold, so the operator gets the name they typed or an error.
    Downstream comparisons still fold, for objects constructed without reaching this check.
    """
    return run_id == run_id.casefold()


def refuse_bad_run_id(run_id: str) -> None:
    """The run-id admission rule: valid and case-stable. Asked wherever a run id becomes a
    directory among siblings, by both the host and the handle's constructors.
    """
    if not is_valid_run_id(run_id):
        raise ValueError(f"{run_id!r} is not a valid run id (allowed: {RUN_ID_ALLOWED})")
    if not is_case_stable_id(run_id):
        raise ValueError(_not_case_stable(run_id))


def refuse_bad_case_id(case_id: object) -> None:
    """The session-store case-id admission rule: a `str` matching `CASE_ID_RE` and case-stable,
    else `InvalidCaseId`."""
    if not isinstance(case_id, str) or not CASE_ID_RE.match(case_id):
        raise InvalidCaseId(repr(case_id))
    if not is_case_stable_id(case_id):
        raise InvalidCaseId(_not_case_stable(case_id))


def _not_case_stable(some_id: str) -> str:
    return (f"{some_id!r} is not case-stable ({CASE_STABLE_REQUIRED}) — use "
            f"{some_id.casefold()!r}")


def _utc_now() -> _dt.datetime:
    return _dt.datetime.now(_dt.UTC)


def mint_run_id(label: str, *, clock: Callable[[], _dt.datetime] = _utc_now) -> str:
    """The host's own run id: `<utc timestamp>-<label>`, case-folded (`20260921t143000z-…`) so
    it passes `refuse_bad_run_id`. Folding is fine here because the id is minted, not typed.
    """
    run_id = f"{clock().strftime('%Y%m%dT%H%M%SZ')}-{label}".casefold()
    refuse_bad_run_id(run_id)
    return run_id
