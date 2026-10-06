from __future__ import annotations

import datetime as _dt
import re
from collections.abc import Callable

from defender._shown import quoted
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


#: The longest run id, in bytes: NAME_MAX (255) minus the longest name a side-file write puts
#: beside the run folder — the longest sidecar suffix (`.accounting_failures.json`, 25 bytes)
#: plus the staged name `write_guarded`'s `replace` mode creates first (`.staged-` and 16 hex
#: digits, 24 bytes), so 255 - 49 = 206 (#1105 R4-35..R4-37). A filesystem with a smaller
#: NAME_MAX is not covered: the id has no path to ask.
RUN_ID_MAX_BYTES = 206


def run_id_fault(text: str) -> str | None:
    """Why `text` cannot be a run id, or `None`: the grammar, case stability and
    `RUN_ID_MAX_BYTES` — the whole rule `RunId` admits by, as one sentence that quotes the
    text the bounded way. Asked of every id the host composes (`<episode>-<label>`) as well,
    so a composed id is refused where it is composed, not by the child that is handed it."""
    if not is_valid_run_id(text):
        return f"{quoted(text)} is not a valid run id (allowed: {RUN_ID_ALLOWED})"
    if not is_case_stable_id(text):
        return (f"{quoted(text)} is not case-stable ({CASE_STABLE_REQUIRED}) — use "
                f"{quoted(text.casefold())}")
    size = len(text.encode("utf-8"))
    if size > RUN_ID_MAX_BYTES:
        return (f"{quoted(text)} is not a valid run id: {size} bytes, over the "
                f"{RUN_ID_MAX_BYTES}-byte bound")
    return None


def episode_id_fault(episode_id: str) -> str | None:
    """Why `episode_id` cannot name an episode, or `None`: it must be a run id (`run_id_fault`)
    with room left for a sibling — every sibling's run id is `<episode_id>-<label>`, so an
    episode id that leaves no room for `-` and one label character names no sibling at all.
    The one statement of the rule: the family model, the branch launcher and the runs
    repository's episode record all ask it."""
    if (why := run_id_fault(episode_id)) is not None:
        return why
    if len(episode_id.encode("utf-8")) + 2 > RUN_ID_MAX_BYTES:
        return (f"{quoted(episode_id)} leaves no room for a sibling's run id "
                f"(<episode id>-<label>, at most {RUN_ID_MAX_BYTES} bytes)")
    return None


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
