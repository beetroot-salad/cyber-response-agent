from __future__ import annotations

import re
import uuid

from defender._shown import quoted
from defender.records._store_errors import InvalidCaseId

RUN_ID_ALLOWED = "ASCII alphanumerics, '_', '.', '-', starting alphanumeric"


def is_valid_run_id(run_id: str) -> bool:
    """Legacy safe-component predicate for box, world and display labels.

    Actual run admission uses `run_id_fault` / `RunId.parse`, which require UUIDs.
    """
    return (
        bool(run_id)
        and run_id.isascii()
        and run_id[0].isalnum()
        and all(c.isalnum() or c in "_.-" for c in run_id)
    )


#: The shape a session store's case (lineage) id must have to name its `.db` file. Lives here
#: so `refuse_bad_case_id` needs no store import; `records.session_store` re-exports it.
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


#: The one shape a tenant, run, arm or episode id has (#1187 O1/O2): canonical lowercase UUID text,
#: `8-4-4-4-12` hex digits. Nothing else is an id — no braces, no `urn:`, no upper case, no
#: missing hyphens — so every id names exactly one folder and carries no meaning.
_UUID_TEXT = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")

UUID_REQUIRED = "canonical lowercase UUID text, e.g. af3ba774-355d-4dbc-b8b6-3becc9d3e7a1"


def uuid_id_fault(text: object, domain: str) -> str | None:
    """The shared canonical UUID rule for tenant, run and episode admission."""
    if not isinstance(text, str) or not _UUID_TEXT.fullmatch(text):
        return f"{quoted(text)} is not a valid {domain} id (allowed: {UUID_REQUIRED})"
    return None


def run_id_fault(text: str) -> str | None:
    """Why `text` cannot be a run id, or `None`: an id is canonical lowercase UUID text and
    nothing else (#1187 O2), the whole rule `RunId` admits by, as one sentence that quotes the
    text the bounded way. A UUID is 36 bytes, so no length bound is asked separately."""
    return uuid_id_fault(text, "run")


def episode_id_fault(episode_id: str) -> str | None:
    """Why `episode_id` cannot name an episode, or `None`: the same UUID rule as a run id
    (#1187 O2). The one statement of the rule: the family model, the episode owner and the
    stored `RunAddress` all ask it."""
    return uuid_id_fault(episode_id, "episode")


def mint_uuid() -> str:
    """A fresh id: a random uuid4 as canonical lowercase text. It carries no label, time or
    parent (#1187 O1); what a run is about lives in its host-written records."""
    return str(uuid.uuid4())


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

#: A full git object id (SHA-1 or SHA-256).
OID = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
