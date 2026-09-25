from __future__ import annotations

import datetime as _dt
import re
from collections.abc import Callable

RUN_ID_ALLOWED = "ASCII alphanumerics, '_', '.', '-', starting alphanumeric"


def is_valid_run_id(run_id: str) -> bool:
    return (
        bool(run_id)
        and run_id.isascii()
        and run_id[0].isalnum()
        and all(c.isalnum() or c in "_.-" for c in run_id)
    )


#: The shape a session store's case (lineage) id must have to name its `.db` file — here, with
#: the other id rules, so the store's path owner can ask it without importing the store.
#: `runtime.session_store` re-exports it (RG-4: pinned by reference, never re-spelled).
CASE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")


CASE_STABLE_REQUIRED = "lower case only, so two ids cannot become one file"


def is_case_stable_id(run_id: str) -> bool:
    """Is this id the only spelling of itself a filesystem can produce?

    ASKED WHERE AN ID BECOMES A FILENAME AMONG SIBLINGS. `is_valid_run_id` admits upper case,
    so `Base` and `base` are two ids to every string comparison in this repo and ONE inode on
    a case-insensitive filesystem — macOS, which this repo supports, and where the default runs
    base lives under a symlinked `/tmp`. A world called `Base` therefore passes every
    distinctness check that stands between it and the family's immutable capture, and then
    appends its own live rows into that capture through the one spelling an exact compare
    cannot see. The same door lets `--world a --world A` past a distinctness set, producing two
    ledger objects and two locks over one file.

    REFUSED, NOT NORMALISED. Folding the id silently would give an operator who typed `Base` a
    world named `base`, and the report, the run dir and the ledger would all agree with each
    other and disagree with what they asked for. A refusal costs one retype and says why.

    Downstream comparisons still fold, and that is not redundancy: `Ledger` and `World` can be
    constructed directly, so the fold is what holds when this predicate was never reached.
    """
    return run_id == run_id.casefold()


def refuse_bad_run_id(run_id: str) -> None:
    """THE run-id admission rule, in one place: valid AND case-stable. Asked wherever a run id
    becomes a directory among siblings — the host's own materialisation and the handle's
    constructors alike — so the id the host mints is, by construction, one the handle admits.
    """
    if not is_valid_run_id(run_id):
        raise ValueError(f"{run_id!r} is not a valid run id (allowed: {RUN_ID_ALLOWED})")
    if not is_case_stable_id(run_id):
        raise ValueError(
            f"{run_id!r} is not case-stable ({CASE_STABLE_REQUIRED}) — use "
            f"{run_id.casefold()!r}")


def _utc_now() -> _dt.datetime:
    return _dt.datetime.now(_dt.UTC)


def mint_run_id(label: str, *, clock: Callable[[], _dt.datetime] = _utc_now) -> str:
    """The host's own run id: `<utc timestamp>-<label>`, CASE-FOLDED so it passes the same
    admission every constructor applies (`refuse_bad_run_id`). The timestamp therefore reads
    `20260921t143000z`, not `…T…Z`: an id the host mints and its own handle then refuses is
    two rules for one name. The label is the operator's alert stem, folded with the rest —
    minted, not typed, so folding it is not the silent renaming `is_case_stable_id` refuses.
    """
    run_id = f"{clock().strftime('%Y%m%dT%H%M%SZ')}-{label}".casefold()
    refuse_bad_run_id(run_id)
    return run_id
