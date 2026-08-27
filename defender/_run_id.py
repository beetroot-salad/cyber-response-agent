from __future__ import annotations


RUN_ID_ALLOWED = "ASCII alphanumerics, '_', '.', '-', starting alphanumeric"


def is_valid_run_id(run_id: str) -> bool:
    return (
        bool(run_id)
        and run_id.isascii()
        and run_id[0].isalnum()
        and all(c.isalnum() or c in "_.-" for c in run_id)
    )


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
