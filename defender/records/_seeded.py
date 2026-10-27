"""Refusing a sibling run folder that already holds state a resumed run would inherit.

The refusal runs before the fork commits (`store.fork`), so a retried resume cannot leave an
orphan session each time. It names the run layout's inherited entries, so it lives with the
layout rather than with the branch code that copies them.
"""

from __future__ import annotations

from pathlib import Path

from defender.records._layout import RUN_LAYOUT, RunPaths
from defender.records._store_errors import BranchError


#: The per-lead evidence directories, shared by the census, the evidence copy and its refusal.
def _lead_dirs() -> tuple[str, ...]:
    """The two per-lead directories a sibling inherits, read from the run layout."""
    return (RUN_LAYOUT.gather_raw.name, RUN_LAYOUT.gather_summaries.name)


#: Derived from `_lead_dirs()` so the census, the copy and the seeded-dir refusal cannot name
#: different sets.
def _inherited() -> tuple[str, ...]:
    """The run-dir entries a sibling inherits from its source: the queries table plus the two
    per-lead directories."""
    return (RUN_LAYOUT.executed_queries.name, *_lead_dirs())


def refuse_seeded_run_dir(run_dir: Path) -> None:
    """Refuse a sibling run dir that already holds inherited state.

    Separate so it can run before `store.fork`, which commits; a retried resume would otherwise
    leave an orphan session each time.
    """
    run_dir = Path(run_dir)
    present = [name for name in (RunPaths(run_dir).investigation.name, *_inherited())
               if _holds_content(run_dir / name)]
    if present:
        raise BranchError(
            f"{run_dir} already holds {present} — a resumed run inherits those from its "
            "source, and a run dir that already carries them is not a fresh sibling: seeding "
            "over them would interleave two runs' evidence in artifacts that are append-only")


def _holds_content(path: Path) -> bool:
    """Does `path` hold anything a run put there?

    Not mere existence: scaffolding creates empty dirs like `gather_raw/` for every run.
    """
    # A symlink counts as content, refused here before the fork rather than later in the copy
    # (after `store.fork` has committed). The scaffolding plants no links.
    if path.is_symlink():
        return True
    if path.is_dir():
        return any(path.iterdir())
    return path.is_file() and path.stat().st_size > 0
