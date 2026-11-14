"""#1485: the migration history read through Alembic's script directory, so a test names this issue's revisions by
suffix and never by a number or a hard-coded predecessor (#1083 piece 1 lands `0016_list_indexes` first)."""
from __future__ import annotations

RETIRE_SUFFIX = "_retire_learning_cutover"
INDEXES_SUFFIX = "_learning_set_aside_indexes"


def scripts():
    from alembic.script import ScriptDirectory

    from defender.migrations import HERE

    return ScriptDirectory(str(HERE))


def by_suffix(suffix: str) -> str:
    """The one revision id ending in `suffix`; an assertion naming the suffix when there is none or several."""
    found = [r.revision for r in scripts().walk_revisions() if r.revision.endswith(suffix)]
    assert len(found) == 1, f"expected one revision ending {suffix!r} in the history, found {found}"
    return found[0]


def down_of(revision: str) -> str:
    """The one revision `revision` is built on."""
    parent = scripts().get_revision(revision).down_revision
    assert isinstance(parent, str), f"{revision} should sit on exactly one revision, not {parent!r}"
    return parent


def ancestors(revision: str) -> set[str]:
    """`revision` and every revision before it."""
    return {r.revision for r in scripts().iterate_revisions(revision, "base")}


def new_files(files: dict[str, str]) -> set[str]:
    """Of `{revision: path}`, the paths of the revisions this change adds: the retirement, and what follows it. With no
    retirement revision yet, none."""
    try:
        retire = by_suffix(RETIRE_SUFFIX)
    except AssertionError:
        return set()
    old = ancestors(down_of(retire))
    return {path for rev, path in files.items() if rev not in old}
