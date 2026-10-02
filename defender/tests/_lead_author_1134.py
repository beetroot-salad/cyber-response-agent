"""The open-trees plumbing for #1134 step 6's tests, and the scene its two new files share. It
defines no tests.

Step 6 moves the lead author and the pitfalls curator onto the drain's held `skills/` mount: the
readers take a `Bound` (the mount's view) plus `where=`, the Path that folder is spelled as; the
draft writer takes the `Held`; the post-agent rules take `tree_for=`, the `DrainTrees.tree_for`
of the lane's open trees; the deps, `run_pitfalls` and `run_under_held_queue_lock` take the open
`trees`. Every existing caller in `defender/tests` changes in call shape only (owner decisions 1
and 2 of 2026-09-29), and this module is the one home of the trees those calls run inside.

Lifetime, the one rule here. A `Held` closed under a reader does not raise: the reader answers
`Bad file descriptor` as a refusal, which reads as "absent" or "refused", a silent wrong answer.
So every call these helpers serve runs inside trees that are open:

* `lead_trees(paths)` opens the lead drain's trees over `paths` exactly as the lane does
  (`open_drain_trees(paths, LEAD_AUTHOR_DRAIN_LABEL)`). It is a `DrainTrees`, so `with
  lead_trees(paths) as trees:` scopes them; passed inline (`trees=lead_trees(paths)`) it stays
  open for the call it is handed to.
* Every other helper hands back an object that REFERENCES the open trees: a bound `tree_for`,
  a `Held`, a view, or deps holding the `Held` and the bound `tree_for`. The descriptors stay
  open exactly as long as that object is referenced and are released when it is collected
  (CPython's refcount; `_io._Handle.__del__` closes each). Nothing here closes trees a caller
  still holds, and no test that uses these looks at its own descriptors.

`lane_tree_for(repo)` is always the REAL `trees.tree_for` over the repo the rules are asked
about, never a stand-in such as `lambda p: None` (that would send every rule down the
plain-path fallback, D3, and test nothing of the handle).
"""
from __future__ import annotations

import dataclasses
import logging
import os
import shutil
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from typing import Any

import pytest

from defender._io import Bound, Held, hold
from defender._paths import PATHS
from defender.learning.core.config import LEAD_AUTHOR_DRAIN_LABEL, LoopPaths
from defender.learning.core.lane_trees import DrainTrees, open_drain_trees

#: The type `DrainTrees.tree_for` has (bound): a working-copy path to `(held mount, name)`, or
#: `None` outside the lane's mounts.
TreeForFn = Callable[[Path | str], "tuple[Held, str] | None"]


# ---------------------------------------------------------------------------------------
# The trees, open
# ---------------------------------------------------------------------------------------


def lead_trees(paths: LoopPaths) -> DrainTrees:
    """The lead drain's trees over `paths`, open: `open_drain_trees(paths,
    LEAD_AUTHOR_DRAIN_LABEL)`, the one held `skills/` mount the lane works through."""
    return open_drain_trees(paths, LEAD_AUTHOR_DRAIN_LABEL)


def lane_tree_for(repo: Path) -> TreeForFn:
    """The lead drain's `trees.tree_for` over the repo at `repo` (the root git-status names are
    relative to). The trees stay open while the returned bound method is referenced."""
    return lead_trees(LoopPaths(repo_root=repo)).tree_for


def lane_fields(paths: LoopPaths) -> dict[str, Any]:
    """`LeadAuthorDeps`' two step-6 fields over `paths`, for a test that builds the deps by
    hand: `skills` (the held `skills/` mount) and `tree_for` (the same trees' lookup)."""
    trees = lead_trees(paths)
    return {"skills": trees.mount(paths.skills_dir), "tree_for": trees.tree_for}


def lead_deps(paths: LoopPaths, **replaced: Any) -> Any:
    """`build_lead_author_deps(paths, trees=<the lead drain's trees over paths>)`, with the
    `replaced` fields swapped in (`dataclasses.replace`). The deps hold the trees' `Held` and
    bound `tree_for`, so the trees stay open while the deps are referenced; a refusal closes
    them and propagates."""
    from defender.learning.leads import lead_author

    trees = lead_trees(paths)
    try:
        deps = lead_author.build_lead_author_deps(paths, trees=trees)
    except BaseException:
        trees.close()
        raise
    return dataclasses.replace(deps, **replaced) if replaced else deps


def held_skills(root: Path) -> Held:
    """`root` held as a lane's `skills/` mount is: made first if missing (a drain's mount point
    always exists; a fixture's tmp root may not yet), then `hold`. For the draft writer, which
    takes the `Held` and `where=root`."""
    root.mkdir(parents=True, exist_ok=True)
    return hold(root)


def drafts_under(catalog: Path) -> dict[str, Any]:
    """`skills=` / `where=` for the draft writer over a test catalog at `<skills>/gather/queries`
    (where a lane's catalog sits, O5.4): its skills root, held, and that root's spelling. The
    drafts land at `catalog/<sys>/_draft/` as they did when the writer took `catalog_dir=`."""
    root = catalog.parents[1]
    return {"skills": held_skills(root), "where": root}


def skills_view(root: Path) -> Bound:
    """The view of `root` held as a `skills/` mount: what the readers take, with `where=root`.
    `root` must exist (the readers' roots in these tests always do)."""
    return hold(root).view()


def repo_skills() -> dict[str, Any]:
    """`skills=` / `where=` for a reader whose call read this checkout's own catalog (the
    default it had before step 6): the view of `PATHS.skills_dir`, spelled as that folder."""
    return {"skills": skills_view(PATHS.skills_dir), "where": PATHS.skills_dir}


@contextmanager
def opened(paths: LoopPaths, label: str = LEAD_AUTHOR_DRAIN_LABEL) -> Iterator[DrainTrees]:
    """`open_drain_trees(paths, label)` scoped to the `with`: the form the new tests use when
    they look at the process's descriptors afterwards."""
    with open_drain_trees(paths, label) as trees:
        yield trees


# ---------------------------------------------------------------------------------------
# The scene the two new step-6 files share
# ---------------------------------------------------------------------------------------

#: What every link target, hard link's other name and moved folder carries (and every plain
#: control at the same address): a reader that followed the plant would put it in its answer.
OUT_MARK = "outside-bytes-5f2a"
#: An identity carrying the mark, for the rows whose answer is a set of ids or `covers:`.
OUT_ID = f"wazuh.{OUT_MARK}"


@dataclasses.dataclass
class Scene:
    """A skills tree under `repo` (committed, unless built bare), a folder `outside` the repo
    where every link points, a run dir, and the lead drain's trees over the repo, open for the
    test's life (the fixture closes them)."""

    tmp: Path
    repo: Path
    outside: Path
    paths: LoopPaths
    run_dir: Path
    trees: DrainTrees
    memo: dict[str, Any] = dataclasses.field(default_factory=dict)

    @property
    def skills_dir(self) -> Path:
        return self.paths.skills_dir

    @property
    def skills(self) -> Held:
        """The held `skills/` mount, as the lane takes it: `trees.mount(skills_dir)`."""
        return self.trees.mount(self.paths.skills_dir)

    @property
    def view(self) -> Bound:
        """The mount's view: what every reader takes, with `where=skills_dir`."""
        return self.skills.view()

    @property
    def tree_for(self) -> TreeForFn:
        return self.trees.tree_for

    def at(self, name: str) -> Path:
        return self.skills_dir / name

    def rel(self, name: str) -> str:
        """`name`'s repo-relative spelling, as git status reports it."""
        return f"defender/skills/{name}"


@contextmanager
def scene_over(tmp_path: Path, repo: Path) -> Iterator[Scene]:
    """A `Scene` over the skills tree in `repo`, its trees open for the `with`."""
    outside = tmp_path / "outside"
    outside.mkdir(exist_ok=True)
    run_dir = tmp_path / "run-x"
    (run_dir / "gather_raw").mkdir(parents=True, exist_ok=True)
    paths = LoopPaths(repo_root=repo, state_dir=tmp_path / "state")
    with lead_trees(paths) as trees:
        yield Scene(tmp=tmp_path, repo=repo, outside=outside, paths=paths, run_dir=run_dir,
                    trees=trees)


def clear(at: Path) -> None:
    if at.is_symlink() or at.is_file():
        at.unlink()
    elif at.is_dir():
        shutil.rmtree(at)


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def place(s: Scene, name: str, text: str, kind: str) -> Path | None:
    """`text` at `name` below the mount as a plain file (`kind="plain"`), a symlink to a file
    outside the repo holding `text` (`"link"`), or a hard link to such a file (`"hardlink"`).
    The outside file is returned for the two link kinds."""
    at = s.at(name)
    clear(at)
    if kind == "plain":
        write(at, text)
        return None
    target = s.outside / f"target-{kind}-{PurePosixPath(name).name}"
    clear(target)
    write(target, text)
    at.parent.mkdir(parents=True, exist_ok=True)
    if kind == "link":
        at.symlink_to(target)
    elif kind == "hardlink":
        os.link(target, at)
    else:
        raise ValueError(kind)
    return target


def plant_folder(s: Scene, site: str, kind: str) -> Path:
    """The real folder at `site` (below the mount) moved outside the repo, and in its place a
    symlink to where it now lies (`kind="link"`) or a plain file (`"file"`). The moved folder
    is returned: a reader that followed the plant would find everything it held there."""
    moved = s.outside / f"moved-{kind}-{site.replace('/', '-')}"
    shutil.move(s.at(site), moved)
    if kind == "link":
        s.at(site).symlink_to(moved, target_is_directory=True)
    elif kind == "file":
        write(s.at(site), "a plain file where a folder belongs\n")
    else:
        raise ValueError(kind)
    return moved


def plant_state(at: Path) -> tuple:
    """What stands at `at`, judged without following: a link's target, a file's bytes."""
    if at.is_symlink():
        return ("link", os.readlink(at))
    if at.is_file():
        st = os.lstat(at)
        return ("file", at.read_bytes(), st.st_ino)
    return ("dir",) if at.is_dir() else ("absent",)


def ancestors(name: str) -> list[str]:
    """Every holding folder of `name` below the mount, innermost first."""
    return [p.as_posix() for p in PurePosixPath(name).parents if p.as_posix() != "."]


def outcome(fn: Callable[[], Any]) -> tuple:
    """`("returned", value)`, or `("raised", class name, message)` for the two refusal classes
    the readers and rules use. Anything else (a `TypeError` from a call shape) propagates."""
    from defender.learning.leads.lead_extraction import LeadAuthorError

    try:
        return ("returned", fn())
    except (LeadAuthorError, OSError) as e:
        return ("raised", type(e).__name__, str(e))


def raised(got: tuple, cls: str, says: str) -> bool:
    return got[0] == "raised" and got[1] == cls and says in got[2]


def logged(caplog: pytest.LogCaptureFixture, level: int = logging.WARNING) -> list[str]:
    return [r.getMessage() for r in caplog.records
            if r.levelno >= level and r.name.startswith("defender")]


def errors(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [r.getMessage() for r in caplog.records
            if r.levelno == logging.ERROR and r.name.startswith("defender")]
