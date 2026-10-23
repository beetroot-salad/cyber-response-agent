"""The open-trees plumbing for #1134 step 6's tests, and the scene its two new files share. It
defines no tests."""
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
from defender.learning.core.config import LEAD_AUTHOR_DRAIN_LABEL, LoopPaths
from defender.learning.core.lane_trees import DrainTrees, open_drain_trees
from defender.tests.support.tenancy._tenants1106 import FIXTURE_AGENT

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
    return lead_trees(LoopPaths(repo_root=repo, state_dir=repo / "defender" / "learning")).tree_for


def lane_fields(paths: LoopPaths) -> dict[str, Any]:
    """`LeadAuthorDeps`' two step-6 fields over `paths`, for a test that builds the deps by
    hand: `skills` (the held `skills/` mount) and `tree_for` (the same trees' lookup)."""
    trees = lead_trees(paths)
    return {"skills": trees.mount(paths.skills_dir), "tree_for": trees.tree_for}


def lead_deps(paths: LoopPaths, *, state: Any = None, **replaced: Any) -> Any:
    """`build_lead_author_deps(paths, trees=<the lead drain's trees over paths>)`, with the
    `replaced` fields swapped in (`dataclasses.replace`). The deps hold the trees' `Held` and
    bound `tree_for`, so the trees stay open while the deps are referenced; a refusal closes
    them and propagates."""
    from defender.learning.leads import lead_author
    from defender.tests.support.learning.curation._curator1134 import open_state

    trees = lead_trees(paths)
    try:
        deps = lead_author.build_lead_author_deps(
            paths, state=state if state is not None else open_state(paths), trees=trees)
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
    """`skills=` / `where=` for a reader that needs a real-shaped skills tree it does not write:
    the committed fixture tenant's `agent/skills` (made-up content), spelled as that folder.

    #1108 P4 O1/O11: it was the view of this checkout's `PATHS.skills_dir`; the product tree
    holds no tenant skills or catalog after P4, so product tests read the fixture instead."""
    root = FIXTURE_AGENT / "skills"
    return {"skills": skills_view(root), "where": root}


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


# ---------------------------------------------------------------------------------------
# #1108 P4 (O7, OD6): the same plumbing rooted at a tenant repo / batch draft
# ---------------------------------------------------------------------------------------
#
# After P4 the lead lane's `skills/` mount is `<draft>/agent/skills` (a P3 batch draft: the tenant
# repo's `agent/` at the batch base, with no `.git`), its rules take that root and repo-relative
# `agent/skills/...` names, and the adapters stay in the product checkout (#1172). The legacy
# helpers above stay as they are for the suites not yet moved; these are their P4 siblings.


def draft_tree_for(root: Path) -> TreeForFn:
    """The lead lane's `tree_for` over the tenant-shaped root `root` (it holds `agent/skills`):
    names are `agent/skills/...`. The trees stay open while the bound method is referenced."""
    return DrainTrees.open((root / "agent" / "skills",)).tree_for


def draft_lead_deps(lane: Any, *, state: Any = None, **replaced: Any) -> Any:
    """`build_lead_author_deps(lane.paths, trees=<the draft's skills mount>, batch=lane.batch)`
    over a `_curator1134.DraftLane` (ASSUMED SEAM `batch=`), `replaced` swapped in."""
    from defender.learning.leads import lead_author
    from defender.tests.support.learning.curation._curator1134 import open_state

    trees = DrainTrees.open((lane.skills_dir,))
    try:
        deps = lead_author.build_lead_author_deps(
            lane.paths, state=state if state is not None else open_state(lane.paths),
            trees=trees, batch=lane.batch)
    except BaseException:
        trees.close()
        raise
    return dataclasses.replace(deps, **replaced) if replaced else deps


@dataclasses.dataclass
class DraftScene(Scene):
    """`Scene` rooted at a tenant-shaped root: `repo` holds `agent/skills` (the mount), `rel`
    spells `agent/skills/<name>`, and `product` is the product checkout the adapters sit in."""

    product: Path | None = None

    @property
    def skills_dir(self) -> Path:
        return self.repo / "agent" / "skills"

    @property
    def skills(self) -> Held:
        return self.trees.mount(self.skills_dir)

    def rel(self, name: str) -> str:
        return f"agent/skills/{name}"


@contextmanager
def draft_scene_over(tmp_path: Path, product: Path) -> Iterator[DraftScene]:
    """`scene_over` after P4: `product`'s `defender/skills` tree (a `seed_tree` fixture) moved
    to a tenant-shaped root `<tmp>/tenant/agent/skills`, committed when `product` has commits
    (the batch base the rules compare against; a P3 draft is this tree without `.git`), and the
    lane's one `skills/` mount held over it. `product` keeps the adapters."""
    from defender.tests.support.learning.curation._drain719 import git

    root = tmp_path / "tenant"
    n = 1
    while root.exists():
        n += 1
        root = tmp_path / f"tenant-{n}"
    skills = root / "agent" / "skills"
    source = product / "defender" / "skills"
    if source.is_dir():
        shutil.copytree(source, skills, symlinks=True)
    else:
        skills.mkdir(parents=True)
    if git(product, "rev-parse", "--verify", "-q", "HEAD", check=False).returncode == 0:
        git(root, "init", "-q", "-b", "main")
        git(root, "config", "user.email", "t@t")
        git(root, "config", "user.name", "t")
        git(root, "add", "-A")
        git(root, "commit", "-q", "--allow-empty", "-m", "tenant base")
    outside = tmp_path / "outside"
    outside.mkdir(exist_ok=True)
    run_dir = tmp_path / "run-x"
    (run_dir / "gather_raw").mkdir(parents=True, exist_ok=True)
    paths = LoopPaths(repo_root=product, state_dir=tmp_path / "state")
    with DrainTrees.open((skills,)) as trees:
        yield DraftScene(tmp=tmp_path, repo=root, outside=outside, paths=paths, run_dir=run_dir,
                         trees=trees, product=product)


def product_lane(tmp_path: Path, product: Path) -> Any:
    """A lead lane over `product`'s seeded `defender/skills` (a `seed_tree` fixture) after P4:
    that tree published as the tenant's `agent/skills` (one export commit) under a real P3 batch
    with the lead lane `skills`; the product checkout keeps the adapters and loses the corpus
    (O1, #1172)."""
    import subprocess

    from defender.tests.support.learning.curation import _curator1134 as C

    agent = tmp_path / "agent-src"
    shutil.copytree(product / "defender" / "skills", agent / "skills")
    subprocess.run(["git", "rm", "-r", "-q", "defender/skills"], cwd=product, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "the product holds no corpus"], cwd=product,
                   check=True)
    return C.draft_lane(tmp_path, lanes=C.LEAD_LANES, agent=agent, product=product)


@contextmanager
def lane_scene(tmp_path: Path, lane: Any) -> Iterator[DraftScene]:
    """A `DraftScene` over a `_curator1134.DraftLane`'s draft: `repo` is the draft's root (it
    holds `agent/skills`), `paths` the lane's (product-rooted, OD16), the lane's one `skills/`
    mount held for the `with`. What landed is the lane's to read (`lane.landed()`)."""
    outside = tmp_path / "outside"
    outside.mkdir(exist_ok=True)
    run_dir = tmp_path / "run-x"
    (run_dir / "gather_raw").mkdir(parents=True, exist_ok=True)
    with DrainTrees.open((lane.skills_dir,)) as trees:
        yield DraftScene(tmp=tmp_path, repo=lane.root, outside=outside, paths=lane.paths,
                         run_dir=run_dir, trees=trees, product=lane.paths.repo_root)
