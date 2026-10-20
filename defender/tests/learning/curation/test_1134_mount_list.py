from __future__ import annotations

import dataclasses
import enum
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from defender import _io
from defender.learning.core import drains
from defender.tests.support.learning.core._state1135 import curation_run_dir, enqueue_case, state_for_paths
from defender.learning.core.config import (
    DrainLabel, LoopPaths,
)
from defender.learning.core.lane_trees import DrainTrees, open_drain_trees
from defender.tests.support.learning.curation._drain_trees_1134 import PAYLOAD
from defender.tests.e2e import _box665 as B
from defender.tests.shared.filesystem.test_1111_rooted_io import HOST_BYTES, census
from defender.tests.support.learning.curation._tree_listing_1134 import descriptors_under, put_plain
from defender.learning.core.state import FINDINGS


#: The two labels are the members of `DrainLabel` (#1179): values no string equals.
AUTHOR = DrainLabel.AUTHOR
LEAD = DrainLabel.LEAD_AUTHOR
KNOWN = (AUTHOR, LEAD)


#: Each known label's mount points, repo-relative, in the contract's order. Literal on purpose:
#: independent of the `LoopPaths` attribute names the implementation reads.
EXPECTED_MOUNTS: dict[DrainLabel, tuple[str, ...]] = {
    AUTHOR: ("defender/lessons", "defender/lessons-questioner"),
    LEAD: ("defender/skills",),
}

#: The same lists through the `LoopPaths` attributes the design names.
MOUNTS_BY_ATTRIBUTE: dict[DrainLabel, Callable[[LoopPaths], tuple[Path, ...]]] = {
    AUTHOR: lambda p: (p.lessons_dir, p.lessons_questioner_dir),
    LEAD: lambda p: (p.skills_dir,),
}

#: Every tree a drain checkout carries that some label mounts.
ALL_TREES = ("defender/lessons", "defender/lessons-questioner", "defender/skills")

DECOY_TREES = ("defender/lessons-actor", "defender/lessons-environment", "defender/skills-old")

class _LookAlike(enum.Enum):
    """A second enum whose members carry the drain labels' values: equal by `.value` and by
    name, never the members themselves."""

    AUTHOR = "author_drain"
    LEAD_AUTHOR = "lead_author_drain"


@dataclasses.dataclass(frozen=True)
class _Valued:
    """Any object carrying a member's value as `.value` (hashable, so the tables accept it)."""

    value: str


UNKNOWN_LABELS: tuple[object, ...] = (
    "author_drain", "lead_author_drain",
    # The members' NAMES (a `DrainLabel[label]` / `__members__` lookup would grant them).
    "AUTHOR", "LEAD_AUTHOR",
    # Look-alikes (a `.value` comparison would grant them).
    _LookAlike.AUTHOR, _LookAlike.LEAD_AUTHOR, _Valued("author_drain"), _Valued("lead_author_drain"),
    "a_third_drain", "", "author", "lead_author", "AUTHOR_DRAIN", "Lead_Author_Drain",
    "author_drain ", " author_drain", "lead_author_drain\n", "author-drain",
    "lead-author-drain", "xauthor_drain", "author_drain_", "lead_author_drain_v2",
    "pitfalls_drain", "author_drain:batch-1", "lead_author_drain:batch-1", "author_drain:",
    "author_drain/batch-1", "lead_author_drain.batch-1",
)

#: The main checkout's directory name, under `tmp_path`.
MAIN = "main"

#: The names a held-root row writes through a handle.
BEFORE, AFTER, PROBE = "written-before-the-swap.md", "written-after-the-swap.md", "probe.md"


@dataclasses.dataclass(frozen=True)
class Leaf:
    """A main checkout `paths` and a drain leaf `wt` beside it (absent until `build`)."""

    paths: LoopPaths
    wt: Path

    @property
    def wt_paths(self) -> LoopPaths:
        return self.paths.with_repo_root(self.wt)

    def build(self, *rels: str) -> None:
        """Make each tree in `rels` under `wt`; by default every tree a checkout carries, the
        decoys included."""
        for rel in rels or (*ALL_TREES, *DECOY_TREES):
            (self.wt / rel).mkdir(parents=True, exist_ok=True)


def _leaf(tmp_path: Path) -> Leaf:
    paths = LoopPaths(repo_root=tmp_path / MAIN, state_dir=tmp_path / "learning-state")
    paths.state_root.mkdir(parents=True, exist_ok=True)  # the handle never creates its root (#1135)
    return Leaf(paths=paths, wt=tmp_path / "wt-leaf")


def rw_mounts(request: Any) -> list[tuple[Path, Path]]:
    """The request's read-write mounts as `(source, target)`, in request order."""
    return [(Path(m.source), Path(m.target)) for m in request.mounts if m.writable]


def ro_mounts(request: Any) -> list[tuple[Path, Path]]:
    """The request's read-only mounts as `(source, target)`, in request order."""
    return [(Path(m.source), Path(m.target)) for m in request.mounts if not m.writable]


def held_roots(top: Path) -> list[str]:
    """What this process's open descriptors name under `top`, sorted: the held roots."""
    return sorted(descriptors_under(top))


def real(*paths: Path) -> list[str]:
    """`paths` as the kernel names them, sorted: what `held_roots` answers for them."""
    return sorted(os.path.realpath(p) for p in paths)


def refused_value_error(fn: Callable[[], Any], what: str) -> None:
    """`fn()` raises `ValueError` (the type is the contract, not the wording)."""
    try:
        got = fn()
    except ValueError:
        return
    pytest.fail(f"{what}: answered {got!r}, not ValueError")


#: Each member's trees, by the `LoopPaths` attribute that names each (and the folder name
#: `relocated_paths` moves it to).
TREE_ATTRS: dict[DrainLabel, tuple[tuple[str, str], ...]] = {
    AUTHOR: (("lessons_dir", "lessons"), ("lessons_questioner_dir", "lessons-questioner")),
    LEAD: (("skills_dir", "skills"),),
}


def relocated_rel(root: Path, name: str) -> str:
    """Where `relocated_paths` puts the tree `name` under `root`. The folder's name carries the
    root's own name, so trees named under one root and rebased onto another name different
    folders."""
    return f"defender/relocated-{root.name}-{name}"


def relocated_rels(label: DrainLabel, root: Path) -> list[str]:
    """`label`'s trees under `relocated_paths` rooted at `root`, in the member's order."""
    return [relocated_rel(root, name) for _attr, name in TREE_ATTRS[label]]


def all_relocated(root: Path) -> list[str]:
    return [rel for label in KNOWN for rel in relocated_rels(label, root)]


def relocated_paths(asked: list[tuple[Path, str]]) -> type[LoopPaths]:
    """A `LoopPaths` subclass, injected through the `paths` argument, whose three drain trees
    are NOT where the shipped paths put them: each is `relocated_rel(repo_root, name)`, a
    sibling of the real trees. Every read of a tree attribute records `(repo_root, attribute)`
    in `asked`. `with_repo_root` keeps the subclass (the shipped one returns a plain
    `LoopPaths`), so `paths.with_repo_root(wt)` still relocates. A class per call, so each test
    reads its own `asked` (the instances are frozen)."""

    class RelocatedPaths(LoopPaths):
        def with_repo_root(self, repo_root: Path) -> LoopPaths:
            return type(self)(repo_root=repo_root, state_dir=self.state_root)

        def _moved(self, attr: str, name: str) -> Path:
            asked.append((self.repo_root, attr))
            return self.repo_root / relocated_rel(self.repo_root, name)

        @property
        def lessons_dir(self) -> Path:  # type: ignore[override]
            return self._moved("lessons_dir", "lessons")

        @property
        def lessons_questioner_dir(self) -> Path:  # type: ignore[override]
            return self._moved("lessons_questioner_dir", "lessons-questioner")

        @property
        def skills_dir(self) -> Path:  # type: ignore[override]
            return self._moved("skills_dir", "skills")

    return RelocatedPaths


def assert_asked_of(asked: list[tuple[Path, str]], wt: Path, label: DrainLabel, who: str) -> None:
    """`who` read `label`'s tree attributes, and every tree read was of the leaf `wt`."""
    assert asked, f"{who} never read a tree attribute"
    assert {root for root, _attr in asked} == {wt}, f"{who} read trees of {asked}, not of {wt}"
    wanted = {attr for attr, _name in TREE_ATTRS[label]}
    assert wanted <= {attr for _root, attr in asked}, (who, asked, wanted)


def assert_raises_non_member(fn: Callable[[], Any], what: str) -> None:
    """`fn()` raises `AttributeError`: a non-member has no `writable_trees` (O1')."""
    try:
        got = fn()
    except AttributeError:
        return
    pytest.fail(f"{what}: answered {got!r} for a non-member, not AttributeError")


@pytest.mark.parametrize("on_disk", ["absent", "built_with_decoys"])
@pytest.mark.parametrize("label", KNOWN)
def test_each_members_writable_trees_are_its_mount_points_in_order(
        tmp_path: Path, label: DrainLabel, on_disk: str):
    lf = _leaf(tmp_path)
    if on_disk == "built_with_decoys":
        lf.build()
        Leaf(lf.paths, lf.paths.repo_root).build()
    got = label.writable_trees(lf.wt_paths)

    assert got == tuple(lf.wt / rel for rel in EXPECTED_MOUNTS[label])
    assert got == MOUNTS_BY_ATTRIBUTE[label](lf.wt_paths)
    assert label.writable_trees(lf.paths) == tuple(
        lf.paths.repo_root / rel for rel in EXPECTED_MOUNTS[label])
    if on_disk == "absent":
        assert not lf.wt.exists(), "writable_trees touched the disk: it is lexical"
        assert not lf.paths.repo_root.exists(), "writable_trees touched the disk"
    else:
        for root in (lf.wt, lf.paths.repo_root):
            for rel in DECOY_TREES:
                assert (root / rel).is_dir(), f"the decoy {root / rel} is not there to find"


def test_the_mount_lists_are_pairwise_disjoint(tmp_path: Path):
    """No mount lies inside another, within a label or across labels, and no tree is listed
    twice (`DrainTrees.open` refuses a nested or duplicate pair, so one would fail every batch)."""
    w = _leaf(tmp_path).wt_paths
    trees = [t for label in KNOWN for t in label.writable_trees(w)]

    assert len(trees) == len(set(trees)) == 3
    for a in trees:
        for b in trees:
            if a != b:
                assert not a.is_relative_to(b), (str(a), str(b))
    assert w.catalog_dir.is_relative_to(w.skills_dir)


@pytest.mark.parametrize("label", KNOWN)
def test_the_drain_box_mounts_exactly_the_labels_list(tmp_path: Path, label: DrainLabel):
    lf = _leaf(tmp_path)

    request = drains._drain_box_request(lf.wt, "batch-1", label, lf.paths)

    expected = [lf.wt / rel for rel in EXPECTED_MOUNTS[label]]
    assert label.writable_trees(lf.wt_paths) == tuple(expected)
    assert rw_mounts(request) == [(m, Path("/workspace") / m.relative_to(lf.wt)) for m in expected]
    assert ro_mounts(request) == [(lf.wt, Path("/workspace"))]
    assert len(request.mounts) == 1 + len(expected)
    assert Path(request.workdir) == lf.wt
    assert request.model_workdir == Path("/workspace")
    assert request.name == "defender-drain-batch-1"
    assert not lf.wt.exists(), "_drain_box_request touched the disk"


@pytest.mark.parametrize("dot_git", ["file", "folder"])
@pytest.mark.parametrize("label", KNOWN)
def test_a_leaf_that_is_a_git_checkout_is_still_mounted_read_only(
        tmp_path: Path, label: DrainLabel, dot_git: str):
    lf = _leaf(tmp_path)
    lf.build()
    git = lf.wt / ".git"
    if dot_git == "file":
        put_plain(git, b"gitdir: /nonexistent/.git/worktrees/wt-leaf\n")
    else:
        (git / "objects").mkdir(parents=True)

    request = drains._drain_box_request(lf.wt, "batch-1", label, lf.paths)

    expected = [lf.wt / rel for rel in EXPECTED_MOUNTS[label]]
    assert ro_mounts(request) == [(lf.wt, Path("/workspace"))], "the git leaf is not mounted read-only"
    assert rw_mounts(request) == [(m, Path("/workspace") / m.relative_to(lf.wt)) for m in expected]
    assert len(request.mounts) == 1 + len(expected)
    assert git.is_file() if dot_git == "file" else git.is_dir()


@pytest.mark.parametrize("swap", ["fresh_folder", "link_to_outside"])
@pytest.mark.parametrize("label", KNOWN)
def test_the_box_rw_mounts_are_the_roots_open_drain_trees_holds_and_a_swap_moves_none(
        tmp_path: Path, label: str, swap: str):
    """For a known label, the box's rw mounts equal `open_drain_trees(wt_paths, label).mounts`,
    and each of them is held, by behaviour."""
    lf = _leaf(tmp_path)
    lf.build()
    outside = tmp_path / "outside"
    outside.mkdir()
    expected = [lf.wt / rel for rel in EXPECTED_MOUNTS[label]]
    others = [lf.wt / rel for rel in (*ALL_TREES, *DECOY_TREES)
              if rel not in EXPECTED_MOUNTS[label]]

    request = drains._drain_box_request(lf.wt, "batch-1", label, lf.paths)
    rw = [source for source, _target in rw_mounts(request)]
    assert rw == expected
    assert held_roots(tmp_path) == []

    with open_drain_trees(lf.wt_paths, label) as trees:
        assert type(trees) is DrainTrees
        assert trees.mounts == tuple(rw)
        assert held_roots(tmp_path) == real(*rw), "the held roots are not the box's rw mounts"

        helds = {m: trees.mount(m) for m in rw}
        for m, held in helds.items():
            assert type(held) is _io.Held, type(held)
            held.write(BEFORE, PAYLOAD, mode="create")
            assert (m / BEFORE).read_bytes() == PAYLOAD, str(m)
        for other in others:
            refused_value_error(lambda other=other: trees.mount(other), str(other))
            assert trees.tree_for(other / PROBE) is None, str(other)

        moved: dict[Path, Path] = {}
        for m in rw:
            moved[m] = m.with_name(f"{m.name}.moved")
            os.rename(m, moved[m])
            if swap == "fresh_folder":
                m.mkdir()
            else:
                decoy = outside / m.name
                put_plain(decoy / AFTER, HOST_BYTES)
                m.symlink_to(decoy, target_is_directory=True)
        swapped_in = census(outside) if swap == "link_to_outside" else {
            m: census(m) for m in rw}

        for m in rw:
            assert trees.mount(m) is helds[m], f"{m} answered another handle after the swap"
            helds[m].write(AFTER, PAYLOAD, mode="replace")
            assert (moved[m] / AFTER).read_bytes() == PAYLOAD, f"{m}: the write left its root"
            assert (moved[m] / BEFORE).read_bytes() == PAYLOAD
        assert swapped_in == (census(outside) if swap == "link_to_outside" else {
            m: census(m) for m in rw}), "a write reached what was swapped in at a mount path"
        assert held_roots(tmp_path) == real(*moved.values())
    assert held_roots(tmp_path) == [], "a root is still held after the trees closed"


@pytest.mark.parametrize("label", UNKNOWN_LABELS)
def test_a_non_member_raises_at_the_box_and_the_holder_and_nothing_is_held(
        tmp_path: Path, label: object):
    lf = _leaf(tmp_path)

    assert_raises_non_member(
        lambda: drains._drain_box_request(lf.wt, "batch-1", label, lf.paths), "the box")
    assert_raises_non_member(lambda: open_drain_trees(lf.wt_paths, label), "the holder")
    assert held_roots(tmp_path) == []
    assert not lf.wt.exists()

    for owner in KNOWN:
        request = drains._drain_box_request(lf.wt, "batch-1", owner, lf.paths)
        assert rw_mounts(request) == [(lf.wt / rel, Path("/workspace") / rel) for rel in EXPECTED_MOUNTS[owner]]
        with pytest.raises(FileNotFoundError):
            open_drain_trees(lf.wt_paths, owner)
        assert held_roots(tmp_path) == []
    lf.build()
    for owner in KNOWN:
        expected = tuple(lf.wt / rel for rel in EXPECTED_MOUNTS[owner])
        with open_drain_trees(lf.wt_paths, owner) as trees:
            assert trees.mounts == expected
            assert held_roots(tmp_path) == real(*expected)
    assert held_roots(tmp_path) == []


def test_a_tree_missing_from_the_leaf_is_refused_never_skipped(tmp_path: Path):
    """A listed tree that is not on disk fails the open as itself, and leaves nothing held: the
    holder never answers a shorter list than the box mounts."""
    lf = _leaf(tmp_path)
    lf.build("defender/lessons")

    with pytest.raises(FileNotFoundError):
        open_drain_trees(lf.wt_paths, AUTHOR)
    assert held_roots(tmp_path) == []

    lf.build("defender/lessons-questioner")
    expected = (lf.wt / "defender/lessons", lf.wt / "defender/lessons-questioner")
    with open_drain_trees(lf.wt_paths, AUTHOR) as trees:
        assert trees.mounts == expected
        assert held_roots(tmp_path) == real(*expected)
    assert held_roots(tmp_path) == []


@pytest.mark.parametrize("label", KNOWN)
def test_the_box_and_the_held_trees_both_follow_whatever_trees_paths_names(
        tmp_path: Path, label: DrainLabel):
    asked: list[tuple[Path, str]] = []
    paths = relocated_paths(asked)(repo_root=tmp_path / MAIN,
                                   state_dir=tmp_path / "learning-state")
    lf = Leaf(paths, tmp_path / "wt-leaf")
    wt = lf.wt
    lf.build(*ALL_TREES, *DECOY_TREES, *all_relocated(wt), *all_relocated(paths.repo_root))
    expected = [wt / rel for rel in relocated_rels(label, wt)]

    request = drains._drain_box_request(wt, "batch-1", label, paths)

    assert rw_mounts(request) == [(m, Path("/workspace") / m.relative_to(wt)) for m in expected]
    assert ro_mounts(request) == [(wt, Path("/workspace"))]
    assert len(request.mounts) == 1 + len(expected)
    assert_asked_of(asked, wt, label, "the box")
    asked.clear()

    wt_paths = paths.with_repo_root(wt)
    assert type(wt_paths) is type(paths)  # the double keeps itself across the rebase
    with open_drain_trees(wt_paths, label) as trees:
        assert trees.mounts == tuple(expected)
        assert held_roots(tmp_path) == real(*expected)
        for m in expected:
            trees.mount(m).write(PROBE, PAYLOAD, mode="create")
            assert (m / PROBE).read_bytes() == PAYLOAD, str(m)
    assert held_roots(tmp_path) == []
    assert_asked_of(asked, wt, label, "the holder")


def relative_paths(how: str, root: Path, tmp_path: Path) -> LoopPaths:
    """A `LoopPaths` whose `repo_root` is the relative `root`: `constructed` directly, or
    `rebased` from the main checkout's paths through `with_repo_root`, the drain's own route."""
    state = tmp_path / "learning-state"
    if how == "constructed":
        return LoopPaths(repo_root=root, state_dir=state)
    return LoopPaths(repo_root=tmp_path / MAIN, state_dir=state).with_repo_root(root)


@pytest.mark.parametrize("how", ["constructed", "rebased"])
@pytest.mark.parametrize("at_cwd", ["the_trees", "a_file_at_each_tree"])
@pytest.mark.parametrize("label", KNOWN)
def test_a_relative_repo_root_is_refused_before_anything_is_held_never_joined_to_the_cwd(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, label: str, at_cwd: str, how: str):
    rel_root = Path("relative-wt")
    abs_root = tmp_path / rel_root
    for rel in EXPECTED_MOUNTS[label]:
        if at_cwd == "the_trees":
            (abs_root / rel).mkdir(parents=True)
        else:
            put_plain(abs_root / rel, b"a file where the tree would be\n")
    monkeypatch.chdir(tmp_path)
    relative = relative_paths(how, rel_root, tmp_path)
    listed = tuple(rel_root / rel for rel in EXPECTED_MOUNTS[label])

    assert relative.repo_root == rel_root
    assert label.writable_trees(relative) == listed
    with pytest.raises(ValueError, match="host root"):
        drains._drain_box_request(
            rel_root, "batch-1", label, LoopPaths(repo_root=tmp_path / MAIN))
    with pytest.raises(ValueError):  # noqa: PT011 — DrainTrees' mount refusal; the type is the contract
        open_drain_trees(relative, label)
    assert held_roots(tmp_path) == [], "a relative mount was held"

    absolute = LoopPaths(repo_root=abs_root, state_dir=tmp_path / "learning-state")
    if at_cwd == "the_trees":
        expected = tuple(abs_root / rel for rel in EXPECTED_MOUNTS[label])
        with open_drain_trees(absolute, label) as trees:
            assert trees.mounts == expected
            assert held_roots(tmp_path) == real(*expected)
    else:
        with pytest.raises(NotADirectoryError):
            open_drain_trees(absolute, label)
    assert held_roots(tmp_path) == []


#: Each lane's own branch prefix (`AuthorBranch`'s default, and the lead lane's).
LANE_PREFIX = {AUTHOR: "lessons/", LEAD: "lead-author/"}


class CheckoutBranch(B.RecordingBranch):
    """`_box665.RecordingBranch` (the recorded worktree lifecycle), whose leaf carries the three
    drain trees as the real worktree, a checkout of the repo, does, plus the decoys,
    `relocated_paths`' trees for this leaf, and the ones it names for the main checkout. The
    leaf sits under its own base, never at `paths.repo_root`, and is kept after the drive
    (`destroy_on_cleanup` off)."""

    def __init__(self, worktree_base: Path, **kw: Any) -> None:
        super().__init__(worktree_base, **kw)
        self.leaves: list[Path] = []

    def start_batch(self, batch_id: str) -> Path:
        wt = super().start_batch(batch_id)
        for rel in (*ALL_TREES, *DECOY_TREES, *all_relocated(wt), *all_relocated(Path(MAIN))):
            (wt / rel).mkdir(parents=True, exist_ok=True)
        self.leaves.append(wt)
        return wt


class WorkStep:
    """The lane's work-step seam (`trigger_author=` for the author lane, `run_lead_author=` for
    the lead lane). It records the `LoopPaths` the lane hands its work step, and on the first
    call opens `open_drain_trees(that paths, label)` while the box is up, the place A3 puts the
    drain's trees. It records the mounts, the descriptors held under the leaf, and what a write
    through each `mount(m)` left at `m / PROBE`. It answers nothing and asserts nothing: both
    lanes contain a work-step fault, so a fault is recorded for the test to report."""

    def __init__(self, label: str) -> None:
        self.label = label
        self.received: list[LoopPaths] = []
        self.mounts: tuple[Path, ...] | None = None
        self.held: list[str] | None = None
        self.landed: dict[Path, bytes] = {}
        self.fault: str | None = None

    def __call__(self, paths: LoopPaths, *_args: Any, **_kw: Any) -> None:
        self.received.append(paths)
        if self.mounts is not None:
            return
        try:
            with open_drain_trees(paths, self.label) as trees:
                self.mounts = trees.mounts
                self.held = held_roots(paths.repo_root)
                for m in trees.mounts:
                    trees.mount(m).write(PROBE, PAYLOAD, mode="create")
                    self.landed[m] = (m / PROBE).read_bytes()
        except Exception as e:  # noqa: BLE001 — reported by the test; the lane would swallow it
            self.fault = f"{type(e).__name__}: {e}"


@dataclasses.dataclass
class Drive:
    """One lane drive's inputs and recorders: the lane's label, the `paths` kind it was handed
    (`shipped`, or `relocated` with its `asked` log), the box recorder, the branch and the work
    step."""

    label: str
    kind: str
    paths: LoopPaths
    asked: list[tuple[Path, str]]
    rec: B.BoxLifecycleRecorder
    branch: CheckoutBranch
    step: WorkStep


def start_drive(tmp_path: Path, label: str, kind: str, prefix: str) -> Drive:
    """The drive's `paths` (`kind`), and a branch whose prefix is the lane's own or the other
    lane's (`prefix`)."""
    asked: list[tuple[Path, str]] = []
    cls = LoopPaths if kind == "shipped" else relocated_paths(asked)
    paths = cls(repo_root=tmp_path / MAIN, state_dir=tmp_path / "learning-state")
    paths.state_root.mkdir(parents=True, exist_ok=True)  # the handle never creates its root (#1135)
    other = LEAD if label == AUTHOR else AUTHOR
    rec = B.BoxLifecycleRecorder()
    branch = CheckoutBranch(tmp_path / "worktrees", events=rec.events,
                            branch_prefix=LANE_PREFIX[label if prefix == "own" else other])
    return Drive(label, kind, paths, asked, rec, branch, WorkStep(label))


def assert_the_lane_mounted_its_leaf_trees_and_its_work_step_held_them(d: Drive) -> None:
    """The drive's verdict, from the `BoxRequest` the box seam was handed and what the work
    step recorded: the rw mounts are the lane's list for `d.kind` under the leaf, in order."""
    [leaf] = d.branch.leaves
    assert leaf != d.paths.repo_root
    request = d.rec.only_request()
    shipped = list(EXPECTED_MOUNTS[d.label])
    rels = shipped if d.kind == "shipped" else relocated_rels(d.label, leaf)
    expected = [leaf / rel for rel in rels]

    assert rw_mounts(request) == [(m, Path("/workspace") / m.relative_to(leaf)) for m in expected], (
        f"the box's rw mounts are {rw_mounts(request)}, not {rels} under the leaf")
    assert ro_mounts(request) == [(leaf, Path("/workspace"))]
    assert len(request.mounts) == 1 + len(expected)
    for m in request.mounts:
        assert Path(m.source).is_absolute(), m
        assert Path(m.target).is_absolute(), m
    [(wt, _)] = ro_mounts(request)
    rw = tuple(source for source, _target in rw_mounts(request))

    step = d.step
    assert step.fault is None, f"the work step's open failed: {step.fault}"
    assert step.received, "the lane never reached its work step"
    for got in step.received:
        assert type(got) is type(d.paths), type(got)
        assert got == d.paths.with_repo_root(wt), got
    assert step.mounts == rw, "the trees the work step holds are not the box's rw mounts"
    assert step.held == real(*rw), "the held roots are not the box's rw mounts"
    assert step.landed == dict.fromkeys(rw, PAYLOAD)
    if d.kind == "relocated":
        assert {attr for root, attr in d.asked if root == wt} >= {
            attr for attr, _name in TREE_ATTRS[d.label]}, d.asked


@pytest.mark.parametrize("prefix", ["own", "other_lanes"])
@pytest.mark.parametrize("kind", ["shipped", "relocated"])
def test_the_author_lane_mounts_its_leafs_two_corpora_and_its_work_step_holds_them(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str, prefix: str):
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")
    d = start_drive(tmp_path, AUTHOR, kind, prefix)
    put_plain(d.paths.state_root / FINDINGS.queue, b'{"finding_id": "f-1"}\n')

    rc = drains.author_drain(d.paths, trigger_author=d.step, branch=d.branch,
                             start_box=d.rec.start_box, stop_box=d.rec.stop_box,
                             scrub=d.rec.scrub)

    assert rc == 0
    assert len(d.step.received) == 2, "both curators' turns are the work step"
    assert_the_lane_mounted_its_leaf_trees_and_its_work_step_held_them(d)


@pytest.mark.parametrize("prefix", ["own", "other_lanes"])
@pytest.mark.parametrize("kind", ["shipped", "relocated"])
def test_the_lead_lane_mounts_its_leafs_skills_and_its_work_step_holds_it(
        tmp_path: Path, kind: str, prefix: str):
    d = start_drive(tmp_path, LEAD, kind, prefix)
    run_dir = curation_run_dir("run-1")
    with state_for_paths(d.paths) as state:
        enqueue_case(state, "case-1", run_dir)

    rc = drains.lead_author_drain(
        d.paths, run_lead_author=d.step, run_pitfalls=lambda *_a, **_kw: 0, branch=d.branch,
        start_box=d.rec.start_box, stop_box=d.rec.stop_box, scrub=d.rec.scrub)

    assert rc == 0
    assert len(d.step.received) == 1, "the one queued case is the work step"
    assert_the_lane_mounted_its_leaf_trees_and_its_work_step_held_them(d)
