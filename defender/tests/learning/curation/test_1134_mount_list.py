from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

import dataclasses
import enum
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from defender import _io
from defender.learning.core.config import (
    DrainLabel, LoopPaths,
)
from defender.learning.core.lane_trees import DrainTrees, open_drain_trees
from defender.tests.support.learning.curation._drain_trees_1134 import PAYLOAD
from defender.tests.shared.filesystem.test_1111_rooted_io import HOST_BYTES, census
from defender.tests.support.learning.curation._tree_listing_1134 import descriptors_under, put_plain


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
    location_path(paths.state_root).mkdir(parents=True, exist_ok=True)  # the handle never creates its root (#1135)
    return Leaf(paths=paths, wt=tmp_path / "wt-leaf")


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
            return type(self)(repo_root=repo_root, state_dir=location_path(self.state_root))

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


#: Each known label's writable lanes as the P4 drain box mounts them, relative to the batch's
#: draft root (the `staged` mount): the same lanes `EXPECTED_MOUNTS` names in a checkout, under
#: the tenant's `agent/` (#1108 P4, OD6).
DRAFT_LANES: dict[DrainLabel, tuple[str, ...]] = {
    AUTHOR: ("agent/lessons", "agent/lessons-questioner"),
    LEAD: ("agent/skills",),
}
ALL_DRAFT_LANES = ("agent/lessons", "agent/lessons-questioner", "agent/skills")


def _drain_tick_over_draft(tmp_path: Path, data_root: Path, monkeypatch: pytest.MonkeyPatch,
                           label: DrainLabel, step: Callable[[Any, Any, Any], None]) -> tuple[int, Any]:
    """One real P4 drain tick of `label`'s lane over the fixture tenant (#1108 P4 flow 4), its
    work step replaced by `step(step_paths, batch, box_spy)`, run once, inside the batch, after
    the box started: through `trigger_author` (author lane, a queued finding wakes it) or
    `run_pitfalls` (lead lane, a queued pitfall wakes it). OD16: the drain hands each lane entry
    its tick's batch as `batch=`; `step_paths` stays the product-rooted `LoopPaths`. Returns
    `(exit status, the BoxSpy)`."""
    from defender.learning.core.state import FINDINGS, PITFALLS
    from defender.tests.support.learning.core._declared870 import shim_row
    from defender.tests.support.learning.curation._drain719 import finding_row, seed
    from defender.tests.tenancy.tenant_1108_p4._drain_support import (
        BoxSpy, author_drain, drain_paths, lead_author_drain, product_repo)
    from defender.tests.tenancy.tenant_1108_p4._support import bind_forge, published_tenant

    box = BoxSpy()
    ran: list[str] = []

    def once(step_paths: Any, batch: Any) -> None:
        if not ran:
            ran.append("ran")
            step(step_paths, batch, box)

    with published_tenant(tmp_path / "forge", root=data_root) as t:
        bind_forge(t)
        paths = drain_paths(t, product_repo(tmp_path))
        if label is AUTHOR:
            monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")
            seed(paths, FINDINGS, [finding_row("f1", run_id="f1")])
            rc = author_drain(t, paths, trigger=lambda step_paths, *_a, batch, **_kw: once(step_paths, batch),
                              box=box)
        else:
            monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "1")
            seed(paths, PITFALLS, [shim_row("p1:1")])
            rc = lead_author_drain(
                t, paths, box=box, run_lead_author=lambda *_a, **_kw: None,
                run_pitfalls=lambda step_paths, *_a, batch, **_kw: once(step_paths, batch) or 0)
    assert ran, "the lane's work step never ran inside a batch"
    return rc, box


def _refused_others(trees: Any, others: list[Path]) -> list[bool]:
    """For each tree outside the label's lanes: refused by `mount` and unknown to `tree_for`."""
    refused = []
    for other in others:
        try:
            trees.mount(other)
        except ValueError:
            refused.append(trees.tree_for(other / PROBE) is None)
        else:
            refused.append(False)
    return refused


def _swap(rw: list[Path], swap: str, outside: Path) -> dict[Path, Path]:
    """Move each mount path aside and put a fresh folder or a link out in its place."""
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
    return moved


def _restore(moved: dict[Path, Path]) -> None:
    """Put the draft back as the box found it, so the rest of the tick is ordinary."""
    for m, aside in moved.items():
        if m.is_symlink():
            m.unlink()
        else:
            os.rmdir(m)
        for name in (BEFORE, AFTER):
            (aside / name).unlink()
        os.rename(aside, m)


def _o4_step(label: DrainLabel, swap: str, outside: Path, seen: dict[str, Any]):
    """The lane's work step for the O4 case: records what the box mounted and how the roots
    `open_drain_trees` holds behave across a swap. Observations only: a raise here is contained
    by the drain as a curator fault.

    ASSUMED SEAM (OD16): `open_drain_trees(paths, label, *, batch)` holds `label`'s lanes under
    `batch.draft_root` (the box's rw mounts) while `paths` stays product-rooted."""

    def swapped_in(rw: list[Path]) -> Any:
        return census(outside) if swap == "link_to_outside" else {m: census(m) for m in rw}

    def step(step_paths: Any, batch: Any, box: Any) -> None:
        [request] = box.requests
        [staged] = [Path(m.source) for m in request.mounts if m.kind == "staged"]
        rw = [Path(m.source) for m in request.mounts if m.writable]
        drafts = staged.parent.parent  # amendment A / U9: <T>/drafts/<id>/stage
        seen.update(staged=staged, rw=rw, held_before=held_roots(drafts),
                    draft_root=Path(batch.draft_root), repo_root=Path(step_paths.repo_root))
        others = [staged / rel for rel in ALL_DRAFT_LANES if rel not in DRAFT_LANES[label]]
        with open_drain_trees(step_paths, label, batch=batch) as trees:
            seen.update(type=type(trees), mounts=trees.mounts, held=held_roots(drafts))
            helds = {m: trees.mount(m) for m in rw}
            seen["held_types"] = {type(h) for h in helds.values()}
            for held in helds.values():
                held.write(BEFORE, PAYLOAD, mode="create")
            seen["before_landed"] = [(m / BEFORE).read_bytes() == PAYLOAD for m in rw]
            seen["others_refused"] = _refused_others(trees, others)
            moved = _swap(rw, swap, outside)
            before = swapped_in(rw)
            seen["same_handle"] = [trees.mount(m) is helds[m] for m in rw]
            for m in rw:
                helds[m].write(AFTER, PAYLOAD, mode="replace")
            seen["after_landed"] = [(moved[m] / AFTER).read_bytes() == PAYLOAD for m in rw]
            seen["swapped_in_untouched"] = swapped_in(rw) == before
            seen["held_moved"] = held_roots(drafts) == real(*moved.values())
        seen["held_after"] = held_roots(drafts)
        _restore(moved)

    return step


@pytest.mark.parametrize("swap", ["fresh_folder", "link_to_outside"])
@pytest.mark.parametrize("label", KNOWN)
def test_the_box_rw_mounts_are_the_roots_open_drain_trees_holds_and_a_swap_moves_none(
        tmp_path: Path, data_root: Path, monkeypatch: pytest.MonkeyPatch, label: DrainLabel,
        swap: str):
    """#1134 O4 over P4's draft (#1108 P4 flow 4): for a known label, the drain box's rw mounts
    are the draft's lanes for that label, they equal the roots `open_drain_trees` holds over the
    paths the drain hands the lane's work step, and each is held by behaviour — a write through
    a held root stays in it when the mount path is swapped (a fresh folder, a link out)."""
    outside = tmp_path / "outside"
    outside.mkdir()
    seen: dict[str, Any] = {}
    step = _o4_step(label, swap, outside, seen)

    _rc, _box = _drain_tick_over_draft(tmp_path, data_root, monkeypatch, label, step)

    staged, rw = seen["staged"], seen["rw"]
    assert [m.relative_to(staged).as_posix() for m in rw] == list(DRAFT_LANES[label])
    assert seen["draft_root"] == staged, "the step's batch is not the draft the box mounted"
    assert not staged.is_relative_to(seen["repo_root"]), "the step's paths are draft-rooted"
    assert seen["held_before"] == []
    assert seen["type"] is DrainTrees
    assert seen["mounts"] == tuple(rw), "the held roots are not the box's rw mounts"
    assert seen["held"] == real(*rw)
    assert seen["held_types"] == {_io.Held}
    assert all(seen["before_landed"])
    assert all(seen["others_refused"]), "a tree outside the label's lanes was held"
    assert all(seen["same_handle"]), "a mount answered another handle after the swap"
    assert all(seen["after_landed"]), "a write left its held root after the swap"
    assert seen["swapped_in_untouched"], "a write reached what was swapped in at a mount path"
    assert seen["held_moved"]
    assert seen["held_after"] == [], "a root is still held after the trees closed"


@pytest.mark.parametrize("label", UNKNOWN_LABELS)
def test_a_non_member_raises_at_the_box_and_the_holder_and_nothing_is_held(
        tmp_path: Path, label: object):
    """The holder half: P4's box is built from the batch's lanes, never from a label (its
    one-list promise is `test_the_box_rw_mounts_are_the_roots_open_drain_trees_holds...`)."""
    lf = _leaf(tmp_path)

    assert_raises_non_member(lambda: open_drain_trees(lf.wt_paths, label), "the holder")
    assert held_roots(tmp_path) == []
    assert not lf.wt.exists()

    for owner in KNOWN:
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

    # The box half (`_drain_box_request` following the paths) is gone with the worktree batch:
    # P4's box mounts the draft's lanes (`test_the_box_rw_mounts_are_the_roots_open_drain_trees_
    # holds...`); the holder still follows whatever trees the paths name.
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
    # The box half (`_drain_box_request` over a relative worktree) is gone: P4's box mounts a
    # draft under the tenant's own (absolute) folder (tenant_1108_delivery/test_box.py).
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
