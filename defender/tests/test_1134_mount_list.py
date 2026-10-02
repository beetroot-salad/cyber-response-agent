"""#1134 v2 step 3: one list of drain mounts, its two labels, and the trees held from it (O4).

The contract is #1134's 2026-10-01 design addendum, A3 (it replaces the 2026-09-28 design's D3
and keeps O4), with the owner's 2026-09-29 decision that each drain label is spelled once:

- `learning/core/config.py` spells the two labels once, as `AUTHOR_DRAIN_LABEL = "author_drain"`
  and `LEAD_AUTHOR_DRAIN_LABEL = "lead_author_drain"`. In `config` those two strings are the
  values of those two constants and appear nowhere else. In `drains`, each lane's
  `_run_worktree_batch(label=...)` passes its constant by name, never a string.
- `LoopPaths.drain_writable_trees(label) -> tuple[Path, ...]` is the one list of trees a drain
  box may write: `AUTHOR_DRAIN_LABEL` -> `(lessons_dir, lessons_questioner_dir)`, in that order,
  `LEAD_AUTHOR_DRAIN_LABEL` -> `(skills_dir,)`, and any other label -> `()`, near misses
  included (a case change, a space, hyphens, a prefix, an extra character, the empty string).
  It is lexical: built from `self.repo_root` as spelled, nothing resolved, nothing on disk read.
- `drains._drain_box_request(wt, batch_id, label, paths)` mounts read-write exactly
  `paths.with_repo_root(wt).drain_writable_trees(label)`, in order, each at its own path
  (target == source), plus the one read-only mount of `wt`, and nothing else. It derives no list
  of its own.
- `lane_trees.open_drain_trees(wt_paths, label) -> DrainTrees` is exactly
  `DrainTrees.open(wt_paths.drain_writable_trees(label))`. `DefenderPaths` does not absolutize
  `repo_root`, so a relative root lists relative mounts, and those are refused with `ValueError`
  before anything is held, never joined to the cwd.

O4 then reads: for every label, the box's read-write mounts equal
`open_drain_trees(paths.with_repo_root(wt), label).mounts`, and those are the held roots. "Held"
is pinned by behaviour, not by comparing objects. While the trees are open, this process holds
exactly one descriptor per rw mount and none on anything else in the tmp dir. A write through
`trees.mount(m)` lands at `m / name`. After `m` is renamed away and a fresh folder, or a link to
an outside folder, is put at its path, the same handle still writes into the folder the box was
given. Nothing lands in the swapped-in folder or behind the link.

Every row builds its paths over a drain leaf `wt` that is NOT `paths.repo_root`, so a list taken
from the main checkout instead of the leaf is caught. Every expected mount is also spelled
literally (`wt / "defender/lessons"`, ...) beside the `LoopPaths` attribute, so no row only
compares the list with itself. The lexical rows leave `wt` absent on disk and check it is still
absent afterwards.

Two seams are injected through the `paths` argument (`_RelistedPaths`, v1's E1: a second label
table in the box or in `open_drain_trees` agrees with the list today, so only a list that
differs from the shipped one shows it) and through the lanes' own seams (`trigger_author=`,
`run_lead_author=`, `branch=`, `start_box=`, `stop_box=`, `scrub=`) for the real drives. Nothing
is monkeypatched (`monkeypatch.chdir` / `setenv` only set the cwd and a threshold). No row forks
or spawns: the leaf has no `.git`, so the lead lane's reset/clean is skipped. No deadline is
needed.

v1's E2-E4 rows pinned `LoopPaths.tree_for`, which v2 drops (`DrainTrees.tree_for` is step 2's,
`test_1134_drain_trees.py`); they are not ported. E1 (a second label table) and E5 (near-miss
labels) are. The AST pins are v1 step 6's H7 and H8.

Red before #1134 v2 step 3: `config` has no label constants and `lane_trees` no
`open_drain_trees`, so this module fails at import.
"""
from __future__ import annotations

import ast
import dataclasses
import inspect
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from defender import _io
from defender.learning.core import config, drains, markers
from defender.learning.core.config import AUTHOR_DRAIN_LABEL, LEAD_AUTHOR_DRAIN_LABEL, LoopPaths
from defender.learning.core.lane_trees import DrainTrees, open_drain_trees
from defender.tests._drain_trees_1134 import PAYLOAD
from defender.tests.e2e import _box665 as B
from defender.tests.test_1111_rooted_io import HOST_BYTES, census
from defender.tests._tree_listing_1134 import descriptors_under, put_plain

# ---------------------------------------------------------------------------------------
# The labels and their trees, spelled literally
# ---------------------------------------------------------------------------------------

AUTHOR = "author_drain"
LEAD = "lead_author_drain"
KNOWN = (AUTHOR, LEAD)

#: Each known label's mount points, repo-relative, in the contract's order. Literal on purpose:
#: independent of the `LoopPaths` attribute names the implementation reads.
EXPECTED_MOUNTS: dict[str, tuple[str, ...]] = {
    AUTHOR: ("defender/lessons", "defender/lessons-questioner"),
    LEAD: ("defender/skills",),
}

#: The same lists through the `LoopPaths` attributes the design names.
MOUNTS_BY_ATTRIBUTE: dict[str, Callable[[LoopPaths], tuple[Path, ...]]] = {
    AUTHOR: lambda p: (p.lessons_dir, p.lessons_questioner_dir),
    LEAD: lambda p: (p.skills_dir,),
}

#: Every tree a drain checkout carries that some label mounts.
ALL_TREES = ("defender/lessons", "defender/lessons-questioner", "defender/skills")

#: Labels no lane names, near misses included (v1's E5): a prefix, a case change, a leading or
#: trailing space or newline, hyphens for underscores, a leading or trailing extra character,
#: the empty string, a suffixed version, and the pitfalls lane (drained inside the lead-author
#: tick, never its own box). A label matched by prefix, by case or after `.strip()` gets a tree.
UNKNOWN_LABELS = (
    "a_third_drain", "", "author", "lead_author", "AUTHOR_DRAIN", "Lead_Author_Drain",
    "author_drain ", " author_drain", "lead_author_drain\n", "author-drain",
    "lead-author-drain", "xauthor_drain", "author_drain_", "lead_author_drain_v2",
    "pitfalls_drain",
)

#: The extra tree `_RelistedPaths` lists: a sibling of the real trees, never nested in one.
RELISTED = "defender/relisted"

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
        """Make each tree in `rels` (every tree a checkout carries, by default) under `wt`."""
        for rel in rels or ALL_TREES:
            (self.wt / rel).mkdir(parents=True, exist_ok=True)


def _leaf(tmp_path: Path) -> Leaf:
    paths = LoopPaths(repo_root=tmp_path / "main", state_dir=tmp_path / "learning-state")
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


# ---------------------------------------------------------------------------------------
# The labels: spelled once, in config, and passed by name
# ---------------------------------------------------------------------------------------

#: Each label's value and the one constant it is spelled as.
LABEL_CONSTANTS = {AUTHOR: "AUTHOR_DRAIN_LABEL", LEAD: "LEAD_AUTHOR_DRAIN_LABEL"}


def test_the_label_constants_are_the_lanes_names():
    """`AUTHOR_DRAIN_LABEL` is `"author_drain"` and `LEAD_AUTHOR_DRAIN_LABEL` is
    `"lead_author_drain"`: the strings each lane passed as `label=` before this step (its log
    prefix, and the `label` of its pending-delivery record), unchanged.

    Catches: a constant with the right name and a misspelled value, which the source pins below
    accept, since they check only that each string is spelled once."""
    assert AUTHOR_DRAIN_LABEL == "author_drain"
    assert LEAD_AUTHOR_DRAIN_LABEL == "lead_author_drain"


def _source_tree(module: Any) -> ast.Module:
    return ast.parse(inspect.getsource(module))


def test_config_spells_each_label_once_as_its_constant():
    """In `config`, the strings `"author_drain"` and `"lead_author_drain"` are the values of
    their two module constants and nothing else, so `drain_writable_trees` compares the
    constants (v1 step 6's H7). A plain or annotated assignment both count.

    Catches: `if label == "author_drain":` beside the constants, a second spelling that agrees
    with the constant until one of them changes. No drive can see that."""
    tree = _source_tree(config)
    owned: dict[str, int] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target, value = node.targets[0], node.value
        elif isinstance(node, ast.AnnAssign):
            target, value = node.target, node.value
        else:
            continue
        if (isinstance(target, ast.Name) and isinstance(value, ast.Constant)
                and value.value in LABEL_CONSTANTS):
            assert LABEL_CONSTANTS[value.value] == target.id, ast.dump(node)
            owned[target.id] = id(value)
    assert sorted(owned) == sorted(LABEL_CONSTANTS.values()), owned

    strays = [(n.lineno, n.value) for n in ast.walk(tree)
              if isinstance(n, ast.Constant) and n.value in LABEL_CONSTANTS
              and id(n) not in owned.values()]
    assert strays == [], strays


def _callee(call: ast.Call) -> str | None:
    f = call.func
    return f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else None


def _batch_calls(node: ast.AST) -> list[ast.Call]:
    return [n for n in ast.walk(node)
            if isinstance(n, ast.Call) and _callee(n) == "_run_worktree_batch"]


def _label_kw(call: ast.Call) -> ast.expr | None:
    return next((k.value for k in call.keywords if k.arg == "label"), None)


def _imported_from_config(tree: ast.Module) -> set[str]:
    """The names `drains` binds by `from defender.learning.core.config import NAME` (unaliased),
    at module level or inside a function."""
    return {a.name for n in ast.walk(tree)
            if isinstance(n, ast.ImportFrom) and n.module == "defender.learning.core.config"
            for a in n.names if a.asname in (None, a.name)}


def _assigned_at_module_level(tree: ast.Module) -> set[str]:
    out: set[str] = set()
    for node in tree.body:
        targets = (node.targets if isinstance(node, ast.Assign)
                   else [node.target] if isinstance(node, ast.AnnAssign) else [])
        out |= {t.id for t in targets if isinstance(t, ast.Name)}
    return out


def test_the_drains_pass_a_constant_to_the_worktree_batch():
    """Every `_run_worktree_batch(label=...)` in `drains` passes a name, never a string (v1 step
    6's H8). Each lane passes its own constant, the one `config` defines: `author_drain` passes
    `AUTHOR_DRAIN_LABEL` and `lead_author_drain` passes `LEAD_AUTHOR_DRAIN_LABEL`, imported
    from `config` (or read as `config.<NAME>`), never re-bound in `drains`.

    Catches: `label="author_drain"`, an f-string or concatenation built at the call, and a
    second module constant in `drains` (`_AUTHOR = "author_drain"`), each a second spelling the
    drives below cannot tell from the constant."""
    tree = _source_tree(drains)
    calls = _batch_calls(tree)
    assert len(calls) >= 2, "expected the author and the lead-author drains' batch calls"
    for call in calls:
        value = _label_kw(call)
        assert value is not None, ast.dump(call)
        assert isinstance(value, (ast.Name, ast.Attribute)), (call.lineno, ast.dump(value))

    imported = _imported_from_config(tree)
    rebound = _assigned_at_module_level(tree)
    for lane, constant in ((AUTHOR, "AUTHOR_DRAIN_LABEL"), (LEAD, "LEAD_AUTHOR_DRAIN_LABEL")):
        [fn] = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == lane]
        [call] = _batch_calls(fn)
        value = _label_kw(call)
        if isinstance(value, ast.Name):
            assert value.id == constant, (lane, value.id)
            assert constant in imported, f"{constant} is not imported from config in drains"
            assert constant not in rebound, f"drains re-binds {constant} at module level"
        else:
            assert isinstance(value, ast.Attribute), (lane, ast.dump(value))
            assert value.attr == constant, (lane, value.attr)
            assert isinstance(value.value, ast.Name), ast.dump(value)
            assert getattr(drains, value.value.id) is config, ast.dump(value)


# ---------------------------------------------------------------------------------------
# drain_writable_trees: the one list
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("label", KNOWN)
def test_drain_writable_trees_is_each_labels_mount_points_in_order(tmp_path: Path, label: str):
    """`drain_writable_trees(label)` is the label's mount points, a tuple in the contract's
    order, under the `LoopPaths` it is asked on.

    True: under the leaf, `author_drain` gives `(lessons_dir, lessons_questioner_dir)` and
    `lead_author_drain` gives `(skills_dir,)`, equal to the literal spellings
    `wt / "defender/..."` (a tuple: a list never equals one). The main checkout's `paths` gives
    the same shape under its own root, so the list follows `repo_root`. The constant and the
    literal label answer alike. Neither root is made on disk.

    Catches: a missing tree, an extra one (the catalog, or the whole `defender/`), a swapped
    order, a list, a list built from a fixed root rather than `self`, and a list that makes its
    folders."""
    lf = _leaf(tmp_path)
    got = lf.wt_paths.drain_writable_trees(label)

    assert got == tuple(lf.wt / rel for rel in EXPECTED_MOUNTS[label])
    assert got == MOUNTS_BY_ATTRIBUTE[label](lf.wt_paths)
    constant = AUTHOR_DRAIN_LABEL if label == AUTHOR else LEAD_AUTHOR_DRAIN_LABEL
    assert lf.wt_paths.drain_writable_trees(constant) == got
    assert lf.paths.drain_writable_trees(label) == tuple(
        lf.paths.repo_root / rel for rel in EXPECTED_MOUNTS[label])
    assert not lf.wt.exists(), "drain_writable_trees touched the disk: it is lexical"
    assert not lf.paths.repo_root.exists(), "drain_writable_trees touched the disk: it is lexical"


@pytest.mark.parametrize("label", UNKNOWN_LABELS)
def test_an_unknown_label_has_no_writable_tree(tmp_path: Path, label: str):
    """An unknown label, near misses included, lists nothing.

    True: `drain_writable_trees(label) == ()`, on the leaf and on the main checkout. The
    positive control on the same `LoopPaths`: both known labels list their trees.

    Catches: an unknown label that falls through to a default tree (the old `else` shape), and a
    label matched by prefix, by case, or after stripping whitespace (v1's E5)."""
    lf = _leaf(tmp_path)

    assert lf.wt_paths.drain_writable_trees(label) == ()
    assert lf.paths.drain_writable_trees(label) == ()
    for owner in KNOWN:
        assert lf.wt_paths.drain_writable_trees(owner) == tuple(
            lf.wt / rel for rel in EXPECTED_MOUNTS[owner])
    assert not lf.wt.exists()


def test_the_mount_lists_are_pairwise_disjoint(tmp_path: Path):
    """No mount lies inside another, within a label or across labels, and no tree is listed
    twice (`DrainTrees.open` refuses a nested or duplicate pair, so one would fail every batch).

    True: over the union of both known labels' lists (three trees), no tree is a
    path-component descendant of a different one, and the union has three distinct members.
    The positive control shows the check is not vacuous: the catalog does lie inside
    `skills_dir`, and the check sees that.

    Catches: a list that grows a nested mount (the catalog beside `skills/`, or `defender/`
    beside a corpus)."""
    w = _leaf(tmp_path).wt_paths
    trees = [t for label in KNOWN for t in w.drain_writable_trees(label)]

    assert len(trees) == len(set(trees)) == 3
    for a in trees:
        for b in trees:
            if a != b:
                assert not a.is_relative_to(b), (str(a), str(b))
    assert w.catalog_dir.is_relative_to(w.skills_dir)


# ---------------------------------------------------------------------------------------
# _drain_box_request mounts that list and nothing else
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("label", [*KNOWN, *UNKNOWN_LABELS])
def test_the_drain_box_mounts_exactly_the_labels_list(tmp_path: Path, label: str):
    """The real `_drain_box_request` mounts exactly the leaf's `drain_writable_trees(label)`
    read-write, each at its own path, plus `wt` read-only, and nothing else.

    True, for both known labels, the unknown (empty) label and every near miss:
    - the rw mounts, in order, are `(m, m)` for each `m` of the literal list under `wt`, which
      is `wt_paths.drain_writable_trees(label)`;
    - the only read-only mount is `wt` at `wt`, and there is no other mount;
    - the workdir is still `wt` and the name still carries the batch id (unchanged);
    - the leaf is not made on disk.

    Catches: the box mounting the main checkout's trees rather than the leaf's, a duplicate or
    extra mount, a mount whose target differs from its source, the lost ro mount of the leaf, a
    near-miss label that gets a tree, and an unknown label that falls through to a default."""
    lf = _leaf(tmp_path)

    request = drains._drain_box_request(lf.wt, "batch-1", label, lf.paths)

    expected = [lf.wt / rel for rel in EXPECTED_MOUNTS.get(label, ())]
    assert lf.wt_paths.drain_writable_trees(label) == tuple(expected)
    assert rw_mounts(request) == [(m, m) for m in expected]
    assert ro_mounts(request) == [(lf.wt, lf.wt)]
    assert len(request.mounts) == 1 + len(expected)
    assert Path(request.workdir) == lf.wt
    assert request.name == "defender-drain-batch-1"
    assert not lf.wt.exists(), "_drain_box_request touched the disk"


# ---------------------------------------------------------------------------------------
# O4: the box's rw mounts are the roots open_drain_trees holds
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("swap", ["fresh_folder", "link_to_outside"])
@pytest.mark.parametrize("label", KNOWN)
def test_the_box_rw_mounts_are_the_roots_open_drain_trees_holds_and_a_swap_moves_none(
        tmp_path: Path, label: str, swap: str):
    """For a known label, the box's rw mounts equal `open_drain_trees(wt_paths, label).mounts`,
    and each of them is held, by behaviour.

    True, over a leaf that carries all three trees:
    - `open_drain_trees` gives the real `DrainTrees`, whose `.mounts` is the box's rw source list
      in order (the literal list);
    - while it is open, this process holds one descriptor per rw mount and none on anything else
      in the tmp dir (the other label's tree is in the leaf and is not held);
    - for each rw mount `m`, a write through `trees.mount(m)` lands at `m / name`, byte-exact;
    - the other label's trees are no mount point (`mount` is `ValueError`, `tree_for` `None`);
    - then every `m` is renamed away and a fresh empty folder, or a link to an outside folder
      holding a decoy at the name, is put at its path. A `replace` write through the same handle
      lands in the renamed folder, beside the first write. The swapped-in folder and the decoy
      are untouched, and the held descriptors now name the renamed folders;
    - closing the trees releases every root.

    Catches: `open_drain_trees` holding a different list than the box mounts (a missing, extra or
    reordered tree), a holder that writes by path instead of through the descriptor it took at
    open (it follows the swap, into the fresh folder or through the link), a holder that also
    holds the other label's tree, and one that never releases its roots."""
    lf = _leaf(tmp_path)
    lf.build()
    outside = tmp_path / "outside"
    outside.mkdir()
    expected = [lf.wt / rel for rel in EXPECTED_MOUNTS[label]]
    others = [lf.wt / rel for rel in ALL_TREES if rel not in EXPECTED_MOUNTS[label]]

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
def test_an_unknown_label_mounts_nothing_writable_and_holds_nothing(tmp_path: Path, label: str):
    """The empty case of O4: an unknown label, or a near miss, has no rw mount and its trees
    hold nothing, over a leaf that is not even on disk.

    True: the box's rw list is empty and its ro mount is `wt`. `open_drain_trees` succeeds with
    `wt` absent, `.mounts == ()`, no descriptor is held, every known mount point is no mount of
    it (`mount` is `ValueError`, `tree_for` of a path below is `None`), and `wt` stays absent.
    The positive control at the same address: each known label over that absent leaf reaches
    for it (`FileNotFoundError`, nothing left held), and once the leaf is built it opens and
    holds its literal list.

    Catches: a holder with a label table of its own that falls through to a default (or
    matches a near miss), and one that answers the empty list without asking the label."""
    lf = _leaf(tmp_path)

    request = drains._drain_box_request(lf.wt, "batch-1", label, lf.paths)
    assert rw_mounts(request) == []
    assert ro_mounts(request) == [(lf.wt, lf.wt)]

    with open_drain_trees(lf.wt_paths, label) as trees:
        assert type(trees) is DrainTrees
        assert trees.mounts == ()
        assert held_roots(tmp_path) == []
        for rel in ALL_TREES:
            m = lf.wt / rel
            refused_value_error(lambda m=m: trees.mount(m), str(m))
            assert trees.tree_for(m / PROBE) is None, str(m)
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
    holder never answers a shorter list than the box mounts.

    True: with `lessons/` built and `lessons-questioner/` missing, `open_drain_trees(...,
    author_drain)` raises `FileNotFoundError` and no descriptor is left under the tmp dir. The
    control: once the questioner corpus is built, the same call holds both trees.

    Catches: a holder that filters its list by existence (its mounts then differ from the
    box's), and one that holds each tree itself and leaks the first when the second fails."""
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


class _RelistedPaths(LoopPaths):
    """A `LoopPaths`, injected through the `paths` argument, whose mount list is NOT the
    shipped one: each label's real list reversed, plus one extra tree `defender/relisted` (a
    sibling of the real trees, since `DrainTrees.open` refuses a nested pair). `with_repo_root`
    keeps the subclass (the shipped one returns a plain `LoopPaths`), so
    `paths.with_repo_root(wt)` still asks this list."""

    def with_repo_root(self, repo_root: Path) -> _RelistedPaths:
        return _RelistedPaths(repo_root=repo_root, state_dir=self.state_root)

    def drain_writable_trees(self, label: str) -> tuple[Path, ...]:
        shipped = super().drain_writable_trees(label)
        return (*reversed(shipped), self.repo_root / RELISTED)


@pytest.mark.parametrize("label", [*KNOWN, "a_third_drain"])
def test_the_box_and_the_held_trees_both_follow_whatever_list_paths_names(
        tmp_path: Path, label: str):
    """`_drain_box_request` and `open_drain_trees` both take their list from
    `drain_writable_trees` on the `LoopPaths` they are handed, never from a label table of
    their own (v1's E1).

    True: given a `LoopPaths` whose list is the shipped one reversed plus `defender/relisted`,
    the box mounts exactly that list rw, in that order, under `wt` (ro is still `wt` alone), and
    `open_drain_trees(paths.with_repo_root(wt), label)` holds exactly the same list in the same
    order: one descriptor per tree, and a write through each `mount(m)` lands at `m / name`. For
    the unknown label the injected list is only the extra tree, and both sides follow it.

    Catches: a box or a holder that keeps its own `if label == ...` list beside the method.
    That second list agrees with the first today, so the equality rows above cannot see it, but
    it lets the mounts and the held roots drift apart (O4's "one list")."""
    paths = _RelistedPaths(repo_root=tmp_path / "main", state_dir=tmp_path / "learning-state")
    wt = tmp_path / "wt-leaf"
    for rel in (*ALL_TREES, RELISTED):
        (wt / rel).mkdir(parents=True)
    expected = [*(wt / rel for rel in reversed(EXPECTED_MOUNTS.get(label, ()))),
                wt / "defender" / "relisted"]

    request = drains._drain_box_request(wt, "batch-1", label, paths)

    assert rw_mounts(request) == [(m, m) for m in expected]
    assert ro_mounts(request) == [(wt, wt)]
    wt_paths = paths.with_repo_root(wt)
    assert type(wt_paths) is _RelistedPaths  # the double keeps itself across the rebase
    with open_drain_trees(wt_paths, label) as trees:
        assert trees.mounts == tuple(expected)
        assert held_roots(tmp_path) == real(*expected)
        for m in expected:
            trees.mount(m).write(PROBE, PAYLOAD, mode="create")
            assert (m / PROBE).read_bytes() == PAYLOAD, str(m)
    assert held_roots(tmp_path) == []


def test_the_list_keeps_the_leafs_spelling_and_the_held_roots_are_the_folders_it_names(
        tmp_path: Path):
    """The list is lexical end to end: a leaf spelled through a link keeps that spelling in
    `drain_writable_trees`, in the box's rw mounts and in the holder's `.mounts`, and the held
    roots are the folders that spelling names.

    True, with `leaf-link -> real-leaf`, for each known label: all three lists are the literal
    `leaf-link/defender/...`; the descriptors held are the real-leaf folders; a write through
    each `mount(m)` lands in `real-leaf`; the resolved spelling is no mount point of the trees.

    Catches: `resolve()` in `drain_writable_trees`, in the box, or in the holder. Each turns
    the list into a spelling the box was never given, so the box's mounts and the held mount
    points stop comparing equal."""
    real_leaf = tmp_path / "real-leaf"
    for rel in ALL_TREES:
        (real_leaf / rel).mkdir(parents=True)
    link = tmp_path / "leaf-link"
    link.symlink_to(real_leaf, target_is_directory=True)
    paths = LoopPaths(repo_root=tmp_path / "main", state_dir=tmp_path / "learning-state")
    w = paths.with_repo_root(link)

    for label in KNOWN:
        expected = tuple(link / rel for rel in EXPECTED_MOUNTS[label])
        assert w.drain_writable_trees(label) == expected
        request = drains._drain_box_request(link, "batch-1", label, paths)
        assert rw_mounts(request) == [(m, m) for m in expected]
        assert ro_mounts(request) == [(link, link)]
        with open_drain_trees(w, label) as trees:
            assert trees.mounts == expected
            assert held_roots(tmp_path) == real(*(real_leaf / rel
                                                  for rel in EXPECTED_MOUNTS[label]))
            for rel in EXPECTED_MOUNTS[label]:
                trees.mount(link / rel).write(PROBE, PAYLOAD, mode="create")
                assert (real_leaf / rel / PROBE).read_bytes() == PAYLOAD
                refused_value_error(lambda rel=rel: trees.mount(real_leaf / rel), rel)
        assert held_roots(tmp_path) == []


# ---------------------------------------------------------------------------------------
# Absolute mounts: a relative root is refused before anything is held
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("at_cwd", ["the_trees", "a_file_at_each_tree"])
@pytest.mark.parametrize("label", KNOWN)
def test_a_relative_repo_root_is_refused_before_anything_is_held_never_joined_to_the_cwd(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, label: str, at_cwd: str):
    """`DefenderPaths` keeps a relative `repo_root` as given, so its list is relative, and
    `open_drain_trees` refuses it with `ValueError` before it opens anything. It never falls
    back to the cwd.

    True, with the cwd at the tmp dir and `LoopPaths(repo_root=Path("relative-wt"))`:
    - the list is the literal relative spelling `relative-wt/defender/...` (lexical);
    - the open is `ValueError` and no descriptor is left under the tmp dir;
    - `the_trees`: the trees exist under the cwd, so a holder joining the cwd would have opened
      them. The control: the same label over the absolute `tmp/relative-wt` opens and holds
      them;
    - `a_file_at_each_tree`: a plain file sits at each relative spelling, so any attempt to open
      one (relative, or joined to the cwd) is `NotADirectoryError`, never `ValueError`. The
      control: the same label over the absolute root is exactly that `NotADirectoryError`. So
      the refusal came before any open.

    Catches: a holder that absolutizes the root or the mounts (`Path.absolute()`, `resolve()`,
    `os.path.abspath`), and one that opens a mount before judging the list."""
    rel_root = Path("relative-wt")
    abs_root = tmp_path / rel_root
    for rel in EXPECTED_MOUNTS[label]:
        if at_cwd == "the_trees":
            (abs_root / rel).mkdir(parents=True)
        else:
            put_plain(abs_root / rel, b"a file where the tree would be\n")
    monkeypatch.chdir(tmp_path)
    relative = LoopPaths(repo_root=rel_root, state_dir=tmp_path / "learning-state")

    assert relative.drain_writable_trees(label) == tuple(
        rel_root / rel for rel in EXPECTED_MOUNTS[label])
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


# ---------------------------------------------------------------------------------------
# The real drives: what each lane hands its box, and what its work step can hold
# ---------------------------------------------------------------------------------------


class CheckoutBranch(B.RecordingBranch):
    """`_box665.RecordingBranch` (the recorded worktree lifecycle), whose leaf carries the three
    drain trees as the real worktree, a checkout of the repo, does, plus `_RelistedPaths`' extra
    `defender/relisted`. The leaf sits under its own base, never at `paths.repo_root`, and is
    kept after the drive (`destroy_on_cleanup` off)."""

    def __init__(self, worktree_base: Path, **kw: Any) -> None:
        super().__init__(worktree_base, **kw)
        self.leaves: list[Path] = []

    def start_batch(self, batch_id: str) -> Path:
        wt = super().start_batch(batch_id)
        for rel in (*ALL_TREES, RELISTED):
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


#: The lanes' `paths`: the shipped `LoopPaths`, and `_RelistedPaths`, whose list only a lane that
#: hands its own `paths` to both the box and the work step can follow.
PATHS_KINDS: dict[str, type[LoopPaths]] = {"shipped": LoopPaths, "relisted": _RelistedPaths}


def expected_rels(kind: str, label: str) -> list[str]:
    """The repo-relative rw list `PATHS_KINDS[kind]` gives for `label`, spelled literally."""
    shipped = list(EXPECTED_MOUNTS[label])
    return shipped if kind == "shipped" else [*reversed(shipped), RELISTED]


def assert_the_lane_mounted_its_leaf_trees_and_its_work_step_held_them(
        paths: LoopPaths, rec: B.BoxLifecycleRecorder, branch: CheckoutBranch, step: WorkStep,
        rels: list[str]) -> None:
    """The drive's verdict, from the `BoxRequest` the box seam was handed and what the work
    step recorded: the rw mounts are `rels` under the leaf, in order."""
    [leaf] = branch.leaves
    assert leaf != paths.repo_root
    request = rec.only_request()
    expected = [leaf / rel for rel in rels]

    assert rw_mounts(request) == [(m, m) for m in expected], (
        f"the box's rw mounts are {rw_mounts(request)}, not {rels} under the leaf")
    assert ro_mounts(request) == [(leaf, leaf)]
    assert len(request.mounts) == 1 + len(expected)
    for m in request.mounts:
        assert Path(m.source).is_absolute(), m
        assert Path(m.target).is_absolute(), m
    [(wt, _)] = ro_mounts(request)
    rw = tuple(source for source, _target in rw_mounts(request))

    assert step.fault is None, f"the work step's open failed: {step.fault}"
    assert step.received, "the lane never reached its work step"
    for got in step.received:
        assert type(got) is type(paths), type(got)
        assert got == paths.with_repo_root(wt), got
    assert step.mounts == rw, "the trees the work step holds are not the box's rw mounts"
    assert step.held == real(*rw), "the held roots are not the box's rw mounts"
    assert step.landed == dict.fromkeys(rw, PAYLOAD)


@pytest.mark.parametrize("kind", list(PATHS_KINDS))
def test_the_author_lane_mounts_its_leafs_two_corpora_and_its_work_step_holds_them(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str):
    """Driven through the real `drains.author_drain`: the box request the lane composes mounts
    the leaf's two lesson corpora rw and the leaf ro, nothing else, all absolute, and the trees
    its work step can hold over the `LoopPaths` the lane hands it are exactly those mounts.

    True: one `BoxRequest` reaches `start_box=`. Over the shipped `LoopPaths`, its rw mounts
    are `(leaf/defender/lessons, leaf/defender/lessons-questioner)` in order, each at its own
    path; its ro mount is the leaf alone. The work step (`trigger_author=`, called for both
    curators) is handed `paths.with_repo_root(wt)`, of `paths`' own type, with `wt` the
    request's ro mount. Inside it, with the box up and the leaf live,
    `open_drain_trees(that paths, author_drain)` holds exactly the rw mounts, by descriptor, and
    a write through each lands in it. Over `_RelistedPaths` the same holds for its list
    (`lessons-questioner`, `lessons`, `relisted`): the box and the work step both follow the
    `paths` the lane was handed.

    Why the open is captured inside the work step rather than after the drive: that is where
    A3 puts the drain's trees, the box is up, and the leaf is guaranteed live there (the real
    lane removes the worktree at cleanup). Why not `test_922_spine.drive_author_drain`: its
    branch hands back `paths.repo_root` as the leaf, so a lane that built the box from the main
    checkout would pass. This drive uses `_box665`'s recorder and branch, with a leaf apart from
    `paths.repo_root` that carries the trees a checkout does.

    Catches: the lane passing another label (the lead's, or a string the list does not know),
    a lane that builds the box from `paths` rather than the leaf, a lane that hands the box or
    the work step a `LoopPaths` of its own making (it drops the injected list), and a lane
    whose box and work step disagree about the trees."""
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")
    paths = PATHS_KINDS[kind](repo_root=tmp_path / "main", state_dir=tmp_path / "learning-state")
    put_plain(paths.pending_file, b'{"finding_id": "f-1"}\n')
    rec = B.BoxLifecycleRecorder()
    branch = CheckoutBranch(tmp_path / "worktrees", events=rec.events)
    step = WorkStep(AUTHOR)

    rc = drains.author_drain(paths, trigger_author=step, branch=branch,
                             start_box=rec.start_box, stop_box=rec.stop_box, scrub=rec.scrub)

    assert rc == 0
    assert len(step.received) == 2, "both curators' turns are the work step"
    assert_the_lane_mounted_its_leaf_trees_and_its_work_step_held_them(
        paths, rec, branch, step, expected_rels(kind, AUTHOR))


@pytest.mark.parametrize("kind", list(PATHS_KINDS))
def test_the_lead_lane_mounts_its_leafs_skills_and_its_work_step_holds_it(
        tmp_path: Path, kind: str):
    """Driven through the real `drains.lead_author_drain` with one queued case: the box request
    the lane composes mounts the leaf's `skills/` rw and the leaf ro, nothing else, all
    absolute, and the trees its work step can hold over the `LoopPaths` the lane hands it are
    exactly that mount.

    True: one `BoxRequest` reaches `start_box=`. Over the shipped `LoopPaths`, its rw mount is
    `leaf/defender/skills` at its own path; its ro mount is the leaf alone. The work step
    (`run_lead_author=`, the claim's serve) is handed `paths.with_repo_root(wt)`, of `paths`'
    own type, and inside it `open_drain_trees(that paths, lead_author_drain)` holds exactly
    `skills/`, by descriptor, and a write through it lands there. Over `_RelistedPaths` the same
    holds for its list (`skills`, `relisted`). The queue is the real one (`markers.enqueue_case_for_curation`, what
    `test_queue_drains_852._queued_run` wraps), so the lane's own wake gate opens. That
    module's `_drain` is not reused: it fixes `start_box=` and `branch=`, and this drive must
    record the request and keep the leaf apart from `paths.repo_root`.

    Catches: the lane passing the author label (it would mount the corpora), a lane that
    builds the box from `paths` rather than the leaf, a lane that hands the box or the work step
    a `LoopPaths` of its own making, and a box and work step that disagree."""
    paths = PATHS_KINDS[kind](repo_root=tmp_path / "main", state_dir=tmp_path / "learning-state")
    run_dir = tmp_path / "runs" / "run-1"
    run_dir.mkdir(parents=True)
    markers.enqueue_case_for_curation("case-1", run_dir, paths)
    rec = B.BoxLifecycleRecorder()
    branch = CheckoutBranch(tmp_path / "worktrees", branch_prefix="lead-author/",
                            events=rec.events)
    step = WorkStep(LEAD)

    rc = drains.lead_author_drain(
        paths, run_lead_author=step, run_pitfalls=lambda *_a, **_kw: 0, branch=branch,
        start_box=rec.start_box, stop_box=rec.stop_box, scrub=rec.scrub)

    assert rc == 0
    assert len(step.received) == 1, "the one queued case is the work step"
    assert_the_lane_mounted_its_leaf_trees_and_its_work_step_held_them(
        paths, rec, branch, step, expected_rels(kind, LEAD))
