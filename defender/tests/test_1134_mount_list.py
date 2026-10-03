"""#1134 v2 step 3: one list of drain mounts, its two labels, and the trees held from it (O4).

The contract is #1134's 2026-10-01 design addendum, A3 (it replaces the 2026-09-28 design's D3
and keeps O4), with the owner's 2026-09-29 decision that each drain label is spelled once:

- `learning/core/config.py` defines the two labels as the members of `DrainLabel`, a plain
  `enum.Enum` (#1179, replacing the step-3 rule that each string is spelled once and the scan
  that enforced it): `AUTHOR = "author_drain"`, `LEAD_AUTHOR = "lead_author_drain"`, aliased as
  `AUTHOR_DRAIN_LABEL` and `LEAD_AUTHOR_DRAIN_LABEL`. No string equals a member, so a label
  spelled as a string anywhere (a literal, `"author" + "_drain"`, a second table keyed by
  strings) grants nothing: the members' values are rows of the unknown-label tests. A member's
  `str()` is its value. In `drains`, each lane's
  `_run_worktree_batch(label=...)` passes its own constant by name, and the name resolves at the
  call (through `_astlib`'s scopes) to `config`'s binding. Nothing in `drains` binds that name
  again (a parameter, a local, a loop target, an import from elsewhere).
- `LoopPaths.drain_writable_trees(label) -> tuple[Path, ...]` is the one list of trees a drain
  box may write: `AUTHOR_DRAIN_LABEL` -> `(lessons_dir, lessons_questioner_dir)`, in that order,
  `LEAD_AUTHOR_DRAIN_LABEL` -> `(skills_dir,)`, and any other label -> `()`, near misses
  included (a case change, a space, hyphens, a prefix, an extra character, the empty string, a
  `<lane>:<batch>`-style suffix). It is lexical: built from `self.repo_root` as spelled,
  nothing resolved, nothing on disk read, so other trees in the leaf (`lessons-actor/`,
  `lessons-environment/`, `skills-old/`) never join it.
- `drains._drain_box_request(wt, batch_id, label, paths)` mounts read-write exactly
  `paths.with_repo_root(wt).drain_writable_trees(label)`, in order, each at its own path
  (target == source), plus the one read-only mount of `wt`, and nothing else. It derives no list
  of its own, asks the list only of the leaf and only for the label it was handed. The leaf
  stays read-only when it is a git checkout (`.git` a file or a folder).
- `lane_trees.open_drain_trees(wt_paths, label) -> DrainTrees` is exactly
  `DrainTrees.open(wt_paths.drain_writable_trees(label))`, asked for the label it was handed.
  `DefenderPaths` and `with_repo_root` keep a relative `repo_root` as given, so its list is
  relative, and those mounts are refused with `ValueError` before anything is held. They are
  never joined to the cwd, nor to the checkout this code runs from.

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
absent afterwards. `Leaf.build()` and the drives' branch also build decoy trees (`DECOY_TREES`)
beside the real ones.

Two seams are injected. The first is the `paths` argument: `relisted_paths` (v1's E1) builds a
`LoopPaths` whose list differs from the shipped one, since a second label table in the box or in
`open_drain_trees` agrees with the list today and only a different list shows it. It also records
every `(repo_root, label)` it is asked. The second is the lanes' own seams (`trigger_author=`,
`run_lead_author=`, `branch=`, `start_box=`, `stop_box=`, `scrub=`), for the real drives. Nothing
is monkeypatched (`monkeypatch.chdir` / `setenv` only set the cwd and a threshold). No row forks
or spawns: the drives' leaf has no `.git`, so the lead lane's reset/clean is skipped, and the
`.git` rows call `_drain_box_request` alone. No deadline is needed.

v1's E2-E4 rows pinned `LoopPaths.tree_for`, which v2 drops (`DrainTrees.tree_for` is step 2's,
`test_1134_drain_trees.py`); they are not ported. E1 (a second label table) and E5 (near-miss
labels) are. The AST pins are v1 step 6's H7 and H8.

Red before #1134 v2 step 3: `config` has no label constants and `lane_trees` no
`open_drain_trees`, so this module fails at import. An adversary pass against the first version
of this file greened these holes; the rows that close each say so:
- x1, a label literal left in a production module outside the batch calls (`claim_markers`);
- H2, a lane parameter or local named like the constant, shadowing the import;
- H3, a second table in `config` keyed by `"author" + "_drain"`;
- H4, a relative root absolutized by `with_repo_root`, or anchored at the checkout;
- H5, the author list globbing every `lessons-*` folder in the leaf;
- H6, the leaf mounted read-write when it is a git worktree;
- H7, the label normalised (`label.partition(":")[0]`) in the list or only in the holder;
- R3, the box rebasing the main checkout's list onto the leaf;
- r6, the batch choosing the box's label from `branch.branch_prefix`.
"""
from __future__ import annotations

import ast
import dataclasses
import enum
import inspect
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from defender import _io
from defender.learning.core import config, drains, markers
from defender.learning.core.config import (
    AUTHOR_DRAIN_LABEL, LEAD_AUTHOR_DRAIN_LABEL, DrainLabel, LoopPaths,
)
from defender.learning.core.lane_trees import DrainTrees, open_drain_trees
from defender.tests._by_path import import_lint_lib
from defender.tests._drain_trees_1134 import PAYLOAD
from defender.tests.e2e import _box665 as B
from defender.tests.test_1111_rooted_io import HOST_BYTES, census
from defender.tests._tree_listing_1134 import descriptors_under, put_plain

# ---------------------------------------------------------------------------------------
# The labels and their trees
# ---------------------------------------------------------------------------------------

#: The two labels are the members of `DrainLabel` (#1179): values no string equals.
AUTHOR = DrainLabel.AUTHOR
LEAD = DrainLabel.LEAD_AUTHOR
KNOWN = (AUTHOR, LEAD)

#: Each member's value, spelled literally: its written form (the pending-delivery record, the
#: quarantine manifest) and its display form, and, as a bare string, a label that grants nothing.
LABEL_VALUES: dict[DrainLabel, str] = {AUTHOR: "author_drain", LEAD: "lead_author_drain"}

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

#: Trees a checkout carries that no label lists (H5): the two retired corpora the real repo
#: still tracks, and a folder named like the skills tree. A list that globs or lists the leaf's
#: folders picks them up.
DECOY_TREES = ("defender/lessons-actor", "defender/lessons-environment", "defender/skills-old")

#: Labels no lane names: first the members' own values as bare strings (#1179: a string is never
#: a label, however it is spelled), then near misses (v1's E5, and H7's spawn-label forms): a prefix,
#: a case change, a leading or trailing space or newline, hyphens for underscores, a leading or
#: trailing extra character, the empty string, a suffixed version, the pitfalls lane (drained
#: inside the lead-author tick, never its own box), and a lane with a `:`, `/` or `.` suffix
#: (`<lane>:<batch_id>` is this codebase's spawn-label shape). A label matched by prefix, by
#: case, after `.strip()`, or up to a separator gets a tree.
UNKNOWN_LABELS = (
    "author_drain", "lead_author_drain",
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


def relisted_rel(root: Path) -> str:
    """The extra tree `relisted_paths` lists under `root`. Its name carries the root's own
    name, so a list asked under one root and rebased onto another names a different tree."""
    return f"defender/relisted-{root.name}"


def relisted_paths(asked: list[tuple[Path, str]]) -> type[LoopPaths]:
    """A `LoopPaths` subclass, injected through the `paths` argument, whose mount list is NOT
    the shipped one: each label's shipped list reversed, plus `relisted_rel(repo_root)`, a
    sibling of the real trees (`DrainTrees.open` refuses a nested pair). Every call records
    `(repo_root, label)` in `asked`. `with_repo_root` keeps the subclass (the shipped one returns
    a plain `LoopPaths`), so `paths.with_repo_root(wt)` still asks this list. A class per call,
    so each test reads its own `asked` (the instances are frozen)."""

    class RelistedPaths(LoopPaths):
        def with_repo_root(self, repo_root: Path) -> LoopPaths:
            return type(self)(repo_root=repo_root, state_dir=self.state_root)

        def drain_writable_trees(self, label: str) -> tuple[Path, ...]:
            asked.append((self.repo_root, label))
            shipped = super().drain_writable_trees(label)
            return (*reversed(shipped), self.repo_root / relisted_rel(self.repo_root))

    return RelistedPaths


def assert_asked_only(asked: list[tuple[Path, str]], wt: Path, label: str, who: str) -> None:
    """`who` asked the list, and every time of the leaf `wt` for exactly `label`."""
    assert asked, f"{who} never asked drain_writable_trees"
    assert set(asked) == {(wt, label)}, f"{who} asked {asked}, not ({wt}, {label!r})"


# ---------------------------------------------------------------------------------------
# The labels: spelled once, in config, and passed by name
# ---------------------------------------------------------------------------------------

#: Each label's value and the one constant it is spelled as.
CONFIG_MODULE = "defender.learning.core.config"


def test_the_label_constants_are_the_lanes_members():
    """`AUTHOR_DRAIN_LABEL` and `LEAD_AUTHOR_DRAIN_LABEL` are the two members of `DrainLabel`, a
    plain `enum.Enum` (never a `str` mixin), whose values are the strings each lane passed as
    `label=` before #1179, unchanged. `drains` sees the same objects. A member's `str()` is its
    value, the display form every log line formats.

    Catches: a `str`/`StrEnum` label (it would equal its string and grant to one), a third
    member, a misspelled value (the written records would change), an alias that is a fresh
    string rather than the member, and a display form that leaks `DrainLabel.AUTHOR`."""
    assert issubclass(DrainLabel, enum.Enum)
    assert not issubclass(DrainLabel, str)
    assert list(DrainLabel) == [AUTHOR, LEAD]
    assert AUTHOR_DRAIN_LABEL is DrainLabel.AUTHOR
    assert LEAD_AUTHOR_DRAIN_LABEL is DrainLabel.LEAD_AUTHOR
    assert drains.AUTHOR_DRAIN_LABEL is DrainLabel.AUTHOR
    assert drains.LEAD_AUTHOR_DRAIN_LABEL is DrainLabel.LEAD_AUTHOR
    for member, value in LABEL_VALUES.items():
        assert member.value == value
        assert str(member) == value
        assert f"{member}" == value
        assert member != value
        assert value != member


def _source_tree(module: Any) -> ast.Module:
    return ast.parse(inspect.getsource(module))


def _callee(call: ast.Call) -> str | None:
    f = call.func
    return f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else None


def _batch_calls(node: ast.AST) -> list[ast.Call]:
    return [n for n in ast.walk(node)
            if isinstance(n, ast.Call) and _callee(n) == "_run_worktree_batch"]


def _label_kw(call: ast.Call) -> ast.expr | None:
    return next((k.value for k in call.keywords if k.arg == "label"), None)


#: What each kind of node binds, by name, other than an import (imports are judged through
#: `_astlib`'s scopes, below).
_BINDS: dict[type, Callable[[Any], list[str]]] = {
    ast.Name: lambda n: [] if isinstance(n.ctx, ast.Load) else [n.id],
    ast.arg: lambda n: [n.arg],
    ast.FunctionDef: lambda n: [n.name],
    ast.AsyncFunctionDef: lambda n: [n.name],
    ast.ClassDef: lambda n: [n.name],
    ast.ExceptHandler: lambda n: [n.name] if n.name else [],
    ast.Global: lambda n: list(n.names),
    ast.Nonlocal: lambda n: list(n.names),
    ast.MatchAs: lambda n: [n.name] if n.name else [],
    ast.MatchStar: lambda n: [n.name] if n.name else [],
    ast.MatchMapping: lambda n: [n.rest] if n.rest else [],
}


def _rebindings(tree: ast.AST, name: str) -> list[tuple[int, str]]:
    """Every place in `tree` that binds `name` other than by an import: an assignment or
    deletion anywhere (tuple targets, loop and `with` targets, a walrus, a class body), a
    parameter of any function or lambda, a `def` or `class`, an `except ... as`, a `global` or
    `nonlocal`, or a `match` capture."""
    out = []
    for n in ast.walk(tree):
        binds = _BINDS.get(type(n))
        if binds is not None and name in binds(n):
            out.append((getattr(n, "lineno", 0), type(n).__name__))
    return out


def _foreign_imports(env: Any, name: str, origin: str) -> list[str]:
    """Each scope of the module (`_astlib`'s envs) where `name` is imported from anywhere but
    `origin`, as that other origin."""
    scopes = {id(e): e for e in (env, *env.scope_of.values())}.values()
    return sorted({e.imports[name] for e in scopes
                   if name in e.imports and e.imports[name] != origin})


def test_the_drains_pass_a_constant_to_the_worktree_batch():
    """Every `_run_worktree_batch(label=...)` in `drains` passes a name, never a string (v1 step
    6's H8). Each lane passes its own constant, resolved at the call through `_astlib` (the
    gates' scope-aware resolver) to `config`'s binding: `author_drain` passes
    `defender.learning.core.config.AUTHOR_DRAIN_LABEL` and `lead_author_drain`
    `...LEAD_AUTHOR_DRAIN_LABEL`, imported or read as `config.<NAME>`. Nothing in `drains`
    binds either name again: no parameter, local, loop target, class attribute or
    module-level assignment, and no import of it from elsewhere, in any scope (round 2's H2).

    Catches: `label="author_drain"`, an f-string or concatenation built at the call, a second
    module constant in `drains` (`_AUTHOR = "author_drain"`), and a lane parameter or local
    named `AUTHOR_DRAIN_LABEL` that shadows the import (the resolver answers `None` for it).
    Each is a second spelling the drives below cannot tell from the constant."""
    astlib = import_lint_lib("_astlib")
    tree = _source_tree(drains)
    env = astlib.module_env(tree)
    calls = _batch_calls(tree)
    assert len(calls) >= 2, "expected the author and the lead-author drains' batch calls"
    for call in calls:
        value = _label_kw(call)
        assert value is not None, ast.dump(call)
        assert isinstance(value, (ast.Name, ast.Attribute)), (call.lineno, ast.dump(value))

    for lane, constant in ((AUTHOR, "AUTHOR_DRAIN_LABEL"), (LEAD, "LEAD_AUTHOR_DRAIN_LABEL")):
        [fn] = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == lane]
        [call] = _batch_calls(fn)
        value = _label_kw(call)
        assert value is not None, ast.dump(call)
        expected = f"{CONFIG_MODULE}.{constant}"
        assert astlib.origin(value, env) == expected, (
            f"{lane} passes {ast.unparse(value)}, which does not resolve to {expected}")
        assert _rebindings(tree, constant) == [], f"drains binds {constant} again"
        assert _foreign_imports(env, constant, expected) == []


# ---------------------------------------------------------------------------------------
# drain_writable_trees: the one list
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("on_disk", ["absent", "built_with_decoys"])
@pytest.mark.parametrize("label", KNOWN)
def test_drain_writable_trees_is_each_labels_mount_points_in_order(
        tmp_path: Path, label: str, on_disk: str):
    """`drain_writable_trees(label)` is the label's mount points, a tuple in the contract's
    order, under the `LoopPaths` it is asked on, whatever else the checkout holds.

    True: under the leaf, `author_drain` gives `(lessons_dir, lessons_questioner_dir)` and
    `lead_author_drain` gives `(skills_dir,)`, equal to the literal spellings
    `wt / "defender/..."` (a tuple: a list never equals one). The main checkout's `paths` gives
    the same shape under its own root, so the list follows `repo_root`. `absent`: neither root
    is made on disk. `built_with_decoys`:
    both roots carry every tree plus `lessons-actor/`, `lessons-environment/` and `skills-old/`,
    and the list is unchanged.

    Catches: a missing tree, an extra one (the catalog, or the whole `defender/`), a swapped
    order, a list, a list built from a fixed root rather than `self`, a list that makes its
    folders, and one that globs the checkout for more corpora (round 2's H5)."""
    lf = _leaf(tmp_path)
    if on_disk == "built_with_decoys":
        lf.build()
        Leaf(lf.paths, lf.paths.repo_root).build()
    got = lf.wt_paths.drain_writable_trees(label)

    assert got == tuple(lf.wt / rel for rel in EXPECTED_MOUNTS[label])
    assert got == MOUNTS_BY_ATTRIBUTE[label](lf.wt_paths)
    assert lf.wt_paths.drain_writable_trees(LABEL_VALUES[label]) == (), (
        "the label's value, as a bare string, got a tree")
    assert lf.paths.drain_writable_trees(label) == tuple(
        lf.paths.repo_root / rel for rel in EXPECTED_MOUNTS[label])
    if on_disk == "absent":
        assert not lf.wt.exists(), "drain_writable_trees touched the disk: it is lexical"
        assert not lf.paths.repo_root.exists(), "drain_writable_trees touched the disk"
    else:
        for root in (lf.wt, lf.paths.repo_root):
            for rel in DECOY_TREES:
                assert (root / rel).is_dir(), f"the decoy {root / rel} is not there to find"


@pytest.mark.parametrize("label", UNKNOWN_LABELS)
def test_an_unknown_label_has_no_writable_tree(tmp_path: Path, label: str):
    """An unknown label, near misses included, lists nothing.

    True: `drain_writable_trees(label) == ()`, on the leaf and on the main checkout. The
    positive control on the same `LoopPaths`: both known labels list their trees.

    Catches: an unknown label that falls through to a default tree (the old `else` shape), and a
    label matched by prefix, by case, after stripping whitespace (v1's E5) or up to a separator
    (`label.partition(":")[0]`, round 2's H7)."""
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


@pytest.mark.parametrize("dot_git", ["file", "folder"])
@pytest.mark.parametrize("label", [*KNOWN, "a_third_drain"])
def test_a_leaf_that_is_a_git_checkout_is_still_mounted_read_only(
        tmp_path: Path, label: str, dot_git: str):
    """A real drain leaf is a git worktree (`.git` is a file naming the main repository's
    worktree dir), or a clone (`.git` a folder). Either way the box mounts the leaf read-only,
    its own trees read-write, and nothing else (round 2's H6).

    True, over a leaf that carries every tree, the decoys and the `.git` entry: the ro mounts
    are exactly `[(wt, wt)]`, the rw mounts are exactly the label's literal list, and there is
    no other mount. The control: the `.git` entry is there, of the kind the row names. The same
    request over a leaf without one is `test_the_drain_box_mounts_exactly_the_labels_list`.

    Catches: a box that grants the leaf write access when it holds a git index, which lets the
    box stage and rewrite everything in the working copy, and one that adds the git folder as a
    mount of its own."""
    lf = _leaf(tmp_path)
    lf.build()
    git = lf.wt / ".git"
    if dot_git == "file":
        put_plain(git, b"gitdir: /nonexistent/.git/worktrees/wt-leaf\n")
    else:
        (git / "objects").mkdir(parents=True)

    request = drains._drain_box_request(lf.wt, "batch-1", label, lf.paths)

    expected = [lf.wt / rel for rel in EXPECTED_MOUNTS.get(label, ())]
    assert ro_mounts(request) == [(lf.wt, lf.wt)], "the git leaf is not mounted read-only"
    assert rw_mounts(request) == [(m, m) for m in expected]
    assert len(request.mounts) == 1 + len(expected)
    assert git.is_file() if dot_git == "file" else git.is_dir()


# ---------------------------------------------------------------------------------------
# O4: the box's rw mounts are the roots open_drain_trees holds
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("swap", ["fresh_folder", "link_to_outside"])
@pytest.mark.parametrize("label", KNOWN)
def test_the_box_rw_mounts_are_the_roots_open_drain_trees_holds_and_a_swap_moves_none(
        tmp_path: Path, label: str, swap: str):
    """For a known label, the box's rw mounts equal `open_drain_trees(wt_paths, label).mounts`,
    and each of them is held, by behaviour.

    True, over a leaf that carries all three trees and the decoys:
    - `open_drain_trees` gives the real `DrainTrees`, whose `.mounts` is the box's rw source list
      in order (the literal list);
    - while it is open, this process holds one descriptor per rw mount and none on anything else
      in the tmp dir (the other label's tree and the decoys are in the leaf and are not held);
    - for each rw mount `m`, a write through `trees.mount(m)` lands at `m / name`, byte-exact;
    - the other label's trees and the decoys are no mount point (`mount` is `ValueError`,
      `tree_for` `None`);
    - then every `m` is renamed away and a fresh empty folder, or a link to an outside folder
      holding a decoy at the name, is put at its path. A `replace` write through the same handle
      lands in the renamed folder, beside the first write. The swapped-in folder and the decoy
      are untouched, and the held descriptors now name the renamed folders;
    - closing the trees releases every root.

    Catches: `open_drain_trees` holding a different list than the box mounts (a missing, extra,
    globbed or reordered tree), a holder that writes by path instead of through the descriptor
    it took at open (it follows the swap, into the fresh folder or through the link), a holder
    that also holds the other label's tree, and one that never releases its roots."""
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
    matches a near miss, or strips a `:<batch>` suffix: round 2's H7), and one that answers the
    empty list without asking the label."""
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


@pytest.mark.parametrize("label", [*KNOWN, *UNKNOWN_LABELS])
def test_the_box_and_the_held_trees_both_follow_whatever_list_paths_names(
        tmp_path: Path, label: str):
    """`_drain_box_request` and `open_drain_trees` both take their list from
    `drain_writable_trees` on the `LoopPaths` they are handed, asked of the leaf for exactly
    the label they were handed, never from a label table of their own (v1's E1).

    True: given `relisted_paths`, whose list is the shipped one reversed plus
    `defender/relisted-<root name>`:
    - the box mounts exactly that list rw under `wt`, in that order (`relisted-wt-leaf`), and ro
      is still `wt` alone;
    - `open_drain_trees(paths.with_repo_root(wt), label)` holds exactly the same list in the same
      order: one descriptor per tree, and a write through each `mount(m)` lands at `m / name`;
    - each side asked the list, and only ever as `(wt, label)`.

    For an unknown label or a near miss, the injected list is only the extra tree, and both
    sides follow it. The leaf also carries the decoys and `defender/relisted-main`, the extra
    tree the main checkout's list names.

    Catches: a box or a holder that keeps its own `if label == ...` list beside the method.
    That second list agrees with the first today, so the equality rows above cannot see it, but
    it lets the mounts and the held roots drift apart (O4's "one list"). Also a box or holder
    that normalises the label before asking (round 2's H7), and a box that asks the main
    checkout's list and rebases it onto the leaf (R3: it mounts `relisted-main`)."""
    asked: list[tuple[Path, str]] = []
    paths = relisted_paths(asked)(repo_root=tmp_path / MAIN,
                                  state_dir=tmp_path / "learning-state")
    lf = Leaf(paths, tmp_path / "wt-leaf")
    wt = lf.wt
    lf.build(*ALL_TREES, *DECOY_TREES, relisted_rel(wt), relisted_rel(paths.repo_root))
    expected = [*(wt / rel for rel in reversed(EXPECTED_MOUNTS.get(label, ()))),
                wt / "defender" / "relisted-wt-leaf"]

    request = drains._drain_box_request(wt, "batch-1", label, paths)

    assert rw_mounts(request) == [(m, m) for m in expected]
    assert ro_mounts(request) == [(wt, wt)]
    assert len(request.mounts) == 1 + len(expected)
    assert_asked_only(asked, wt, label, "the box")
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
    assert_asked_only(asked, wt, label, "the holder")


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
    paths = LoopPaths(repo_root=tmp_path / MAIN, state_dir=tmp_path / "learning-state")
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
    """`DefenderPaths` and `with_repo_root` keep a relative `repo_root` as given, so its list
    and the box's rw mounts are relative, and `open_drain_trees` refuses it with `ValueError`
    before it opens anything. It never falls back to the cwd.

    True, with the cwd at the tmp dir and a `repo_root` of `Path("relative-wt")`, built directly
    or through the main checkout's `with_repo_root`:
    - the root and the list keep the literal relative spelling `relative-wt/defender/...`;
    - `_drain_box_request(Path("relative-wt"), ...)` mounts that relative list rw as spelled,
      and `relative-wt` ro (nothing absolutized on the way to the box);
    - the open is `ValueError` and no descriptor is left under the tmp dir;
    - `the_trees`: the trees exist under the cwd, so a holder joining the cwd would have opened
      them. The control: the same label over the absolute `tmp/relative-wt` opens and holds
      them;
    - `a_file_at_each_tree`: a plain file sits at each relative spelling, so any attempt to open
      one (relative, or joined to the cwd) is `NotADirectoryError`, never `ValueError`. The
      control: the same label over the absolute root is exactly that `NotADirectoryError`. So
      the refusal came before any open.

    Catches: a holder that absolutizes the root or the mounts (`Path.absolute()`, `resolve()`,
    `os.path.abspath`), a `with_repo_root` that does (round 2's H4: the box and the holder then
    agree on a cwd-joined leaf), and a holder that opens a mount before judging the list."""
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
    assert relative.drain_writable_trees(label) == listed
    request = drains._drain_box_request(
        rel_root, "batch-1", label, LoopPaths(repo_root=tmp_path / MAIN))
    assert rw_mounts(request) == [(m, m) for m in listed]
    assert ro_mounts(request) == [(rel_root, rel_root)]
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


@pytest.mark.parametrize("how", ["constructed", "rebased"])
@pytest.mark.parametrize("label", KNOWN)
def test_a_relative_root_is_anchored_neither_at_the_cwd_nor_at_this_checkout(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, label: str, how: str):
    """A `repo_root` of `Path(".")` lists bare `defender/...` mounts, and `open_drain_trees`
    refuses them with `ValueError`. It never anchors them at the checkout this code runs from
    (`config.REPO_ROOT`), which does carry those trees (round 2's H4).

    True, with the cwd at an empty tmp dir: the list is `defender/...` as spelled; the open is
    `ValueError`; no descriptor is held under the tmp dir, and the descriptors under each of the
    checkout's real trees are what they were before the call. The preconditions: the checkout's
    trees are real folders and the cwd has none. The control: the same label over
    `config.REPO_ROOT` itself opens and holds those very trees, so a holder anchoring there
    would have succeeded.

    Catches: a holder that resolves a relative list against the repo it was imported from,
    which a cwd-only row cannot see (the cwd holds nothing, so a cwd join fails anyway)."""
    checkout_trees = [config.REPO_ROOT / rel for rel in EXPECTED_MOUNTS[label]]
    for tree in checkout_trees:
        assert tree.is_dir(), f"precondition: the checkout carries {tree}"
    monkeypatch.chdir(tmp_path)
    for rel in EXPECTED_MOUNTS[label]:
        assert not (tmp_path / rel).exists(), f"precondition: the cwd holds no {rel}"
    dot = relative_paths(how, Path("."), tmp_path)

    assert dot.drain_writable_trees(label) == tuple(Path(rel) for rel in EXPECTED_MOUNTS[label])
    before = {tree: sorted(descriptors_under(tree)) for tree in checkout_trees}
    with pytest.raises(ValueError):  # noqa: PT011 — DrainTrees' mount refusal; the type is the contract
        open_drain_trees(dot, label)
    assert held_roots(tmp_path) == []
    assert {tree: sorted(descriptors_under(tree)) for tree in checkout_trees} == before, (
        "a relative mount was held in the checkout")

    with open_drain_trees(LoopPaths(repo_root=config.REPO_ROOT), label) as trees:
        assert trees.mounts == tuple(checkout_trees)
        for tree in checkout_trees:
            assert os.path.realpath(tree) in descriptors_under(tree), str(tree)
    assert {tree: sorted(descriptors_under(tree)) for tree in checkout_trees} == before


# ---------------------------------------------------------------------------------------
# The real drives: what each lane hands its box, and what its work step can hold
# ---------------------------------------------------------------------------------------

#: Each lane's own branch prefix (`AuthorBranch`'s default, and the lead lane's).
LANE_PREFIX = {AUTHOR: "lessons/", LEAD: "lead-author/"}


class CheckoutBranch(B.RecordingBranch):
    """`_box665.RecordingBranch` (the recorded worktree lifecycle), whose leaf carries the three
    drain trees as the real worktree, a checkout of the repo, does, plus the decoys,
    `relisted_paths`' extra tree for this leaf, and the one it names for the main checkout. The
    leaf sits under its own base, never at `paths.repo_root`, and is kept after the drive
    (`destroy_on_cleanup` off)."""

    def __init__(self, worktree_base: Path, **kw: Any) -> None:
        super().__init__(worktree_base, **kw)
        self.leaves: list[Path] = []

    def start_batch(self, batch_id: str) -> Path:
        wt = super().start_batch(batch_id)
        for rel in (*ALL_TREES, *DECOY_TREES, relisted_rel(wt), relisted_rel(Path(MAIN))):
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
    (`shipped`, or `relisted` with its `asked` log), the box recorder, the branch and the work
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
    cls = LoopPaths if kind == "shipped" else relisted_paths(asked)
    paths = cls(repo_root=tmp_path / MAIN, state_dir=tmp_path / "learning-state")
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
    rels = shipped if d.kind == "shipped" else [*reversed(shipped), relisted_rel(leaf)]
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

    step = d.step
    assert step.fault is None, f"the work step's open failed: {step.fault}"
    assert step.received, "the lane never reached its work step"
    for got in step.received:
        assert type(got) is type(d.paths), type(got)
        assert got == d.paths.with_repo_root(wt), got
    assert step.mounts == rw, "the trees the work step holds are not the box's rw mounts"
    assert step.held == real(*rw), "the held roots are not the box's rw mounts"
    assert step.landed == dict.fromkeys(rw, PAYLOAD)
    if d.kind == "relisted":
        assert_asked_only(d.asked, wt, d.label, "the lane")


@pytest.mark.parametrize("prefix", ["own", "other_lanes"])
@pytest.mark.parametrize("kind", ["shipped", "relisted"])
def test_the_author_lane_mounts_its_leafs_two_corpora_and_its_work_step_holds_them(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str, prefix: str):
    """Driven through the real `drains.author_drain`: the box request the lane composes mounts
    the leaf's two lesson corpora rw and the leaf ro, nothing else, all absolute, and the trees
    its work step can hold over the `LoopPaths` the lane hands it are exactly those mounts.

    True: one `BoxRequest` reaches `start_box=`. Over the shipped `LoopPaths`, its rw mounts
    are `(leaf/defender/lessons, leaf/defender/lessons-questioner)` in order, each at its own
    path; its ro mount is the leaf alone. The leaf's decoys are not mounted. The work step
    (`trigger_author=`, called for both curators) is handed `paths.with_repo_root(wt)`, of
    `paths`' own type, with `wt` the request's ro mount. Inside it, with the box up and the leaf
    live, `open_drain_trees(that paths, author_drain)` holds exactly the rw mounts, by
    descriptor, and a write through each lands in it. Over `relisted_paths` the same holds for
    its list (`lessons-questioner`, `lessons`, `relisted-<leaf>`), and every ask was of the leaf
    for `author_drain`: the box and the work step both follow the `paths` the lane was handed.
    All of it holds with the branch's prefix the lead lane's (`lead-author/`).

    Why the open is captured inside the work step rather than after the drive: that is where
    A3 puts the drain's trees, the box is up, and the leaf is guaranteed live there (the real
    lane removes the worktree at cleanup). Why not `test_922_spine.drive_author_drain`: its
    branch hands back `paths.repo_root` as the leaf, so a lane that built the box from the main
    checkout would pass. This drive uses `_box665`'s recorder and branch, with a leaf apart from
    `paths.repo_root` that carries the trees a checkout does.

    Catches: the lane passing another label (the lead's, or a string the list does not know),
    a batch that picks the box's label from the branch prefix (round 2's r6), a lane that builds
    the box from `paths` rather than the leaf, a lane that hands the box or the work step a
    `LoopPaths` of its own making (it drops the injected list), and a lane whose box and work
    step disagree about the trees."""
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")
    d = start_drive(tmp_path, AUTHOR, kind, prefix)
    put_plain(d.paths.pending_file, b'{"finding_id": "f-1"}\n')

    rc = drains.author_drain(d.paths, trigger_author=d.step, branch=d.branch,
                             start_box=d.rec.start_box, stop_box=d.rec.stop_box,
                             scrub=d.rec.scrub)

    assert rc == 0
    assert len(d.step.received) == 2, "both curators' turns are the work step"
    assert_the_lane_mounted_its_leaf_trees_and_its_work_step_held_them(d)


@pytest.mark.parametrize("prefix", ["own", "other_lanes"])
@pytest.mark.parametrize("kind", ["shipped", "relisted"])
def test_the_lead_lane_mounts_its_leafs_skills_and_its_work_step_holds_it(
        tmp_path: Path, kind: str, prefix: str):
    """Driven through the real `drains.lead_author_drain` with one queued case: the box request
    the lane composes mounts the leaf's `skills/` rw and the leaf ro, nothing else, all
    absolute, and the trees its work step can hold over the `LoopPaths` the lane hands it are
    exactly that mount.

    True: one `BoxRequest` reaches `start_box=`. Over the shipped `LoopPaths`, its rw mount is
    `leaf/defender/skills` at its own path; its ro mount is the leaf alone. The work step
    (`run_lead_author=`, the claim's serve) is handed `paths.with_repo_root(wt)`, of `paths`'
    own type, and inside it `open_drain_trees(that paths, lead_author_drain)` holds exactly
    `skills/`, by descriptor, and a write through it lands there. Over `relisted_paths` the same
    holds for its list (`skills`, `relisted-<leaf>`), every ask of the leaf for
    `lead_author_drain`. All of it holds with the branch's prefix the author lane's
    (`lessons/`). The queue is the real one (`markers.enqueue_case_for_curation`, what
    `test_queue_drains_852._queued_run` wraps), so the lane's own wake gate opens. That
    module's `_drain` is not reused: it fixes `start_box=` and `branch=`, and this drive must
    record the request and keep the leaf apart from `paths.repo_root`.

    Catches: the lane passing the author label (it would mount the corpora), a batch that picks
    the box's label from the branch prefix (round 2's r6), a lane that builds the box from
    `paths` rather than the leaf, a lane that hands the box or the work step a `LoopPaths` of
    its own making, and a box and work step that disagree."""
    d = start_drive(tmp_path, LEAD, kind, prefix)
    run_dir = tmp_path / "runs" / "run-1"
    run_dir.mkdir(parents=True)
    markers.enqueue_case_for_curation("case-1", run_dir, d.paths)

    rc = drains.lead_author_drain(
        d.paths, run_lead_author=d.step, run_pitfalls=lambda *_a, **_kw: 0, branch=d.branch,
        start_box=d.rec.start_box, stop_box=d.rec.stop_box, scrub=d.rec.scrub)

    assert rc == 0
    assert len(d.step.received) == 1, "the one queued case is the work step"
    assert_the_lane_mounted_its_leaf_trees_and_its_work_step_held_them(d)
