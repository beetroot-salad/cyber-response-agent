"""#1134 v3 step 1, B2: `defender._tree_listing` — `entry_kind(view, name)` and
`list_tree(view, *, depth)`, two helpers built only from `Bound.entries()` / `Bound.under()` —
and addendum 3's D2: `Bound.entries()` answers a dead folder absent.

The contract is #1134's "Design addendum 2" (owner-approved 2026-10-02), B2, as the step-1
contract settles it, amended by "Addendum 3" (owner-approved 2026-10-03): no `Bound.read_bytes`
(D1), a folder deleted under a listing is absent (D2), no hand-rolled AST pin and sound test
helpers (D3). It replaces v2's `Bound.kind` / `Bound.walk`, whose review findings (#1-#9)
this file dissolves: the core gains no walk, no kind and no descriptor chain, and each helper is
nothing but `entries()` calls, so it answers exactly what those listings answer.

What each section pins:

- Records and signatures. `EntryKind(name, folder, kind, absent, reason)` and
  `TreeListing(absent, reason, entries, refused, gone)` are frozen dataclasses with those fields
  in that order. `entry_kind(view, name)`; `list_tree(view, *, depth)` with `depth` required and
  keyword-only. The kinds are `_io`'s `ENTRY_FILE` / `ENTRY_DIR` / `ENTRY_OTHER`.
- Adds nothing to the core but D2 (v2's findings #1-#9, #11, #12, #15 dissolve by absence):
  `Bound` has no `walk`, `kind`, `read_bytes` or `_leaf`; `_io` has no `ENTRY_ABSENT`,
  `ENTRY_UNLISTED`, `WalkRead`, `BytesRead`, `_walk_at`, `_kind_at`, `_list_below`,
  `_folder_parts`, `_reopen_dir`, and no `ENTRY_*` but the three.
- No I/O of its own (no hand-rolled AST pin over the module: step 7's census scans it with
  `_astlib` resolution; #1140 review finding 15): (b) through a recording `os_` seam, `entry_kind`'s I/O EQUALS (as a sequence) that of the one `entries()` call it is
  specified to make, and `list_tree`'s equals (as a multiset) the union of the `entries()` calls
  it is specified to make (the top, and each `"dir"` row above the last level, once); (c) a FIFO
  at a leaf or at a holding folder is never opened (a writer parked in its open stays parked),
  and no non-directory entry is ever handed to `os_.open`; (d) no descriptor outlives a call.
- `entry_kind`: the kind of every plant at the name, as `entries()` judged it (a hard link is
  `"file"`, a link of any sort, FIFO, socket or device `"other"`, a real directory `"dir"`), from
  exactly one listing of its folder; a linked, file or FIFO holding folder (in the name or in the
  view's prefix) is that listing's refusal, verbatim; a missing leaf or folder is absent; a root
  absent at `bind` is absent, one refused there relays its reason (#3); a closed root answers
  `Bad file descriptor`, never raises. `name` is the POSIX spelling, `folder` the view-relative
  parent. Exactly one of kind / absent / reason. The name grammar is `Bound.read`'s: `""`, `"."`
  and every malformed name are `ValueError` before any I/O, in every view state.
- `list_tree`: depth `0`, negatives, `None`, `True` / `False`, floats and strings are
  `ValueError` before any I/O, in every view state (#6). Depth 1 is exactly `view.entries()`;
  depth N lists exactly N levels and never lists a folder at level N, which is still reported
  `"dir"`. Names are view-relative, in path-parts order (`tuple(name.split("/"))`, swept over
  every character below `/`), and so are `refused` and `gone`. An absent top and an empty top are
  told apart; a top refused at `bind` or closed answers its reason. A plant at a name is its own
  row and is never entered; a plant at the view's own folder refuses the top; a still plant at a
  nested folder's name is that folder's row (not a refusal), the rest still listed.
- Coherence: on a still tree, for each folder the listing covers (the top and every `"dir"` row
  above the last level), `entry_kind` of each of its rows answers the listing's kind, of a name
  it lacks absent; a folder in `refused` is `entry_kind`'s refusal with the same reason; one in
  `gone` (or an absent top) is `entry_kind`'s absent. A hard link is `"file"` to both helpers and
  refused by `read`: kind is the listing's judgement, refusing it is the read's.
- D2 (#1140 review findings 2 and 11), with REAL deletions (`ListingFaults` removes the folder
  with `shutil.rmtree` at a chosen moment, and the real kernel and CPython answer): a folder
  removed after the step into it, before its reopen, between the reopen and the scan, or after
  the scan's first entry, is absent to its own `entries()` and `gone` from `list_tree` (its
  `"dir"` row stays, nothing below it listed), never a present, empty (or stale) folder; a live
  empty folder is still present with `{}`; a filesystem counting 1 link for a live directory
  (btrfs) still lists it (the dead mark is `st_nlink == 0`). `list_tree` stops at the first
  level holding no folder, so `depth=sys.maxsize` answers at once (finding 5).
- v2's findings, dissolved (each row names its finding): #1 an 1100-deep chain, in a child whose
  soft `RLIMIT_NOFILE` is a few descriptors above what it holds: `list_tree(depth=3)` lists three
  levels and `entry_kind` of the deep leaf answers `"file"`. #2 a non-empty folder REALLY moved out
  of the tree after its parent's listing (and a file, a FIFO, a symlink to it or nothing put at its
  name) is `refused` (`Not a directory` / the alias sentence) or `gone`, its `"dir"` row stays and
  nothing of the moved folder is listed; a writer thread swapping one repeatedly while
  `list_tree` runs keeps every `"dir"` row above the last level listed XOR refused XOR gone, and
  a listed one never empty. #3 a bind-time refusal is relayed as the reason. #4 a held root
  REALLY removed since: `entries()` answers it absent (D2), so do both helpers, and they agree;
  emptied but not removed, it is present and empty. #5 a REAL permission bit: `entry_kind(P)` is
  `"dir"` while `list_tree` reports P refused and `entry_kind(P/C)` refused with the same reason; with read but
  no search P's own listing is refused too; with search but no read P is refused while
  `entry_kind(P/C/x)` still answers from P/C's own listing. #6 depth 0 is rejected. #7 (a name
  removed between `getdents` and its judgement on a `DT_UNKNOWN` filesystem lists as `"other"`)
  is existing `entries()` behaviour, B4, out of scope: no row. #8 any errno, injected on any route
  of a sub-folder's listing (step, reopen, scandir, midway, entry), is that folder's own answer:
  `refused[sub]` is exactly `view.under(sub).entries().reason`, or `sub` is `gone` when that
  answers absent (ENOENT at the step); the rest is listed, nothing below it is, and it is never a
  silently empty `"dir"`. ENOENT is injected at the step only: elsewhere the kernel and CPython
  never raise it (finding 11), and the D2 rows drive the real removal instead. #9 neither helper
  writes: the tree's census is unchanged by every call, and a folder moved away is never re-created. #14 a `close()` landing mid-listing
  never redirects a listing to a reused descriptor number; every later folder answers `Bad file
  descriptor`.

Round 2 (the adversary's holes against the first commit, each row red on its exploit and
green on the honest implementation and on the adversary's own honest baseline):

- H2, independent of the seam (its AST half dropped under addendum 3, D3): in a child
  interpreter with an audit hook, every audit event
  raised during a helper call is a folder step (`O_PATH | O_NOFOLLOW`), a `"."` reopen
  (`O_RDONLY | O_DIRECTORY`) or an `os.scandir` of a descriptor, and none names a non-folder
  entry; `read` of a file recorded the same way is caught. (Kills a module that reaches the real
  `os` through `operator.attrgetter` and opens every `"file"` row.)
- H3, (b) on a faulted tree: with folders refused and gone, `list_tree`'s I/O is still one
  listing of each folder it must list, judged on disk; a refused or gone folder is never asked
  again. (Kills a retry of a refused or absent folder.)
- H7, grammar: an `int` and any other object are `ValueError` too, never spelled by `str()`.
- H8, order: names that are not valid UTF-8 on disk sort by the code points of their listed
  (surrogate-escaped) `str` names in `entries`, `refused` and `gone`, never by their bytes.

Round 3 (addendum 3's adversary, against the tests-only commit `90a646c8`; each row red on its
exploit, green on the honest implementation and on the adversary's own baseline):

- H1, depth: a chain `CHAIN_DEPTH` (100) folders deep is listed to its leaf at `sys.maxsize` /
  `10**12` (kills a silent cap on the depth).
- H2, the dead mark: a seam flipping a listed folder's link count at the end of its scan pins that
  the count after the scan decides (absent when it drops to 0, present when it rises from 0); live
  folders named `notes (deleted)` / `empty (deleted)` are present (kills a `/proc` name check).
- H3, the dead check's `fstat` is a sixth listing route (`fstat` in `LISTING_ROUTES`): any errno
  there is the folder's own refusal, never a raise, never absent or present.
- H4, no descriptor outlives a refusal on the `scandir`, `midway`, `entry` or `fstat` route, nor
  a real removal mid-scan.

Every negative row has a positive control on the same address. Every plant is a real
filesystem entry; `os_` stand-ins (`_tree_listing_1134.py`) stand in only for what cannot be
made for real (an errno on a chosen route, a permission error at a chosen moment, the moment a
real removal lands, a link count another filesystem reports). Real permission bits are exercised
in-process when the test runs unprivileged (CI) and, as root, in a child interpreter that drops
to uid/gid 65534 itself; neither path skips. As root nothing in a tree handed to 65534 is
changed by path: modes and owners change through no-follow descriptors (finding 10). Nothing is
monkeypatched; no test forks; every child process runs under a deadline. Device-node plants skip
where `mknod` is refused (CI's runner).

Red before #1134 v3 step 1: there is no `defender._tree_listing`, so every row that calls a
helper fails on `ModuleNotFoundError: No module named 'defender._tree_listing'` (in-process, or
reported by the child). One row is green on main and must stay so: `_io` gains no walk, kind,
byte read or `ENTRY_*` beyond the three.

Red against v3's step 1 (`b0a1e3b9`, before addendum 3): the core row (`read_bytes`, `_leaf`,
`BytesRead` are there), every D2 row's removal case (present and empty, or the stale names), the
removed-held-root row (present and empty), the btrfs row's 0-link control, and the huge-depth
row (it never returns, and the child is killed).
"""
from __future__ import annotations

import collections
import contextlib
import dataclasses
import errno
import inspect
import os
import shutil
import stat
import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path, PurePosixPath
from typing import Any

import pytest

from defender import _io
from defender.tests import _spec1133 as S
from defender.tests._tree_listing_1134 import (
    FD_MARGIN,
    FOLDER_PLANTS,
    HOST_BYTES,
    LISTING_ROUTES,
    REMOVAL_MOMENTS,
    PLAIN,
    STATES,
    SWAP_PLANTS,
    CallRecorder,
    FailsOn,
    ListingFaults,
    NoDeviceNodes,
    OsCallLog,
    ParkedWriter,
    RealOs,
    RefusesListing,
    ReportsLinks,
    Scratch,
    SwapsOnStep,
    bound_in,
    build_chain,
    census,
    descriptors_under,
    hand_over,
    make_scratch,
    open_fd_count,
    opened,
    owned_tree,
    plant_entry,
    plant_folder,
    put_plain,
    remove_chain,
    run_child,
    run_unprivileged,
    set_mode,
    state_tree,
    tree_listing,
)
from defender.tests.test_1111_rooted_io import in_time

#: The kinds, spelled here so a module-level name needs nothing new; the records row pins them
#: to `_io`'s constants.
FILE, DIR, OTHER = "file", "dir", "other"
#: The reasons a refused listing gives (path-free words).
ALIAS = _io.ALIAS_READ_REFUSAL
NOT_A_DIR = os.strerror(errno.ENOTDIR)
BAD_FD = os.strerror(errno.EBADF)
DENIED = os.strerror(errno.EACCES)
#: The reason a listing through each holding-folder plant gives: a linked folder is the alias
#: sentence (`_step`'s ELOOP), a file or FIFO there `Not a directory`.
FOLDER_REASON = {kind: (NOT_A_DIR if kind in ("folder_file", "folder_fifo") else ALIAS)
                 for kind in FOLDER_PLANTS}
#: The row a still holding-folder plant is in its parent's listing.
FOLDER_PLANT_KIND = {kind: (FILE if kind == "folder_file" else OTHER) for kind in FOLDER_PLANTS}

#: The ways to reach a view: `bind(root)`, `hold(root).view()`, and an `under(...)` derivation
#: of each, bound at `UNDER` (so every name below is relative to a two-component prefix).
VIEWS = ("bind", "held", "bind-under", "held-under")
BINDERS = ("bind", "held")
UNDER = "v/w"


def TL() -> Any:  # noqa: N802 — names the module it hands back
    """`defender._tree_listing`, resolved per call: a missing module fails the calling row."""
    return tree_listing()


def entry_kind(view: Any, name: Any) -> Any:
    return TL().entry_kind(view, name)


def list_tree(view: Any, depth: Any) -> Any:
    return TL().list_tree(view, depth=depth)


@pytest.fixture
def scratch(tmp_path: Path) -> Scratch:
    return make_scratch(tmp_path)


def base_of(how: str, s: Scratch) -> Path:
    """The real folder the view `how` names (made if missing)."""
    base = s.root / UNDER if how.endswith("-under") else s.root
    base.mkdir(parents=True, exist_ok=True)
    return base


@contextlib.contextmanager
def view_of(how: str, s: Scratch, os_: Any = os) -> Iterator[Any]:
    """The view `how` over `s.root` (closed on exit): `bind`, `held`, or `under(UNDER)` of one."""
    base_of(how, s)
    with opened(how.removesuffix("-under"), s.root, os_) as view:
        yield view.under(UNDER) if how.endswith("-under") else view


def planted_or_skip(at: Path, kind: str, s: Scratch) -> Any:
    try:
        return plant_entry(at, kind, root=s.root, host=s.host)
    except NoDeviceNodes:
        pytest.skip("making a device node needs CAP_MKNOD, which CI's non-root runner lacks")


def level(name: str) -> int:
    return name.count("/") + 1


def parent_of(name: str) -> str:
    return name.rpartition("/")[0]


def parts_order(names: list[str]) -> list[str]:
    return sorted(names, key=lambda n: tuple(n.split("/")))


def to_depth(rows: dict[str, str], depth: int) -> dict[str, str]:
    return {n: k for n, k in rows.items() if level(n) <= depth}


def assert_kind(got: Any, *, name: str, folder: str, kind: str | None = None,
                absent: bool = False, reason: str | None = None) -> None:
    """`got` is an `EntryKind` with exactly these fields, in exactly one state."""
    assert type(got) is TL().EntryKind, f"entry_kind answered a {type(got).__name__}"
    assert sum((got.kind is not None, got.absent, got.reason is not None)) == 1, (
        f"entry_kind's answer is not in exactly one state: {got!r}")
    assert (got.name, got.folder, got.kind, got.absent, got.reason) == (
        name, folder, kind, absent, reason), f"entry_kind({name!r}) answered {got!r}"


def listed(got: Any) -> dict[str, str]:
    """A listed `TreeListing`'s entries; its types and orders checked."""
    assert type(got) is TL().TreeListing, f"list_tree answered a {type(got).__name__}"
    assert (got.absent, got.reason) == (False, None), f"the top was not listed: {got!r}"
    assert type(got.entries) is dict, f"entries is a {type(got.entries).__name__}, not a dict"
    assert type(got.refused) is dict, got
    assert type(got.gone) is tuple, got
    for what, names in (("entries", list(got.entries)), ("refused", list(got.refused)),
                        ("gone", list(got.gone))):
        assert names == parts_order(names), f"{what} is not in path-parts order: {names}"
    return got.entries


def assert_tree(got: Any, entries: dict[str, str], refused: dict[str, str] | None = None,
                gone: tuple[str, ...] = ()) -> None:
    """`got` lists exactly `entries` (in that order), `refused` and `gone`."""
    refused = refused or {}
    assert list(entries) == parts_order(list(entries)), "the expectation itself is misordered"
    rows = listed(got)
    assert list(rows.items()) == list(entries.items()), (
        f"list_tree listed\n  {list(rows.items())}\nnot\n  {list(entries.items())}")
    assert list(got.refused.items()) == list(refused.items()), f"refused: {got.refused!r}"
    assert got.gone == tuple(gone), f"gone: {got.gone!r}"


def assert_tree_absent(got: Any) -> None:
    assert type(got) is TL().TreeListing, f"list_tree answered a {type(got).__name__}"
    assert (got.absent, got.reason, got.entries, got.refused, got.gone) == (
        True, None, None, {}, ()), f"an absent top listed as {got!r}"


def assert_tree_refused(got: Any, reason: str) -> None:
    assert type(got) is TL().TreeListing, f"list_tree answered a {type(got).__name__}"
    assert (got.absent, got.reason, got.entries, got.refused, got.gone) == (
        False, reason, None, {}, ()), f"a refused top answered {got!r}, not {reason!r}"


def _probe(view: Any, folder: str) -> Any:
    """`entry_kind` of a name the folder does not hold."""
    return entry_kind(view, f"{folder}/no-such-entry-1134" if folder else "no-such-entry-1134")


def _folder_incoherence(view: Any, got: Any, folder: str) -> list[str]:
    """One folder's half of `incoherence`."""
    children = [n for n in got.entries if parent_of(n) == folder]
    ek = _probe(view, folder)
    state = (ek.kind, ek.absent, ek.reason)
    if folder in got.refused or folder in got.gone:
        want = (None, False, got.refused[folder]) if folder in got.refused else (None, True, None)
        out = [] if state == want else [f"{folder}: listed as {want} vs entry_kind {ek!r}"]
        return out + ([f"{folder}: flagged, yet rows below it: {children}"] if children else [])
    out = [] if state == (None, True, None) else [f"{folder}: a name it lacks is {ek!r}"]
    for child in children:
        ek = entry_kind(view, child)
        if (ek.kind, ek.folder, ek.absent, ek.reason) != (got.entries[child], folder, False, None):
            out.append(f"{child}: listed {got.entries[child]!r} vs entry_kind {ek!r}")
    return out


def incoherence(view: Any, got: Any, depth: int) -> list[str]:
    """Where `entry_kind` disagrees with the listing `got` on a still tree (empty: coherent).
    For the top and every `"dir"` row above the last level: listed -> each of its rows is
    `entry_kind`'s kind and a name it lacks is absent; refused -> `entry_kind` below it is that
    refusal, same reason; gone (or an absent top) -> absent."""
    if got.absent or got.reason is not None:
        ek = _probe(view, "")
        same = (ek.kind, ek.absent, ek.reason) == (None, got.absent, got.reason)
        return [] if same else [f"top: list_tree {got!r} vs entry_kind {ek!r}"]
    folders = [""] + [n for n, k in got.entries.items() if k == DIR and level(n) < depth]
    return [problem for folder in folders for problem in _folder_incoherence(view, got, folder)]


# =======================================================================================
# The records and the signatures
# =======================================================================================

def test_the_records_are_frozen_dataclasses_with_the_contracts_fields():
    """`EntryKind(name, folder, kind, absent, reason)` and `TreeListing(absent, reason, entries,
    refused, gone)`, frozen, in that field order. The kinds the helpers answer are `_io`'s
    constants."""
    tl = TL()
    assert dataclasses.is_dataclass(tl.EntryKind)
    assert dataclasses.is_dataclass(tl.TreeListing)
    assert [f.name for f in dataclasses.fields(tl.EntryKind)] == [
        "name", "folder", "kind", "absent", "reason"]
    assert [f.name for f in dataclasses.fields(tl.TreeListing)] == [
        "absent", "reason", "entries", "refused", "gone"]
    ek = tl.EntryKind(name="a/x.md", folder="a", kind=FILE, absent=False, reason=None)
    lt = tl.TreeListing(absent=False, reason=None, entries={"a": DIR}, refused={}, gone=())
    for record, field in ((ek, "kind"), (lt, "reason")):
        with pytest.raises(dataclasses.FrozenInstanceError):
            setattr(record, field, "changed")
    assert (_io.ENTRY_FILE, _io.ENTRY_DIR, _io.ENTRY_OTHER) == (FILE, DIR, OTHER)


def test_entry_kind_takes_a_view_and_a_name_and_list_tree_a_required_keyword_depth(scratch):
    """`entry_kind(view, name)`; `list_tree(view, *, depth)`: `depth` keyword-only with no
    default, so omitting it or passing it positionally is Python's own `TypeError`. Control:
    `depth=1` by keyword lists."""
    tl = TL()
    assert list(inspect.signature(tl.entry_kind).parameters) == ["view", "name"]
    params = inspect.signature(tl.list_tree).parameters
    assert list(params) == ["view", "depth"]
    assert params["depth"].kind is inspect.Parameter.KEYWORD_ONLY
    assert params["depth"].default is inspect.Parameter.empty
    put_plain(scratch.root / "x.md")
    with _io.bind(scratch.root) as bound:
        with pytest.raises(TypeError):
            tl.list_tree(bound)
        with pytest.raises(TypeError):
            tl.list_tree(bound, 1)
        assert_tree(tl.list_tree(bound, depth=1), {"x.md": FILE})


# =======================================================================================
# Nothing is added to the core (v2 findings #1-#9, #11, #12, #15 dissolve by absence)
# =======================================================================================

#: v2's additions to `_io`, none of which B1 keeps.
V2_IO_NAMES = ("ENTRY_ABSENT", "ENTRY_UNLISTED", "WalkRead", "_walk_at", "_kind_at",
               "_list_below", "_folder_parts", "_reopen_dir", "BytesRead")


def test_v2s_walk_kind_and_their_helpers_are_not_in_the_core():
    """The core gains no walk, no kind and no byte read: `Bound` has none of `walk`, `kind`,
    `read_bytes` (addendum 3, D1) or the `_leaf` that `read_bytes` shared with `read`, and
    `_io` has none of v2's records, kinds or descriptor-chain helpers, nor `BytesRead`. `_io`'s
    `ENTRY_*` names are exactly the three listing kinds. (Green on main; it must stay so.)"""
    for verb in ("walk", "kind", "read_bytes", "_leaf"):
        assert not hasattr(_io.Bound, verb), f"Bound grew {verb}"
    present = [name for name in V2_IO_NAMES if hasattr(_io, name)]
    assert not present, f"_io carries v2's {present}"
    assert {n for n in dir(_io) if n.startswith("ENTRY_")} == {
        "ENTRY_FILE", "ENTRY_DIR", "ENTRY_OTHER"}


# =======================================================================================
# entry_kind: the leaf's kind, from its folder's one listing
# =======================================================================================

#: What `entry_kind` answers for each plant at the name: `entries()`'s judgement.
KIND_OF = {"plain": FILE, "directory": DIR, "empty_directory": DIR, "symlink": OTHER,
           "dangling": OTHER, "dir_link_inside": OTHER, "dir_link_outside": OTHER,
           "hardlink": FILE, "fifo": OTHER, "socket": OTHER, "char_device": OTHER,
           "block_device": OTHER}


@pytest.mark.parametrize("how", VIEWS)
@pytest.mark.parametrize("rel", ["x", "a/b/x"], ids=["top", "nested"])
@pytest.mark.parametrize("kind", list(KIND_OF))
def test_entry_kind_answers_each_plant_at_the_name_as_its_folders_listing_judges_it(
        scratch, kind, rel, how):
    """A plain file is `"file"`, and so is a hard link (refusing it is the read's job); a real
    directory (full or empty) is `"dir"`; a symlink (to a file, to a folder inside or outside the
    root, dangling), a FIFO, a socket or a device node is `"other"`. That is exactly the row
    `entries()` of the holding folder has for it. `name` is the spelling given (a `str` or a
    `PurePosixPath`), `folder` the view-relative parent (`""` at the top). Promptly, and nothing
    changes. Control, same address: the plant replaced by a plain file is `"file"`."""
    base = base_of(how, scratch)
    planted = planted_or_skip(base / rel, kind, scratch)
    folder = parent_of(rel)
    before = census(scratch.tmp)
    with view_of(how, scratch) as view:
        got = in_time(lambda: entry_kind(view, rel), fifo=planted.fifo)
        spelled = in_time(lambda: entry_kind(view, PurePosixPath(rel)), fifo=planted.fifo)
        listing = (view.under(folder) if folder else view).entries()
    assert_kind(got, name=rel, folder=folder, kind=KIND_OF[kind])
    assert_kind(spelled, name=rel, folder=folder, kind=KIND_OF[kind])
    assert got.kind == listing.entries[PurePosixPath(rel).name]
    assert census(scratch.tmp) == before

    planted.remove()
    put_plain(base / rel)
    with view_of(how, scratch) as view:
        assert_kind(entry_kind(view, rel), name=rel, folder=folder, kind=FILE)


@pytest.mark.parametrize("how", VIEWS)
def test_entry_kind_of_a_missing_leaf_or_holding_folder_is_absent(scratch, how):
    """A name missing from an existing folder's listing, a missing holding folder (one level or
    two), and any name under a view whose own folder is missing are absent: `absent=True`, no
    kind, no reason, never a raise, and nothing is created (#9). Control, same names: made real,
    each answers its kind."""
    base = base_of(how, scratch)
    (base / "a").mkdir()
    before = census(scratch.tmp)
    asks = [("nothing-here", ""), ("a/missing.md", "a"), ("missing/x.md", "missing"),
            ("a/missing/deeper/x.md", "a/missing/deeper")]
    with view_of(how, scratch) as view:
        for name, folder in asks:
            assert_kind(entry_kind(view, name), name=name, folder=folder, absent=True)
        for name in ("x.md", "a/x.md"):
            assert_kind(entry_kind(view.under("gone-folder"), name), name=name,
                        folder=parent_of(name), absent=True)
    assert census(scratch.tmp) == before
    assert not os.path.lexists(base / "missing")
    assert not os.path.lexists(base / "gone-folder")

    for name, _folder in asks:
        put_plain(base / name)
    put_plain(base / "gone-folder" / "a" / "x.md")
    with view_of(how, scratch) as view:
        for name, folder in asks:
            assert_kind(entry_kind(view, name), name=name, folder=folder, kind=FILE)
        assert_kind(entry_kind(view.under("gone-folder"), "a"), name="a", folder="", kind=DIR)


#: How the name is split between the view's prefix and the name for a holding-folder plant
#: under `a/b/x.md`: all in the name, `a` in the prefix, or `a/b` in the prefix.
SPLITS = {"in-the-name": ("", "a/b/x.md"), "partly": ("a", "b/x.md"),
          "in-the-prefix": ("a/b", "x.md")}


@pytest.mark.parametrize("how", VIEWS)
@pytest.mark.parametrize("split", list(SPLITS))
@pytest.mark.parametrize("kind", FOLDER_PLANTS)
@pytest.mark.parametrize("site", ["a", "a/b"])
def test_entry_kind_through_a_linked_or_non_directory_holding_folder_is_that_listings_refusal(
        scratch, site, kind, split, how):
    """A symlinked holding folder (whatever it points at: the rest of the name as a real file,
    an empty folder, nothing) is refused with the alias sentence; a file or a FIFO there with
    `Not a directory`; wherever the plant falls (in the name, in the view's prefix, or split
    across them). The reason is VERBATIM the refusal of the one listing `entry_kind` makes, and
    the kind a link reaches never comes back. Promptly; nothing changes. Control: the plant
    replaced by real folders and a plain file, `"file"`."""
    base = base_of(how, scratch)
    planted = plant_folder(base, PurePosixPath("a/b/x.md"), PurePosixPath(site), kind,
                           host=scratch.host)
    prefix, name = SPLITS[split]
    folder = parent_of(name)
    before = census(scratch.tmp)
    with view_of(how, scratch) as outer:
        view = outer.under(prefix) if prefix else outer
        got = in_time(lambda: entry_kind(view, name), fifo=planted.fifo)
        listing = in_time(lambda: (view.under(folder) if folder else view).entries(),
                          fifo=planted.fifo)
    assert listing.reason == FOLDER_REASON[kind], listing
    assert_kind(got, name=name, folder=folder, reason=FOLDER_REASON[kind])
    assert census(scratch.tmp) == before

    planted.remove()
    put_plain(base / "a" / "b" / "x.md")
    with view_of(how, scratch) as outer:
        view = outer.under(prefix) if prefix else outer
        assert_kind(entry_kind(view, name), name=name, folder=folder, kind=FILE)


#: Roots `bind` refuses (a plain file, a FIFO) or fails to open through the seam, and the
#: reason each relays.
BIND_REFUSALS = {"file-root": NOT_A_DIR, "fifo-root": NOT_A_DIR, "EACCES": DENIED,
                 "EMFILE": os.strerror(errno.EMFILE), "EIO": os.strerror(errno.EIO)}


def _refused_bind(state: str, s: Scratch) -> Any:
    if state == "file-root":
        (s.tmp / "file-root").write_bytes(PLAIN)
        return _io.bind(s.tmp / "file-root")
    if state == "fifo-root":
        os.mkfifo(s.tmp / "fifo-root")
        return _io.bind(s.tmp / "fifo-root")
    return _io.bind(s.root, os_=FailsOn(str(s.root), err=getattr(errno, state)))


@pytest.mark.parametrize("state", list(BIND_REFUSALS))
def test_finding_3_a_root_refused_at_bind_is_relayed_as_the_reason_never_a_kind(scratch, state):
    """v2 finding #3 (kind folded a bind-time failure into `"other"`): a `Bound` whose root
    `bind` refused (a plain file, a FIFO, EACCES, EMFILE, EIO opening it) answers that reason,
    verbatim, from both helpers, for every name and depth and through `under(...)`: `entry_kind`
    has no kind and is not absent, and `list_tree`'s top is refused. Never a raise, never a
    hang. Control: the root a real directory, both helpers list it."""
    reason = BIND_REFUSALS[state]
    put_plain(scratch.root / "a" / "x.md")
    bound = _refused_bind(state, scratch)
    try:
        for view in (bound, bound.under("a")):
            assert view.entries().reason == reason
            for name in ("x.md", "a/x.md"):
                got = in_time(lambda view=view, name=name: entry_kind(view, name))
                assert_kind(got, name=name, folder=parent_of(name), reason=reason)
            for depth in (1, 3):
                assert_tree_refused(in_time(lambda view=view, d=depth: list_tree(view, d)), reason)
    finally:
        bound.close()

    with _io.bind(scratch.root) as live:
        assert_kind(entry_kind(live, "a/x.md"), name="a/x.md", folder="a", kind=FILE)
        assert_tree(list_tree(live, 2), {"a": DIR, "a/x.md": FILE})


@pytest.mark.parametrize("root", ["no-such-root", "dangling-root"])
def test_both_helpers_through_a_root_absent_at_bind_are_absent(scratch, root):
    """A `Bound` absent at `bind` (nothing at the root, a dangling root link): `entry_kind` of
    every name is absent and `list_tree`'s top is absent, through `under(...)` too. Nothing is
    created. Control: a real folder made at the spelling, both helpers list it."""
    at = scratch.tmp / root
    if root == "dangling-root":
        at.symlink_to(scratch.tmp / "made-later", target_is_directory=True)
    before = census(scratch.tmp)
    with _io.bind(at) as bound:
        for view in (bound, bound.under("a")):
            for name in ("x.md", "a/x.md"):
                assert_kind(entry_kind(view, name), name=name, folder=parent_of(name),
                            absent=True)
            assert_tree_absent(list_tree(view, 2))
    assert census(scratch.tmp) == before

    put_plain((scratch.tmp / "made-later" if root == "dangling-root" else at) / "a" / "x.md")
    with _io.bind(at) as bound:
        assert_kind(entry_kind(bound, "a/x.md"), name="a/x.md", folder="a", kind=FILE)
        assert_tree(list_tree(bound, 2), {"a": DIR, "a/x.md": FILE})


@pytest.mark.parametrize("how", BINDERS)
def test_both_helpers_after_the_root_is_closed_answer_bad_file_descriptor_never_raise(
        scratch, how):
    """A closed root (bound or held, and the views derived from it) answers `Bad file
    descriptor` as the reason: `entry_kind` refused, `list_tree`'s top refused. Never an
    exception. Control: the same views before the close list."""
    put_plain(scratch.root / "a" / "x.md")
    if how == "bind":
        owner = _io.bind(scratch.root)
        views = [owner, owner.under("a")]
    else:
        owner = _io.hold(scratch.root)
        views = [owner.view(), owner.view().under("a")]
    assert_tree(list_tree(views[0], 2), {"a": DIR, "a/x.md": FILE})
    assert_kind(entry_kind(views[1], "x.md"), name="x.md", folder="", kind=FILE)
    owner.close()
    for view in views:
        for name in ("x.md", "a/x.md"):
            assert_kind(in_time(lambda view=view, name=name: entry_kind(view, name)), name=name,
                        folder=parent_of(name), reason=BAD_FD)
        assert_tree_refused(in_time(lambda view=view: list_tree(view, 3)), BAD_FD)
    assert descriptors_under(scratch.tmp) == []


@pytest.mark.parametrize("how", BINDERS)
def test_finding_4_a_removed_held_root_is_absent_to_entries_and_both_helpers(scratch, how):
    """v2 finding #4 (kind and walk said absent where entries said present-and-empty), settled
    by addendum 3, D2: a root `bind` or `hold` opened, REALLY removed since (`rmdir`, after its
    contents), is absent to `view.entries()` itself (the reopened folder is dead), so
    `list_tree` answers an absent top, and `entry_kind` of a name at the top, or in a folder
    that went with it, is absent: all three agree. A folder made again at the path is not the
    held one: the answers stay. Control: before the removal the same view lists the tree, and a
    held root emptied but NOT removed is present and empty (`{}`), never absent."""
    put_plain(scratch.root / "x.md")
    put_plain(scratch.root / "sub" / "y.md")
    with opened(how, scratch.root) as view:
        assert_tree(list_tree(view, 2), {"sub": DIR, "sub/y.md": FILE, "x.md": FILE})
        assert_kind(entry_kind(view, "x.md"), name="x.md", folder="", kind=FILE)

        (scratch.root / "sub" / "y.md").unlink()
        (scratch.root / "sub").rmdir()
        (scratch.root / "x.md").unlink()
        top = view.entries()
        assert (top.absent, top.reason, top.entries) == (False, None, {}), (
            f"a live, emptied root is not present and empty: {top!r}")
        assert_tree(list_tree(view, 2), {})
        assert_kind(entry_kind(view, "x.md"), name="x.md", folder="", absent=True)

        scratch.root.rmdir()
        for _ in range(2):
            top = view.entries()
            assert (top.absent, top.reason, top.entries) == (True, None, None), top
            got = list_tree(view, 2)
            assert_tree_absent(got)
            assert_kind(entry_kind(view, "x.md"), name="x.md", folder="", absent=True)
            assert_kind(entry_kind(view, "sub/y.md"), name="sub/y.md", folder="sub",
                        absent=True)
            assert incoherence(view, got, 2) == []
            put_plain(scratch.root / "x.md")  # a new folder at the old path: not the held one
    assert descriptors_under(scratch.tmp) == []


# =======================================================================================
# The grammar and the depth: refused before any I/O, in every state
# =======================================================================================

#: Names outside `Bound.read`'s grammar: `""` and `"."` (the view itself: callers use
#: `view.entries()`), absolute, climbing, empty components, a NUL, and non-names (bytes,
#: `None`, an `int`, any other object: never spelled by `str()`; round 2, H7).
ENTRY_KIND_BAD_NAMES = ["", ".", "..", "../x", "/abs/x", "a/../x", "a//x", "./x", "a/", "x\x00y",
                        pytest.param(PurePosixPath("."), id="purepath-dot"),
                        pytest.param(b"x", id="bytes"), pytest.param(None, id="none"),
                        pytest.param(7, id="int"), pytest.param(object(), id="object")]

#: What `entry_kind(view, "rec.md")` answers in each state (`kind`, `absent`, `reason`).
STATE_KIND = {"present": (FILE, False, None), "held": (FILE, False, None),
              "under": (FILE, False, None), "absent_at_bind": (None, True, None),
              "refused_at_bind": (None, False, NOT_A_DIR),
              "linked_prefix": (None, False, ALIAS), "closed": (None, False, BAD_FD),
              "closed_held": (None, False, BAD_FD)}


@pytest.mark.parametrize("state", STATES)
@pytest.mark.parametrize("name", ENTRY_KIND_BAD_NAMES)
def test_entry_kind_refuses_a_name_outside_the_grammar_before_any_io(scratch, state, name):
    """`Bound.read`'s grammar: `""`, `"."`, every malformed name and anything that is not a
    `str` or a `PurePath` are `ValueError`, and the `os_` seam sees no call after the view was
    made. In every state: present, held, prefixed, absent or refused at `bind`, behind a linked
    prefix, closed (a `ValueError`, not the closed root's refusal). Nothing changes. Control,
    same state: `entry_kind(view, "rec.md")` answers that state's kind, absence or reason."""
    state_tree(scratch)
    before = census(scratch.tmp)
    rec = CallRecorder()
    with bound_in(state, scratch, rec) as view:
        rec.calls.clear()
        with pytest.raises(ValueError):  # noqa: PT011 — the type is the contract, not the wording
            entry_kind(view, name)
        assert rec.calls == [], f"entry_kind({name!r}) reached the os_ seam: {rec.calls}"
    assert census(scratch.tmp) == before

    kind, absent, reason = STATE_KIND[state]
    with bound_in(state, scratch) as view:
        assert_kind(entry_kind(view, "rec.md"), name="rec.md", folder="", kind=kind,
                    absent=absent, reason=reason)


#: Depths `list_tree` refuses: zero, negatives, and anything that is not a positive `int`
#: (`True` is an `int` equal to 1 and must still be refused).
BAD_DEPTHS = [pytest.param(0, id="zero"), pytest.param(-1, id="minus-one"),
              pytest.param(-3, id="minus-three"), pytest.param(None, id="none"),
              pytest.param(True, id="true"), pytest.param(False, id="false"),
              pytest.param(1.0, id="float-one"), pytest.param(2.5, id="float"),
              pytest.param("1", id="str")]
#: What `list_tree(view, depth=1)` answers in each state: rows, or `("absent",)` /
#: `("refused", reason)`.
STATE_LIST = {"present": {"a": DIR, "linked": OTHER, "rec.md": FILE},
              "held": {"a": DIR, "linked": OTHER, "rec.md": FILE},
              "under": {"rec.md": FILE}, "absent_at_bind": ("absent",),
              "refused_at_bind": ("refused", NOT_A_DIR), "linked_prefix": ("refused", ALIAS),
              "closed": ("refused", BAD_FD), "closed_held": ("refused", BAD_FD)}


@pytest.mark.parametrize("state", STATES)
@pytest.mark.parametrize("depth", BAD_DEPTHS)
def test_finding_6_list_tree_refuses_a_depth_that_is_not_a_positive_int_before_any_io(
        scratch, state, depth):
    """v2 finding #6 (depth 0 answered present-and-empty for a folder its listing refused):
    depth `0`, a negative, `None`, `True` / `False`, a float (even `1.0`) or a string is a
    `ValueError` and the `os_` seam sees no call after the view was made, in every state, a
    closed or refused root included. Nothing changes. Control, same state: `depth=1` answers
    that state's listing."""
    state_tree(scratch)
    before = census(scratch.tmp)
    rec = CallRecorder()
    with bound_in(state, scratch, rec) as view:
        rec.calls.clear()
        with pytest.raises(ValueError):  # noqa: PT011 — the type is the contract, not the wording
            TL().list_tree(view, depth=depth)
        assert rec.calls == [], f"list_tree(depth={depth!r}) reached the os_ seam: {rec.calls}"
    assert census(scratch.tmp) == before

    want = STATE_LIST[state]
    with bound_in(state, scratch) as view:
        got = list_tree(view, 1)
    if isinstance(want, dict):
        assert_tree(got, want)
    elif want == ("absent",):
        assert_tree_absent(got)
    else:
        assert_tree_refused(got, want[1])


# =======================================================================================
# list_tree over a catalog-shaped tree
# =======================================================================================

CATALOG_FILES = ("top.md", "gather/queries/README.md", "gather/queries/elastic/x.md",
                 "gather/queries/elastic/_draft/d1.md", "gather/queries/splunk/y.md")


def build_catalog(base: Path) -> None:
    """A tree shaped like the skills mount (`<sys>/_draft/<file>.md` at depth 3 below
    `gather/queries`): nested folders, files at several depths, one empty folder."""
    for rel in CATALOG_FILES:
        put_plain(base / rel)
    (base / "empty").mkdir()


#: Every row of `build_catalog` from its top, written out by hand in path-parts order
#: (`tuple(name.split("/"))`: in ASCII `R` < `_` < `e` < `s`).
CATALOG_ROWS = {
    "empty": DIR,
    "gather": DIR,
    "gather/queries": DIR,
    "gather/queries/README.md": FILE,
    "gather/queries/elastic": DIR,
    "gather/queries/elastic/_draft": DIR,
    "gather/queries/elastic/_draft/d1.md": FILE,
    "gather/queries/elastic/x.md": FILE,
    "gather/queries/splunk": DIR,
    "gather/queries/splunk/y.md": FILE,
    "top.md": FILE,
}
#: The same tree from `under("gather/queries")`: no `gather/queries/` in front.
QUERIES_ROWS = {
    "README.md": FILE,
    "elastic": DIR,
    "elastic/_draft": DIR,
    "elastic/_draft/d1.md": FILE,
    "elastic/x.md": FILE,
    "splunk": DIR,
    "splunk/y.md": FILE,
}
#: The folders at each level of `build_catalog`, by last component.
LEVEL_FOLDERS = {1: ("empty", "gather"), 2: ("queries",), 3: ("elastic", "splunk"),
                 4: ("_draft",)}


@pytest.mark.parametrize("how", VIEWS)
@pytest.mark.parametrize("depth", [1, 2, 3, 4, 5, 6])
def test_list_tree_lists_exactly_depth_levels_in_path_parts_order(scratch, depth, how):
    """Every entry within `depth` levels of the view's folder, and nothing deeper: names
    relative to the view, kinds as each folder's listing judged them, dict order path-parts
    order. A folder at the last level is still a `"dir"` row. A depth past the tree's own adds
    nothing. Nothing is refused or gone; nothing changes; the two helpers agree."""
    build_catalog(base_of(how, scratch))
    before = census(scratch.tmp)
    with view_of(how, scratch) as view:
        got = list_tree(view, depth)
        assert incoherence(view, got, depth) == []
    assert_tree(got, to_depth(CATALOG_ROWS, depth))
    assert census(scratch.tmp) == before


@pytest.mark.parametrize("how", BINDERS)
@pytest.mark.parametrize("prefix", ["str", "purepath", "chained"])
@pytest.mark.parametrize("depth", [1, 2, 3, 4])
def test_list_tree_names_are_relative_to_the_view_it_was_called_on(scratch, depth, prefix, how):
    """Through `under("gather/queries")` (a `str`, a `PurePosixPath`, or `under("gather")
    .under("queries")`), the rows are `README.md`, `elastic/x.md`, ... — never prefixed with
    `gather/queries/`."""
    build_catalog(scratch.root)
    with opened(how, scratch.root) as outer:
        view = {"str": lambda: outer.under("gather/queries"),
                "purepath": lambda: outer.under(PurePosixPath("gather/queries")),
                "chained": lambda: outer.under("gather").under("queries")}[prefix]()
        got = list_tree(view, depth)
    assert_tree(got, to_depth(QUERIES_ROWS, depth))


@pytest.mark.parametrize("how", VIEWS)
@pytest.mark.parametrize("prefix", ["", "gather/queries", "empty"])
def test_list_tree_to_depth_one_is_exactly_entries(scratch, prefix, how):
    """Depth 1 is `view.entries()`'s rows: the same names with the same kinds (compared as a
    mapping: `entries()` keeps the listing's own order, `list_tree` path-parts order), nothing
    refused, nothing gone."""
    build_catalog(base_of(how, scratch))
    with view_of(how, scratch) as outer:
        view = outer.under(prefix) if prefix else outer
        got = list_tree(view, 1)
        rows = view.entries().entries
    assert dict(listed(got)) == rows
    assert (got.refused, got.gone) == ({}, ())


@pytest.mark.parametrize("how", BINDERS)
@pytest.mark.parametrize("depth", sorted(LEVEL_FOLDERS))
def test_list_tree_never_lists_a_folder_at_the_last_level(scratch, depth, how):
    """A folder at level `depth` is reported `"dir"` and never listed by any route: through a
    seam that would refuse stepping into it, nothing is refused, and the seam was never asked to
    open or list it. Non-vacuity: the seam does see the listings above (a folder at level
    `depth - 1`, or the top's own `.`)."""
    build_catalog(scratch.root)
    seam = RefusesListing("step", *LEVEL_FOLDERS[depth])
    with opened(how, scratch.root, seam) as view:
        got = list_tree(view, depth)
    assert_tree(got, to_depth(CATALOG_ROWS, depth))
    touched = [name for name in LEVEL_FOLDERS[depth] if seam.touched(name)]
    assert not touched, f"list_tree(depth={depth}) entered a last-level folder: {touched}"
    above = LEVEL_FOLDERS[depth - 1] if depth > 1 else ()
    assert all(seam.touched(name) for name in above), f"the seam saw none of it: {seam.seen}"
    assert any(seen.endswith("/.") for seen in seam.seen), seam.seen


# =======================================================================================
# list_tree: plants at a name, at a nested folder, at the view's own folder
# =======================================================================================

@pytest.mark.parametrize("how", VIEWS)
@pytest.mark.parametrize("kind", list(KIND_OF))
def test_list_tree_lists_each_plant_as_its_own_kind_and_never_enters_a_link(scratch, kind, how):
    """Inside a listed folder, each plant is one row of its own kind (a hard link `"file"`, a
    link of any sort, FIFO, socket or device `"other"`, a real folder `"dir"`, entered and
    listed if above the last level). Only real folders are entered: a link's target (`inner.md`,
    `keep`) never shows under the link's name. Promptly; nothing refused or gone; nothing
    changes; the helpers agree."""
    base = base_of(how, scratch)
    put_plain(base / "box" / "sub" / "deeper.md")
    planted = planted_or_skip(base / "box" / "e", kind, scratch)
    before = census(scratch.tmp)
    with view_of(how, scratch) as view:
        got = in_time(lambda: list_tree(view, 3), fifo=planted.fifo)
        assert incoherence(view, got, 3) == []
    want = {"box": DIR, "box/e": KIND_OF[kind]}
    if kind == "directory":
        want["box/e/keep"] = FILE
    want.update({"box/sub": DIR, "box/sub/deeper.md": FILE})
    if kind == "dir_link_inside" and base == scratch.root:
        # The link's target was made at the root's top: listed under its own name only.
        want.update({"linked-dir-of-e": DIR, "linked-dir-of-e/inner.md": FILE})
    assert_tree(got, want)
    assert census(scratch.tmp) == before


def _inside_target_rows(kind: str, site: str) -> dict[str, str]:
    """The rows a link's target adds when `plant_folder` made it INSIDE the listed tree: it is
    listed under its own name only."""
    stem = "-".join(site.split("/"))
    if kind == "folder_link_inside":
        rest = PurePosixPath("a/b/x.md").relative_to(site)
        target = f"elsewhere-{stem}"
        rows = {target: DIR}
        walked = target
        for part in rest.parts[:-1]:
            walked = f"{walked}/{part}"
            rows[walked] = DIR
        rows[f"{walked}/{rest.name}"] = FILE
        return rows
    if kind == "folder_link_empty_inside":
        return {f"bare-{stem}": DIR}
    return {}


@pytest.mark.parametrize("how", VIEWS)
@pytest.mark.parametrize("kind", FOLDER_PLANTS)
@pytest.mark.parametrize("site", ["a", "a/b"])
def test_a_still_plant_at_a_nested_folders_name_is_its_row_and_the_rest_is_listed(
        scratch, site, kind, how):
    """A link, file or FIFO standing (before any listing) where a holding folder belongs is
    just a row of its parent's listing (`"other"`, or `"file"` for a file): it is never entered,
    is not a refusal (`refused == {}`), and nothing below it is listed, while the rest of the
    shape is. `entry_kind` of a name BELOW it is refused with the reason (the alias sentence, or
    `Not a directory`): its one listing walks through the plant. Control: real folders there,
    `a/b/x.md` is listed and `"file"`."""
    base = base_of(how, scratch)
    put_plain(base / "keep" / "k.md")
    put_plain(base / "top.md")
    planted = plant_folder(base, PurePosixPath("a/b/x.md"), PurePosixPath(site), kind,
                           host=scratch.host)
    before = census(scratch.tmp)
    with view_of(how, scratch) as view:
        got = in_time(lambda: list_tree(view, 4), fifo=planted.fifo)
        below = in_time(lambda: entry_kind(view, "a/b/x.md"), fifo=planted.fifo)
        assert in_time(lambda: incoherence(view, got, 4), fifo=planted.fifo) == []
    want = {"a": FOLDER_PLANT_KIND[kind]} if site == "a" else {
        "a": DIR, "a/b": FOLDER_PLANT_KIND[kind]}
    want.update(_inside_target_rows(kind, site))
    want.update({"keep": DIR, "keep/k.md": FILE, "top.md": FILE})
    assert_tree(got, dict(sorted(want.items(), key=lambda r: tuple(r[0].split("/")))))
    assert_kind(below, name="a/b/x.md", folder="a/b", reason=FOLDER_REASON[kind])
    assert census(scratch.tmp) == before

    planted.remove()
    put_plain(base / "a" / "b" / "x.md")
    with view_of(how, scratch) as view:
        rows = listed(list_tree(view, 4))
        assert_kind(entry_kind(view, "a/b/x.md"), name="a/b/x.md", folder="a/b", kind=FILE)
    assert (rows["a"], rows["a/b"], rows["a/b/x.md"]) == (DIR, DIR, FILE)


@pytest.mark.parametrize("how", BINDERS)
@pytest.mark.parametrize("kind", FOLDER_PLANTS)
@pytest.mark.parametrize("site", ["a/b", "a"], ids=["at-the-view", "above-it"])
def test_list_tree_of_a_view_whose_own_folder_is_a_plant_is_refused(scratch, site, kind, how):
    """A view `under("a/b")` whose folder (or the folder above it) is a link, a file or a FIFO:
    `list_tree`'s top is refused with exactly `view.entries()`'s reason (the alias sentence, or
    `Not a directory`) at every depth, and nothing a link reaches is listed. Promptly; nothing
    changes. Control: real folders, the view lists `x.md`."""
    planted = plant_folder(scratch.root, PurePosixPath("a/b/x.md"), PurePosixPath(site), kind,
                           host=scratch.host)
    before = census(scratch.tmp)
    with opened(how, scratch.root) as outer:
        view = outer.under("a/b")
        top = in_time(view.entries, fifo=planted.fifo)
        got = [in_time(lambda d=d: list_tree(view, d), fifo=planted.fifo) for d in (1, 3)]
    assert top.reason == FOLDER_REASON[kind]
    for listing in got:
        assert_tree_refused(listing, FOLDER_REASON[kind])
    assert census(scratch.tmp) == before

    planted.remove()
    put_plain(scratch.root / "a" / "b" / "x.md")
    with opened(how, scratch.root) as outer:
        assert_tree(list_tree(outer.under("a/b"), 3), {"x.md": FILE})


@pytest.mark.parametrize("how", BINDERS)
def test_an_absent_top_and_an_empty_top_are_told_apart(scratch, how):
    """A view whose folder is a real, empty directory lists nothing (`absent=False`,
    `entries == {}`); one whose folder is missing (one level or two) is `absent=True` with
    `entries=None`. Both have nothing refused or gone. Nothing is created."""
    (scratch.root / "empty").mkdir()
    before = census(scratch.tmp)
    with opened(how, scratch.root) as view:
        assert_tree(list_tree(view.under("empty"), 2), {})
        for missing in ("missing", "missing/deeper", "empty/missing"):
            assert_tree_absent(list_tree(view.under(missing), 2))
    assert census(scratch.tmp) == before


# =======================================================================================
# Ordering
# =======================================================================================

#: Every character below `/` in code-point order, control characters too (v2 hole D: a sort
#: key that stands `\x1f` in for the separator).
BELOW_SLASH = "".join(map(chr, range(1, ord("/"))))


@pytest.mark.parametrize("prefix", ["", "p"], ids=["root", "under-p"])
@pytest.mark.parametrize("sibling", ["a b", "a!b", "a+b", "a,b", "a-b", "a.b", "a.md", "a\x01b",
                                     "a\tb", "a\x1fb"])
def test_list_tree_sorts_by_path_parts_not_by_the_joined_string(scratch, prefix, sibling):
    """A folder `a/` holding `b` sorts `a`, `a/b`, then a file beside it whose name continues
    `a` with a character below `/`. That is path-parts order; plain string order puts the file
    before `a/b`. At the root and under `p`."""
    base = scratch.root / prefix if prefix else scratch.root
    put_plain(base / "a" / "b")
    put_plain(base / sibling)
    names = ["a", "a/b", sibling]
    assert sorted(names) != names, "the row must tell path-parts order from string order"
    with _io.bind(scratch.root) as bound:
        got = list_tree(bound.under(prefix) if prefix else bound, 2)
    assert_tree(got, {"a": DIR, "a/b": FILE, sibling: FILE})


@pytest.mark.parametrize("how", BINDERS)
@pytest.mark.parametrize("prefix", ["", "p"], ids=["root", "under-p"])
def test_list_tree_sorts_every_character_below_the_separator_in_one_listing(scratch, prefix, how):
    """Every character below `/` at once, beside `a/b`: `a` and `a/b` first, then the siblings
    in code-point order. A sort key that stands any one character in for the separator puts
    some sibling on the wrong side of `a/b`."""
    base = scratch.root / prefix if prefix else scratch.root
    put_plain(base / "a" / "b")
    siblings = [f"a{c}b" for c in BELOW_SLASH] + ["a.md"]
    for sibling in siblings:
        put_plain(base / sibling)
    with opened(how, scratch.root) as view:
        got = list_tree(view.under(prefix) if prefix else view, 2)
    assert_tree(got, {"a": DIR, "a/b": FILE, **{sibling: FILE for sibling in siblings}})


@pytest.mark.parametrize("outcome", ["refused", "gone"])
def test_refused_and_gone_are_in_path_parts_order_too(scratch, outcome):
    """Folders refused (EACCES at the reopen) or gone (REALLY removed after the step into them,
    before the reopen: `entries()` answers the dead folder absent) are reported in path-parts
    order: `a/c` before `a b` (string order is the other way). The listing of `a` itself, and
    the rest, still list."""
    for rel in ("a/c/x.md", "a b/y.md", "z/z.md"):
        put_plain(scratch.root / rel)
    seam = (ListingFaults({"a b": errno.EACCES, "c": errno.EACCES}) if outcome == "refused"
            else ListingFaults(remove={"a b", "c"}))
    with _io.bind(scratch.root, os_=seam) as bound:
        got = list_tree(bound, 3)
    rows = {"a": DIR, "a/c": DIR, "a b": DIR, "z": DIR, "z/z.md": FILE}
    if outcome == "refused":
        assert_tree(got, rows, refused={"a/c": DENIED, "a b": DENIED})
    else:
        assert sorted(seam.removed) == sorted(
            os.path.realpath(scratch.root / f) for f in ("a/c", "a b")), seam.removed
        assert_tree(got, rows, gone=("a/c", "a b"))


#: Names that are not valid UTF-8 on disk (each `\x80` / `\xff` byte decodes, as every
#: listed name does, to a lone surrogate) beside valid ones. In code-point order
#: `"a" < "aä" (U+00E4) < "a\udc80" < "a\udcff"`; as the bytes on disk, `b"a\x80"` sorts before
#: `b"a\xc3\xa4"`, so a key that compares the bytes swaps the middle two (and `"bä"` /
#: `"b\udc80"` likewise).
UNDECODABLE_TREE = {
    b"a/x.md": FILE, b"a\xc3\xa4/r.md": FILE, b"a\x80/r.md": FILE,
    b"a\xff/a": FILE, b"a\xff/a\xc3\xa4": FILE, b"a\xff/a\x80": FILE, b"a\xff/a\xff": FILE,
    b"a\xff/b\xc3\xa4/g.md": FILE, b"a\xff/b\x80/g.md": FILE,
}


def _undecodable_tree(base: Path) -> None:
    """`UNDECODABLE_TREE`'s files (and their folders) under `base`, made by bytes paths; a
    filesystem that refuses such a name skips the row."""
    root = os.fsencode(base)
    for rel in UNDECODABLE_TREE:
        folder, _sep, _leaf = rel.rpartition(b"/")
        try:
            os.makedirs(root + b"/" + folder, exist_ok=True)
        except OSError as e:
            if e.errno in (errno.EILSEQ, errno.EINVAL):
                pytest.skip(f"this filesystem refuses a name that is not valid UTF-8: {e}")
            raise
        with open(root + b"/" + rel, "wb") as out:
            out.write(PLAIN)


@pytest.mark.parametrize("how", VIEWS)
@pytest.mark.parametrize("depth", [2, 3])
def test_names_that_are_not_valid_utf8_sort_by_their_code_points_too(scratch, depth, how):
    """Round 2, H8: names that are not valid UTF-8 on disk are listed as `entries()` names
    them (lone surrogates for the undecodable bytes), and `entries`, `refused` and `gone` are
    all in path-parts order over those `str` names, by code point: `a`, `aä`, `a\udc80`,
    `a\udcff`, never the order of the bytes on disk. Folders `aä` and `a\udc80` are refused
    (EACCES at their reopen), `bä` and `b\udc80` gone (REALLY removed after the step into
    them)."""
    _undecodable_tree(base_of(how, scratch))
    a_uml, a_80, a_ff = "a\u00e4", os.fsdecode(b"a\x80"), os.fsdecode(b"a\xff")
    b_uml, b_80 = "b\u00e4", os.fsdecode(b"b\x80")
    assert (a_80, a_ff, b_80) == ("a\udc80", "a\udcff", "b\udc80")
    faults = ListingFaults({a_uml: errno.EACCES, a_80: errno.EACCES}, remove={b_uml, b_80})
    with view_of(how, scratch, faults) as view:
        got = list_tree(view, depth)
    rows = {"a": DIR, "a/x.md": FILE, a_uml: DIR, a_80: DIR, a_ff: DIR,
            f"{a_ff}/a": FILE, f"{a_ff}/{a_uml}": FILE, f"{a_ff}/{a_80}": FILE,
            f"{a_ff}/{a_ff}": FILE, f"{a_ff}/{b_uml}": DIR, f"{a_ff}/{b_80}": DIR}
    gone = (f"{a_ff}/{b_uml}", f"{a_ff}/{b_80}") if depth == 3 else ()
    on_disk = sorted(rows, key=lambda n: tuple(p.encode("utf-8", "surrogateescape")
                                               for p in n.split("/")))
    assert on_disk != list(rows), "the row must tell code-point order from the bytes' order"
    assert_tree(got, rows, refused={a_uml: DENIED, a_80: DENIED}, gone=gone)


# =======================================================================================
# Coherence on a still tree
# =======================================================================================

def _mixed_tree(base: Path, s: Scratch) -> None:
    """Folders, files and plants at several depths, and folders a seam refuses (`R`, EACCES
    at its reopen) or REALLY removes after the step into them (`G`)."""
    build_catalog(base)
    for name, kind in (("hard", "hardlink"), ("lnk", "symlink"), ("dl", "dir_link_outside"),
                       ("ff", "fifo"), ("sock", "socket"), ("dang", "dangling")):
        plant_entry(base / "gather" / name, kind, root=s.root, host=s.host)
    put_plain(base / "gather" / "R" / "r.md")
    put_plain(base / "gather" / "G" / "g.md")
    put_plain(base / "gather" / "queries" / "R" / "deep.md")


@pytest.mark.parametrize("how", VIEWS)
@pytest.mark.parametrize("depth", [1, 2, 3, 4])
def test_the_two_helpers_agree_on_a_still_tree(scratch, depth, how):
    """For each folder the listing covers (the top, and every `"dir"` row above the last
    level): listed -> `entry_kind` of each of its rows is the listed kind (plants included) and
    of a name it lacks is absent; refused -> `entry_kind` below it is refused with the SAME
    reason. Run through one seam that refuses every folder named `R` (EACCES at its reopen).
    (A folder found gone has been removed, so the tree is no longer still: the gone half of
    coherence is pinned by the removal rows, `test_d2_*`.)"""
    base = base_of(how, scratch)
    _mixed_tree(base, scratch)

    with view_of(how, scratch, ListingFaults({"R": errno.EACCES})) as view:
        got = list_tree(view, depth)
        mismatches = incoherence(view, got, depth)
    assert mismatches == [], mismatches
    rows = listed(got)
    if depth >= 2:
        assert (rows["gather/hard"], rows["gather/lnk"], rows["gather/dl"], rows["gather/ff"],
                rows["gather/sock"], rows["gather/dang"]) == (FILE, OTHER, OTHER, OTHER, OTHER,
                                                               OTHER)
    if depth >= 3:
        assert got.refused.get("gather/R") == DENIED, got
        assert listed(got)["gather/G/g.md"] == FILE, got
    if depth >= 4:
        assert got.refused.get("gather/queries/R") == DENIED, got


def test_a_hard_link_is_a_file_to_both_helpers_and_refused_by_read(scratch):
    """Kind is the listing's judgement; refusing an alias is the read's. A hard-linked regular
    file is `"file"` to `entry_kind` and in `list_tree`, while `read` of the same name refuses
    it with the alias sentence. Control: a single-linked file is `"file"` and reads back."""
    plant_entry(scratch.root / "a" / "hard.md", "hardlink", root=scratch.root, host=scratch.host)
    put_plain(scratch.root / "a" / "plain.md")
    with _io.bind(scratch.root) as bound:
        assert_kind(entry_kind(bound, "a/hard.md"), name="a/hard.md", folder="a", kind=FILE)
        assert listed(list_tree(bound, 2))["a/hard.md"] == FILE
        refused = bound.read("a/hard.md")
        assert (refused.text, refused.absent, refused.reason) == (None, False, ALIAS)
        assert_kind(entry_kind(bound, "a/plain.md"), name="a/plain.md", folder="a", kind=FILE)
        assert bound.read("a/plain.md").text == PLAIN.decode()


# =======================================================================================
# Finding #5: real permission bits
# =======================================================================================

#: `(folder, mode)` for each real-permission case, applied to the owned tree below.
PERMISSION_CASES = {
    "P-0o000": ("P", 0o000),
    "P-read-no-search-0o400": ("P", 0o400),
    "P-search-no-read-0o100": ("P", 0o100),
    "nested-C-0o000": ("P/C", 0o000),
    "control-P-0o500": ("P", 0o500),
}
PERMISSION_FILES = ("P/C/x.md", "P/C2/y.md", "P/f.md", "top.md")
FULL_PERMISSION_ROWS = {"P": DIR, "P/C": DIR, "P/C/x.md": FILE, "P/C2": DIR,
                        "P/C2/y.md": FILE, "P/f.md": FILE, "top.md": FILE}


def _permission_scenarios(root: Path) -> list[dict[str, Any]]:
    r = str(root)
    return [
        {"root": r, "op": "list_tree", "depth": 3},
        {"root": r, "how": "held", "op": "list_tree", "depth": 3},
        {"root": r, "prefix": "P", "op": "list_tree", "depth": 2},
        {"root": r, "op": "entry_kind", "name": "P"},
        {"root": r, "op": "entry_kind", "name": "P/f.md"},
        {"root": r, "op": "entry_kind", "name": "P/C"},
        {"root": r, "op": "entry_kind", "name": "P/C/x.md"},
        {"root": r, "prefix": "P", "op": "entry_kind", "name": "C"},
        {"root": r, "prefix": "P", "op": "entries"},
        {"root": r, "prefix": "P/C", "op": "entries"},
    ]


def _tree(entries: dict[str, str], refused: dict[str, str] | None = None) -> dict[str, Any]:
    return {"absent": False, "reason": None, "entries": [list(r) for r in entries.items()],
            "refused": [list(r) for r in (refused or {}).items()], "gone": []}


def _kind(name: str, folder: str, kind: str | None = None, reason: str | None = None) -> dict:
    return {"name": name, "folder": folder, "kind": kind, "absent": False, "reason": reason}


def _entries(name: str, rows: dict[str, str] | None = None, reason: str | None = None) -> dict:
    return {"name": name, "absent": False, "reason": reason,
            "entries": None if rows is None else sorted(map(list, rows.items()))}


def _refused_top(reason: str) -> dict[str, Any]:
    return {"absent": False, "reason": reason, "entries": None, "refused": [], "gone": []}


def _permission_answers(case: str) -> list[dict[str, Any]]:
    """What each `_permission_scenarios` row answers, read off the kernel's rules: listing a
    folder reopens `.` through its own handle, which needs SEARCH on it, then reads it, which
    needs READ; stepping into a child needs search on the parent only."""
    p_refused = _tree({"P": DIR, "top.md": FILE}, {"P": DENIED})
    if case in ("P-0o000", "P-read-no-search-0o400"):
        return [p_refused, p_refused, _refused_top(DENIED), _kind("P", "", DIR),
                _kind("P/f.md", "P", reason=DENIED), _kind("P/C", "P", reason=DENIED),
                _kind("P/C/x.md", "P/C", reason=DENIED), _kind("C", "", reason=DENIED),
                _entries("P", reason=DENIED), _entries("P/C", reason=DENIED)]
    if case == "P-search-no-read-0o100":
        return [p_refused, p_refused, _refused_top(DENIED), _kind("P", "", DIR),
                _kind("P/f.md", "P", reason=DENIED), _kind("P/C", "P", reason=DENIED),
                _kind("P/C/x.md", "P/C", FILE), _kind("C", "", reason=DENIED),
                _entries("P", reason=DENIED), _entries("P/C", {"x.md": FILE})]
    if case == "nested-C-0o000":
        rows = {n: k for n, k in FULL_PERMISSION_ROWS.items() if n != "P/C/x.md"}
        return [_tree(rows, {"P/C": DENIED}), _tree(rows, {"P/C": DENIED}),
                _tree({"C": DIR, "C2": DIR, "C2/y.md": FILE, "f.md": FILE}, {"C": DENIED}),
                _kind("P", "", DIR), _kind("P/f.md", "P", FILE), _kind("P/C", "P", DIR),
                _kind("P/C/x.md", "P/C", reason=DENIED), _kind("C", "", DIR),
                _entries("P", {"C": DIR, "C2": DIR, "f.md": FILE}),
                _entries("P/C", reason=DENIED)]
    assert case == "control-P-0o500", case
    return [_tree(FULL_PERMISSION_ROWS), _tree(FULL_PERMISSION_ROWS),
            _tree({"C": DIR, "C/x.md": FILE, "C2": DIR, "C2/y.md": FILE, "f.md": FILE}),
            _kind("P", "", DIR), _kind("P/f.md", "P", FILE), _kind("P/C", "P", DIR),
            _kind("P/C/x.md", "P/C", FILE), _kind("C", "", DIR),
            _entries("P", {"C": DIR, "C2": DIR, "f.md": FILE}), _entries("P/C", {"x.md": FILE})]


def owners_and_modes(top: Path) -> dict[str, Any]:
    """Each entry under `top` that this process can see: its permission bits, owner and group,
    judged through descriptors (`os.fwalk` opens each folder no-follow; each entry is stat-ed
    off its folder's descriptor without following it), so a name swapped for a link mid-scan is
    never followed. Run while a folder is unreadable, it is partial but the same both times; a
    helper that "healed" a folder by `chmod`, or made anything, changes it."""
    out: dict[str, Any] = {}
    for dirpath, dirnames, filenames, dirfd in os.fwalk(top, follow_symlinks=False):
        for entry in (".", *dirnames, *filenames):
            rel = os.path.normpath(os.path.relpath(os.path.join(dirpath, entry), top))
            try:
                st = os.stat(entry, dir_fd=dirfd, follow_symlinks=False)
            except OSError as e:
                out[rel] = ("unseen", e.errno)
                continue
            out[rel] = (st.st_mode, st.st_uid, st.st_gid, st.st_size)
    return out


@pytest.mark.parametrize("case", list(PERMISSION_CASES))
def test_finding_5_a_real_permission_bit_refuses_that_folder_in_both_helpers(tmp_path, case):
    """v2 finding #5 (kind raised where walk said "unlisted"), through REAL permission bits:
    unprivileged and owning the tree (in-process on CI; as root, in a child that drops to
    uid/gid 65534 itself — never skipped). P with no access, or read but no search: the root's
    listing still says P is `"dir"`, and `entry_kind(P)` agrees, while `list_tree` reports P in
    `refused` with `Permission denied` (its own listing reopens `.` through P, which needs
    search) and the rest of the tree listed; `entry_kind` of anything in P or below is refused
    with that same reason, as is `under("P")`'s top. P with search but no read: P is refused
    the same way, yet `entry_kind(P/C/x.md)` answers `"file"`, from P/C's own listing (each call
    lists one folder; nothing is claimed about what `list_tree` never listed). C (below P) with
    no access: only C is refused, its siblings listed. Each row is also exactly what that
    folder's own `entries()` answers. Neither helper changes a mode or makes anything. Control:
    P readable and searchable (0o500), everything is listed.

    The mode is set through a no-follow descriptor while the tree is still this process's own
    (before `hand_over`), and put back by `owned_tree` through `fwalk`'s descriptors: as root,
    nothing in a tree `NOBODY` owns is changed by path (#1140 review finding 10)."""
    folder, mode = PERMISSION_CASES[case]
    with owned_tree(tmp_path) as root:
        for rel in PERMISSION_FILES:
            put_plain(root / rel)
        set_mode(root, folder, mode)
        hand_over(root)
        before = owners_and_modes(root)
        rows = run_unprivileged(_permission_scenarios(root))
        after = owners_and_modes(root)
    for row in rows:
        assert "raised" not in row, f"a helper raised: {row}"
    assert rows == _permission_answers(case), rows
    assert after == before, "a helper changed a mode, an owner or the tree"


@pytest.mark.parametrize("modes", [{"P": 0o000}, {"P": 0o100}, {"P": 0o200},
                                   {"P/C": 0o000, "P": 0o300}],
                         ids=["P-0o000", "P-0o100", "P-0o200", "P-C-0o000-P-0o300"])
def test_owned_tree_puts_every_mode_back_and_removes_the_tree(tmp_path, modes):
    """#1140 review finding 12: whatever modes the body leaves (an unreadable, unsearchable or
    write-only folder, nested ones), leaving `owned_tree` removes the whole tree, handed over
    or not, as root or not. Control: inside the body the tree exists with those modes."""
    with owned_tree(tmp_path) as root:
        top = root.parent
        for rel in ("P/C/x.md", "P/f.md", "top.md"):
            put_plain(root / rel)
        for rel, mode in sorted(modes.items(), key=lambda m: -m[0].count("/")):
            set_mode(root, rel, mode)
        hand_over(root)
        st = os.stat(root / "P", follow_symlinks=False)
        assert stat.S_IMODE(st.st_mode) == modes["P"], oct(st.st_mode)
    assert not os.path.lexists(top), f"owned_tree left {sorted(os.listdir(top))} behind"


# =======================================================================================
# Finding #2: a folder swapped after its parent was listed
# =======================================================================================

def _swap_tree(base: Path, site: str) -> Path:
    """`sub` (holding `inner.md` and `deeper/d.md`) under `base` or `base/a`, with siblings
    listed before and after it. Answers the folder holding `sub`."""
    parent = base / "a" if site == "nested" else base
    put_plain(parent / "sub" / "inner.md")
    put_plain(parent / "sub" / "deeper" / "d.md")
    put_plain(base / "aaa" / "a1.md")
    put_plain(base / "zzz" / "z.md")
    put_plain(base / "top.md")
    if site == "nested":
        put_plain(base / "a" / "peer" / "p.md")
    return parent


def _swap_rows(site: str, *, with_sub: bool) -> dict[str, str]:
    sub = "a/sub" if site == "nested" else "sub"
    rows = {"a": DIR, "a/peer": DIR, "a/peer/p.md": FILE} if site == "nested" else {}
    rows[sub] = DIR
    if with_sub:
        rows.update({f"{sub}/deeper": DIR, f"{sub}/deeper/d.md": FILE, f"{sub}/inner.md": FILE})
    rows.update({"aaa": DIR, "aaa/a1.md": FILE, "top.md": FILE, "zzz": DIR, "zzz/z.md": FILE})
    return dict(sorted(rows.items(), key=lambda r: tuple(r[0].split("/"))))


#: What the swapped folder's own listing answers, by what was left at its name.
SWAP_ANSWER = {"file": ("refused", NOT_A_DIR), "fifo": ("refused", NOT_A_DIR),
               "symlink": ("refused", ALIAS), "nothing": ("gone", None)}


@pytest.mark.parametrize("how", VIEWS)
@pytest.mark.parametrize("site", ["top", "nested"])
@pytest.mark.parametrize("plant", SWAP_PLANTS)
def test_finding_2_a_folder_moved_away_after_its_parents_listing_is_refused_or_gone(
        scratch, plant, site, how):
    """v2 finding #2 (a folder swapped after being listed was kept as an empty `"dir"`), with a
    REAL change on disk: the moment `list_tree` first steps into the non-empty folder `sub`
    (after its parent's listing named it `"dir"`), the folder is renamed out of the tree and a
    plain file, a FIFO, a symlink TO the moved folder, or nothing is left at its name. `sub`'s
    own listing then answers for what stands there: a file or FIFO `refused[sub] == Not a
    directory`, the symlink `refused[sub] ==` the alias sentence, nothing `sub in gone`. Its
    `"dir"` row stays; nothing of the moved folder (`inner.md`, `deeper/`) is listed under any
    name; every other folder is listed. After it, `entry_kind` below `sub` answers the same
    refusal or absence. #9: nothing is re-created at `sub`'s name, and the moved folder is
    untouched. Control: the same tree with no swap is listed whole."""
    base = base_of(how, scratch)
    parent = _swap_tree(base, site)
    sub = "a/sub" if site == "nested" else "sub"
    away = scratch.tmp / "moved-away"
    moved = census(parent / "sub")
    seam = SwapsOnStep(parent, "sub", away=away, plant=plant)
    with view_of(how, scratch, seam) as view:
        got = in_time(lambda: list_tree(view, 4), fifo=parent / "sub" if plant == "fifo" else None)
    assert seam.fired, "list_tree never stepped into sub, so the swap never happened"

    outcome, reason = SWAP_ANSWER[plant]
    if outcome == "refused":
        assert_tree(got, _swap_rows(site, with_sub=False), refused={sub: reason})
    else:
        assert_tree(got, _swap_rows(site, with_sub=False), gone=(sub,))
    assert census(away) == moved, "the moved folder changed"
    at = parent / "sub"
    if plant == "nothing":
        assert not os.path.lexists(at), "a read-only listing re-created the moved folder"
    elif plant == "file":
        assert not at.is_symlink()
        assert at.read_bytes() == HOST_BYTES
    elif plant == "fifo":
        assert stat.S_ISFIFO(os.lstat(at).st_mode)
    else:
        assert os.readlink(at) == str(away)
    with view_of(how, scratch) as still:
        after = entry_kind(still, f"{sub}/inner.md")
    if outcome == "refused":
        assert_kind(after, name=f"{sub}/inner.md", folder=sub, reason=reason)
    else:
        assert_kind(after, name=f"{sub}/inner.md", folder=sub, absent=True)


@pytest.mark.parametrize("how", VIEWS)
@pytest.mark.parametrize("site", ["top", "nested"])
def test_finding_2_control_the_same_tree_unswapped_is_listed_whole(scratch, site, how):
    """The swap rows' positive control: no swap, the same tree and depth list `sub` with
    everything in it, nothing refused or gone."""
    _swap_tree(base_of(how, scratch), site)
    with view_of(how, scratch, RealOs()) as view:
        got = list_tree(view, 4)
    assert_tree(got, _swap_rows(site, with_sub=True))


# =======================================================================================
# Addendum 3, D2: a folder REALLY removed during its own listing is absent, never empty
# =======================================================================================

def _d2_tree(base: Path) -> None:
    """`sub` (two entries, one a folder), a live empty folder `empty`, and a sibling `peer`."""
    put_plain(base / "sub" / "inner.md")
    put_plain(base / "sub" / "deeper" / "d.md")
    put_plain(base / "peer" / "p.md")
    (base / "empty").mkdir()


@pytest.mark.parametrize("how", VIEWS)
@pytest.mark.parametrize("moment", REMOVAL_MOMENTS)
def test_d2_a_folder_removed_during_its_own_listing_is_absent_to_entries(scratch, moment, how):
    """Addendum 3, D2, through `entries()` itself: `sub` is REALLY removed (`shutil.rmtree`)
    after the step into it succeeded, at each moment of its own listing: before the `"."`
    reopen, between the reopen and the scan, or after the scan handed back its first entry.
    The kernel lets the reopen of the dead folder succeed and the C library ends its listing
    early (or hands back what it had buffered); `view.under("sub").entries()` still answers
    ABSENT (`absent`, no reason, no entries), never present-and-empty, never the stale names.

    Controls on the same view: before the removal `sub` lists its two entries; through the
    same seam, the sibling `peer` (never removed) lists its file and the live EMPTY folder
    `empty` is present with `{}`, never absent."""
    base = base_of(how, scratch)
    _d2_tree(base)
    with view_of(how, scratch, RealOs()) as view:
        before = view.under("sub").entries()
    assert (before.absent, before.reason, before.entries) == (
        False, None, {"deeper": DIR, "inner.md": FILE}), before

    seam = ListingFaults(remove={"sub"}, moment=moment)
    with view_of(how, scratch, seam) as view:
        got = view.under("sub").entries()
        peer, empty = view.under("peer").entries(), view.under("empty").entries()
    assert seam.removed == [os.path.realpath(base / "sub")], seam.removed
    assert not os.path.lexists(base / "sub"), "the seam did not remove sub"
    assert (got.absent, got.reason, got.entries) == (True, None, None), (
        f"a folder removed {moment} answered {got!r}, not absent")
    assert (peer.absent, peer.reason, peer.entries) == (False, None, {"p.md": FILE}), peer
    assert (empty.absent, empty.reason, empty.entries) == (False, None, {}), (
        f"a live empty folder answered {empty!r}, not present and empty")
    assert descriptors_under(scratch.tmp) == []


@pytest.mark.parametrize("how", VIEWS)
@pytest.mark.parametrize("site", ["top", "nested"])
@pytest.mark.parametrize("moment", REMOVAL_MOMENTS)
def test_d2_a_folder_removed_after_its_parents_listing_is_gone_never_an_empty_dir(
        scratch, moment, site, how):
    """#1140 review finding 2, for real: `list_tree(depth=4)` lists the tree and, once its
    parent's listing has named the non-empty `sub` a `"dir"`, `sub` is REALLY removed after
    the step into it, at each moment of its own listing. `sub` is in `gone` (its `"dir"` row
    stays), nothing of it is listed, nothing is refused, every other folder is listed whole;
    never an empty `"dir"` that is neither listed, refused nor gone. Afterwards `entry_kind`
    below it is absent. Control: the same tree through the same view kind, with no removal,
    is listed whole, `sub` with everything in it."""
    base = base_of(how, scratch)
    parent = _swap_tree(base, site)
    sub = "a/sub" if site == "nested" else "sub"
    with view_of(how, scratch, RealOs()) as view:
        assert_tree(list_tree(view, 4), _swap_rows(site, with_sub=True))

    seam = ListingFaults(remove={"sub"}, moment=moment)
    with view_of(how, scratch, seam) as view:
        got = list_tree(view, 4)
        after = entry_kind(view, f"{sub}/inner.md")
    assert seam.removed == [os.path.realpath(parent / "sub")], seam.removed
    assert_tree(got, _swap_rows(site, with_sub=False), gone=(sub,))
    assert_kind(after, name=f"{sub}/inner.md", folder=sub, absent=True)
    assert not os.path.lexists(parent / "sub"), "a read-only listing re-created sub"


@pytest.mark.parametrize("how", VIEWS)
def test_d2_a_live_folder_whose_filesystem_counts_one_link_is_still_present(scratch, how):
    """A dead folder is one with NO link left (`st_nlink == 0`), not one with fewer than two:
    a filesystem such as btrfs counts 1 for every live directory, whatever it holds. Through
    a seam whose `fstat` of a reopened (listed) folder's descriptor reports 1 link, `entries()`
    of a full and of an empty live folder are present (`{"x.md": "file"}`, `{}`), and
    `list_tree` lists the tree whole. Non-vacuity: each listing asked that `fstat` once its
    scan was done. Control: the same seam reporting 0 links on the same live folders makes them
    absent, so the count is what decides."""
    base = base_of(how, scratch)
    put_plain(base / "full" / "x.md")
    (base / "empty").mkdir()
    one = ReportsLinks(1, 1)
    with view_of(how, scratch, one) as view:
        full, empty = view.under("full").entries(), view.under("empty").entries()
        tree = list_tree(view, 3)
    assert (full.absent, full.reason, full.entries) == (False, None, {"x.md": FILE}), full
    assert (empty.absent, empty.reason, empty.entries) == (False, None, {}), empty
    assert_tree(tree, {"empty": DIR, "full": DIR, "full/x.md": FILE})
    assert one.asked_after >= 5, (
        f"the listings asked fstat of their folder after its scan {one.asked_after} times")

    zero = ReportsLinks(0, 0)
    with view_of(how, scratch, zero) as view:
        full, empty = view.under("full").entries(), view.under("empty").entries()
    assert (full.absent, full.entries, empty.absent, empty.entries) == (
        True, None, True, None), (full, empty)


@pytest.mark.parametrize("how", VIEWS)
@pytest.mark.parametrize("flip", ["dies-at-scan-end", "lives-at-scan-end"])
def test_d2_the_folder_is_judged_by_its_link_count_once_its_scan_is_done(scratch, flip, how):
    """Round 3 (adversary H2): the judgement is the link count AFTER the scan, and nothing
    else. Through a seam whose `fstat` of a listed folder's descriptor reports the real count
    until that descriptor's scan is exhausted and 0 after it, the folder is absent (a check made
    before or during the scan, or by any other mark, would call it present); the mirror (0 until
    the scan is done, the real count after) is present with its entries (a check made before the
    scan would call it absent). Both through `entries()` and through `list_tree` (`gone`, or
    listed whole)."""
    base = base_of(how, scratch)
    put_plain(base / "sub" / "x.md")
    (base / "sub" / "empty").mkdir()
    seam = ReportsLinks(None, 0) if flip == "dies-at-scan-end" else ReportsLinks(0, None)
    with view_of(how, scratch, seam) as view:
        got = view.under("sub").entries()
        tree = list_tree(view, 2)
    assert seam.asked_after, "no listing asked fstat after its scan; the row is void"
    if flip == "dies-at-scan-end":
        assert (got.absent, got.reason, got.entries) == (True, None, None), got
        assert_tree_absent(tree)
    else:
        assert (got.absent, got.reason, got.entries) == (
            False, None, {"empty": DIR, "x.md": FILE}), got
        assert_tree(tree, {"sub": DIR, "sub/empty": DIR, "sub/x.md": FILE})


@pytest.mark.parametrize("how", VIEWS)
def test_d2_a_live_folder_named_like_a_deleted_one_is_present(scratch, how):
    """Round 3 (adversary H2): `/proc` spells a removed folder's descriptor with a
    `" (deleted)"` suffix, but no name is a dead mark: live folders named `notes (deleted)`
    (holding a file) and `empty (deleted)` are present to their own `entries()`, listed by
    `list_tree` with what they hold, never `gone`, and `entry_kind` of the file is `"file"`."""
    base = base_of(how, scratch)
    put_plain(base / "notes (deleted)" / "x.md")
    (base / "empty (deleted)").mkdir()
    with view_of(how, scratch) as view:
        notes = view.under("notes (deleted)").entries()
        empty = view.under("empty (deleted)").entries()
        tree = list_tree(view, 2)
        kind = entry_kind(view, "notes (deleted)/x.md")
    assert (notes.absent, notes.reason, notes.entries) == (False, None, {"x.md": FILE}), notes
    assert (empty.absent, empty.reason, empty.entries) == (False, None, {}), empty
    assert_tree(tree, {"empty (deleted)": DIR, "notes (deleted)": DIR,
                       "notes (deleted)/x.md": FILE})
    assert_kind(kind, name="notes (deleted)/x.md", folder="notes (deleted)", kind=FILE)


#: Trees `list_tree` must answer at once whatever its depth: once a level holds no folder,
#: nothing below it remains to list (#1140 review finding 5).
HUGE_DEPTHS = [sys.maxsize, 10**12]
#: A chain deeper than any depth another row asks for (each level re-walks from the root, so
#: listing it costs about CHAIN_DEPTH**2 / 2 steps: well under a second).
CHAIN_DEPTH = 100


def test_list_tree_stops_once_a_level_is_empty_whatever_the_depth(tmp_path):
    """#1140 review finding 5: `list_tree` stops at the first level that holds no folder to
    list, so a huge depth (`sys.maxsize`, the repo's own "no limit" sentinel, or `10**12`) on
    a flat folder, a three-level tree, an empty folder or a chain `CHAIN_DEPTH` folders deep
    answers exactly what the tree's own depth answers, promptly: in a child interpreter killed
    after 20 s (the worker never spins). The chain is deeper than any other row's depth, so a
    silent cap on the depth shows (round 3, adversary H1): its leaf is listed. Control: the
    same scenarios at the trees' own depth, in the same child."""
    flat, deep, empty = tmp_path / "flat", tmp_path / "deep", tmp_path / "empty"
    chain = tmp_path / "chain"
    chain.mkdir()
    build_chain(chain, CHAIN_DEPTH, "leaf.md")
    for rel in ("a.md", "b.md"):
        put_plain(flat / rel)
    for rel in ("x.md", "a/y.md", "a/b/z.md"):
        put_plain(deep / rel)
    empty.mkdir()
    trees = {str(flat): 1, str(deep): 3, str(empty): 1, str(chain): CHAIN_DEPTH + 1}
    scenarios = [{"root": root, "op": "list_tree", "depth": depth}
                 for root, own in trees.items() for depth in (own, *HUGE_DEPTHS)]
    started = time.monotonic()
    rows = run_child({"mode": "plain", "scenarios": scenarios}, deadline=20.0)["rows"]
    took = time.monotonic() - started
    by_root: dict[str, list[Any]] = collections.defaultdict(list)
    for scenario, row in zip(scenarios, rows, strict=True):
        assert "raised" not in row, f"list_tree raised: {scenario} -> {row}"
        by_root[scenario["root"]].append(row)
    for root, answers in by_root.items():
        assert all(a == answers[0] for a in answers), f"{root}: {answers}"
    assert [r[0] for r in by_root[str(deep)][0]["entries"]] == [
        "a", "a/b", "a/b/z.md", "a/y.md", "x.md"], by_root[str(deep)][0]
    assert by_root[str(empty)][0]["entries"] == [], by_root[str(empty)][0]
    leaf = "/".join(["d"] * CHAIN_DEPTH + ["leaf.md"])
    assert [leaf, "file"] in by_root[str(chain)][0]["entries"], "the chain's leaf is not listed"
    assert len(by_root[str(chain)][0]["entries"]) == CHAIN_DEPTH + 1
    assert took < 20.0, took


STRESS_NAMES = frozenset({"top.md", "box", "box/inner.md", "box/deep", "box/deep/x.md"})


def _flag_violations(got: Any, depth: int) -> list[str]:
    """Refused and gone: disjoint, each a dir row above the last level with nothing listed
    below it, and refused only for what a swap can cause."""
    rows, out = got.entries, []
    flagged = set(got.refused) | set(got.gone)
    if set(got.refused) & set(got.gone):
        out.append(f"both refused and gone: {sorted(set(got.refused) & set(got.gone))}")
    for name in flagged:
        if rows.get(name) != DIR or level(name) >= depth:
            out.append(f"{name} is refused or gone but not a dir row above the last level")
        if any(n.startswith(name + "/") for n in rows):
            out.append(f"{name} is refused or gone, yet rows below it are listed")
    out += [f"a refusal no swap can cause: {r!r}" for r in got.refused.values()
            if r not in (NOT_A_DIR, ALIAS)]
    return out


def _listed_violations(got: Any, depth: int) -> list[str]:
    """Every row hangs under a listed dir row; a listed `box` / `box/deep` has its own rows."""
    rows, out = got.entries, []
    flagged = set(got.refused) | set(got.gone)
    for name in rows:
        up = parent_of(name)
        if up and (rows.get(up) != DIR or up in flagged):
            out.append(f"{name} is listed under {up!r}, which is not a listed dir row")
    own = {"box": {"box/inner.md", "box/deep"}, "box/deep": {"box/deep/x.md"}}
    for name in (n for n, k in rows.items() if k == DIR and level(n) < depth and n not in flagged):
        missing = own.get(name, set()) - set(rows)
        if missing:
            out.append(f"{name} was listed but its rows {sorted(missing)} are missing (a "
                       "silently empty dir)")
    return out


def stress_violations(got: Any, depth: int) -> list[str]:
    """What breaks the listing invariant in one `list_tree` over the swapped `box` tree."""
    if (got.absent, got.reason) != (False, None) or type(got.entries) is not dict:
        return [f"the top was not listed: {got!r}"]
    rows, out = got.entries, []
    if not set(rows) <= STRESS_NAMES:
        out.append(f"names that never stood at those paths: {sorted(set(rows) - STRESS_NAMES)}")
    if rows.get("top.md") != FILE:
        out.append("top.md is not a file row")
    if list(rows) != parts_order(list(rows)):
        out.append(f"not in path-parts order: {list(rows)}")
    return out + _flag_violations(got, depth) + _listed_violations(got, depth)


@pytest.mark.parametrize("how", BINDERS)
def test_finding_2_a_writer_thread_swapping_a_folder_never_breaks_the_listing_invariant(
        scratch, how):
    """A real writer thread renames the non-empty `box` out of the tree and back, over and
    over, leaving a file, a FIFO, a symlink to it, or nothing at its name in between, while
    `list_tree(depth=3)` runs again and again (bounded by a deadline, never by an outcome).
    EVERY answer keeps the invariant: the top is listed; every `"dir"` row above the last level
    is listed XOR refused (`Not a directory` / the alias sentence, nothing else) XOR gone; nothing
    is listed below a refused or gone folder or under a row that is not a listed dir; a listed
    `box` (or `box/deep`) always has its own rows (the folder is never empty, so an empty
    listing would be a silent one); no name appears that never stood at that path. Afterwards
    the tree is as it was (#9: nothing was made)."""
    put_plain(scratch.root / "top.md")
    box = scratch.root / "box"
    put_plain(box / "inner.md")
    put_plain(box / "deep" / "x.md")
    away = scratch.tmp / "away"
    before = census(scratch.tmp)
    stop = threading.Event()
    failures: list[BaseException] = []
    swaps = [0]

    def writer() -> None:
        try:
            while not stop.is_set():
                plant = SWAP_PLANTS[swaps[0] % len(SWAP_PLANTS)]
                os.rename(box, away)
                if plant == "file":
                    box.write_bytes(HOST_BYTES)
                elif plant == "fifo":
                    os.mkfifo(box)
                elif plant == "symlink":
                    box.symlink_to(away, target_is_directory=True)
                time.sleep(0)
                if plant != "nothing":
                    os.unlink(box)
                os.rename(away, box)
                swaps[0] += 1
        except BaseException as e:  # noqa: BLE001 — reported by the test thread
            failures.append(e)

    thread = threading.Thread(target=writer, daemon=True)
    outcomes: collections.Counter[str] = collections.Counter()
    with opened(how, scratch.root) as view:
        thread.start()
        try:
            give_up = time.monotonic() + 1.5
            while time.monotonic() < give_up and outcomes.total() < 600:
                got = list_tree(view, 3)
                broken = stress_violations(got, 3)
                assert not broken, f"after {outcomes.total()} listings, {got!r}: {broken}"
                outcomes[repr((got.entries.get("box"), sorted(got.refused), got.gone))] += 1
        finally:
            stop.set()
            thread.join(5 * 3.0)
    assert not thread.is_alive(), "the writer thread never stopped"
    assert not failures, f"the writer thread failed: {failures!r}"
    assert swaps[0] > 0, "the writer thread never swapped"
    assert outcomes.total() > 0, "no listing ran"
    assert census(scratch.tmp) == before, "the tree changed beyond the writer's own swaps"


# =======================================================================================
# Finding #8: any errno on any route of a sub-folder's listing
# =======================================================================================

def _errno_tree(root: Path) -> None:
    for rel in ("aaa/a1.md", "sub/inner.md", "sub/below/b.md", "zzz/z.md", "top.md"):
        put_plain(root / rel)


ERRNO_REST = {"aaa": DIR, "aaa/a1.md": FILE, "sub": DIR, "top.md": FILE, "zzz": DIR,
              "zzz/z.md": FILE}
ERRNO_WHOLE = {"aaa": DIR, "aaa/a1.md": FILE, "sub": DIR, "sub/below": DIR,
               "sub/below/b.md": FILE, "sub/inner.md": FILE, "top.md": FILE, "zzz": DIR,
               "zzz/z.md": FILE}

def _drivable(route: str, err: int) -> bool:
    """Whether an injected `err` on `route` models something the kernel and CPython can
    actually produce. ENOENT is the step's alone (the folder's name is gone when it is stepped
    into): reopening `"."` off a removed folder's handle succeeds; `os.scandir` of a descriptor
    makes no `getdents` call; the C library reads `getdents`' ENOENT on a removed folder as the
    end of the listing; and `DirEntry`'s type questions answer from `d_type`, or catch
    `FileNotFoundError` and answer False (#1140 review finding 11). What a removal at those
    moments really does is driven for real by the `test_d2_*` rows (`ListingFaults`)."""
    return err != errno.ENOENT or route == "step"


#: What `sub`'s own listing answers for a fault on each route, by name: `"gone"` or the reason.
#: The step and the reopen are judged by `_read_reason` (ELOOP / EMLINK the alias sentence) and
#: ENOENT at the step is absent; a fault while reading the listing is the error's own words.
NAMED_LISTING_FAULTS = [
    *[pytest.param(route, code, want, id=f"{route}-{errno.errorcode[code]}")
      for route in ("step", "reopen")
      for code, want in ((errno.ENOENT, "gone"), (errno.ELOOP, ALIAS), (errno.EMLINK, ALIAS),
                         (errno.ENOTDIR, NOT_A_DIR), (errno.EACCES, DENIED),
                         (errno.EIO, os.strerror(errno.EIO)))
      if _drivable(route, code)],
    *[pytest.param(route, code, want, id=f"{route}-{errno.errorcode[code]}")
      for route in ("scandir", "midway", "entry", "fstat")
      for code, want in ((errno.ELOOP, os.strerror(errno.ELOOP)),
                         (errno.ENOTDIR, NOT_A_DIR), (errno.EACCES, DENIED),
                         (errno.EIO, os.strerror(errno.EIO)))],
]


def _check_sub_answer(got: Any, oracle: Any) -> list[str]:
    """`got` reports `sub` as its own listing (`oracle`) answered, the rest listed."""
    out = []
    if oracle.absent:
        if got.gone != ("sub",) or got.refused != {}:
            out.append(f"sub's listing answered absent, but refused={got.refused} gone={got.gone}")
    elif oracle.reason is None:
        out.append(f"the seam did not refuse sub's listing: {oracle!r}")
    elif got.refused != {"sub": oracle.reason} or got.gone != ():
        out.append(f"sub's listing answered {oracle.reason!r}, but refused={got.refused} "
                   f"gone={got.gone}")
    if (got.absent, got.reason) != (False, None) or got.entries != ERRNO_REST:
        out.append(f"the rest was not listed exactly: {got.entries}")
    return out


@pytest.mark.parametrize("how", BINDERS)
@pytest.mark.parametrize(("route", "err", "want"), NAMED_LISTING_FAULTS)
def test_finding_8_a_fault_on_any_route_of_a_sub_folders_listing_is_that_folders_answer(
        scratch, route, err, want, how):
    """v2 finding #8 (subtree-hiding errnos below were unpinned): a fault injected while
    listing `sub` (stepping into it, reopening it, scanning it, partway through, judging an
    entry) is reported exactly as `view.under("sub").entries()` answers that fault:
    `refused["sub"]` is its reason, verbatim, or `sub` is `gone` when it answers absent (ENOENT
    at the step; `_drivable` says why ENOENT is driven nowhere else). Never a silently empty
    `"dir"`: the row stays and is flagged. Nothing below `sub` is listed or even opened; every
    other folder is listed. `entry_kind` below `sub` answers the same. Control: no fault, the
    whole tree is listed."""
    _errno_tree(scratch.root)
    seam = RefusesListing(route, "sub", err=err)
    with opened(how, scratch.root, seam) as view:
        got = list_tree(view, 3)
        below_touched = seam.touched("below")
        oracle = view.under("sub").entries()
        ek = entry_kind(view, "sub/inner.md")
    assert _check_sub_answer(got, oracle) == []
    if want == "gone":
        assert oracle.absent
        assert_tree(got, ERRNO_REST, gone=("sub",))
        assert_kind(ek, name="sub/inner.md", folder="sub", absent=True)
    else:
        assert oracle.reason == want
        assert_tree(got, ERRNO_REST, refused={"sub": want})
        assert_kind(ek, name="sub/inner.md", folder="sub", reason=want)
    assert not below_touched, f"list_tree went below the refused sub: {seam.seen}"

    with opened(how, scratch.root, RealOs()) as view:
        assert_tree(list_tree(view, 3), ERRNO_WHOLE)


@pytest.mark.parametrize("route", LISTING_ROUTES)
def test_finding_8_every_errno_on_every_route_is_the_folders_own_answer(scratch, route):
    """The whole errno table on each route of `sub`'s listing (but ENOENT off the step: see
    `_drivable`): every one is reported as `sub`'s own `entries()` answers it (refused with its
    reason, or gone when absent), the rest listed, nothing below `sub` touched, never a raise.
    Control: no fault, the whole tree is listed."""
    _errno_tree(scratch.root)
    broken = []
    for err in (e for e in sorted(errno.errorcode) if _drivable(route, e)):
        seam = RefusesListing(route, "sub", err=err)
        with _io.bind(scratch.root, os_=seam) as bound:
            try:
                got = list_tree(bound, 3)
            except Exception as e:  # noqa: BLE001 — a raise is itself the failure reported
                broken.append((errno.errorcode[err], f"raised {type(e).__name__}: {e}"))
                continue
            touched = seam.touched("below")
            oracle = bound.under("sub").entries()
        problems = _check_sub_answer(got, oracle) + (["went below sub"] if touched else [])
        if problems:
            broken.append((errno.errorcode[err], problems))
    assert not broken, f"route {route}: {broken}"
    with _io.bind(scratch.root) as bound:
        assert_tree(list_tree(bound, 3), ERRNO_WHOLE)


# =======================================================================================
# (b) The I/O is exactly the specified listings'
# =======================================================================================

def _seam_tree(base: Path) -> None:
    for rel in ("x.md", "a/x.md", "a/b/x.md"):
        put_plain(base / rel)
    (base / "linked").symlink_to(base / "a", target_is_directory=True)
    os.mkfifo(base / "ff")


#: Names whose `entry_kind` is compared with its folder's listing: present at several depths,
#: missing leaf, missing folder, linked folder, FIFO folder, a folder itself.
SEAM_NAMES = ["x.md", "a/x.md", "a/b/x.md", "a/b/missing.md", "missing/x.md", "linked/x.md",
              "ff/x.md", "a/b"]


@pytest.mark.parametrize("how", VIEWS)
@pytest.mark.parametrize("name", SEAM_NAMES)
def test_b_entry_kind_makes_exactly_the_io_of_its_one_listing(scratch, name, how):
    """Through a seam that logs every `os_` call (descriptors named by what they open), the
    calls `entry_kind(view, name)` makes EQUAL, in order, those of
    `view.under(<name's folder>).entries()` (`view.entries()` at the top): one listing, nothing
    before or after it, nothing opened beyond what it opens. Non-vacuity: that listing does go
    through the seam."""
    _seam_tree(base_of(how, scratch))
    folder = parent_of(name)
    log = OsCallLog()
    with view_of(how, scratch, log) as view:
        log.calls.clear()
        entry_kind(view, name)
        made = list(log.calls)
    log = OsCallLog()
    with view_of(how, scratch, log) as view:
        log.calls.clear()
        (view.under(folder) if folder else view).entries()
        specified = list(log.calls)
    assert specified, "the listing made no call through the seam; the check is void"
    assert made == specified, f"entry_kind's I/O\n  {made}\nis not its listing's\n  {specified}"


def list_tree_io(how: str, s: Scratch, depth: int, seam: Any = RealOs) -> tuple[Any, Any]:
    """`list_tree(view, depth)` through an `OsCallLog` over a fresh `seam()`: its answer, and
    its calls as a multiset."""
    log = OsCallLog(seam())
    with view_of(how, s, log) as view:
        log.calls.clear()
        got = list_tree(view, depth)
        return got, collections.Counter(log.calls)


def listings_io(how: str, s: Scratch, folders: list[str], seam: Any = RealOs) -> Any:
    """The calls of `view.under(f).entries()` (`view.entries()` for `""`) for each of
    `folders`, once each, through an `OsCallLog` over a fresh `seam()`, as one multiset."""
    specified: collections.Counter[tuple[Any, ...]] = collections.Counter()
    log = OsCallLog(seam())
    with view_of(how, s, log) as view:
        for folder in folders:
            log.calls.clear()
            (view.under(folder) if folder else view).entries()
            assert log.calls, f"listing {folder!r} made no call through the seam"
            specified.update(log.calls)
    return specified


def real_folders(base: Path, depth: int) -> list[str]:
    """The folders `list_tree(depth)` must list under `base`, judged on disk independently of
    the code under test: `""` (the top) and every real directory (never a link to one) at a
    level above `depth`."""
    out = [""]

    def walk(rel: str, at_level: int) -> None:
        for entry in os.scandir(base / rel if rel else base):
            if entry.is_dir(follow_symlinks=False) and at_level < depth:
                child = f"{rel}/{entry.name}" if rel else entry.name
                out.append(child)
                walk(child, at_level + 1)

    walk("", 1)
    return out


def assert_same_multiset(made: Any, specified: Any) -> None:
    assert made == specified, (
        f"list_tree's I/O differs from its listings': extra {made - specified}, "
        f"missing {specified - made}")


@pytest.mark.parametrize("how", VIEWS)
@pytest.mark.parametrize("depth", [1, 2, 3, 5])
def test_b_list_tree_makes_exactly_the_io_of_its_specified_listings_each_once(
        scratch, depth, how):
    """The `os_` calls `list_tree(view, depth=N)` makes equal, as a multiset, the union of the
    calls of the `entries()` listings it is specified to make: the top, and `under(f)` for each
    `"dir"` row `f` above level N, each exactly once (every folder's calls name its own
    descriptors, so a folder listed twice, a last-level folder listed, or any other call shows).
    Non-vacuity: each specified listing goes through the seam."""
    build_catalog(base_of(how, scratch))
    _got, made = list_tree_io(how, scratch, depth)
    folders = [""] + [n for n, k in to_depth(CATALOG_ROWS, depth).items()
                      if k == DIR and level(n) < depth]
    assert sorted(folders) == sorted(real_folders(base_of(how, scratch), depth))
    assert_same_multiset(made, listings_io(how, scratch, folders))


@pytest.mark.parametrize("how", VIEWS)
@pytest.mark.parametrize("depth", [2, 3, 4])
def test_b_list_tree_lists_a_refused_or_gone_folder_exactly_once_too(scratch, depth, how):
    """Round 2, H3: on a tree where every folder named `R` is refused (EACCES at its reopen)
    and every folder named `G` is gone (REALLY removed after the step into it, before its
    reopen; made again between the two runs compared), `list_tree`'s `os_` calls still equal,
    as a multiset, those of one `entries()` listing of each folder it is specified to list (the
    top and every real directory above the last level, judged on disk), refused and gone ones
    included: a refused or gone folder is listed exactly once, never asked again. Non-vacuity:
    at depth 3 and more, the refused and gone folders are among those listings and answered
    as such."""
    base = base_of(how, scratch)
    _mixed_tree(base, scratch)

    def faults() -> ListingFaults:
        return ListingFaults({"R": errno.EACCES}, remove={"G"})

    folders = real_folders(base, depth)
    got, made = list_tree_io(how, scratch, depth, faults)
    put_plain(base / "gather" / "G" / "g.md")
    assert_same_multiset(made, listings_io(how, scratch, folders, faults))
    if depth >= 3:
        assert {"gather/R", "gather/G"} <= set(folders), folders
        assert got.refused.get("gather/R") == DENIED, got
        assert "gather/G" in got.gone, got


@pytest.mark.parametrize("how", VIEWS)
def test_c_no_non_directory_entry_is_ever_handed_to_os_open(scratch, how):
    """Neither helper opens a file, hard link, FIFO, socket, symlink or dangling link, nor
    anything a link reaches: no such name is ever passed to `os_.open` (kinds come from the
    listing). Non-vacuity: the folders' names do reach `os_.open`."""
    base = base_of(how, scratch)
    box = base / "box"
    put_plain(box / "sub" / "deeper.md")
    put_plain(box / "file-e.md")
    for name, kind in (("fifo-e", "fifo"), ("sock-e", "socket"), ("hard-e", "hardlink"),
                       ("link-e", "symlink"), ("dangling-e", "dangling"),
                       ("dirlink-e", "dir_link_outside")):
        plant_entry(box / name, kind, root=scratch.root, host=scratch.host)
    log = OsCallLog()
    with view_of(how, scratch, log) as view:
        got = in_time(lambda: list_tree(view, 3), fifo=box / "fifo-e")
        for name in ("file-e.md", "fifo-e", "sock-e", "hard-e", "link-e", "dangling-e",
                     "dirlink-e", "sub/deeper.md"):
            in_time(lambda name=name: entry_kind(view, f"box/{name}"), fifo=box / "fifo-e")
    opened_names = [c[1][0] for c in log.calls if c[0] == "open" and c[1]]
    never = {"file-e.md", "fifo-e", "sock-e", "hard-e", "link-e", "dangling-e", "dirlink-e",
             "deeper.md", "inner.md"}
    assert not never & set(map(str, opened_names)), (
        f"a helper opened a non-directory entry: {sorted(never & set(map(str, opened_names)))}")
    assert {"box", "sub"} <= set(map(str, opened_names)), opened_names
    assert listed(got)["box/fifo-e"] == OTHER


@pytest.mark.parametrize("how", VIEWS)
def test_c_neither_helper_opens_a_fifo_at_a_leaf_or_at_a_holding_folder(scratch, how):
    """A FIFO at a leaf and a FIFO standing where a holding folder belongs are never opened to
    read: a writer parked in each FIFO's write open stays parked while `entry_kind` judges the
    leaf FIFO (`"other"`), the FIFO folder (`"other"`) and a name below it (refused, `Not a
    directory`), and `list_tree` lists the tree. Non-vacuity: opening each read end afterwards
    is what lets its writer go."""
    base = base_of(how, scratch)
    put_plain(base / "a" / "keep.md")
    put_plain(base / "top.md")
    os.mkfifo(base / "a" / "leaf-fifo")
    os.mkfifo(base / "ff")
    with view_of(how, scratch) as view, ParkedWriter(base / "a" / "leaf-fifo") as leaf, \
            ParkedWriter(base / "ff") as folder:
        kinds = [in_time(lambda n=n: entry_kind(view, n)) for n in ("a/leaf-fifo", "ff", "ff/x")]
        got = in_time(lambda: list_tree(view, 3))
        parked = (leaf.parked(), folder.parked())
        released = (leaf.release(), folder.release())
    assert parked == (True, True), f"a helper opened a FIFO to read (leaf, folder): {parked}"
    assert released == (True, True), "a writer never parked in its open; the check is void"
    assert_kind(kinds[0], name="a/leaf-fifo", folder="a", kind=OTHER)
    assert_kind(kinds[1], name="ff", folder="", kind=OTHER)
    assert_kind(kinds[2], name="ff/x", folder="ff", reason=NOT_A_DIR)
    assert_tree(got, {"a": DIR, "a/keep.md": FILE, "a/leaf-fifo": OTHER, "ff": OTHER,
                      "top.md": FILE})


#: The audited tree's entries that are not folders, and what its links reach: no audit event
#: during a helper call may name one.
AUDIT_NON_FOLDERS = frozenset({
    "f1.md", "pipe", "sock", "lnk", "dlnk", "hard", "f2.md", "pipe2", "f3.md", "f4.md",
    "link-target-of-lnk", "linked-dir-of-dlnk", "inner.md", "other-name-of-hard"})
#: The names whose `entry_kind` is audited: every kind at each depth, a folder, missing ones.
#: (None has a non-folder in a holding position: a name below a plant is the `ParkedWriter`
#: and plant rows' business.)
AUDIT_NAMES = ("f1.md", "pipe", "sock", "lnk", "dlnk", "hard", "d1", "missing.md", "d1/f2.md",
               "d1/pipe2", "d1/d2", "d1/missing/x.md", "d1/d2/f3.md", "d1/d2/d3/f4.md")


def _audit_tree(base: Path, s: Scratch) -> None:
    for rel in ("f1.md", "d1/f2.md", "d1/d2/f3.md", "d1/d2/d3/f4.md"):
        put_plain(base / rel)
    os.mkfifo(base / "pipe")
    os.mkfifo(base / "d1" / "pipe2")
    for name, kind in (("sock", "socket"), ("lnk", "symlink"), ("dlnk", "dir_link_outside"),
                       ("hard", "hardlink")):
        plant_entry(base / name, kind, root=s.root, host=s.host)


def audit_violations(events: list[list[Any]]) -> list[str]:
    """What in one helper call's audit events is not a listing's I/O. Allowed: an `open` of
    one folder component as an `O_PATH | O_NOFOLLOW` handle (a step), an `open` of `"."`
    `O_RDONLY | O_DIRECTORY` (the reopen for listing), and an `os.scandir` of a descriptor.
    Nothing else, and no event naming a non-folder entry (or what a link reaches)."""
    out = []
    for name, args in events:
        if name == "os.scandir":
            if not (len(args) == 1 and type(args[0]) is int):
                out.append(f"os.scandir of {args!r}, not of a descriptor")
        elif name == "open":
            path, _mode, flags = args
            reopen = (path == "." and type(flags) is int and bool(flags & os.O_DIRECTORY)
                      and flags & os.O_ACCMODE == os.O_RDONLY and not flags & os.O_CREAT)
            step = (type(path) is str and "/" not in path and path not in ("", ".", "..")
                    and type(flags) is int and bool(flags & os.O_PATH)
                    and bool(flags & os.O_NOFOLLOW))
            if not (reopen or step):
                out.append(f"open of {path!r} with flags {flags!r}")
        else:
            out.append(f"the audit event {name} {args!r}")
        named = sorted(os.path.basename(a) for a in args
                       if type(a) is str and os.path.basename(a) in AUDIT_NON_FOLDERS)
        if named:
            out.append(f"{name} names a non-folder entry: {named}")
    return out


@pytest.mark.parametrize("how", VIEWS)
def test_c_an_audit_hook_sees_only_folder_steps_reopens_and_listings(scratch, how):
    """Round 2, H2, independent of the `os_` seam: a child interpreter installs an audit hook
    (never the test worker) and records every audit event raised during each helper call,
    whatever `os` the code reached (the seam, the real module through another module's
    import, a private handle). For `list_tree` at depths 1-4 and `entry_kind` of every kind of
    entry at each depth, every event is a folder step (`O_PATH | O_NOFOLLOW` open of one
    component), a `"."` reopen (`O_RDONLY | O_DIRECTORY`) or an `os.scandir` of a descriptor,
    and none names a file, FIFO, socket, link, hard link or link target. Non-vacuity, inside
    the same child: every helper call raised events, and `read` of a file through the same
    view, recorded the same way, is flagged as opening it."""
    base = base_of(how, scratch)
    _audit_tree(base, scratch)
    warm = scratch.tmp / "warm"
    put_plain(warm / "w" / "x.md")
    view = {"root": str(scratch.root), "how": how.removesuffix("-under"),
            "prefix": UNDER if how.endswith("-under") else None}
    scenarios = [*({**view, "op": "list_tree", "depth": d} for d in (1, 2, 3, 4)),
                 *({**view, "op": "entry_kind", "name": n} for n in AUDIT_NAMES),
                 {**view, "op": "read", "name": "f1.md"}]
    warmup = [{"root": str(warm), "how": view["how"], "op": op, **extra}
              for op, extra in (("list_tree", {"depth": 2}), ("entry_kind", {"name": "w/x.md"}),
                                ("read", {"name": "w/x.md"}))]
    rows = run_child({"mode": "audited", "scenarios": scenarios, "warmup": warmup})["rows"]

    *helper_rows, control = rows
    problems = {}
    for scenario, row in zip(scenarios[:-1], helper_rows, strict=True):
        what = f"{scenario['op']}({scenario.get('name', scenario.get('depth'))!r})"
        assert "raised" not in row["answer"], f"{what} raised in the child: {row['answer']}"
        assert row["events"], f"{what} raised no audit event; the hook saw nothing"
        if audit_violations(row["events"]):
            problems[what] = audit_violations(row["events"])
    assert not problems, f"a helper made I/O beyond its listings: {problems}"
    assert control["answer"]["text"] == PLAIN.decode(), control
    flagged = audit_violations(control["events"])
    assert any("'f1.md'" in problem for problem in flagged), (
        f"the hook did not catch read opening a file: {control['events']}")
    assert helper_rows[3]["answer"]["entries"] is not None, helper_rows[3]


# =======================================================================================
# (d) No descriptor outlives a call
# =======================================================================================

#: Each outcome a helper can answer, and the call that answers it.
FD_OUTCOMES = ("listed", "absent-top", "refused-top", "refused-sub", "gone-sub", "closed",
               "kind-present", "kind-absent", "kind-refused",
               *(f"refused-sub-{route}" for route in ("scandir", "midway", "entry", "fstat")),
               "removed-sub")


@pytest.mark.parametrize("outcome", FD_OUTCOMES)
def test_d_neither_helper_leaves_a_descriptor_open(scratch, outcome):
    """Whatever a helper answers (a listed tree; an absent or refused top; a refused or gone
    folder below; a closed root; a kind, an absence, a refusal), this process holds the same
    number of descriptors after the call as before it, and none on the tree once the view is
    closed. Non-vacuity: the scan sees the view's own handle while it is open."""
    build_catalog(scratch.root)
    (scratch.root / "linked").symlink_to(scratch.root / "gather", target_is_directory=True)
    os_ = {"refused-sub": RefusesListing("reopen", "queries", err=errno.EIO),
           "gone-sub": RefusesListing("step", "queries", err=errno.ENOENT),
           "removed-sub": ListingFaults(remove={"queries"}, moment="midway"),
           **{f"refused-sub-{route}": RefusesListing(route, "queries", err=errno.EIO)
              for route in ("scandir", "midway", "entry", "fstat")}}.get(outcome, os)
    bound = _io.bind(scratch.root, os_=os_)
    try:
        assert descriptors_under(scratch.tmp) == [os.path.realpath(scratch.root)]
        if outcome == "closed":
            bound.close()
        call = {
            "listed": lambda: list_tree(bound, 5),
            "absent-top": lambda: list_tree(bound.under("missing/deeper"), 3),
            "refused-top": lambda: list_tree(bound.under("linked/queries"), 3),
            "refused-sub": lambda: list_tree(bound, 4),
            "gone-sub": lambda: list_tree(bound, 4),
            "removed-sub": lambda: list_tree(bound, 4),
            **{f"refused-sub-{route}": lambda: list_tree(bound, 4)
               for route in ("scandir", "midway", "entry", "fstat")},
            "closed": lambda: list_tree(bound, 3),
            "kind-present": lambda: entry_kind(bound, "gather/queries/elastic/x.md"),
            "kind-absent": lambda: entry_kind(bound, "gather/missing/x.md"),
            "kind-refused": lambda: entry_kind(bound, "linked/queries"),
        }[outcome]
        count = open_fd_count()
        got = call()
        assert open_fd_count() == count, f"the {outcome} call changed the descriptor count"
    finally:
        bound.close()
    assert descriptors_under(scratch.tmp) == [], f"the {outcome} call left a descriptor open"
    if outcome.startswith("refused-sub"):
        assert got.refused == {"gather/queries": os.strerror(errno.EIO)}, got
    elif outcome in ("gone-sub", "removed-sub"):
        assert got.gone == ("gather/queries",)
    elif outcome == "kind-refused":
        assert got.reason == ALIAS


# =======================================================================================
# Finding #1: no descriptor chain
# =======================================================================================

#: Deeper than the default soft fd limit of a shell on this devcontainer (1024): a descriptor
#: per level cannot fit, under any limit a few descriptors above what the child holds. The
#: deepest path stays under PATH_MAX.
CHAIN = 1100


def test_finding_1_a_deep_chain_is_listed_to_its_depth_under_a_low_descriptor_limit(tmp_path):
    """v2 finding #1 (an unbounded walk held one descriptor per level and failed with EMFILE):
    an 1100-level chain `d/d/.../d/leaf.md`, read in a child interpreter whose soft
    `RLIMIT_NOFILE` is only `FD_MARGIN` descriptors above what it holds (it proves the limit
    bites: it cannot open even twice that many more). `list_tree(depth=3)` (bound and held)
    lists exactly three `"dir"` levels; `entry_kind` of the deep leaf answers `"file"` and of the
    deepest folder `"dir"`; a view under the 1099th folder lists the last two levels. No
    descriptor chain is held: each listing re-walks from the root, stepping one folder at a
    time."""
    base = tmp_path / "chain"
    base.mkdir()
    deep = "/".join(["d"] * CHAIN)
    above = "/".join(["d"] * (CHAIN - 1))
    try:
        build_chain(base, CHAIN, "leaf.md")
        answer = run_child({"mode": "low_fd_limit", "scenarios": [
            {"root": str(base), "op": "list_tree", "depth": 3},
            {"root": str(base), "how": "held", "op": "list_tree", "depth": 3},
            {"root": str(base), "op": "entry_kind", "name": f"{deep}/leaf.md"},
            {"root": str(base), "op": "entry_kind", "name": deep},
            {"root": str(base), "prefix": above, "op": "list_tree", "depth": 2},
        ]})
    finally:
        remove_chain(base, CHAIN, "leaf.md")
    assert answer["spare"] < 2 * FD_MARGIN, (
        f"the child's limit does not bite: it could open {answer['spare']} more descriptors")
    three = _tree({"d": DIR, "d/d": DIR, "d/d/d": DIR})
    assert answer["rows"] == [
        three, three,
        {"name": f"{deep}/leaf.md", "folder": deep, "kind": FILE, "absent": False,
         "reason": None},
        {"name": deep, "folder": above, "kind": DIR, "absent": False, "reason": None},
        _tree({"d": DIR, "d/leaf.md": FILE}),
    ], [str(row)[:300] for row in answer["rows"]]


# =======================================================================================
# Finding #14: a close landing mid-listing
# =======================================================================================

def _race_trees(tmp_path: Path) -> tuple[Path, Path]:
    trees = []
    for who in ("root", "decoy"):
        top = tmp_path / who
        put_plain(top / f"{who}-marker")
        put_plain(top / "fa" / f"{who}-only")
        trees.append(top)
    return trees[0], trees[1]


def test_finding_14_a_close_landing_mid_list_tree_never_lists_the_reused_number(tmp_path):
    """`close()` lands during `list_tree`'s first listing (fired through the `os_` seam at its
    first relative operation): it returns promptly and frees the root's number, which a DECOY
    folder of the same shape then takes. The top listing still answers the ROOT's names (it
    works off its own dup); every later folder's listing answers `Bad file descriptor`
    (`refused["fa"]`), never the decoy's `fa/decoy-only`. A later call answers the closed root's
    refusal; `entry_kind` too."""
    root, decoy = _race_trees(tmp_path)
    spy = S.OsSpy()
    held = S.hold(root, os_=spy)
    view = held.view()
    [root_fd] = S.open_fds_on(root)
    state: dict[str, Any] = {}

    def close_mid_listing(_op: str, _args: tuple, _kwargs: dict) -> None:
        spy.hook = None
        state["closed_promptly"] = S.run_in_thread(held.close, timeout=1.0)
        if state["closed_promptly"] and root_fd not in S.open_fds_on(root):
            fd = os.open(decoy, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            if fd != root_fd:
                os.dup2(fd, root_fd, inheritable=False)
                os.close(fd)
            state["decoy_on"] = root_fd

    spy.hook = close_mid_listing
    try:
        got = list_tree(view, 3)
        assert state.get("closed_promptly"), "close() did not land, or waited for the listing"
        assert "decoy_on" in state, "close() released nothing while the listing ran"
        assert_tree(got, {"fa": DIR, "root-marker": FILE}, refused={"fa": BAD_FD})
        assert_tree_refused(in_time(lambda: list_tree(view, 3)), BAD_FD)
        assert_kind(entry_kind(view, "fa/root-only"), name="fa/root-only", folder="fa",
                    reason=BAD_FD)
    finally:
        if "decoy_on" in state:
            os.close(state["decoy_on"])
        held.close()


# =======================================================================================
# Finding #9: write-free
# =======================================================================================

@pytest.mark.parametrize("how", VIEWS)
def test_finding_9_neither_helper_writes_or_creates_anything(scratch, how):
    """Neither helper writes: across every kind of answer (listed at every depth, a missing
    folder, a missing view folder, a plant at a holding folder, a FIFO, a refused sub-folder),
    the tree's census (content, modes, link counts, mtimes) is unchanged and no missing name is
    created. The logged `os_` calls hold no write: no `mkdir`, no `O_CREAT`, `O_WRONLY` or
    `O_RDWR` open, no unlink or rename."""
    base = base_of(how, scratch)
    build_catalog(base)
    (base / "linked").symlink_to(base / "gather", target_is_directory=True)
    os.mkfifo(base / "ff")
    before = census(scratch.tmp)
    log = OsCallLog()
    with view_of(how, scratch, log) as view:
        for depth in (1, 3, 6):
            list_tree(view, depth)
        list_tree(view.under("missing/deeper"), 2)
        list_tree(view.under("linked"), 2)
        for name in ("missing/x.md", "a/b/c/x.md", "linked/x.md", "ff/x.md", "ff",
                     "gather/queries/elastic/_draft/d1.md"):
            entry_kind(view, name)
    assert census(scratch.tmp) == before
    for missing in ("missing", "a"):
        assert not os.path.lexists(base / missing), f"a helper created {missing}"
    writes = os.O_CREAT | os.O_WRONLY | os.O_RDWR
    bad = [c for c in log.calls
           if c[0] in ("mkdir", "makedirs", "unlink", "rename", "replace", "rmdir", "remove",
                       "write", "symlink", "link", "mkfifo", "mknod", "chmod")
           or (c[0] == "open" and len(c[1]) > 1 and isinstance(c[1][1], int)
               and c[1][1] & writes)]
    assert not bad, f"a helper made a write call: {bad}"
    assert any(c[0] == "scandir" for c in log.calls), "the log saw no listing; the check is void"


# =======================================================================================
# Addendum 3, D2, through `entries()` alone (the move's adversary, 2026-10-03)
# =======================================================================================
#
# When B2's helpers moved to their first consumers, step 1 kept only `entries()`'s rows, and a
# scoped adversary greened them with dead checks that the helper rows had been catching for
# them. These rows pin each of those through `entries()` itself, on every step of the stack.

def _entries_state(got: Any) -> tuple[Any, ...]:
    return got.name, got.absent, got.reason, got.entries


@pytest.mark.parametrize("how", VIEWS)
def test_a3_a_live_folder_holding_a_folder_counted_one_link_is_present(scratch, how):
    """The dead mark is `st_nlink == 0` and nothing else: on a filesystem counting 1 link for
    every live directory (btrfs), a folder that HOLDS a folder is still present, and so is its
    parent (the classic `2 + subfolders` count would call both dead). Through a seam reporting
    1 link for every listed folder: `full` (holding `inner/` and `x.md`) lists both, the view's
    own folder lists `full`. Non-vacuity: each listing asked that `fstat` after its scan.
    Control: the same seam reporting 0 links makes `full` absent."""
    base = base_of(how, scratch)
    put_plain(base / "full" / "x.md")
    (base / "full" / "inner").mkdir()
    spelled = f"{UNDER}/full" if how.endswith("-under") else "full"
    one = ReportsLinks(1, 1)
    with view_of(how, scratch, one) as view:
        full, top = view.under("full").entries(), view.entries()
    assert _entries_state(full) == (spelled, False, None, {"inner": DIR, "x.md": FILE}), full
    assert (top.absent, top.reason, (top.entries or {}).get("full")) == (False, None, DIR), top
    assert one.asked_after >= 2, one.asked_after

    with view_of(how, scratch, ReportsLinks(0, 0)) as view:
        assert _entries_state(view.under("full").entries()) == (spelled, True, None, None)


@pytest.mark.parametrize("how", BINDERS)
@pytest.mark.parametrize("folder", ["empty", "full", ""], ids=["empty", "full", "the-root"])
def test_a3_a_fault_on_the_dead_checks_fstat_is_a_refusal_for_any_folder(scratch, folder, how):
    """The `fstat` route faulted (EIO) on an EMPTY folder, a full one, and the view's own folder
    (the root): each is that folder's own refusal, named as the caller spelled it, with the
    errno's words; never absent, never present (an empty listing is no excuse to skip the
    check, and the root is no exception). Controls: with no fault each folder lists."""
    root_name = os.path.basename(scratch.root)
    put_plain(scratch.root / "full" / "x.md")
    (scratch.root / "empty").mkdir()
    rows = {"empty": {}, "full": {"x.md": FILE}, "": {"empty": DIR, "full": DIR}}[folder]
    seam = RefusesListing("fstat", folder or root_name, err=errno.EIO)
    with opened(how, scratch.root, seam) as view:
        got = (view.under(folder) if folder else view).entries()
    assert _entries_state(got) == (folder, False, os.strerror(errno.EIO), None), got
    with opened(how, scratch.root, RealOs()) as view:
        assert _entries_state((view.under(folder) if folder else view).entries()) == (
            folder, False, None, rows)


#: Every way a listing answers absent through the dead check: a REAL removal at each moment
#: of the folder's own listing, a removed held root, and a link count of 0.
ABSENT_ANSWERS = (*(f"removed-{moment}" for moment in REMOVAL_MOMENTS), "removed-root",
                  "zero-links")


@pytest.mark.parametrize("answer", ABSENT_ANSWERS)
def test_a3_no_descriptor_outlives_an_absent_answer(scratch, answer):
    """Whatever makes `entries()` answer absent, this process holds the same number of
    descriptors right after the call as before it (one held until the view closes would show
    here, though `descriptors_under` after the close could not see it), and none on the tree
    once the view is closed; the answer is absent, named as spelled. Control: a live listing
    through the real `os` leaves the count unchanged too."""
    put_plain(scratch.root / "sub" / "inner.md")
    seam = {"removed-root": RealOs(), "zero-links": ReportsLinks(0, 0)}.get(answer) or (
        ListingFaults(remove={"sub"}, moment=answer.removeprefix("removed-")))
    name = "" if answer == "removed-root" else "sub"
    bound = _io.bind(scratch.root, os_=seam)
    try:
        if answer == "removed-root":
            shutil.rmtree(scratch.root)
        count = open_fd_count()
        got = (bound.under(name) if name else bound).entries()
        assert open_fd_count() == count, f"the {answer} listing changed the descriptor count"
    finally:
        bound.close()
    assert descriptors_under(scratch.tmp) == [], f"the {answer} listing left a descriptor open"
    assert _entries_state(got) == (name, True, None, None), got

    put_plain(scratch.root / "sub" / "inner.md")
    with _io.bind(scratch.root) as live:
        count = open_fd_count()
        control = live.under("sub").entries()
        assert open_fd_count() == count
    assert _entries_state(control) == ("sub", False, None, {"inner.md": FILE})


@pytest.mark.parametrize("how", VIEWS)
def test_a3_through_the_real_os_a_folder_removed_before_its_scan_is_absent(scratch, how):
    """D2 with no seam at all: the view is bound over the real `os` module itself, and `sub` is
    REALLY removed the moment its listing calls `os.scandir` (a profile hook on that C call, set
    only around the one `entries()` call and always reset). `under("sub").entries()` answers
    absent, never present and empty. Non-vacuity: the hook fired and `sub` is gone. Control:
    the same call with no hook lists `sub`."""
    base = base_of(how, scratch)
    put_plain(base / "sub" / "inner.md")
    with view_of(how, scratch) as view:
        assert view.under("sub").entries().entries == {"inner.md": FILE}
        fired: list[str] = []

        def remove_on_scandir(_frame: Any, event: str, arg: Any) -> None:
            if event == "c_call" and getattr(arg, "__name__", None) == "scandir" and not fired:
                fired.append("scandir")
                shutil.rmtree(base / "sub")

        sys.setprofile(remove_on_scandir)
        try:
            got = view.under("sub").entries()
        finally:
            sys.setprofile(None)
    assert fired == ["scandir"], "the listing never called os.scandir; the row is void"
    assert not os.path.lexists(base / "sub")
    assert (got.absent, got.reason, got.entries) == (True, None, None), got
