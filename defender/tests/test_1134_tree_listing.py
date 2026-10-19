from __future__ import annotations

import collections
import contextlib
import errno
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


@pytest.mark.parametrize("how", VIEWS)
@pytest.mark.parametrize("kind", list(KIND_OF))
def test_list_tree_lists_each_plant_as_its_own_kind_and_never_enters_a_link(scratch, kind, how):
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
    (scratch.root / "empty").mkdir()
    before = census(scratch.tmp)
    with opened(how, scratch.root) as view:
        assert_tree(list_tree(view.under("empty"), 2), {})
        for missing in ("missing", "missing/deeper", "empty/missing"):
            assert_tree_absent(list_tree(view.under(missing), 2))
    assert census(scratch.tmp) == before


#: Every character below `/` in code-point order, control characters too (v2 hole D: a sort
#: key that stands `\x1f` in for the separator).
BELOW_SLASH = "".join(map(chr, range(1, ord("/"))))


@pytest.mark.parametrize("how", BINDERS)
@pytest.mark.parametrize("prefix", ["", "p"], ids=["root", "under-p"])
def test_list_tree_sorts_every_character_below_the_separator_in_one_listing(scratch, prefix, how):
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


def test_a_hard_link_is_a_file_to_both_helpers_and_refused_by_read(scratch):
    plant_entry(scratch.root / "a" / "hard.md", "hardlink", root=scratch.root, host=scratch.host)
    put_plain(scratch.root / "a" / "plain.md")
    with _io.bind(scratch.root) as bound:
        assert_kind(entry_kind(bound, "a/hard.md"), name="a/hard.md", folder="a", kind=FILE)
        assert listed(list_tree(bound, 2))["a/hard.md"] == FILE
        refused = bound.read("a/hard.md")
        assert (refused.text, refused.absent, refused.reason) == (None, False, ALIAS)
        assert_kind(entry_kind(bound, "a/plain.md"), name="a/plain.md", folder="a", kind=FILE)
        assert bound.read("a/plain.md").text == PLAIN.decode()


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


def _d2_tree(base: Path) -> None:
    """`sub` (two entries, one a folder), a live empty folder `empty`, and a sibling `peer`."""
    put_plain(base / "sub" / "inner.md")
    put_plain(base / "sub" / "deeper" / "d.md")
    put_plain(base / "peer" / "p.md")
    (base / "empty").mkdir()


@pytest.mark.parametrize("how", VIEWS)
@pytest.mark.parametrize("moment", REMOVAL_MOMENTS)
def test_d2_a_folder_removed_during_its_own_listing_is_absent_to_entries(scratch, moment, how):
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


#: Trees `list_tree` must answer at once whatever its depth: once a level holds no folder,
#: nothing below it remains to list (#1140 review finding 5).
HUGE_DEPTHS = [sys.maxsize, 10**12]
#: A chain deeper than any depth another row asks for (each level re-walks from the root, so
#: listing it costs about CHAIN_DEPTH**2 / 2 steps: well under a second).
CHAIN_DEPTH = 100


def test_list_tree_stops_once_a_level_is_empty_whatever_the_depth(tmp_path):
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


@pytest.mark.parametrize("how", VIEWS)
def test_c_no_non_directory_entry_is_ever_handed_to_os_open(scratch, how):
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


#: Each outcome a helper can answer, and the call that answers it.
FD_OUTCOMES = ("listed", "absent-top", "refused-top", "refused-sub", "gone-sub", "closed",
               "kind-present", "kind-absent", "kind-refused",
               *(f"refused-sub-{route}" for route in ("scandir", "midway", "entry", "fstat")),
               "removed-sub")


@pytest.mark.parametrize("outcome", FD_OUTCOMES)
def test_d_neither_helper_leaves_a_descriptor_open(scratch, outcome):
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


CHAIN = 1100


def test_finding_1_a_deep_chain_is_listed_to_its_depth_under_a_low_descriptor_limit(tmp_path):
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


def _race_trees(tmp_path: Path) -> tuple[Path, Path]:
    trees = []
    for who in ("root", "decoy"):
        top = tmp_path / who
        put_plain(top / f"{who}-marker")
        put_plain(top / "fa" / f"{who}-only")
        trees.append(top)
    return trees[0], trees[1]


def test_finding_14_a_close_landing_mid_list_tree_never_lists_the_reused_number(tmp_path):
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


def _entries_state(got: Any) -> tuple[Any, ...]:
    return got.name, got.absent, got.reason, got.entries


@pytest.mark.parametrize("how", BINDERS)
@pytest.mark.parametrize("folder", ["empty", "full", ""], ids=["empty", "full", "the-root"])
def test_a3_a_fault_on_the_dead_checks_fstat_is_a_refusal_for_any_folder(scratch, folder, how):
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
