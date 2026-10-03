"""#1134 step 1, addendum 3's D2: `Bound.entries()` answers a dead folder absent, never
present and empty.

The contract is #1134's "Addendum 3" (owner-approved 2026-10-03), D2: `Bound.entries()`
answers `absent` when the reopened folder is dead (`st_nlink == 0`), not present-and-empty; and
D3's sound test helpers (no chmod or lchown by path while running as root, `owned_tree`
restores unreadable folders, `ParkedWriter` releases on a failed setup). The core gains nothing
else (D1: no `Bound.read_bytes`). B2's two fixed-shape listings over `entries()` /
`under()` land with their first consumers, and their rows join this file there: `list_tree`
with the shared readers (step 4), `entry_kind` with the lead author (helpers moved to their
first consumers, 2026-10-03).

What each section pins:

- Adds nothing to the core but D2 (v2's findings #1-#9, #11, #12, #15 dissolve by absence):
  `Bound` has no `walk`, `kind`, `read_bytes` or `_leaf`; `_io` has no `ENTRY_ABSENT`,
  `ENTRY_UNLISTED`, `WalkRead`, `BytesRead`, `_walk_at`, `_kind_at`, `_list_below`,
  `_folder_parts`, `_reopen_dir`, and no `ENTRY_*` but the three.
- v2's finding #4, settled by D2: a held root REALLY removed since is absent to its own
  `entries()`, and so is a folder that went with it; emptied but not removed, it is present
  and empty.
- D2 (#1140 review findings 2 and 11), with REAL deletions (`ListingFaults` removes the folder
  with `shutil.rmtree` at a chosen moment, and the real kernel and CPython answer): a folder
  removed after the step into it, before its reopen, between the reopen and the scan, or after
  the scan's first entry, is absent to its own `entries()`, never a present, empty (or stale)
  folder; a live empty folder is still present with `{}`; a filesystem counting 1 link for a
  live directory (btrfs) still lists it (the dead mark is `st_nlink == 0`).
- Round 3 (addendum 3's adversary): H2, the link count AFTER the scan decides (a seam flipping
  it at the end of the scan: absent when it drops to 0, present when it rises from 0), and no
  name is a dead mark (live folders named `notes (deleted)` / `empty (deleted)` are present);
  H3, the dead check's `fstat` is a listing route of its own: any errno there is the folder's
  own refusal, with that errno's words, never a raise, never absent or present; H4, no
  descriptor outlives a refusal on the `scandir`, `midway`, `entry` or `fstat` route, nor a
  real removal mid-scan.
- D3: `owned_tree` puts every mode back and removes the tree, whatever the body left.

Every negative row has a positive control on the same address. Every plant is a real
filesystem entry; `os_` stand-ins (`_tree_listing_1134.py`) stand in only for what cannot be
made for real (an errno on a chosen route, the moment a real removal lands, a link count another
filesystem reports). Nothing is monkeypatched; no test forks.

Red before #1134 step 1 (main): every removal row (present and empty, or the stale names), the
removed-held-root row (present and empty), the btrfs and link-count rows (main asks no `fstat`
of a listed folder), and every `fstat`-route row. Green on main, guards that must stay so: the
core row, the `owned_tree` row, the live folders named like deleted ones, and H4 on the
`scandir`, `midway` and `entry` routes.
"""
from __future__ import annotations

import contextlib
import errno
import os
import stat
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from defender import _io
from defender.tests._tree_listing_1134 import (
    REMOVAL_MOMENTS,
    ListingFaults,
    RealOs,
    RefusesListing,
    ReportsLinks,
    Scratch,
    descriptors_under,
    hand_over,
    make_scratch,
    open_fd_count,
    opened,
    owned_tree,
    put_plain,
    set_mode,
)

#: The kinds, spelled here so a module-level name needs nothing new; the core row pins the
#: `ENTRY_*` names to exactly the three.
FILE, DIR = "file", "dir"

#: The ways to reach a view: `bind(root)`, `hold(root).view()`, and an `under(...)` derivation
#: of each, bound at `UNDER` (so every name below is relative to a two-component prefix).
VIEWS = ("bind", "held", "bind-under", "held-under")
BINDERS = ("bind", "held")
UNDER = "v/w"


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


def assert_absent(got: Any, what: str) -> None:
    assert (got.absent, got.reason, got.entries) == (True, None, None), (
        f"{what} answered {got!r}, not absent")


def assert_listed(got: Any, rows: dict[str, str], what: str) -> None:
    assert (got.absent, got.reason, got.entries) == (False, None, rows), (
        f"{what} answered {got!r}, not present with {rows}")


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
# v2's finding #4: a removed held root
# =======================================================================================

@pytest.mark.parametrize("how", BINDERS)
def test_finding_4_a_removed_held_root_is_absent_to_entries(scratch, how):
    """v2 finding #4 (a removed root answered present-and-empty), settled by addendum 3, D2: a
    root `bind` or `hold` opened, REALLY removed since (`rmdir`, after its contents), is absent
    to `view.entries()` itself (the reopened folder is dead), and so is a folder that went with
    it (`under("sub")`). A folder made again at the path is not the held one: the answers stay.
    Control: before the removal the same view lists the tree, and a held root emptied but NOT
    removed is present and empty (`{}`), never absent."""
    put_plain(scratch.root / "x.md")
    put_plain(scratch.root / "sub" / "y.md")
    with opened(how, scratch.root) as view:
        assert_listed(view.entries(), {"sub": DIR, "x.md": FILE}, "the live root")
        assert_listed(view.under("sub").entries(), {"y.md": FILE}, "the live sub")

        (scratch.root / "sub" / "y.md").unlink()
        (scratch.root / "sub").rmdir()
        (scratch.root / "x.md").unlink()
        assert_listed(view.entries(), {}, "a live, emptied root")

        scratch.root.rmdir()
        for _ in range(2):
            assert_absent(view.entries(), "the removed root")
            assert_absent(view.under("sub").entries(), "a folder that went with the root")
            put_plain(scratch.root / "x.md")  # a new folder at the old path: not the held one
    assert descriptors_under(scratch.tmp) == []


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
def test_d2_a_live_folder_whose_filesystem_counts_one_link_is_still_present(scratch, how):
    """A dead folder is one with NO link left (`st_nlink == 0`), not one with fewer than two:
    a filesystem such as btrfs counts 1 for every live directory, whatever it holds. Through
    a seam whose `fstat` of a reopened (listed) folder's descriptor reports 1 link, `entries()`
    of a full and of an empty live folder are present (`{"x.md": "file"}`, `{}`). Non-vacuity:
    each listing asked that `fstat` once its scan was done. Control: the same seam reporting 0
    links on the same live folders makes them absent, so the count is what decides."""
    base = base_of(how, scratch)
    put_plain(base / "full" / "x.md")
    (base / "empty").mkdir()
    one = ReportsLinks(1, 1)
    with view_of(how, scratch, one) as view:
        full, empty = view.under("full").entries(), view.under("empty").entries()
    assert (full.absent, full.reason, full.entries) == (False, None, {"x.md": FILE}), full
    assert (empty.absent, empty.reason, empty.entries) == (False, None, {}), empty
    assert one.asked_after >= 2, (
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
    scan would call it absent)."""
    base = base_of(how, scratch)
    put_plain(base / "sub" / "x.md")
    (base / "sub" / "empty").mkdir()
    seam = ReportsLinks(None, 0) if flip == "dies-at-scan-end" else ReportsLinks(0, None)
    with view_of(how, scratch, seam) as view:
        got = view.under("sub").entries()
    assert seam.asked_after, "no listing asked fstat after its scan; the row is void"
    if flip == "dies-at-scan-end":
        assert (got.absent, got.reason, got.entries) == (True, None, None), got
    else:
        assert (got.absent, got.reason, got.entries) == (
            False, None, {"empty": DIR, "x.md": FILE}), got


@pytest.mark.parametrize("how", VIEWS)
def test_d2_a_live_folder_named_like_a_deleted_one_is_present(scratch, how):
    """Round 3 (adversary H2): `/proc` spells a removed folder's descriptor with a
    `" (deleted)"` suffix, but no name is a dead mark: live folders named `notes (deleted)`
    (holding a file) and `empty (deleted)` are present to their own `entries()`, with what they
    hold."""
    base = base_of(how, scratch)
    put_plain(base / "notes (deleted)" / "x.md")
    (base / "empty (deleted)").mkdir()
    with view_of(how, scratch) as view:
        notes = view.under("notes (deleted)").entries()
        empty = view.under("empty (deleted)").entries()
    assert (notes.absent, notes.reason, notes.entries) == (False, None, {"x.md": FILE}), notes
    assert (empty.absent, empty.reason, empty.entries) == (False, None, {}), empty


# =======================================================================================
# Round 3, H3: the dead check's `fstat` is a listing route of its own
# =======================================================================================

def _errno_tree(root: Path) -> None:
    for rel in ("aaa/a1.md", "sub/inner.md", "sub/below/b.md", "zzz/z.md", "top.md"):
        put_plain(root / rel)


def _drivable(route: str, err: int) -> bool:
    """Whether an injected `err` on `route` models something the kernel and CPython can
    actually produce. ENOENT is the step's alone (the folder's name is gone when it is stepped
    into): reopening `"."` off a removed folder's handle succeeds; `os.scandir` of a descriptor
    makes no `getdents` call; the C library reads `getdents`' ENOENT on a removed folder as the
    end of the listing; and `DirEntry`'s type questions answer from `d_type`, or catch
    `FileNotFoundError` and answer False (#1140 review finding 11). What a removal at those
    moments really does is driven for real by the `test_d2_*` rows (`ListingFaults`)."""
    return err != errno.ENOENT or route == "step"


#: What `sub` holds, and its sibling `aaa`, when nothing faults.
SUB_ROWS = {"below": DIR, "inner.md": FILE}
AAA_ROWS = {"a1.md": FILE}


@pytest.mark.parametrize("how", BINDERS)
@pytest.mark.parametrize("err", [errno.ELOOP, errno.ENOTDIR, errno.EACCES, errno.EIO],
                         ids=errno.errorcode.get)
def test_h3_a_fault_on_the_dead_checks_fstat_is_that_folders_refusal_in_its_words(
        scratch, err, how):
    """Round 3, H3: the `fstat` that judges whether a listed folder is dead is a listing route
    of its own. An errno there (injected on the descriptor the `"."` reopen handed back, never
    on a step handle) is `sub`'s own refusal: no entries, not absent, the errno's own words as
    the reason, never a raise. Controls: through the same seam, the sibling `aaa` lists its file;
    with no fault, `sub` lists its two entries."""
    _errno_tree(scratch.root)
    seam = RefusesListing("fstat", "sub", err=err)
    with opened(how, scratch.root, seam) as view:
        got = view.under("sub").entries()
        sibling = view.under("aaa").entries()
    assert (got.absent, got.reason, got.entries) == (False, os.strerror(err), None), got
    assert_listed(sibling, AAA_ROWS, "the unfaulted sibling")

    with opened(how, scratch.root, RealOs()) as view:
        assert_listed(view.under("sub").entries(), SUB_ROWS, "sub with no fault")


def test_h3_every_errno_on_the_dead_checks_fstat_is_a_refusal_never_a_raise(scratch):
    """The whole errno table on the `fstat` route (but ENOENT: see `_drivable`): each is `sub`'s
    own refusal with that errno's words, never a raise, never absent, never present. Control: no
    fault, `sub` lists its two entries."""
    _errno_tree(scratch.root)
    broken = []
    for err in (e for e in sorted(errno.errorcode) if _drivable("fstat", e)):
        seam = RefusesListing("fstat", "sub", err=err)
        with _io.bind(scratch.root, os_=seam) as bound:
            try:
                got = bound.under("sub").entries()
            except Exception as e:  # noqa: BLE001 — a raise is itself the failure reported
                broken.append((errno.errorcode[err], f"raised {type(e).__name__}: {e}"))
                continue
        if (got.absent, got.reason, got.entries) != (False, os.strerror(err), None):
            broken.append((errno.errorcode[err], got))
    assert not broken, broken
    with _io.bind(scratch.root) as bound:
        assert_listed(bound.under("sub").entries(), SUB_ROWS, "sub with no fault")


# =======================================================================================
# Round 3, H4: no descriptor outlives a refused or removed listing
# =======================================================================================

#: Each refusal or removal a listing can meet after its reopen, and the seam that drives it.
FD_FAULTS = {
    **{f"refused-{route}": (lambda route=route: RefusesListing(route, "sub", err=errno.EIO))
       for route in ("scandir", "midway", "entry", "fstat")},
    "removed-midway": lambda: ListingFaults(remove={"sub"}, moment="midway"),
}


@pytest.mark.parametrize("fault", list(FD_FAULTS))
def test_h4_no_descriptor_outlives_a_refused_or_removed_listing(scratch, fault):
    """Round 3, H4: a listing refused on the `scandir`, `midway`, `entry` or `fstat` route
    (EIO), or meeting a REAL removal mid-scan, leaves this process holding the same number of
    descriptors after the call as before it, and none on the tree once the view is closed; the
    call answers the refusal (`Input/output error`) or absence. Non-vacuity: the scan sees the
    view's own handle while it is open. Control: an unfaulted listing of the same folder through
    the real `os` leaves the count unchanged too and lists it."""
    _errno_tree(scratch.root)
    bound = _io.bind(scratch.root, os_=FD_FAULTS[fault]())
    try:
        assert descriptors_under(scratch.tmp) == [os.path.realpath(scratch.root)]
        count = open_fd_count()
        got = bound.under("sub").entries()
        assert open_fd_count() == count, f"the {fault} listing changed the descriptor count"
    finally:
        bound.close()
    assert descriptors_under(scratch.tmp) == [], f"the {fault} listing left a descriptor open"
    if fault.startswith("refused"):
        assert (got.absent, got.reason, got.entries) == (False, os.strerror(errno.EIO), None), got
    else:
        assert_absent(got, "sub removed mid-scan")

    put_plain(scratch.root / "sub" / "inner.md")  # the removal took sub: it is made again
    with _io.bind(scratch.root) as bound:
        count = open_fd_count()
        control = bound.under("sub").entries()
        assert open_fd_count() == count, "an unfaulted listing changed the descriptor count"
    assert_listed(control, {"inner.md": FILE} if fault.startswith("removed") else SUB_ROWS,
                  "sub with no fault")
    assert descriptors_under(scratch.tmp) == []


# =======================================================================================
# D3: sound test helpers
# =======================================================================================

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
