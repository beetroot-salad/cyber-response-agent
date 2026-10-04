"""#1177: `stat_entries` answers a deleted folder absent, as `Bound.entries()` does (#1134
addendum 3, D2), because both are built on one listing step; plus the four `list_tree` rows the
#1134 reviews named.

The contract is #1177's intent+design comment (discuss-issue, base `80888efb`):
- O1: a folder no name holds any more (`st_nlink == 0` on the reopened descriptor) when its
  listing ends is ABSENT to `stat_entries` (`absent=True`, no reason, no stats): removed
  before its reopen, between the reopen and the scan, or mid-scan, and a held root really
  `rmdir`ed. Judged by the link count once the scan is done (a seam flipping it at the end
  of the scan decides), and a live folder a filesystem counts 1 link for is present.
- O2: a live folder is unchanged: a live empty folder is present with `{}`, a live non-empty
  one lists every entry (positive controls beside every O1 row).
- O3: an entry vanishing from a LIVE folder mid-scan is still a refusal (the per-entry stat's
  ENOENT); only a dead folder turns absent. A fault on the listing routes of a live folder is
  `stat_entries`' own refusal (`_read_reason`'s words), never a raise, never absent.
- O4: `list_tree` (a) never answers from a cache: a change between two calls on the same view
  is seen; (b) its records refuse `setattr` and `delattr` on EVERY field; (c) holds no
  descriptor chain at any depth: `depth=sys.maxsize` over a `CHAIN_DEPTH` chain lists the
  leaf inside a child whose soft descriptor limit is `FD_MARGIN` above what it holds; (d)
  never touches a device node: an audited listing of a tree holding a char and a block device
  raises no event naming either (skips where `mknod` is refused: CI's non-root runner).

Every plant is a real filesystem entry and every removal a real one; `os_` stand-ins
(`_tree_listing_1134.py`) stand in only for the moment a removal lands, an errno on a chosen
route, or a link count another filesystem reports. Nothing is monkeypatched.
"""
from __future__ import annotations

import dataclasses
import errno
import os
import shutil
import stat
import sys
from pathlib import Path
from typing import Any

import pytest

from defender import _io
from defender.tests._tree_listing_1134 import (
    FD_MARGIN,
    REMOVAL_MOMENTS,
    ListingFaults,
    RealOs,
    RefusesListing,
    ReportsLinks,
    Scratch,
    build_chain,
    descriptors_under,
    make_scratch,
    opened,
    put_plain,
    run_child,
)
from defender.tests.test_1134_tree_listing import (
    BINDERS,
    CHAIN_DEPTH,
    DIR,
    FILE,
    OTHER,
    TL,
    UNDER,
    VIEWS,
    _audit_tree,
    assert_tree,
    audit_violations,
    base_of,
    list_tree,
    planted_or_skip,
    view_of,
)

ENOENT_WORDS = os.strerror(errno.ENOENT)


@pytest.fixture
def scratch(tmp_path: Path) -> Scratch:
    return make_scratch(tmp_path)


def kinds_of(got: Any) -> dict[str, int] | None:
    """A `StatsRead`'s stats as `{name: S_IFMT}`, or `None` when it carries none."""
    if got.stats is None:
        return None
    return {name: stat.S_IFMT(st.st_mode) for name, st in got.stats.items()}


def assert_absent(got: Any, what: str) -> None:
    assert (got.absent, got.reason, got.stats) == (True, None, None), (
        f"{what}: stat_entries answered {got!r}, not absent")


def assert_listed(got: Any, kinds: dict[str, int], what: str) -> None:
    assert (got.absent, got.reason) == (False, None), f"{what}: {got!r} was not listed"
    assert kinds_of(got) == kinds, f"{what}: listed {kinds_of(got)}, not {kinds}"


def _d2_tree(base: Path) -> None:
    """`sub` (a file and a folder), a sibling `peer`, and a live empty folder `empty`."""
    put_plain(base / "sub" / "inner.md")
    put_plain(base / "sub" / "deeper" / "d.md")
    put_plain(base / "peer" / "p.md")
    (base / "empty").mkdir()


# =======================================================================================
# O1 + O2: a deleted folder is absent to stat_entries; a live one is unchanged
# =======================================================================================

@pytest.mark.parametrize("how", VIEWS)
@pytest.mark.parametrize("moment", REMOVAL_MOMENTS)
def test_a_folder_removed_during_its_own_listing_is_absent_to_stat_entries(
        scratch, moment, how):
    """`sub` is REALLY removed (`shutil.rmtree`) after the step into it, at each moment of its
    own listing: before the `"."` reopen, between the reopen and the scan, or after the scan
    handed back its first entry. `stat_entries(view.under("sub"))` answers ABSENT, never
    present-and-empty, never the stale names, never a refusal. `entries()` of the same removal
    agrees (absent). Controls, through the same seam on the same view: before the removal
    `sub` lists both entries; `peer` lists its file; the live EMPTY folder `empty` is present
    with `{}`. No descriptor outlives the calls."""
    base = base_of(how, scratch)
    _d2_tree(base)
    with view_of(how, scratch, RealOs()) as view:
        before = _io.stat_entries(view.under("sub"))
    assert_listed(before, {"inner.md": stat.S_IFREG, "deeper": stat.S_IFDIR}, "sub before")

    seam = ListingFaults(remove={"sub"}, moment=moment)
    with view_of(how, scratch, seam) as view:
        got = _io.stat_entries(view.under("sub"))
        peer = _io.stat_entries(view.under("peer"))
        empty = _io.stat_entries(view.under("empty"))
    assert seam.removed == [os.path.realpath(base / "sub")], seam.removed
    assert not os.path.lexists(base / "sub"), "the seam did not remove sub"
    assert_absent(got, f"sub removed at {moment}")
    assert_listed(peer, {"p.md": stat.S_IFREG}, "peer")
    assert_listed(empty, {}, "the live empty folder")

    put_plain(base / "sub" / "inner.md")
    put_plain(base / "sub" / "deeper" / "d.md")
    agree = ListingFaults(remove={"sub"}, moment=moment)
    with view_of(how, scratch, agree) as view:
        listed = view.under("sub").entries()
    assert (listed.absent, listed.reason, listed.entries) == (True, None, None), listed
    assert descriptors_under(scratch.tmp) == []


@pytest.mark.parametrize("how", BINDERS)
def test_a_removed_held_root_is_absent_to_stat_entries(scratch, how):
    """A root `bind` or `hold` opened, emptied and REALLY `rmdir`ed since, is absent to
    `stat_entries` of the view itself, on every later call, even once a new folder is made at
    the old path (it is not the held one). Controls: before the removal the view lists its
    entries; emptied but NOT removed it is present and empty (`{}`), never absent."""
    put_plain(scratch.root / "x.md")
    (scratch.root / "sub").mkdir()
    with opened(how, scratch.root) as view:
        assert_listed(_io.stat_entries(view), {"x.md": stat.S_IFREG, "sub": stat.S_IFDIR},
                      "the root before")
        (scratch.root / "x.md").unlink()
        (scratch.root / "sub").rmdir()
        assert_listed(_io.stat_entries(view), {}, "the emptied live root")
        scratch.root.rmdir()
        for _ in range(2):
            assert_absent(_io.stat_entries(view), "the removed held root")
            put_plain(scratch.root / "x.md")
    assert descriptors_under(scratch.tmp) == []


@pytest.mark.parametrize("how", VIEWS)
@pytest.mark.parametrize("flip", ["dies-at-scan-end", "lives-at-scan-end"])
def test_stat_entries_judges_the_folder_by_its_link_count_once_its_scan_is_done(
        scratch, flip, how):
    """The dead mark is the link count AFTER the scan, and nothing else: through a seam whose
    `fstat` of a listed folder's descriptor reports the real count until that descriptor's scan
    is exhausted and 0 after it, `stat_entries` answers absent (a check made before or during
    the scan, or none at all, would answer present); the mirror (0 until the scan is done, the
    real count after) is present with its entries (a check made before the scan would answer
    absent). Non-vacuity: the seam was asked after the scan."""
    base = base_of(how, scratch)
    put_plain(base / "sub" / "x.md")
    (base / "sub" / "empty").mkdir()
    seam = ReportsLinks(None, 0) if flip == "dies-at-scan-end" else ReportsLinks(0, None)
    with view_of(how, scratch, seam) as view:
        got = _io.stat_entries(view.under("sub"))
    assert seam.asked_after, "stat_entries asked no fstat after its scan"
    if flip == "dies-at-scan-end":
        assert_absent(got, "a folder whose link count drops to 0 at the end of its scan")
    else:
        assert_listed(got, {"x.md": stat.S_IFREG, "empty": stat.S_IFDIR},
                      "a folder whose link count rises from 0 at the end of its scan")


@pytest.mark.parametrize("how", VIEWS)
def test_a_live_folder_counted_one_link_is_present_to_stat_entries(scratch, how):
    """A dead folder has NO link left, not fewer than two: btrfs counts 1 for every live
    directory. Through a seam reporting 1 link, a full and an empty live folder are present
    (`{"x.md": file}`, `{}`). Control: the same seam reporting 0 makes both absent, so the
    count decides."""
    base = base_of(how, scratch)
    put_plain(base / "full" / "x.md")
    (base / "empty").mkdir()
    one = ReportsLinks(1, 1)
    with view_of(how, scratch, one) as view:
        full = _io.stat_entries(view.under("full"))
        empty = _io.stat_entries(view.under("empty"))
    assert_listed(full, {"x.md": stat.S_IFREG}, "a full folder counted 1 link")
    assert_listed(empty, {}, "an empty folder counted 1 link")
    assert one.asked_after >= 2, one.asked_after

    zero = ReportsLinks(0, 0)
    with view_of(how, scratch, zero) as view:
        full = _io.stat_entries(view.under("full"))
        empty = _io.stat_entries(view.under("empty"))
    assert_absent(full, "a full folder counted 0 links")
    assert_absent(empty, "an empty folder counted 0 links")


# =======================================================================================
# O3: a live folder's faults stay refusals
# =======================================================================================

class VanishesBeforeStat(RealOs):
    """The real `os`, except that the scan of the folder `folder` REALLY unlinks the entry
    `victim` just before handing it back, so its no-follow stat meets ENOENT while the folder
    itself stays alive."""

    def __init__(self, folder: Path, victim: str) -> None:
        self.folder, self.victim, self.unlinked = folder, victim, False

    def scandir(self, path: Any) -> Any:
        it = os.scandir(path)
        if isinstance(path, int) and os.path.realpath(f"/proc/self/fd/{path}") == str(
                self.folder):
            return _Unlinks(it, self)
        return it


class _Unlinks:
    def __init__(self, it: Any, seam: VanishesBeforeStat) -> None:
        self._it, self._seam = it, seam

    def __iter__(self) -> _Unlinks:
        return self

    def __next__(self) -> Any:
        entry = next(self._it)
        if entry.name == self._seam.victim:
            os.unlink(self._seam.folder / entry.name)
            self._seam.unlinked = True
        return entry

    def __enter__(self) -> _Unlinks:
        return self

    def __exit__(self, *_exc: object) -> None:
        self._it.close()

    def close(self) -> None:
        self._it.close()


@pytest.mark.parametrize("how", VIEWS)
def test_an_entry_vanishing_from_a_live_folder_mid_scan_is_a_refusal(scratch, how):
    """`sub` stays alive while one of its entries is REALLY unlinked between the scan naming it
    and its no-follow stat: `stat_entries` refuses (`No such file or directory`), never absent
    (the folder is not dead) and never a raise. Control: the same seam on a folder with no
    victim lists it whole; and `entries()` (which stats nothing) of the same vanishing lists
    the folder, present."""
    base = base_of(how, scratch)
    put_plain(base / "sub" / "keep.md")
    put_plain(base / "sub" / "victim.md")
    put_plain(base / "other" / "a.md")
    sub = Path(os.path.realpath(base / "sub"))
    seam = VanishesBeforeStat(sub, "victim.md")
    with view_of(how, scratch, seam) as view:
        got = _io.stat_entries(view.under("sub"))
        other = _io.stat_entries(view.under("other"))
    assert seam.unlinked, "the seam unlinked nothing; the row is void"
    assert os.path.isdir(base / "sub"), "sub must stay alive"
    assert (got.absent, got.reason, got.stats) == (False, ENOENT_WORDS, None), got
    assert_listed(other, {"a.md": stat.S_IFREG}, "a folder with no victim")

    put_plain(base / "sub" / "victim.md")
    seam = VanishesBeforeStat(sub, "victim.md")
    with view_of(how, scratch, seam) as view:
        listed = view.under("sub").entries()
    assert seam.unlinked
    assert (listed.absent, listed.reason) == (False, None), listed
    assert descriptors_under(scratch.tmp) == []


#: The listing routes past the reopen, each errno answered in `_read_reason`'s words (ELOOP is
#: the alias sentence there, unlike `entries()`'s `strerror`).
STAT_LISTING_FAULTS = [
    pytest.param(route, code, want, id=f"{route}-{errno.errorcode[code]}")
    for route in ("scandir", "midway", "fstat")
    for code, want in ((errno.EACCES, os.strerror(errno.EACCES)),
                       (errno.EIO, os.strerror(errno.EIO)),
                       (errno.ELOOP, _io.ALIAS_READ_REFUSAL))
]


@pytest.mark.parametrize("how", VIEWS)
@pytest.mark.parametrize(("route", "code", "want"), STAT_LISTING_FAULTS)
def test_a_live_folders_listing_fault_is_stat_entries_own_refusal(scratch, how, route, code,
                                                                  want):
    """Any errno on the scan, mid-scan, or on the dead check's own `fstat` of a LIVE folder is
    `stat_entries`' refusal in `_read_reason`'s words: never absent, never a raise, nothing
    listed, no descriptor left open. Control: through the same seam, a sibling folder the seam
    does not fault lists its file."""
    base = base_of(how, scratch)
    put_plain(base / "sub" / "a.md")
    put_plain(base / "sub" / "b.md")
    put_plain(base / "peer" / "p.md")
    seam = RefusesListing(route, "sub", err=code)
    with view_of(how, scratch, seam) as view:
        got = _io.stat_entries(view.under("sub"))
        peer = _io.stat_entries(view.under("peer"))
    assert (got.absent, got.reason, got.stats) == (False, want, None), got
    assert_listed(peer, {"p.md": stat.S_IFREG}, "the unfaulted sibling")
    assert descriptors_under(scratch.tmp) == []


# =======================================================================================
# O4: the four list_tree rows
# =======================================================================================

@pytest.mark.parametrize("how", VIEWS)
def test_list_tree_answers_from_the_disk_on_every_call_never_a_cache(scratch, how):
    """(a) A second `list_tree(depth=3)` on the SAME view sees what changed on disk since the
    first, at EVERY listed level: a folder added at the top, a file added and one removed in a
    level-1 folder, and a file added and one removed in a level-2 folder (`a/n/`), so a cache of
    any one folder's listing, nested ones included, shows. A third call after undoing the
    changes answers the first tree again. Control: a fresh view over the changed tree answers
    what the reused one does (independent adversary, hole 3: depth 2 alone left nested
    listings uncovered)."""
    base = base_of(how, scratch)
    put_plain(base / "a" / "x.md")
    put_plain(base / "a" / "n" / "deep.md")
    put_plain(base / "b" / "gone.md")
    first = {"a": DIR, "a/n": DIR, "a/n/deep.md": FILE, "a/x.md": FILE, "b": DIR,
             "b/gone.md": FILE}
    changed = {"a": DIR, "a/n": DIR, "a/n/new.md": FILE, "a/x.md": FILE, "a/y.md": FILE,
               "b": DIR, "c": DIR}
    with view_of(how, scratch) as view:
        assert_tree(list_tree(view, 3), first)
        put_plain(base / "a" / "y.md")
        put_plain(base / "a" / "n" / "new.md")
        (base / "a" / "n" / "deep.md").unlink()
        (base / "b" / "gone.md").unlink()
        (base / "c").mkdir()
        assert_tree(list_tree(view, 3), changed)
        with view_of(how, scratch) as fresh:
            assert_tree(list_tree(fresh, 3), changed)
        (base / "a" / "y.md").unlink()
        (base / "a" / "n" / "new.md").unlink()
        put_plain(base / "a" / "n" / "deep.md")
        put_plain(base / "b" / "gone.md")
        (base / "c").rmdir()
        assert_tree(list_tree(view, 3), first)


def test_every_field_of_both_records_is_frozen():
    """(b) `EntryKind` and `TreeListing` are frozen dataclasses (`__dataclass_params__.frozen`)
    and EVERY field of each refuses both `setattr` and `delattr`, its value unchanged after.
    Non-vacuity: each record has the fields the contract names."""
    tl = TL()
    records = [
        tl.EntryKind(name="a/x.md", folder="a", kind=FILE, absent=False, reason=None),
        tl.TreeListing(absent=False, reason=None, entries={"a": DIR}, refused={}, gone=()),
    ]
    assert [len(dataclasses.fields(r)) for r in records] == [5, 5]
    for record in records:
        assert type(record).__dataclass_params__.frozen, type(record).__name__  # type: ignore[attr-defined]
        for field in dataclasses.fields(record):
            before = getattr(record, field.name)
            with pytest.raises(dataclasses.FrozenInstanceError):
                setattr(record, field.name, OTHER)
            with pytest.raises(dataclasses.FrozenInstanceError):
                delattr(record, field.name)
            assert getattr(record, field.name) == before, (type(record).__name__, field.name)


@pytest.mark.parametrize("how", VIEWS)
def test_the_records_the_helpers_return_are_frozen_in_every_field(scratch, how):
    """(b), on what the helpers actually hand back (independent adversary, hole 4): the
    `TreeListing` `list_tree` returns and the `EntryKind` `entry_kind` returns are instances of
    the module's frozen records, and EVERY field of each refuses `setattr` and `delattr`, its
    value unchanged after. Non-vacuity: both answers carry content."""
    from defender.tests.test_1134_tree_listing import entry_kind
    base = base_of(how, scratch)
    put_plain(base / "a" / "x.md")
    with view_of(how, scratch) as view:
        records = [list_tree(view, 2), entry_kind(view, "a/x.md")]
    tl = TL()
    assert type(records[0]) is tl.TreeListing, records[0]
    assert records[0].entries, records[0]
    assert type(records[1]) is tl.EntryKind, records[1]
    assert records[1].kind == FILE, records[1]
    for record in records:
        for field in dataclasses.fields(record):
            before = getattr(record, field.name)
            with pytest.raises(dataclasses.FrozenInstanceError):
                setattr(record, field.name, OTHER)
            with pytest.raises(dataclasses.FrozenInstanceError):
                delattr(record, field.name)
            assert getattr(record, field.name) == before, (type(record).__name__, field.name)


def test_list_tree_holds_no_descriptor_chain_at_any_depth_under_a_low_limit(tmp_path):
    """(c) A chain `CHAIN_DEPTH` folders deep, listed at `depth=sys.maxsize` (bound and held)
    and through a view under its 10th folder, inside a child whose soft `RLIMIT_NOFILE` is only
    `FD_MARGIN` descriptors above what it holds (it proves the limit bites): every level is
    listed, the leaf included. A descriptor held per level would hit EMFILE past depth
    `FD_MARGIN`."""
    base = tmp_path / "chain"
    base.mkdir()
    build_chain(base, CHAIN_DEPTH, "leaf.md")
    under = "/".join(["d"] * 10)
    answer = run_child({"mode": "low_fd_limit", "scenarios": [
        {"root": str(base), "op": "list_tree", "depth": sys.maxsize},
        {"root": str(base), "how": "held", "op": "list_tree", "depth": sys.maxsize},
        {"root": str(base), "prefix": under, "op": "list_tree", "depth": sys.maxsize},
    ]})
    assert answer["spare"] < 2 * FD_MARGIN, (
        f"the child's limit does not bite: it could open {answer['spare']} more descriptors")
    leaf = "/".join(["d"] * CHAIN_DEPTH + ["leaf.md"])
    below = "/".join(["d"] * (CHAIN_DEPTH - 10) + ["leaf.md"])
    for row, want_leaf, rows in zip(answer["rows"], (leaf, leaf, below),
                                    (CHAIN_DEPTH + 1, CHAIN_DEPTH + 1, CHAIN_DEPTH - 9),
                                    strict=True):
        assert "raised" not in row, str(row)[:300]
        assert (row["absent"], row["reason"], row["refused"], row["gone"]) == (
            False, None, [], []), str(row)[:300]
        assert [want_leaf, FILE] in row["entries"], f"the leaf is not listed: {str(row)[:300]}"
        assert len(row["entries"]) == rows, len(row["entries"])


#: The device plants and the names an audit event may never carry.
DEVICE_NAMES = {"chr": "char_device", "blk": "block_device"}


@pytest.mark.parametrize("how", VIEWS)
def test_an_audited_listing_never_touches_a_device_node(scratch, how):
    """(d) The audited tree (files, FIFOs, a socket, links, a hard link) also holds a char
    device and a block device, at the top and in a sub-folder. In a child with an audit hook,
    `list_tree` at depths 1-3 and `entry_kind` of each device raise only folder steps, `"."`
    reopens and scans of descriptors, and no event names a device. The kinds are right: each
    device is `"other"`. Control: in the same child, `read` of a device through the same view
    is caught naming it. Skips where `mknod` is refused (CI's non-root runner)."""
    base = base_of(how, scratch)
    _audit_tree(base, scratch)
    for name, kind in DEVICE_NAMES.items():
        planted_or_skip(base / name, kind, scratch)
        planted_or_skip(base / "d1" / name, kind, scratch)
    warm = scratch.tmp / "warm"
    put_plain(warm / "w" / "x.md")
    view = {"root": str(scratch.root), "how": how.removesuffix("-under"),
            "prefix": UNDER if how.endswith("-under") else None}
    names = [*DEVICE_NAMES, *(f"d1/{n}" for n in DEVICE_NAMES)]
    scenarios = [*({**view, "op": "list_tree", "depth": d} for d in (1, 2, 3)),
                 *({**view, "op": "entry_kind", "name": n} for n in names),
                 {**view, "op": "read", "name": "chr"}]
    warmup = [{"root": str(warm), "how": view["how"], "op": op, **extra}
              for op, extra in (("list_tree", {"depth": 2}), ("entry_kind", {"name": "w/x.md"}),
                                ("read", {"name": "w/x.md"}))]
    rows = run_child({"mode": "audited", "scenarios": scenarios, "warmup": warmup})["rows"]

    def device_events(events: list[list[Any]]) -> list[str]:
        return [f"{name} {args!r}" for name, args in events
                if any(type(a) is str and os.path.basename(a) in DEVICE_NAMES for a in args)]

    *helper_rows, control = rows
    problems = {}
    for scenario, row in zip(scenarios[:-1], helper_rows, strict=True):
        what = f"{scenario['op']}({scenario.get('name', scenario.get('depth'))!r})"
        assert "raised" not in row["answer"], f"{what} raised in the child: {row['answer']}"
        assert row["events"], f"{what} raised no audit event; the hook saw nothing"
        found = device_events(row["events"]) + audit_violations(row["events"])
        if found:
            problems[what] = found
    assert not problems, f"a helper touched a device node: {problems}"
    for row, name in zip(helper_rows[3:], names, strict=True):
        assert row["answer"]["kind"] == OTHER, (name, row["answer"])
    top = dict(map(tuple, helper_rows[1]["answer"]["entries"]))
    assert {top[n] for n in (*DEVICE_NAMES, *(f"d1/{n}" for n in DEVICE_NAMES))} == {OTHER}, top
    assert device_events(control["events"]), (
        f"the hook did not catch read naming a device: {control['events']}")


class _FailsMidwayAndFstat(RefusesListing):
    """`RefusesListing`'s `midway` route on `sub`, whose dead check's `fstat` of the reopened
    descriptor then fails too (`fstat_err`): the scan's error and the check made on it both
    fault."""

    def __init__(self, err: int, fstat_err: int) -> None:
        super().__init__("midway", "sub", err=err)
        self.fstat_err, self.fstat_failed = fstat_err, 0

    def fstat(self, fd: Any) -> os.stat_result:
        if fd in self._reopened:
            self.fstat_failed += 1
            raise OSError(self.fstat_err, os.strerror(self.fstat_err))
        return os.fstat(fd)


@pytest.mark.parametrize("how", VIEWS)
@pytest.mark.parametrize("fstat_err", [errno.EIO, errno.EBADF])
def test_a_scan_fault_whose_dead_check_also_faults_is_still_a_refusal(scratch, how,
                                                                      fstat_err):
    """Adversary hole (tests-only commit): a scan that faults mid-way on a live folder, whose
    dead check's own `fstat` then faults too, is still `stat_entries`' refusal (the scan's
    error, in `_read_reason`'s words), never a raise, never absent, no descriptor left open.
    Non-vacuity: the dead check was asked. Control: the sibling lists its file."""
    base = base_of(how, scratch)
    put_plain(base / "sub" / "a.md")
    put_plain(base / "sub" / "b.md")
    put_plain(base / "peer" / "p.md")
    seam = _FailsMidwayAndFstat(errno.EACCES, fstat_err)
    with view_of(how, scratch, seam) as view:
        got = _io.stat_entries(view.under("sub"))
        peer = _io.stat_entries(view.under("peer"))
    assert seam.fstat_failed, "the dead check never asked fstat; the row is void"
    assert (got.absent, got.reason, got.stats) == (False, os.strerror(errno.EACCES), None), got
    assert_listed(peer, {"p.md": stat.S_IFREG}, "the unfaulted sibling")
    assert descriptors_under(scratch.tmp) == []


class _DiesThenFaults(RealOs):
    """The real `os`, except that the scan of the folder `folder` REALLY removes it
    (`shutil.rmtree`) after handing back its first entry, then fails with `err`: a dead folder
    whose scan faults with an errno other than ENOENT."""

    def __init__(self, folder: Path, err: int) -> None:
        self.folder, self.err, self.removed, self.raised = folder, err, False, False

    def scandir(self, path: Any) -> Any:
        it = os.scandir(path)
        if isinstance(path, int) and os.path.realpath(f"/proc/self/fd/{path}") == str(
                self.folder):
            return _DiesThenFaultsIt(it, self)
        return it


class _DiesThenFaultsIt:
    def __init__(self, it: Any, seam: _DiesThenFaults) -> None:
        self._it, self._seam, self._given = it, seam, 0

    def __iter__(self) -> _DiesThenFaultsIt:
        return self

    def __next__(self) -> Any:
        if self._given == 1:
            shutil.rmtree(self._seam.folder)
            self._seam.removed = True
            self._seam.raised = True
            raise OSError(self._seam.err, os.strerror(self._seam.err))
        self._given += 1
        return next(self._it)

    def __enter__(self) -> _DiesThenFaultsIt:
        return self

    def __exit__(self, *_exc: object) -> None:
        self._it.close()

    def close(self) -> None:
        self._it.close()


@pytest.mark.parametrize("how", VIEWS)
@pytest.mark.parametrize("err", [errno.EIO, errno.EACCES, errno.ENOENT])
@pytest.mark.parametrize("reader", ["entries", "stat_entries"])
def test_a_folder_that_dies_mid_scan_and_then_faults_is_absent_to_both_readers(
        scratch, how, err, reader):
    """Independent adversary, holes 1 and 2: `sub` is REALLY removed mid-scan and the scan
    then fails with EIO, EACCES or ENOENT. The folder is dead, so BOTH `entries()` and
    `stat_entries` answer absent (no reason, nothing listed), whatever the errno, never the
    scan's refusal. Non-vacuity: the seam removed `sub` and raised. Control: the same seam on
    a live sibling it does not touch lists its file."""
    base = base_of(how, scratch)
    put_plain(base / "sub" / "a.md")
    put_plain(base / "sub" / "b.md")
    put_plain(base / "peer" / "p.md")
    seam = _DiesThenFaults(Path(os.path.realpath(base / "sub")), err)
    with view_of(how, scratch, seam) as view:
        if reader == "entries":
            got = view.under("sub").entries()
            rows, peer = got.entries, view.under("peer").entries().entries
        else:
            got = _io.stat_entries(view.under("sub"))
            rows, peer = got.stats, kinds_of(_io.stat_entries(view.under("peer")))
    assert seam.removed, "the seam did not remove sub"
    assert seam.raised, "the seam did not raise"
    assert (got.absent, got.reason, rows) == (True, None, None), (
        f"{reader}: a folder dead mid-scan whose scan raised {errno.errorcode[err]} "
        f"answered {got!r}")
    assert peer in ({"p.md": FILE}, {"p.md": stat.S_IFREG}), peer
    assert descriptors_under(scratch.tmp) == []
