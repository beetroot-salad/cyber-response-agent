"""#1134 v3 step 2: `DrainTrees` (`defender/learning/core/lane_trees.py`), the drain's holder of
one `Held` per writable mount, and D7's guard-plus-positive-control matrix run through the
handles it hands out.

The contract is #1134's 2026-10-01 design addendum, A3 part 1 (unchanged by addendum 2, B3). It
replaces the 2026-09-28 design's D3 `tree_for` on `LoopPaths`, and keeps D7's matrix and O3's
regression. The reads through a handle are #1133's `Bound.read` / `entries` / `under`, as
#1133 shipped them (addendum 3 dropped `Bound.read_bytes`, so a byte-exact control reads the
file by path in the test). Addendum 2 dropped v2's `Bound.kind` and `Bound.walk`; this file is
v2's, its kind rows retargeted onto the listing of the record's folder (`entries()`, whose row
for the record is its kind) and its walk rows onto the listings of the tree's fixed shape (one
`under(...).entries()` per folder). B2's helpers over a view (`entry_kind`, `list_tree`) land
with their first consumers, higher in the stack, so no row here needs them (helpers moved to
their first consumers, 2026-10-03). The API forks A3 leaves open were settled for this step:

    DrainTrees.open(mounts: tuple[Path, ...], *, os_=os) -> DrainTrees
    .mounts -> tuple[Path, ...]; .tree_for(path) -> tuple[Held, str] | None; .mount(path) -> Held
    .close(); context manager (`__enter__` gives the trees, `__exit__` closes them)

What each section pins:

- Opening. The whole tuple is judged before anything is opened. A relative mount, a `..`, a
  NUL or a `//` anchor in one, a duplicate (spelled the same after `Path` normalises it) or one
  mount inside another (any pair, adjacent or not) is `ValueError`, and nothing is opened
  through `os_`. Two mounts whose names only share a prefix (`lessons`, `lessons-questioner`)
  are not nested. The empty tuple, an unknown label's list, opens nothing, maps nothing, and
  answers `ValueError` for every `mount`. Otherwise each mount is held once, in the order given
  (never sorted), by its own spelling, through the `os_` given (exactly `len(mounts)` opens by
  path), and never again by path, whatever runs through the handles. `.mounts` is the tuple as
  given, as `Path`s. If a mount cannot be held (missing, not a directory, or a fault of `os_`:
  an `OSError`, a `ValueError`, or a `BaseException` that is no `Exception`), that exception
  propagates as itself, and every root already held has been closed by the time it does. This
  is checked while the traceback still holds the call's frames, so a handle that was only
  dropped is still open there.
- `tree_for(path)`. Purely lexical: no `os_` call, nothing on disk read or made, nothing
  resolved. A mount spelled through a link maps only under that spelling, and a link at a record
  or a holding folder neither moves a path out of its mount nor moves one in. Containment is by
  whole path components (`lessons-questioner/x` is never in `lessons`). The answer is the very
  `Held` opened for that mount (one object per mount, never re-held per call) and the POSIX name
  below it, a `str`. The mount itself is `"."`, however `pathlib` spells it. A catalog path maps
  to the `skills/` handle with its `gather/queries/...` name, never to a handle rooted at the
  catalog. A `..` below a mount is `ValueError`. A path outside every mount is `None`, including
  a `..` that would collapse into a mount, which is never re-homed there. The same `..` spelling
  is `ValueError` or `None` depending only on whether it sits below a held mount. A relative
  path is `ValueError`, even with the cwd set so that it would name a real mount (`DrainTrees`
  has no repo root to join it to, and `None` would send the caller to a plain path), and so is
  a path anchored at `//`. Every matrix row asks `tree_for` with its plant already in place.
- `mount(path)`. The same `Held` `tree_for` hands out, for an exact mount point under the same
  normalisation. Any other path is `ValueError`: inside a mount, its parent, the catalog, a
  `..` spelling, a sibling, a relative path.
- Lifetime. `__enter__` gives the trees themselves. `__exit__` closes every root exactly once,
  also while any exception unwinds (`asyncio.CancelledError` and other `BaseException`s
  included), and that exception propagates as itself. `close()` is idempotent: nothing closes a
  root a second time after it (a second `close()`, the exit, each handle's own `close()`, garbage
  collection). A root whose close fails (EIO) leaves no other root open; the close fault is not
  swallowed, and a work-step exception unwinding at the time stays reachable from what
  propagates. After `close()`, `write`, `mkdir` and `unlink` are `OSError(EBADF)` and touch nothing. A
  view taken before the close answers `Bad file descriptor` from `read`, and so
  does `entries()` of the record's folder and of the folder the drain lists (neither raises).
  `tree_for` and `mount` still answer, with the closed `Held`.
- The handles are the real `Held`, both by exact type and by behaviour. Mounts renamed away
  after `open`, with a fresh folder or a link to an outside folder put at each path, are still
  the folders written, read and listed, through every route asked after the swap (`tree_for` of
  a record, `mount`, `tree_for` of the mount point): no route re-resolves a mount by its name.
  (v1's E2 hole was a look-alike handle that passed every equality check.)
- D7's matrix, over three trees under one working copy. `lessons/` and `lessons-questioner/`
  are flat: their record sits at the mount's top level, so a plant goes at the name only.
  `skills/` holds `gather/defender-sql.md`, `gather/queries/elastic/failed-logons.md` and the
  record `gather/queries/elastic/_draft/x.md`. Its holding folders `gather`, `gather/queries`,
  `<sys>` (`elastic`) and `_draft` are each a plant site. Every handle comes from `tree_for` of
  the record's absolute path, the drain's shape, and is planted after `open`. The verbs:
  `Held.write` in the two modes the drain uses (`replace`, `create`), `Held.unlink`,
  `Held.mkdir` (of the draft folder), through `held.view()` `read`, and `entries()` of the
  record's folder (the record's row there is its kind). The listings are the tree's fixed shape:
  for skills `view().under("gather/queries")` and, below it, `elastic` and `elastic/_draft` (the
  catalog's `<sys>/_draft/<file>.md`), each listed by its own `under(...).entries()`; for a
  corpus `view()` (flat). The plants at the name are a symlink to an outside file, a symlink to an
  outside folder, a hard link, a FIFO and a directory. At a holding folder they are a link to an
  outside folder that holds the rest of the name, and a plain file. For the listings, a plant is
  at the listed folder, above it, or below it. Each row asserts three things.
  (1) Nothing is read from or written at what the plant reaches: the census of the whole tmp
  dir is unchanged, a read's answer holds none of its bytes, and over a FIFO a writer parked in
  its open stays parked through every verb that judges by a listing (nothing opened it to read).
  (2) The plant is left in place: same type, inode, link count and link target.
  (3) The control: the plant removed, the same verb through the SAME handle succeeds on the same
  address, byte-exact. Writes land `PAYLOAD`, which holds a NUL and bytes that are not UTF-8, so
  no text path can reproduce it. A refusal at the name is exactly `_io.NotPlainEntry`, a linked
  folder exactly `OSError(ELOOP)` and a file at a folder exactly `NotADirectoryError`, each with
  the core's errno and alias mark (`_spec1133.assert_refusal`).
- O3, the headline regression (C2's shape). With `skills/gather/queries`, `gather`, `elastic`
  or `_draft` replaced by a link to an EMPTY outside folder, by a dangling link, or by a plain
  file, a draft written through `tree_for`'s handle is refused, nothing lands at or creates the
  target, and the plant stays. The control, plant removed, lands the draft under `skills/`.
- No following open, by any route. A child interpreter (`_drain_trees_1134.child`) runs each
  matrix row whose plant reaches something (a link to a file or a folder, a hard link's other
  name, a linked holding folder) through `DrainTrees` with an audit hook armed. Nothing may be
  opened by a spelling that could follow a link: an absolute path under the tmp dir or under
  `/proc`, a relative name spanning folders, or a relative name other than `.` opened without
  `O_NOFOLLOW`. No descriptor opened or listed may name anything under the outside folder, no
  target is named, and no process is spawned. In each row the child also asks `mount` and
  `tree_for` of every mount point while armed: each answers the held root, opening nothing. Non-vacuity: in each row the watch sees, and the
  rule flags, an `O_PATH` open of the plant by its absolute spelling. The rows that list a
  folder or read a leaf also show the call's own opens.

Not repeated here: the bare core verbs' own rules, pinned by #1133 (`test_1133_*`) and step 1
(`test_1134_tree_listing.py`). That covers the name grammar, a folder removed under its own
listing, the errno ladders, and the close race.

Every plant is a real filesystem entry. Fakes enter only through `DrainTrees.open(..., os_=)`,
as pass-throughs over the real `os` (`_spec1133.OsSpy`, `_tree_listing_1134.CallRecorder`).
Nothing is monkeypatched (`monkeypatch.chdir` only sets the cwd). The worker never installs an
audit hook and never forks; the one child runs under a deadline.

Red before #1134 step 2: `defender/learning/core/lane_trees.py` does not exist, so this module
fails at import. An adversary pass against v2's first version of this file greened five holes;
the rows that close each say so: H1 (`mount` or `tree_for` of a mount point re-resolving the
mount by name), H2 (`tree_for` peeking at the disk), H3 (cleanup skipping a `BaseException`),
H4 (nesting judged only between neighbours), H5 (mounts held in sorted order). v3's scoped
adversary pass over the retargeted rows greened one more, closed by its own row: v3-H1 (each
mount held over its `realpath`, not its spelling). The kind and walk rows were retargeted from
B2's helpers onto `entries()` when the helpers moved to their first consumers (2026-10-03);
each keeps its three assertions (nothing reached, the plant left in place, the control exact)
and the swapped-mount rows still list through the held roots.
"""
from __future__ import annotations

import asyncio
import dataclasses
import errno
import gc
import os
import shutil
import stat
from collections.abc import Callable
from pathlib import Path, PurePosixPath
from typing import Any

import pytest

from defender import _io
from defender.learning.core.lane_trees import DrainTrees
from defender.tests import _spec1133 as S
from defender.tests._drain_trees_1134 import (
    FILE_VERBS,
    PAYLOAD,
    PAYLOAD_TEXT,
    do_verb,
    watch_in_child,
)
from defender.tests._tree_listing_1134 import (
    CHILD_DEADLINE,
    HOST_BYTES,
    CallRecorder,
    ParkedWriter,
    Planted,
    census,
    descriptors_under,
    plant_entry,
    plant_folder,
    put_plain,
)
from defender.tests.test_1111_rooted_io import in_time

# ---------------------------------------------------------------------------------------
# The working copy: three drain mounts and an outside folder
# ---------------------------------------------------------------------------------------

LESSONS, QUESTIONER, SKILLS = "lessons", "lessons-questioner", "skills"
#: The three trees a drain box mounts writable, in `DrainLabel.writable_trees`' order.
LABELS = (LESSONS, QUESTIONER, SKILLS)

#: Each mount's record under test, below the mount. Nothing is there until a plant or a control
#: puts something there.
RECORD = {
    LESSONS: "bastion-session-interactivity-signal.md",
    QUESTIONER: "asks-which-host-owns-the-session.md",
    SKILLS: "gather/queries/elastic/_draft/x.md",
}
#: The files each mount holds beside its record.
NEIGHBOURS = {
    LESSONS: ("example-seed-lesson.md",),
    QUESTIONER: ("names-the-window-before-the-query.md",),
    SKILLS: ("gather/defender-sql.md", "gather/queries/elastic/failed-logons.md"),
}
#: The catalog: the folder of the skills mount the drain lists.
CATALOG = "gather/queries"
#: The skills record's holding folders below the mount, outermost first.
SKILL_SITES = tuple(PurePosixPath(p) for p in (
    "gather", "gather/queries", "gather/queries/elastic", "gather/queries/elastic/_draft"))
#: The folders below the listed one in each tree's known shape, each listed on its own: a corpus
#: is flat, the catalog is at most `<sys>/_draft/<file>.md` (addendum 2, B2).
BELOW = {LESSONS: (), QUESTIONER: (), SKILLS: ("elastic", "elastic/_draft")}
#: What the drain's listings hold (relative to the listed folder: the corpus mount, or the
#: catalog under skills) once the record is a plain file, written out in path-parts order.
LISTING = {
    LESSONS: [("bastion-session-interactivity-signal.md", "file"),
              ("example-seed-lesson.md", "file")],
    QUESTIONER: [("asks-which-host-owns-the-session.md", "file"),
                 ("names-the-window-before-the-query.md", "file")],
    SKILLS: [("elastic", "dir"), ("elastic/_draft", "dir"), ("elastic/_draft/x.md", "file"),
             ("elastic/failed-logons.md", "file")],
}

#: The text a `read` control reads back (a text read of `PAYLOAD` is refused, by design).
TEXT = "a plain lesson, ünïcode and all\n"
ALIAS = _io.ALIAS_READ_REFUSAL
NOT_A_DIR = os.strerror(errno.ENOTDIR)
BAD_FD = os.strerror(errno.EBADF)


def leaf(name: str) -> str:
    """The last component of a record name: its row in its folder's listing."""
    return PurePosixPath(name).name


def folder_rows(rows: list[tuple[str, str]], folder: str) -> dict[str, str]:
    """The rows `folder`'s own listing holds, out of a listed tree's `(name, kind)` rows named
    relative to its top (`""` is the top)."""
    return {n.rpartition("/")[2]: k for n, k in rows if n.rpartition("/")[0] == folder}


#: Each tree's listings, folder by folder (`""` the listed folder), once the record is plain.
LISTINGS = {label: {folder: folder_rows(LISTING[label], folder)
                    for folder in ("", *BELOW[label])} for label in LABELS}


@dataclasses.dataclass(frozen=True)
class Drain:
    """A tmp working copy `wc` holding the three mounts under `wc/defender/`, and an `outside`
    folder beside it, where links point and hard links keep their other names. `tmp` holds
    both, and the census is taken over it."""

    tmp: Path

    @property
    def wc(self) -> Path:
        return self.tmp / "wc"

    @property
    def defender(self) -> Path:
        return self.wc / "defender"

    @property
    def outside(self) -> Path:
        return self.tmp / "outside"

    def mount(self, label: str) -> Path:
        return self.defender / label

    @property
    def mounts(self) -> tuple[Path, ...]:
        return tuple(self.mount(label) for label in LABELS)

    def path(self, label: str) -> Path:
        """The record's absolute path, as the drain spells it to `tree_for`."""
        return self.mount(label) / RECORD[label]

    def build(self, *labels: str) -> None:
        """Each mount's neighbours and its record's holding folders, real. Existing files are
        left as they are."""
        for label in labels or LABELS:
            for rel in NEIGHBOURS[label]:
                at = self.mount(label) / rel
                if not at.exists():
                    put_plain(at, f"{label}/{rel}: a neighbour no call may disturb\n".encode())
            self.path(label).parent.mkdir(parents=True, exist_ok=True)


def make_drain(tmp: Path) -> Drain:
    d = Drain(tmp)
    d.outside.mkdir(parents=True)
    d.build()
    return d


@pytest.fixture
def drain(tmp_path: Path) -> Drain:
    return make_drain(tmp_path)


@pytest.fixture
def trees(drain: Drain) -> Any:
    with DrainTrees.open(drain.mounts) as opened:
        yield opened


def assert_maps(trees: Any, spelled: Any, mount: Path, name: str) -> None:
    """`tree_for(spelled)` is the very `Held` held for `mount` and the POSIX `name` below it."""
    got = trees.tree_for(spelled)
    assert got is not None, f"{spelled!r} did not map (expected {mount} + {name!r})"
    held, rel = got
    assert type(held) is _io.Held, f"{spelled!r} mapped to a {type(held).__name__}, not a Held"
    assert held is trees.mount(mount), f"{spelled!r} mapped to a handle other than {mount}'s"
    assert type(rel) is str, f"{spelled!r} mapped to a {type(rel).__name__} name"
    assert rel == name, f"{spelled!r} mapped to {rel!r}, not {name!r}"


def handle(trees: Any, d: Drain, label: str) -> tuple[Any, str]:
    """The record's `(held, name)`, as the drain gets it: `tree_for` of its absolute path."""
    assert_maps(trees, d.path(label), d.mount(label), RECORD[label])
    return trees.tree_for(d.path(label))


def refused_value_error(fn: Callable[[], Any], what: str) -> None:
    """`fn()` raised `ValueError` (the type is the contract; no wording is settled). A return,
    `None` included, fails the row; any other exception propagates as itself."""
    try:
        got = fn()
    except ValueError:
        return
    pytest.fail(f"{what} was not refused with ValueError; it answered {got!r}")


# ---------------------------------------------------------------------------------------
# Plants, their state, and the deadline
# ---------------------------------------------------------------------------------------

#: Plants AT the record's name: a link to an outside file, a link to an outside folder (holding
#: `inner.md`), a hard link (its other name outside), a FIFO, a directory (holding `keep`).
NAME_PLANTS = ("symlink", "dir_link_outside", "hardlink", "fifo", "directory")
#: Plants AT a holding folder: a link to an outside folder that holds the rest of the record's
#: name (so a following verb would find a real file there), and a plain file.
FOLDER_PLANTS = ("folder_link_outside", "folder_file")

#: The record's row in its folder's listing for a plant AT the record's name: the entry itself,
#: as the listing judges it. A plant at a holding folder is never a row: it is that listing's
#: refusal, with `READ_REASON`'s reason (`expected_row`).
KIND_OF = {"symlink": "other", "dir_link_outside": "other", "hardlink": "file", "fifo": "other",
           "directory": "dir"}
#: How a listing lists a plant at its own name: a link of any sort is `other`, a plain file `file`.
LISTED_KIND = {"symlink": "other", "dir_link_outside": "other", "folder_link_outside": "other",
               "folder_file": "file"}
#: A refused read's reason: the alias sentence for a plant at the name or a linked folder,
#: `Not a directory` for a file at a folder.
READ_REASON = {**dict.fromkeys((*NAME_PLANTS, "folder_link_outside"), ALIAS),
               "folder_file": NOT_A_DIR}
#: The class each refusal raises, exactly: the core's leaf refusal for a plant at the name, the
#: core's folder refusals otherwise.
REFUSAL_TYPE = {**dict.fromkeys(NAME_PLANTS, _io.NotPlainEntry),
                "folder_link_outside": OSError, "folder_file": NotADirectoryError}


def _rows(name_plants: tuple[str, ...], folder_plants: tuple[str, ...]) -> list[Any]:
    rows = [pytest.param(label, None, kind, id=f"{label}:{kind}@name")
            for label in LABELS for kind in name_plants]
    rows += [pytest.param(SKILLS, site, kind, id=f"skills:{kind}@{site}")
             for site in SKILL_SITES for kind in folder_plants]
    return rows


PLANT_ROWS = _rows(NAME_PLANTS, FOLDER_PLANTS)


def plant(d: Drain, label: str, site: PurePosixPath | None, kind: str) -> Planted:
    """`kind` at the record's own name (`site` None), or at its holding folder `site`, which
    replaces the real folder and what it held."""
    if site is None:
        return plant_entry(d.path(label), kind, root=d.mount(label), host=d.outside)
    shutil.rmtree(d.mount(label) / site)
    return plant_folder(d.mount(label), PurePosixPath(RECORD[label]), site, kind,
                        host=d.outside)


def entry_state(at: Path) -> tuple[Any, ...]:
    """The planted entry itself, judged without following it: its type, inode, link count and,
    for a link, its target. Equal before and after means the same entry was left in place."""
    st = os.lstat(at)
    target = os.readlink(at) if stat.S_ISLNK(st.st_mode) else None
    return stat.S_IFMT(st.st_mode), st.st_ino, st.st_nlink, target


def raised(fn: Callable[[], Any]) -> BaseException:
    """What `fn` raised. A return fails the row."""
    try:
        got = fn()
    except Exception as e:  # noqa: BLE001 — the refusal under test, judged by the caller
        return e
    pytest.fail(f"the call was not refused; it answered {got!r}")


def judged_by_stat(fn: Callable[[], Any], planted: Planted) -> Any:
    """`fn()` under `in_time`'s deadline (its exception re-raised). Over a FIFO plant a writer is
    first parked in the FIFO's open, and it must still be parked once the call is done: nothing
    opened the FIFO to read. Non-vacuity: the reader opened afterwards is what lets it go."""
    if planted.fifo is None:
        return in_time(fn)
    with ParkedWriter(planted.fifo) as writer:
        try:
            return in_time(fn, fifo=planted.fifo)
        finally:
            assert writer.parked(), "the call opened the FIFO to read: the parked writer went"
            assert writer.release(), "the writer was never parked in its open; the check is void"


def assert_refused(exc: BaseException, kind: str, *, where: str) -> None:
    """The core's row for a `kind` plant (type, errno, alias mark), and exactly its class."""
    S.assert_refusal(exc, "symlink" if kind == "dir_link_outside" else kind, where=where)
    want = REFUSAL_TYPE[kind]
    assert type(exc) is want, f"{where}: raised {type(exc).__name__}, not exactly {want.__name__}"


def assert_landed(d: Drain, label: str) -> None:
    """`PAYLOAD` is at the record: one plain single-linked file, below real holding folders,
    with no staged name left beside it."""
    at = d.path(label)
    st = os.lstat(at)
    assert stat.S_ISREG(st.st_mode), f"{at} is not a regular file"
    assert st.st_nlink == 1, f"{at} has {st.st_nlink} names"
    assert at.read_bytes() == PAYLOAD
    for parent in at.relative_to(d.mount(label)).parents[:-1]:
        assert stat.S_ISDIR(os.lstat(d.mount(label) / parent).st_mode), f"{parent} is not real"
    assert not [n for n in os.listdir(at.parent) if ".staged-" in n], "a staged name was left"


# =======================================================================================
# Opening: the whole list judged first, then one hold per mount
# =======================================================================================

def _malformed(d: Drain) -> dict[str, tuple[Any, ...]]:
    """Mount lists `open` refuses, each with its bad member LAST, so a judge that opened as it
    went would already have opened the good ones."""
    les, que, ski = d.mounts
    return {
        "relative": (les, que, Path("defender/skills")),
        "relative-str": (les, que, "defender/skills"),
        "dotdot": (les, que, d.defender / "other" / ".." / "skills"),
        "dotdot-at-the-end": (les, que, ski / "gather" / ".."),
        "duplicate": (les, que, ski, les),
        "duplicate-trailing-slash": (les, que, ski, f"{ski}/"),
        "duplicate-dot": (les, que, ski, que / "."),
        "nested-catalog-after-skills": (les, que, ski, ski / CATALOG),
        "nested-skills-after-catalog": (ski / CATALOG, ski),
        "nested-parent-after-child": (les, que, d.defender),
        "nested-child-after-parent": (d.defender, les),
        # #1134 step 2, H4: nesting judged between EVERY pair, not only neighbours in the list.
        "nested-not-adjacent-child-later": (les, ski, les / "sub", que),
        "nested-not-adjacent-parent-later": (les / "sub", ski, les),
        "relative-with-a-missing-absolute-before-it": (d.tmp / "no-such-mount", "lessons"),
        # A NUL can name no folder; refused before any open, wherever it sits.
        "nul-first": (Path(f"{les}\0x"), que, ski),
        "nul-last": (les, que, Path(f"{ski}\0x")),
        # `//x` is its own anchor to `pathlib` (it would match no mount lexically), while the OS
        # opens it as `/x`.
        "double-slash-anchor-alone": (Path("//" + str(les).lstrip("/")),),
        "double-slash-anchor-last": (les, que, Path("//" + str(ski).lstrip("/"))),
    }


@pytest.mark.parametrize("case", list(_malformed(Drain(Path("/x")))))
def test_open_judges_the_whole_list_before_opening_anything(drain, case):
    """A relative mount, a `..`, a NUL or a `//` anchor in one, a duplicate (equal once `Path`
    normalises a trailing `/` or a `.`) or one mount inside another (adjacent in the list or not)
    is `ValueError`, and nothing is opened through `os_`,
    nothing is left open, and nothing changes. That holds even when the bad mount comes after
    good ones, or after a missing one (which a hold would answer `FileNotFoundError`).
    Control: two mounts whose names only share a prefix (`lessons`, `lessons-questioner`) are
    not nested, and open, once each."""
    d = drain
    spy = S.OsSpy()
    before = census(d.tmp)

    with pytest.raises(ValueError):  # noqa: PT011 — the type is the contract; no wording is settled
        DrainTrees.open(_malformed(d)[case], os_=spy)

    assert spy.opens == [], f"{case}: opened {[o.path for o in spy.opens]} before refusing"
    assert descriptors_under(d.tmp) == []
    assert census(d.tmp) == before

    siblings = (d.mount(LESSONS), d.mount(QUESTIONER))
    with DrainTrees.open(siblings, os_=spy) as trees:
        assert [(o.path, o.dir_fd) for o in spy.opens] == [(str(m), None) for m in siblings]
        assert trees.mounts == siblings


#: Mount lists in the order given: the drain's, and one no sort would keep (#1134 step 2, H5).
ORDERS = {"drain": (LESSONS, QUESTIONER, SKILLS), "skills-first": (SKILLS, LESSONS, QUESTIONER)}


@pytest.mark.parametrize("order", list(ORDERS))
def test_open_holds_each_mount_once_in_order_by_its_spelling_and_never_again_by_path(
        drain, order):
    """Exactly one open by path per mount, in the order given (never sorted), of the mount as
    spelled, through the `os_` given. `.mounts` is the tuple as given, in that order, each a
    `Path` (a `str` member is coerced). Then every verb through every handle opens nothing by
    path: the roots are held, not re-resolved and not re-held per call."""
    d = drain
    spy = S.OsSpy()
    given = tuple(d.mount(label) for label in ORDERS[order])
    given = (str(given[0]), *given[1:])

    with DrainTrees.open(given, os_=spy) as trees:
        assert [(o.path, o.dir_fd, o.errno) for o in spy.opens] == [
            (str(m), None, None) for m in given]
        assert type(trees.mounts) is tuple
        assert trees.mounts == tuple(Path(m) for m in given)
        assert all(isinstance(m, Path) for m in trees.mounts), trees.mounts
        for label in LABELS:
            held, name = handle(trees, d, label)
            held.write(name, PAYLOAD, mode="replace")
            assert d.path(label).read_bytes() == PAYLOAD
            assert held.view().read(name, errors="replace").text == PAYLOAD_TEXT
            assert do_verb(held, name, "entries").entries[leaf(name)] == "file"
            assert held.unlink(name) is True
        by_path = [o.path for o in spy.opens if o.dir_fd is None]
        assert by_path == [str(m) for m in given], f"a verb re-opened a root: {by_path}"
        assert len(spy.opens) > len(d.mounts), "the verbs went around the os_ the trees were given"


class Boom(BaseException):
    """A fault that is no `Exception`, as `KeyboardInterrupt` and `asyncio.CancelledError` are
    not: a cleanup keyed on `Exception` or `OSError` misses it (#1134 step 2, H3)."""


#: Faults an `os_` raises opening a root by path, each made afresh per row: its own `OSError`,
#: a non-`OSError` `Exception` (`os.open`'s own answer to a NUL), and two `BaseException`s.
INJECTED: dict[str, Callable[[Path], BaseException]] = {
    "os_fault": lambda bad: OSError(errno.EIO, "an os_ fault opening the root", str(bad)),
    "value_error": lambda bad: ValueError("embedded null byte"),
    "boom": lambda bad: Boom(f"the batch is torn down while holding {bad}"),
    "cancelled": lambda bad: asyncio.CancelledError(),
}


class RefusesToOpen(S.OsSpy):
    """`S.OsSpy`, except that opening `root` by path raises `error`, that one instance."""

    def __init__(self, root: Path, error: BaseException) -> None:
        super().__init__()
        self.root, self.error = str(root), error

    def open(self, path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        if kwargs.get("dir_fd") is None and str(path) == self.root:
            raise self.error
        return super().open(path, flags, *args, **kwargs)


@pytest.mark.parametrize("fault", ["missing", "not_a_directory", *INJECTED])
@pytest.mark.parametrize("failing", [0, 1, 2], ids=LABELS)
def test_a_mount_that_cannot_be_held_raises_as_itself_once_every_root_held_before_it_is_closed(
        drain, failing, fault):
    """The failing mount's own exception propagates unchanged: the very instance `os_` raised
    (an `OSError`, a `ValueError`, or a `BaseException` that is no `Exception`), or the hold's
    `FileNotFoundError` / `NotADirectoryError` naming that mount. Every root held
    before it was passed to `os_.close` and no descriptor is left open on the tree. Both are
    checked while `info` still holds the traceback, so a handle the call only dropped would
    still be alive (and open) there. No mount after the failing one was opened. Nothing
    changes."""
    d = drain
    bad = d.mounts[failing]
    error = INJECTED[fault](bad) if fault in INJECTED else None
    if error is None:
        shutil.rmtree(bad)
        if fault == "not_a_directory":
            bad.write_bytes(b"a file where the mount should be\n")
    spy = S.OsSpy() if error is None else RefusesToOpen(bad, error)
    want = type(error) if error is not None else (
        FileNotFoundError if fault == "missing" else NotADirectoryError)
    before = census(d.tmp)

    with pytest.raises(want) as info:
        DrainTrees.open(d.mounts, os_=spy)

    if error is not None:
        assert info.value is error, f"the os_ fault was replaced by {info.value!r}"
    else:
        assert type(info.value) is want, f"{fault}: raised {info.value!r}, not {want.__name__}"
        assert info.value.filename == str(bad), info.value
    attempted = d.mounts[:failing + (error is None)]
    assert [o.path for o in spy.opens] == [str(m) for m in attempted]
    held = [o.fd for o in spy.opens if o.fd is not None]
    assert len(held) == failing
    assert set(held) <= set(spy.closes), f"roots {held} held, closed {spy.closes}"
    assert descriptors_under(d.tmp) == [], "a root held before the failure is still open"
    assert census(d.tmp) == before


def test_an_empty_mount_list_holds_nothing_and_maps_nothing(drain):
    """An unknown label's list is `()`: nothing is opened, `.mounts` is `()`, every absolute
    path is `None` (the real mount points included), every `mount` is `ValueError`, and a
    relative path is still `ValueError`."""
    d = drain
    spy = S.OsSpy()
    with DrainTrees.open((), os_=spy) as trees:
        assert trees.mounts == ()
        for p in (*d.mounts, *(d.path(label) for label in LABELS), d.wc, Path("/")):
            assert trees.tree_for(p) is None, str(p)
            assert trees.tree_for(str(p)) is None, str(p)
            refused_value_error(lambda p=p: trees.mount(p), f"mount({p})")
        refused_value_error(lambda: trees.tree_for("defender/lessons/x.md"), "a relative path")
        refused_value_error(lambda: trees.mount("defender/lessons"), "a relative mount")
    assert (spy.opens, spy.closes) == ([], [])


# =======================================================================================
# tree_for: lexical, by components, the held root and the POSIX name below it
# =======================================================================================

#: Names below each mount: its own files, a deep name, the catalog folder, and names under
#: folders that do not exist (mapping makes nothing).
MAPPED = [
    (LESSONS, "example-seed-lesson.md"),
    (LESSONS, RECORD[LESSONS]),
    (LESSONS, "sub/deeper/y.md"),
    (QUESTIONER, "names-the-window-before-the-query.md"),
    (QUESTIONER, "_index/z.md"),
    (SKILLS, "gather/defender-sql.md"),
    (SKILLS, CATALOG),
    (SKILLS, "gather/queries/elastic/failed-logons.md"),
    (SKILLS, RECORD[SKILLS]),
    (SKILLS, "gather/queries/newsys/_draft/0a1b2c3d.md"),
]


@pytest.mark.parametrize(("label", "name"), MAPPED)
def test_tree_for_maps_a_path_in_a_mount_to_that_mounts_held_root_and_its_posix_name(
        drain, trees, label, name):
    """As a `Path` and as a `str`: the `Held` held for that mount (the same object
    `mount(...)` answers) and the name below it, a POSIX `str` with no leading `./`. Mapping
    reads and makes nothing: an absent name stays absent."""
    d = drain
    before = census(d.tmp)
    for spelled in (d.mount(label) / name, str(d.mount(label) / name)):
        assert_maps(trees, spelled, d.mount(label), name)
    assert census(d.tmp) == before


@pytest.mark.parametrize("label", LABELS)
def test_a_mount_point_maps_to_dot_however_pathlib_spells_it(drain, trees, label):
    m = drain.mount(label)
    for spelled in (m, str(m), f"{m}/", m / ".", f"{m}/."):
        assert_maps(trees, spelled, m, ".")


def test_containment_is_by_whole_path_components_never_by_string_prefix(drain):
    """With all three mounts held, a questioner path maps to the questioner mount, never to
    `lessons`. With `lessons` alone, the questioner mount and every sibling whose name only
    extends `lessons` (`lessons-other/`, `lessons.md`) are `None`; with `skills` alone, so are
    `skillsX/` and `skills-old/`. Controls: a path in the held mount maps."""
    d = drain
    les, que, ski = d.mounts
    with DrainTrees.open(d.mounts) as all_three:
        for spelled in (que / "x.md", f"{que}/x.md"):
            assert_maps(all_three, spelled, que, "x.md")
        assert_maps(all_three, les / "x.md", les, "x.md")
    with DrainTrees.open((les,)) as lessons_only:
        for spelled in (que, que / "x.md", f"{que}/x.md", d.defender / "lessons-other" / "x.md",
                        d.defender / "lessons.md", f"{les}x/y.md"):
            assert lessons_only.tree_for(spelled) is None, str(spelled)
        assert_maps(lessons_only, les / "x.md", les, "x.md")
    with DrainTrees.open((ski,)) as skills_only:
        for spelled in (d.defender / "skillsX" / "y", d.defender / "skills-old" / "y",
                        f"{ski}X/gather/x.md"):
            assert skills_only.tree_for(spelled) is None, str(spelled)
        assert_maps(skills_only, ski / "y", ski, "y")


#: A `..` component below a mount: right below it, deeper, at the end, and one that would
#: collapse into a sibling mount. Each is beside its control, the `..` made a plain folder.
DOTDOT_BELOW = [
    (LESSONS, "a/../b.md"),
    (LESSONS, "../x.md"),
    (LESSONS, ".."),
    (QUESTIONER, "../lessons/x.md"),
    (SKILLS, "gather/queries/../../../lessons/x.md"),
    (SKILLS, "gather/queries/elastic/_draft/.."),
]


@pytest.mark.parametrize(("label", "dotted"), DOTDOT_BELOW)
def test_a_dotdot_below_a_mount_is_value_error(drain, trees, label, dotted):
    """`ValueError`, as a `Path` and as a `str`: never `None` (which would send the caller to a
    plain path) and never a name with `..` in it. Control: the same path with each `..` a plain
    folder maps, the name kept as written."""
    m = drain.mount(label)
    for spelled in (m / dotted, f"{m}/{dotted}"):
        refused_value_error(lambda s=spelled: trees.tree_for(s), f"tree_for({spelled})")
    plain = dotted.replace("..", "up")
    assert_maps(trees, m / plain, m, plain)


#: A `..` outside every mount, spelled from the working copy: collapsed, each lands in a mount.
DOTDOT_OUTSIDE = [
    "defender/learning/../lessons/x.md",
    "defender/../defender/lessons-questioner/x.md",
    "defender/other/../skills/gather/queries/elastic/_draft/x.md",
    "../wc/defender/skills/gather/defender-sql.md",
    "defender/other/../lessons",
]


@pytest.mark.parametrize("dotted", DOTDOT_OUTSIDE)
def test_a_dotdot_outside_every_mount_is_none_never_rehomed_into_one(drain, trees, dotted):
    """`None`, as a `Path` and as a `str`: never collapsed and mapped into the mount it would
    land in, and never `ValueError`. Control: the collapsed spelling maps into that mount."""
    d = drain
    spelled = d.wc / dotted
    assert trees.tree_for(spelled) is None
    assert trees.tree_for(str(spelled)) is None
    collapsed = Path(os.path.normpath(spelled))
    home = next(m for m in d.mounts if collapsed == m or collapsed.is_relative_to(m))
    assert_maps(trees, collapsed, home, collapsed.relative_to(home).as_posix())


def test_one_dotdot_spelling_is_value_error_below_a_held_mount_and_none_outside_them(drain):
    """`<defender>/skills/../lessons/x.md` is below the skills mount when skills is held
    (`ValueError`), and outside every mount when only the two corpora are (`None`, not
    re-homed into `lessons`)."""
    d = drain
    les, que, ski = d.mounts
    dotted = d.defender / "skills" / ".." / "lessons" / "x.md"
    for mounts in (d.mounts, (ski,)):
        with DrainTrees.open(mounts) as with_skills:
            refused_value_error(lambda t=with_skills: t.tree_for(dotted), "below skills")
    with DrainTrees.open((les, que)) as corpora:
        assert corpora.tree_for(dotted) is None
        assert_maps(corpora, les / "x.md", les, "x.md")


def test_a_path_outside_every_mount_is_none(drain, trees):
    """The mounts' parent, the working copy, other trees in it, siblings whose names extend a
    mount's, another working copy, the outside folder, a host path and `/`: each `None`, as a
    `Path` and as a `str`. Control: a name in each mount maps."""
    d = drain
    outside = [d.defender, d.wc, d.tmp, d.defender / "learning" / "x", d.defender / "tests" / "x.py",
               d.defender / "lessons-other" / "x.md", d.defender / "lessons.md",
               d.defender / "skillsX" / "y", d.defender / "skills-old" / "y",
               d.tmp / "wc-other" / "defender" / "lessons" / "x.md", d.outside / "x.md",
               Path("/etc/passwd"), Path("/")]
    for p in outside:
        assert trees.tree_for(p) is None, str(p)
        assert trees.tree_for(str(p)) is None, str(p)
    for m in d.mounts:
        assert_maps(trees, m / "x.md", m, "x.md")


#: Relative spellings: repo-relative, mount-relative, a bare name, the cwd itself.
RELATIVE = ("defender/lessons/x.md", "defender/lessons", "lessons/x.md", "lessons", "x.md", ".",
            "", "./defender/skills/gather/queries/elastic/_draft/x.md", "../lessons/x.md")


@pytest.mark.parametrize("cwd", ["wc", "defender", "lessons"])
def test_a_relative_path_is_refused_even_where_the_cwd_makes_it_name_a_mount(
        drain, trees, monkeypatch, cwd):
    """`DrainTrees` has no repo root: a relative path is `ValueError` for `tree_for` and for
    `mount`, as a `str` and as a `Path`. The cwd is set so that each relative spelling names a
    real mount or a path in one, so joining it to the cwd would have mapped it. Control: the
    absolute spellings map."""
    d = drain
    monkeypatch.chdir({"wc": d.wc, "defender": d.defender, "lessons": d.mount(LESSONS)}[cwd])
    for spelled in RELATIVE:
        for form in (spelled, Path(spelled)):
            refused_value_error(lambda f=form: trees.tree_for(f), f"tree_for({form!r})")
            refused_value_error(lambda f=form: trees.mount(f), f"mount({form!r})")
    assert_maps(trees, d.mount(LESSONS) / "x.md", d.mount(LESSONS), "x.md")
    assert trees.mount(d.mount(LESSONS)) is trees.tree_for(d.mount(LESSONS))[0]


def test_a_path_anchored_at_two_slashes_is_value_error_never_none(drain, trees):
    """`//x` is its own anchor to `pathlib`, so it lies lexically under no mount, while the OS
    opens it as `/x`. `tree_for` and `mount` refuse it (`ValueError`), as a `str` and as a
    `Path`, for a record, a mount point and an outside path alike: never `None`, which would
    send the caller to a plain path that reaches the mount. Control: one `/` maps."""
    d = drain
    for p in (d.path(LESSONS), d.mount(SKILLS), d.mount(QUESTIONER) / "x.md", d.outside / "x.md"):
        doubled = "//" + str(p).lstrip("/")
        for form in (doubled, Path(doubled)):
            refused_value_error(lambda f=form: trees.tree_for(f), f"tree_for({form!r})")
            refused_value_error(lambda f=form: trees.mount(f), f"mount({form!r})")
    assert_maps(trees, d.path(LESSONS), d.mount(LESSONS), RECORD[LESSONS])
    assert_maps(trees, d.mount(SKILLS), d.mount(SKILLS), ".")
    assert trees.tree_for(d.outside / "x.md") is None


def test_a_catalog_path_maps_to_the_skills_mounts_handle_never_one_rooted_at_the_catalog(drain):
    """A template, a draft and the catalog folder itself map to the `skills/` mount's `Held`
    with their full names below `skills/` (decision 2: the trust root is the mount point). The
    catalog is no mount (`mount(catalog)` is `ValueError`) and is never opened by path. A draft
    spelled from the catalog folder, written through that handle, lands at `skills/<name>`."""
    d = drain
    ski = d.mount(SKILLS)
    spy = S.OsSpy()
    with DrainTrees.open(d.mounts, os_=spy) as trees:
        for name in (CATALOG, "gather/queries/elastic/failed-logons.md", RECORD[SKILLS]):
            assert_maps(trees, ski / name, ski, name)
        refused_value_error(lambda: trees.mount(ski / CATALOG), "the catalog is no mount")
        held, name = trees.tree_for(ski / CATALOG / "elastic" / "_draft" / "x.md")
        held.write(name, PAYLOAD, mode="replace")
    assert_landed(d, SKILLS)
    assert [o.path for o in spy.opens if o.dir_fd is None] == [str(m) for m in d.mounts]


def test_tree_for_and_mount_make_no_os_call_and_touch_nothing_on_disk(drain):
    """Mapping is lexical: after `open`, no `tree_for` or `mount` call (in a mount, a mount
    point, outside, deep under absent folders, refused for `..`, `mount` refused) asks `os_` for
    anything at all, the tree is unchanged, and an absent record stays absent."""
    d = drain
    rec = CallRecorder()
    with DrainTrees.open(d.mounts, os_=rec) as trees:
        mark = len(rec.calls)
        before = census(d.tmp)
        asked = [*d.mounts, *(d.path(label) for label in LABELS), d.defender, d.wc,
                 d.mount(SKILLS) / "gather/queries/newsys/_draft/0a1b2c3d.md",
                 d.mount(LESSONS) / "sub" / "deeper" / "y.md", d.outside / "x.md", Path("/")]
        for p in asked:
            trees.tree_for(p)
            trees.tree_for(str(p))
        for m in d.mounts:
            trees.mount(m)
        refused_value_error(lambda: trees.tree_for(d.mount(LESSONS) / ".." / "x.md"), "..")
        refused_value_error(lambda: trees.mount(d.defender), "the mounts' parent")
        refused_value_error(lambda: trees.tree_for("lessons/x.md"), "relative")
        assert rec.calls[mark:] == [], f"mapping asked os_ for {rec.calls[mark:]}"
        assert census(d.tmp) == before
        assert not os.path.lexists(d.path(LESSONS)), "mapping made the record"


def test_tree_for_is_lexical_no_link_moves_a_path_into_or_out_of_a_mount(drain):
    """Nothing is resolved. Held by their real spelling, the mounts do not map a path spelled
    through a link to the working copy, and `mount` refuses it. Held through that link, they map
    only the linked spelling, and `.mounts` keeps it. A record that is a link to an outside file,
    and a draft under a `gather/queries` replaced by a link to the outside folder, still map to
    their mount with their own names, while what those links reach is `None`. Nothing on disk
    changes."""
    d = drain
    les, _que, ski = d.mounts
    alias = d.tmp / "wc-alias"
    alias.symlink_to(d.wc, target_is_directory=True)
    aliased = tuple(alias / m.relative_to(d.wc) for m in d.mounts)
    put_plain(d.outside / "secret.md", HOST_BYTES)
    (les / "leak.md").symlink_to(d.outside / "secret.md")
    shutil.rmtree(ski / CATALOG)
    (ski / CATALOG).symlink_to(d.outside, target_is_directory=True)
    before = census(d.tmp)

    with DrainTrees.open(d.mounts) as real:
        for m in aliased:
            assert real.tree_for(m / "x.md") is None, str(m)
            assert real.tree_for(m) is None, str(m)
            refused_value_error(lambda m=m: real.mount(m), f"mount({m})")
        assert_maps(real, les / "leak.md", les, "leak.md")
        assert_maps(real, d.path(SKILLS), ski, RECORD[SKILLS])
        assert real.tree_for(d.outside / "secret.md") is None
        assert real.tree_for(d.outside / "elastic" / "_draft" / "x.md") is None
    with DrainTrees.open(aliased) as via_alias:
        assert via_alias.mounts == aliased
        for label, m in zip(LABELS, aliased, strict=True):
            assert_maps(via_alias, m / RECORD[label], m, RECORD[label])
        for m in d.mounts:
            assert via_alias.tree_for(m / "x.md") is None, str(m)
    assert census(d.tmp) == before


# =======================================================================================
# mount(): the held root of an exact mount point, and nothing else
# =======================================================================================

def test_a_mount_spelled_through_a_link_is_held_by_that_spelling_through_the_os_given(drain):
    """Each mount is opened by path exactly as spelled, never by a spelling resolved first:
    with the mounts spelled through a link to the working copy, the `os_` given sees one open
    by path per mount, of the linked spelling, in order (v3 step 2's adversary, H1: a holder
    that `realpath`s each mount before holding it greened every row whose mounts are
    `tmp_path`, already resolved). Through those handles a write lands in the real folder the
    link reaches, its folder's listing sees it, and nothing more is opened by path."""
    d = drain
    alias = d.tmp / "wc-alias"
    alias.symlink_to(d.wc, target_is_directory=True)
    aliased = tuple(alias / m.relative_to(d.wc) for m in d.mounts)
    spy = S.OsSpy()
    with DrainTrees.open(aliased, os_=spy) as trees:
        assert [(o.path, o.dir_fd) for o in spy.opens] == [(str(m), None) for m in aliased]
        for label, m in zip(LABELS, aliased, strict=True):
            held, name = trees.tree_for(m / RECORD[label])
            held.write(name, PAYLOAD, mode="replace")
            assert_landed(d, label)
            assert do_verb(held, name, "entries").entries[leaf(name)] == "file"
        by_path = [o.path for o in spy.opens if o.dir_fd is None]
        assert by_path == [str(m) for m in aliased], f"a verb re-opened a root: {by_path}"


def test_mount_answers_the_held_root_of_an_exact_mount_point_and_nothing_else(drain, trees):
    """For each mount point, however `pathlib` spells it: the `Held` `tree_for` hands out for
    every path in that mount. A path in a mount, the mounts' parent, the catalog, a `..`
    spelling of a mount, a sibling whose name extends a mount's, the outside folder and `/`
    are each `ValueError`, as a `Path` and as a `str`."""
    d = drain
    les, _que, ski = d.mounts
    for label in LABELS:
        m = d.mount(label)
        held = trees.mount(m)
        assert type(held) is _io.Held
        for spelled in (str(m), f"{m}/", m / ".", f"{m}/."):
            assert trees.mount(spelled) is held, repr(spelled)
        assert trees.tree_for(d.path(label))[0] is held
    not_mounts = [les / "x.md", ski / CATALOG, d.defender, d.wc, d.defender / "other" / ".." /
                  "lessons", les / "..", d.defender / "lessons-other", d.outside, Path("/")]
    for p in not_mounts:
        for spelled in (p, str(p)):
            refused_value_error(lambda s=spelled: trees.mount(s), f"mount({spelled})")


# =======================================================================================
# Lifetime
# =======================================================================================

def _root_fds(spy: S.OsSpy, mounts: tuple[Path, ...]) -> list[int]:
    roots = [o.fd for o in spy.opens if o.dir_fd is None and o.path in {str(m) for m in mounts}]
    assert len(roots) == len(mounts), spy.opens
    return [fd for fd in roots if fd is not None]


def test_the_with_block_gives_the_trees_and_its_exit_closes_every_root_once(drain):
    d = drain
    spy = S.OsSpy()
    opened = DrainTrees.open(d.mounts, os_=spy)
    roots = _root_fds(spy, d.mounts)
    with opened as entered:
        assert entered is opened
        assert len(descriptors_under(d.tmp)) == len(d.mounts), "the roots are not held open"
        mark = len(spy.closes)
    assert sorted(spy.closes[mark:]) == sorted(roots)
    assert descriptors_under(d.tmp) == []


#: The work step's own faults, each made afresh per row: an `Exception`, and two
#: `BaseException`s that are not (#1134 step 2, H3).
WORK_FAULTS: dict[str, Callable[[], BaseException]] = {
    "runtime_error": lambda: RuntimeError("the work step's own fault"),
    "boom": lambda: Boom("the batch is torn down mid-step"),
    "cancelled": asyncio.CancelledError,
}


@pytest.mark.parametrize("kind", list(WORK_FAULTS))
def test_an_exception_in_the_with_block_propagates_as_itself_after_every_root_is_closed(
        drain, kind):
    """Whatever the work step raises, an `Exception` or not: that very instance propagates, and
    every root was closed on the way out (checked while `info` holds the traceback, so trees the
    exit left open would still be alive there)."""
    d = drain
    spy = S.OsSpy()
    fault = WORK_FAULTS[kind]()
    inside: dict[str, Any] = {}

    def work_step() -> None:
        with DrainTrees.open(d.mounts, os_=spy) as trees:
            inside["handle"] = handle(trees, d, SKILLS)
            inside["roots"] = _root_fds(spy, d.mounts)
            raise fault

    with pytest.raises(type(fault)) as info:
        work_step()
    assert info.value is fault, f"the work step's fault was replaced by {info.value!r}"
    held, name = inside["handle"]
    roots = inside["roots"]
    assert sorted(spy.closes) == sorted(roots)
    assert descriptors_under(d.tmp) == []
    assert raised(lambda: held.write(name, PAYLOAD, mode="replace")).errno == errno.EBADF


def test_close_is_idempotent_and_closes_each_root_exactly_once(drain):
    """`close()` closes each root once. After it, nothing closes any root again: not a second
    `close()`, not the `with` exit, not an explicit `close()` of each handle, not collecting
    them. A second close of a number the process may have reused by then would close another
    file."""
    d = drain
    spy = S.OsSpy()
    trees = DrainTrees.open(d.mounts, os_=spy)
    roots = _root_fds(spy, d.mounts)
    helds = [trees.mount(m) for m in d.mounts]
    trees.close()
    assert sorted(spy.closes) == sorted(roots)
    for held in helds:
        held.close()
    trees.close()
    with trees:
        pass
    del helds, held
    gc.collect()
    assert sorted(spy.closes) == sorted(roots), "a root was closed again after close()"
    assert descriptors_under(d.tmp) == []


class FailsClosing(S.OsSpy):
    """`S.OsSpy`, except that closing the descriptor its open of `root` by path returned closes
    it, then raises `fault`, once: `close(2)` can report EIO after releasing the descriptor."""

    def __init__(self, root: Path, fault: OSError) -> None:
        super().__init__()
        self.root, self.fault = str(root), fault
        self.fd: int | None = None

    def open(self, path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        fd = super().open(path, flags, *args, **kwargs)
        if kwargs.get("dir_fd") is None and str(path) == self.root:
            self.fd = fd
        return fd

    def close(self, fd: int) -> None:
        super().close(fd)
        if fd == self.fd:
            self.fd = None
            raise self.fault


def _chain(exc: BaseException | None) -> list[BaseException]:
    """`exc` and every exception it carries as `__context__` or `__cause__`, transitively."""
    seen: list[BaseException] = []
    todo = [exc]
    while todo:
        e = todo.pop()
        if e is not None and all(e is not s for s in seen):
            seen.append(e)
            todo += [e.__context__, e.__cause__]
    return seen


@pytest.mark.parametrize("how", ["close", "with_exit", "with_exit_unwinding"])
@pytest.mark.parametrize("failing", [0, 1, 2], ids=LABELS)
def test_a_root_whose_close_fails_never_keeps_the_other_roots_open(drain, failing, how):
    """Closing one root fails (EIO). Every other root is still closed (`os_.close` saw each root
    exactly once) and nothing is left open, by `close()`, by the `with` exit, and by the exit
    while a work-step exception unwinds. The close fault is never swallowed: `close()` and the
    plain exit raise it as itself. While unwinding, the work step's exception is not lost: both
    are reachable from what propagates (the implementation raises the close fault with the work
    exception as its `__context__`). A later `close()` closes nothing more."""
    d = drain
    fault = OSError(errno.EIO, "closing the root failed", str(d.mounts[failing]))
    work = RuntimeError("the work step's own fault")
    spy = FailsClosing(d.mounts[failing], fault)
    trees = DrainTrees.open(d.mounts, os_=spy)
    roots = _root_fds(spy, d.mounts)

    def release() -> None:
        if how == "close":
            trees.close()
            return
        with trees:
            if how == "with_exit_unwinding":
                raise work

    exc = raised(release)

    assert sorted(spy.closes) == sorted(roots), f"roots {roots}, closed {spy.closes}"
    assert descriptors_under(d.tmp) == [], "a root was left open behind the failed close"
    chain = _chain(exc)
    assert any(e is fault for e in chain), f"the close fault was swallowed: {exc!r}"
    if how == "with_exit_unwinding":
        assert any(e is work for e in chain), f"the work step's exception was lost: {exc!r}"
    else:
        assert exc is fault, f"the close fault was replaced by {exc!r}"
    trees.close()
    assert sorted(spy.closes) == sorted(roots)


@pytest.mark.parametrize("label", LABELS)
def test_after_close_the_verbs_are_ebadf_the_views_answer_bad_fd_and_the_map_still_answers(
        drain, label):
    """A handle taken inside the block, and its view (and the catalog and record-folder `under`
    views) taken before the close: `write`, `mkdir` and `unlink` raise `OSError(EBADF)` and
    nothing changes; `read` answers `Bad file descriptor`, and so does `entries()` of the
    record's folder and of the folder the drain lists, over those views (neither raises).
    `tree_for` and `mount` still answer, with that same (closed) `Held`."""
    d = drain
    put_plain(d.path(label), PAYLOAD)
    with DrainTrees.open(d.mounts) as trees:
        held, name = handle(trees, d, label)
        view = held.view()
        listed = view.under(CATALOG) if label == SKILLS else view
        folder = name.rpartition("/")[0]
        record_folder = view.under(folder) if folder else view
        assert view.read(name, errors="replace").text == PAYLOAD_TEXT
        assert record_folder.entries().entries[leaf(name)] == "file"
    before = census(d.tmp)

    for verb, target in (("replace", name), ("create", "new.md"), ("unlink", name),
                         ("mkdir", "new-folder")):
        exc = raised(lambda v=verb, t=target: do_verb(held, t, v))
        assert type(exc) is OSError, f"{verb} after close raised {exc!r}"
        assert exc.errno == errno.EBADF, f"{verb} after close raised {exc!r}"
    assert census(d.tmp) == before
    rec = view.read(name)
    assert (rec.text, rec.absent, rec.reason) == (None, False, BAD_FD)
    listing = listed.entries()
    assert (listing.entries, listing.absent, listing.reason) == (None, False, BAD_FD), listing
    judged = record_folder.entries()
    assert (judged.entries, judged.absent, judged.reason) == (None, False, BAD_FD), judged
    assert trees.tree_for(d.path(label)) == (held, name)
    assert trees.tree_for(d.path(label))[0] is held
    assert trees.mount(d.mount(label)) is held


# =======================================================================================
# The handles are the real Held: one per mount, held by descriptor
# =======================================================================================

def test_each_mount_is_held_once_as_the_real_held(drain, trees):
    """Exactly `_io.Held` (never a subclass or a look-alike), one object per mount, the same one
    for every path in it, and three different ones."""
    d = drain
    helds = []
    for label in LABELS:
        m = d.mount(label)
        held = trees.mount(m)
        assert type(held) is _io.Held, type(held)
        for spelled in (m, d.path(label), m / NEIGHBOURS[label][0], m / "not-there" / "x.md"):
            assert trees.tree_for(spelled)[0] is held, str(spelled)
        helds.append(held)
    assert len({id(h) for h in helds}) == len(LABELS)


#: How the drain reaches a held mount: `tree_for` of a record, `mount` of the mount point, and
#: `tree_for` of the mount point itself (`"."`). Each answers `(held, record name)` here.
ROUTES: dict[str, Callable[[Any, Drain, str], tuple[Any, str]]] = {
    "tree_for_record": lambda trees, d, label: trees.tree_for(d.path(label)),
    "mount": lambda trees, d, label: (trees.mount(d.mount(label)), RECORD[label]),
    "tree_for_mount_point": lambda trees, d, label: (
        trees.tree_for(d.mount(label))[0], RECORD[label]),
}


@pytest.mark.parametrize("route", list(ROUTES))
@pytest.mark.parametrize("swap", ["fresh_folder", "link_to_outside"])
def test_mounts_swapped_after_open_are_never_reached_the_held_folders_are(drain, swap, route):
    """After `open`, every mount is renamed away and a fresh empty folder, or a link to an
    outside folder holding a decoy of every file, is put at its path. Asked AFTER the swap, each
    route (`tree_for` of a record, `mount`, `tree_for` of the mount point) answers the same
    `Held` it answered at `open` (both are lexical), and through it the write lands in the
    renamed folder, the read and every listing of the tree's shape see it, and the delete
    removes from it. The folders
    now at the mount paths, and what the links reach, are untouched: no route re-resolves the
    mount by its name (#1134 step 2, H1)."""
    d = drain
    with DrainTrees.open(d.mounts) as trees:
        at_open = {label: trees.mount(d.mount(label)) for label in LABELS}
        for label in LABELS:
            m = d.mount(label)
            os.rename(m, m.with_name(f"{label}.moved"))
            if swap == "fresh_folder":
                m.mkdir()
            else:
                decoy = d.outside / f"decoy-{label}"
                for rel in (RECORD[label], *NEIGHBOURS[label]):
                    put_plain(decoy / rel, HOST_BYTES)
                m.symlink_to(decoy, target_is_directory=True)
        swapped = census(d.outside) if swap == "link_to_outside" else {
            label: census(d.mount(label)) for label in LABELS}

        for label in LABELS:
            moved = d.mount(label).with_name(f"{label}.moved")
            held, name = ROUTES[route](trees, d, label)
            assert held is at_open[label], f"{route} answered another handle for {label}"
            assert name == RECORD[label]
            held.write(name, PAYLOAD, mode="replace")
            assert (moved / RECORD[label]).read_bytes() == PAYLOAD, f"{route}: {label}"
            view = held.view()
            assert view.read(name, errors="replace").text == PAYLOAD_TEXT
            assert do_verb(held, name, "entries").entries[leaf(name)] == "file"
            listed = do_verb(held, CATALOG if label == SKILLS else ".", "listing",
                             below=BELOW[label])
            assert {f: (got.absent, got.reason, got.entries) for f, got in listed.items()} == {
                f: (False, None, rows) for f, rows in LISTINGS[label].items()}, listed
            assert held.unlink(name) is True
            assert not os.path.lexists(moved / RECORD[label])
        assert swapped == (census(d.outside) if swap == "link_to_outside" else {
            label: census(d.mount(label)) for label in LABELS}), "a swapped-in folder was touched"


# =======================================================================================
# D7's matrix through the drain's handles: every verb at every plant site of every tree
# =======================================================================================

@pytest.mark.parametrize("verb", ["replace", "create", "unlink"])
@pytest.mark.parametrize(("label", "site", "kind"), PLANT_ROWS)
def test_a_write_or_delete_through_a_drain_handle_refuses_a_plant_and_lands_once_it_is_gone(
        drain, trees, label, site, kind, verb):
    """The core's refusal, exactly typed, promptly; over a FIFO, without opening it. (1) Nothing
    is written anywhere, what the plant reaches included, and (2) the plant stays. (3) Through
    the same handle, the plant removed: `replace` over a plain file and `create` over nothing
    land `PAYLOAD` byte-exact (making any holding folder the plant took), and `unlink` removes
    a plain file and keeps its folder. The outside folder is untouched."""
    d = drain
    planted = plant(d, label, site, kind)
    held, name = handle(trees, d, label)  # mapped with the plant in place: lexical, it never looks (H2)
    state, before = entry_state(planted.at), census(d.tmp)
    where = f"{verb} through {label} with a {kind} at {site or 'the name'}"

    exc = raised(lambda: judged_by_stat(lambda: do_verb(held, name, verb), planted))

    assert_refused(exc, kind, where=where)
    assert census(d.tmp) == before, f"{where}: the refused call changed the tree"
    assert entry_state(planted.at) == state, f"{where}: the plant was replaced"

    planted.remove()
    if verb == "unlink":
        d.build(label)
    if verb != "create":
        put_plain(d.path(label))
    outside = census(d.outside)  # after the removal: a hard link's other name drops to one
    got = do_verb(held, name, verb)
    if verb == "unlink":
        assert got is True
        assert not os.path.lexists(d.path(label)), "the plain file was reported gone but is there"
        assert stat.S_ISDIR(os.lstat(d.path(label).parent).st_mode), "the delete took the folder"
    else:
        assert_landed(d, label)
    assert census(d.outside) == outside, f"{where}: the control reached the outside folder"


@pytest.mark.parametrize(("label", "site", "kind"), PLANT_ROWS)
def test_a_read_through_a_drain_handles_view_refuses_a_plant_and_reads_a_plain_file_exactly(
        drain, trees, label, site, kind):
    """The read's record, refused: no content, not absent, the core's path-free reason (the
    alias sentence, or `Not a directory` for a file at a folder), and none of the planted bytes
    anywhere in it, promptly. (1) Nothing changes, (2) the plant stays. (3) Through the same
    view, the plant removed and its folders real: `read` returns a plain file's text exactly,
    and a file holding `PAYLOAD` reads as `PAYLOAD_TEXT` with `errors="replace"`."""
    verb = "read"
    d = drain
    planted = plant(d, label, site, kind)
    held, name = handle(trees, d, label)  # mapped with the plant in place: lexical, it never looks (H2)
    state, before = entry_state(planted.at), census(d.tmp)
    where = f"{verb} through {label} with a {kind} at {site or 'the name'}"

    got = in_time(lambda: do_verb(held, name, verb), fifo=planted.fifo)

    assert type(got) is _io.RecordRead, got
    assert (got.text, got.absent, got.reason) == (None, False, READ_REASON[kind]), f"{where}: {got}"
    assert HOST_BYTES.decode() not in repr(got), f"{where}: the planted bytes came back"
    assert census(d.tmp) == before, f"{where}: the read changed the tree"
    assert entry_state(planted.at) == state, f"{where}: the plant was replaced"

    planted.remove()
    d.build(label)
    put_plain(d.path(label), TEXT.encode())
    got = do_verb(held, name, verb)
    assert (got.text, got.absent, got.reason) == (TEXT, False, None)
    put_plain(d.path(label), PAYLOAD)
    got = held.view().read(name, errors="replace")
    assert (got.text, got.absent, got.reason) == (PAYLOAD_TEXT, False, None)


def expected_row(site: PurePosixPath | None, kind: str) -> tuple[Any, ...]:
    """The record folder's listing, as `(absent, reason, the record's row)`: a plant at the name
    is in that listing as itself (`KIND_OF`); a plant at a holding folder refuses the listing,
    with the reason a read gets, and has no row."""
    if site is None:
        return False, None, KIND_OF[kind]
    return False, READ_REASON[kind], None


def row_answer(got: Any, label: str) -> tuple[Any, ...]:
    """An `EntriesRead` of the record's folder (or its JSON fields, from the child) as
    `expected_row` spells it. The listing must name that folder, whatever it answers."""
    fields = got if isinstance(got, dict) else dataclasses.asdict(got)
    assert fields["name"] == RECORD[label].rpartition("/")[0], fields
    rows = fields["entries"]
    row = None if rows is None else dict(rows if isinstance(rows, dict) else map(tuple, rows)).get(
        leaf(RECORD[label]))
    return fields["absent"], fields["reason"], row


@pytest.mark.parametrize(("label", "site", "kind"), PLANT_ROWS)
def test_the_record_folders_listing_through_a_drain_handles_view_lists_the_plant_itself(
        drain, trees, label, site, kind):
    """`entries()` of the record's folder through `held.view()`: the record's row is the
    entry's own kind, without following it or opening it (a FIFO writer stays parked): a link of
    any sort is `other` (never the `file` or `dir` it reaches), a hard link `file`, a FIFO
    `other`, a directory `dir`. A linked or file holding folder is that listing refused, with
    the reason a read gets (no row, never what the link reaches). (1) Nothing changes, (2) the
    plant stays. (3) Through the same view, the plant removed: the folder is listed without the
    record, then with `file` for a plain file there."""
    d = drain
    planted = plant(d, label, site, kind)
    held, name = handle(trees, d, label)  # mapped with the plant in place: lexical, it never looks (H2)
    state, before = entry_state(planted.at), census(d.tmp)

    got = judged_by_stat(lambda: do_verb(held, name, "entries"), planted)

    assert type(got) is _io.EntriesRead, got
    assert row_answer(got, label) == expected_row(site, kind), (
        f"a {kind} at {site or 'the name'} in {label} is {got!r}")
    assert HOST_BYTES.decode() not in repr(got)
    assert census(d.tmp) == before
    assert entry_state(planted.at) == state

    planted.remove()
    d.build(label)
    assert row_answer(do_verb(held, name, "entries"), label) == (False, None, None)
    put_plain(d.path(label))
    assert row_answer(do_verb(held, name, "entries"), label) == (False, None, "file")


#: The skills record's folder: what the drain's draft writer makes.
DRAFT_FOLDER = str(PurePosixPath(RECORD[SKILLS]).parent)


@pytest.mark.parametrize(("site", "kind"), [
    pytest.param(site, kind, id=f"{kind}@{site}") for site in SKILL_SITES for kind in FOLDER_PLANTS])
def test_mkdir_of_the_draft_folder_through_the_skills_handle_refuses_a_plant_on_the_way(
        drain, trees, site, kind):
    """`mkdir("gather/queries/elastic/_draft")` through `tree_for`'s handle, with a link or a
    file at that folder or at any folder above it: the core's folder refusal, exactly typed.
    (1) Nothing is made anywhere (a linked folder's target gains nothing), (2) the plant stays.
    (3) Plant removed: the same `mkdir` makes every folder, real, and the outside folder is
    untouched."""
    d = drain
    ski = d.mount(SKILLS)
    planted = plant(d, SKILLS, site, kind)
    assert_maps(trees, ski / DRAFT_FOLDER, ski, DRAFT_FOLDER)  # mapped with the plant in place: lexical, it never looks (H2)
    held, name = trees.tree_for(ski / DRAFT_FOLDER)
    state, before = entry_state(planted.at), census(d.tmp)

    assert_refused(raised(lambda: held.mkdir(name)), kind, where=f"mkdir with a {kind} at {site}")
    assert census(d.tmp) == before
    assert entry_state(planted.at) == state

    planted.remove()
    outside = census(d.outside)
    held.mkdir(name)
    for folder in SKILL_SITES:
        assert stat.S_ISDIR(os.lstat(ski / folder).st_mode), f"{folder} is not a real folder"
    assert census(d.outside) == outside


#: The listing's plants: links at the record (each tree), and a link or file at each skills
#: holding folder, which is the listed catalog folder, a folder above it, or one below it.
LIST_PLANTS_AT_NAME = ("symlink", "dir_link_outside")
LIST_ROWS = _rows(LIST_PLANTS_AT_NAME, FOLDER_PLANTS)


def listed_path(d: Drain, label: str) -> Path:
    """What the drain lists: a corpus mount itself, or the catalog under skills."""
    return d.mount(SKILLS) / CATALOG if label == SKILLS else d.mount(label)


def expected_listings(label: str, site: PurePosixPath | None,
                      kind: str) -> dict[str, tuple[Any, ...]]:
    """Each listing of the tree's shape (`""` the listed folder, then `BELOW`), as `(absent,
    reason, rows)`. A listing whose folder is the plant, or lies below it, is refused with the
    core's reason (its walk meets the plant: never followed); one whose folder is above the plant
    lists the plant as its own kind (`LISTED_KIND`), and the rest as they are."""
    top = PurePosixPath(CATALOG) if label == SKILLS else PurePosixPath(".")
    at = PurePosixPath(RECORD[label]) if site is None else site
    out: dict[str, tuple[Any, ...]] = {}
    for folder, rows in LISTINGS[label].items():
        listed = top / folder if folder else top
        if label == SKILLS and (at == listed or at in listed.parents):
            out[folder] = (False, READ_REASON[kind], None)
        elif at.parent == listed:
            out[folder] = (False, None, {**rows, at.name: LISTED_KIND[kind]})
        else:
            out[folder] = (False, None, rows)
    return out


def listings_answer(got: dict[str, Any]) -> dict[str, tuple[Any, ...]]:
    """`do_verb(..., "listing")`'s records (or their JSON fields, from the child) as
    `expected_listings` spells them."""
    out = {}
    for folder, record in got.items():
        fields = record if isinstance(record, dict) else dataclasses.asdict(record)
        rows = fields["entries"]
        out[folder] = (fields["absent"], fields["reason"],
                       None if rows is None else dict(
                           rows if isinstance(rows, dict) else map(tuple, rows)))
    return out


@pytest.mark.parametrize(("label", "site", "kind"), LIST_ROWS)
def test_the_drains_listings_through_a_held_mount_list_a_plant_as_itself_and_never_follow_it(
        drain, trees, label, site, kind):
    """The listings of each tree's fixed shape, from `tree_for` of the listed folder: the
    catalog (`view().under("gather/queries")`) and, below it, `elastic` and `elastic/_draft`,
    each by its own `entries()`; a corpus `view()` (flat). A link or file at the catalog folder
    or at `gather` refuses every listing with the core's reason and lists nothing. A link at
    `<sys>`, `_draft` or the record is one row of its parent's listing, `other` (a file there
    `file`), and every listing that would go through it is refused with the core's reason:
    nothing behind it is listed. (1) Nothing changes, (2) the plant stays. (3) Plant removed,
    folders real, record plain: the listings hold the whole shape."""
    d = drain
    planted = plant(d, label, site, kind)
    assert_maps(trees, listed_path(d, label), d.mount(label),
                CATALOG if label == SKILLS else ".")  # mapped with the plant in place: lexical, it never looks (H2)
    held, name = trees.tree_for(listed_path(d, label))
    state, before = entry_state(planted.at), census(d.tmp)

    got = in_time(lambda: do_verb(held, name, "listing", below=BELOW[label]))

    assert all(type(record) is _io.EntriesRead for record in got.values()), got
    assert listings_answer(got) == expected_listings(label, site, kind), got
    assert HOST_BYTES.decode() not in repr(got)
    assert census(d.tmp) == before
    assert entry_state(planted.at) == state

    planted.remove()
    d.build(label)
    put_plain(d.path(label))
    got = do_verb(held, name, "listing", below=BELOW[label])
    assert listings_answer(got) == {f: (False, None, rows)
                                    for f, rows in LISTINGS[label].items()}, got


# =======================================================================================
# O3: a link at a catalog folder never lets a draft land outside skills/
# =======================================================================================

#: C2's plants at a holding folder: a link to an EMPTY outside folder (a write that followed it
#: would CREATE the draft there), a dangling link (it would create the target folder), a file.
O3_PLANTS = ("folder_link_empty_outside", "folder_link_dangling", "folder_file")


@pytest.mark.parametrize("mode", ["replace", "create"])
@pytest.mark.parametrize("kind", O3_PLANTS)
@pytest.mark.parametrize("site", SKILL_SITES, ids=str)
def test_o3_a_draft_written_through_the_skills_handle_never_lands_outside_skills(
        drain, trees, site, kind, mode):
    """The headline regression. The draft writer's call, `held.write(name, ...)` with
    `(held, name) = tree_for(<skills>/gather/queries/elastic/_draft/x.md)`, with
    `gather/queries` (or `gather`, `elastic`, `_draft`) replaced by a link to an empty outside
    folder, a dangling link, or a plain file. It is refused, a linked folder as exactly
    `OSError(ELOOP)` and a file as exactly `NotADirectoryError`, never the leaf class. Nothing
    lands at the target, which stays empty or absent. The plant stays, and nothing anywhere
    changes. Control: the plant removed, the same write lands the draft under `skills/`."""
    d = drain
    ski = d.mount(SKILLS)
    planted = plant(d, SKILLS, site, kind)
    held, name = handle(trees, d, SKILLS)  # mapped with the plant in place: lexical, it never looks (H2)
    assert held is trees.mount(ski)
    target = None if kind == "folder_file" else Path(os.readlink(planted.at))
    state, before = entry_state(planted.at), census(d.tmp)
    where = f"the draft write ({mode}) with a {kind} at {site}"

    exc = raised(lambda: held.write(name, PAYLOAD, mode=mode))

    want = NotADirectoryError if kind == "folder_file" else OSError
    assert type(exc) is want, f"{where}: raised {exc!r}, not exactly {want.__name__}"
    assert exc.errno == (errno.ENOTDIR if kind == "folder_file" else errno.ELOOP), where
    assert census(d.tmp) == before, f"{where}: something was written"
    if kind == "folder_link_empty_outside":
        assert target is not None
        assert os.listdir(target) == [], f"{where}: the draft landed outside skills/"
    if kind == "folder_link_dangling":
        assert target is not None
        assert not os.path.lexists(target), f"{where}: the link's target was created"
    assert entry_state(planted.at) == state

    planted.remove()
    held.write(name, PAYLOAD, mode=mode)
    assert_landed(d, SKILLS)


# =======================================================================================
# No following open, by any route: an audit hook in a child interpreter
# =======================================================================================
#
# The core opens each mount by its own spelling (in `open`, before the watch is armed) and
# everything below it by ONE component relative to a held descriptor, no-follow (`O_NOFOLLOW`),
# or `.` reopened off such a descriptor. Anything else opened by name while a verb runs could
# follow a link at the name or at a holding folder, whatever the verb answers: a path under the
# tmp dir or `/proc` spelled absolutely, a relative name that spans folders, or a relative name
# opened without `O_NOFOLLOW`. A descriptor opened or listed (`fdopen`, `scandir`) must not name
# anything under the outside folder. No target may be named at all, and no process spawned.

#: The names the plants' targets carry (`plant_entry`, `plant_folder`): a link's file or
#: folder, a hard link's other name, a linked holding folder's stand-in, and the file inside a
#: linked folder.
TARGET_PREFIXES = ("link-target-of-", "linked-dir-of-", "other-name-of-", "elsewhere-")
#: The plants that reach something outside the mount.
REACHING_AT_NAME = ("symlink", "dir_link_outside", "hardlink")


def _watch_rows() -> list[tuple[str, str, PurePosixPath | None, str, str]]:
    """`(id, label, site, kind, verb)`: each file verb over each reaching plant at each tree's
    record, the listings over the record's links, and every verb, `mkdir` and the listings
    included, over a linked skills holding folder."""
    rows = [(f"{verb}:{label}:{kind}@name", label, None, kind, verb)
            for label in LABELS for kind in REACHING_AT_NAME for verb in FILE_VERBS]
    rows += [(f"listing:{label}:{kind}@name", label, None, kind, "listing")
             for label in LABELS for kind in LIST_PLANTS_AT_NAME]
    rows += [(f"{verb}:skills:folder_link_outside@{site}", SKILLS, site, "folder_link_outside",
              verb) for site in SKILL_SITES for verb in (*FILE_VERBS, "mkdir", "listing")]
    return rows


WATCH_ROWS = _watch_rows()


def _verb_path(d: Drain, label: str, verb: str) -> Path:
    if verb == "listing":
        return listed_path(d, label)
    return d.mount(SKILLS) / DRAFT_FOLDER if verb == "mkdir" else d.path(label)


@pytest.fixture(scope="module")
def watched(tmp_path_factory: pytest.TempPathFactory) -> dict[str, tuple[dict, Drain, Planted]]:
    """One child interpreter runs every `WATCH_ROWS` row, each over its own working copy with
    its plant in place, through `DrainTrees` with the audit watch armed around `tree_for` and
    the verb."""
    top = tmp_path_factory.mktemp("drain-watch-1134")
    scenarios, built = [], {}
    for i, (row_id, label, site, kind, verb) in enumerate(WATCH_ROWS):
        d = make_drain(top / f"row-{i}")
        planted = plant(d, label, site, kind)
        scenarios.append({"id": row_id, "mounts": [str(m) for m in d.mounts], "verb": verb,
                          "path": str(_verb_path(d, label, verb)), "control": str(planted.at),
                          "below": list(BELOW[label])})
        built[row_id] = (d, planted)
    rows = watch_in_child(scenarios, deadline=CHILD_DEADLINE)
    return {row_id: (rows[row_id], *built[row_id]) for row_id in built}


def _under(path: str, top: str) -> bool:
    return path == top or path.startswith(top + os.sep)


def following(seen: dict[str, list[Any]], d: Drain) -> list[str]:
    """What the watch saw that could have followed a link (see the section comment)."""
    tops = (str(d.tmp), os.path.realpath(d.tmp))
    outside = (str(d.outside), os.path.realpath(d.outside))
    bad = []
    for spelled, flags in seen["by_name"]:
        if spelled.startswith("<"):
            bad.append(spelled)
        elif os.path.isabs(spelled):
            if spelled.startswith("/proc/") or any(_under(spelled, t) for t in tops):
                bad.append(spelled)
        elif (spelled != "." and ("/" in spelled or flags is None or not flags & os.O_NOFOLLOW)
              or spelled.startswith(TARGET_PREFIXES) or spelled == "inner.md"):
            bad.append(spelled)
    bad += [p for p in seen["by_fd"] if p is not None and any(_under(p, o) for o in outside)]
    return bad


def _assert_watched_answer(row: dict[str, Any], label: str, site: PurePosixPath | None,
                           kind: str, verb: str) -> None:
    """The child's call answered what the matrix pins for that row: the refusal ran."""
    if verb in ("replace", "create", "unlink", "mkdir"):
        _typ, code, _marked = S.ROWS["symlink" if kind == "dir_link_outside" else kind]
        assert row.get("raised") == [REFUSAL_TYPE[kind].__name__, code], row
        return
    assert "raised" not in row, row
    if verb == "entries":
        assert row_answer(row["result"], label) == expected_row(site, kind), row
    elif verb == "listing":
        assert listings_answer(row["result"]) == expected_listings(label, site, kind), row
    else:
        assert (row["result"]["text"], row["result"]["reason"]) == (None, READ_REASON[kind]), row


@pytest.mark.parametrize(("row_id", "label", "site", "kind", "verb"),
                         [pytest.param(*row, id=row[0]) for row in WATCH_ROWS])
def test_no_verb_through_a_drain_handle_opens_anything_by_a_spelling_that_could_follow_a_plant(
        watched, row_id, label, site, kind, verb):
    """Below the `os_` seam, by any route (an audit hook in a child interpreter): with the
    plant in place, `tree_for` and the verb open nothing by a following spelling, list or read
    nothing under the outside folder, name no target and spawn nothing, and the verb still
    answers its refusal. Non-vacuity: the watch saw, and the rule flagged, an `O_PATH` open of
    the plant by its absolute spelling; for a skills row it saw the call's own open of
    `gather`; for a corpus read, the leaf's own no-follow open; for a corpus listing, its `.`."""
    row, d, planted = watched[row_id]
    assert "failed" not in row, row["failed"]
    assert following(row["control"], d) == [str(planted.at)], (
        f"the watch did not see, or did not flag, an absolute open of the plant: {row['control']}")

    _assert_watched_answer(row, label, site, kind, verb)
    assert row["remapped"] == [True] * len(LABELS), f"mount / tree_for(mount) drifted: {row}"
    assert following(row, d) == [], f"{verb} opened by a spelling that follows links: {row}"
    spelled = [s for s, _flags in row["by_name"]]
    if label == SKILLS:
        assert "gather" in spelled, f"the watch saw none of the call's own opens: {row}"
    elif verb == "read":
        assert RECORD[label] in spelled, f"the watch did not see the leaf's own open: {row}"
    elif verb in ("entries", "listing"):
        assert "." in spelled, f"the watch did not see the listing's own open: {row}"
