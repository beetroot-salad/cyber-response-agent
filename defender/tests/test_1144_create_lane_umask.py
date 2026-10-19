from __future__ import annotations

import errno
import os
import stat
from collections.abc import Callable, Iterator
from pathlib import Path, PurePosixPath
from typing import Any

import pytest

from defender import _io
from defender.tests._create_lane import (
    assert_single_plain,
    no_unnamed_files,
    unnamed_files_unsupported,
)
from defender.tests._spec1133 import inode
from defender.tests._umask import umask
from defender.tests.test_1111_rooted_io import PassThroughOs

#: (the record each case creates, the same-process control it replaces beside it), by depth. The
#: nested pair sits in `served/`, beside the episode record O1 names.
NAMES = {
    "top": (PurePosixPath("created.json"), PurePosixPath("replaced.json")),
    "nested": (PurePosixPath("served/base.jsonl"), PurePosixPath("served/replaced.jsonl")),
}
#: More than one buffer's worth, and past 64 KiB, so "the whole body" means something.
BODY = '{"record": "write-once"}\n' * 4096
#: `BODY` as JSONL rows: `append_jsonl` writes each as one of `BODY`'s lines.
BODY_ROWS = [{"record": "write-once"}] * 4096
#: The sizes a lane keyed on the body's length would treat differently from `BODY`.
SMALL_BODIES = {"small": "{}\n", "empty": ""}

#: (umask, the mode every lane must land under it): `0o644 & ~umask`, spelled out.
UMASKS = [(0o077, 0o600), (0o027, 0o640), (0o022, 0o644), (0o002, 0o644)]
UMASK_IDS = [f"umask{m:03o}" for m, _ in UMASKS]
TIGHT = UMASKS[0]
LANES = ("default", "unnamed", "old_kernel", "fallback")
#: The lanes whose case requires the record to BE the unnamed file the real open made.
UNNAMED_LANES = frozenset({"unnamed", "old_kernel"})

PROC_FD = "/proc/self/fd/"


class _Lane:
    """What the create's unnamed lane did, as the injected seams saw it. `unnamed` holds a
    duplicate of each unnamed file's descriptor (held open until teardown, so that file's inode
    cannot be freed and reused by a later one); `refusals` counts the seam's refusals."""

    def __init__(self) -> None:
        self.unnamed: list[int] = []
        self.refusals = 0


@pytest.fixture
def seen() -> Iterator[_Lane]:
    lane = _Lane()
    yield lane
    for fd in lane.unnamed:
        os.close(fd)


@pytest.fixture(scope="session")
def no_unnamed_files_here(tmp_path_factory) -> str | None:
    """Why this run's tmp filesystem cannot make an unnamed file, or None when it can: probed
    once, in the folder every test's `tmp_path` sits under."""
    return unnamed_files_unsupported(tmp_path_factory.getbasetemp())


def _needs_the_unnamed_lane(reason: str | None, lane: str = "unnamed") -> None:
    """Skip a case whose `lane` needs the unnamed lane to run (`UNNAMED_LANES`), where this
    filesystem cannot make an unnamed file (`reason`)."""
    if reason is not None and lane in UNNAMED_LANES:
        pytest.skip(reason)


def _inode_of(fd: int) -> tuple[int, int]:
    st = os.fstat(fd)
    return st.st_dev, st.st_ino


def _opener(real: Callable[[Any], int], lane: str, seen: _Lane) -> Callable[[Any], int]:
    """The `open_unnamed=` seam for `lane`, over the seam's real opener (`write_guarded`'s takes
    a folder path; `rooted_write`'s and `hold`'s a folder descriptor). `unnamed`: pass through
    to `real` and keep a duplicate of the descriptor it returned. `old_kernel`: the same, with
    the file then set to 0644 outright, the mode a kernel before 6.0 left an unnamed file at on a
    filesystem without POSIX ACLs, unmasked. `fallback`: answer as a filesystem without
    `O_TMPFILE` does, and count the refusal."""
    refuse = no_unnamed_files(errno.EOPNOTSUPP)

    def open_unnamed(where: Any) -> int:
        if lane == "fallback":
            seen.refusals += 1
            return refuse(where)
        fd = real(where)
        if lane == "old_kernel":
            os.fchmod(fd, 0o644)
        seen.unnamed.append(os.dup(fd))
        return fd
    return open_unnamed


def _open_unnamed_kw(real: Callable[[Any], int], lane: str, seen: _Lane) -> dict[str, Any]:
    """The `open_unnamed=` keyword for `lane`: none at all for `default`."""
    return {} if lane == "default" else {"open_unnamed": _opener(real, lane, seen)}


# Each seam's create of `name` (through `lane`), then its replace of `control`, under `root`.

def _path_seam(root: Path, name: PurePosixPath, control: PurePosixPath, body: str, lane: str,
               seen: _Lane) -> None:
    (root / name).parent.mkdir(parents=True, exist_ok=True)
    _io.write_guarded(root / name, body, mode="create",
                      **_open_unnamed_kw(_io.open_unnamed, lane, seen))
    _io.write_guarded(root / control, body, mode="replace")


def _rooted_seam(root: Path, name: PurePosixPath, control: PurePosixPath, body: str, lane: str,
                 seen: _Lane) -> None:
    _io.rooted_mkdir(root, str(name.parent))
    _io.rooted_write(root, name, body, mode="create",
                     **_open_unnamed_kw(_io.open_unnamed_at, lane, seen))
    _io.rooted_write(root, control, body, mode="replace")


def _held_writes(held: _io.Held, name: PurePosixPath, control: PurePosixPath, body: str) -> None:
    with held:
        held.write(name, body, mode="create")
        held.write(control, body, mode="replace")


def _held_seam(root: Path, name: PurePosixPath, control: PurePosixPath, body: str, lane: str,
               seen: _Lane) -> None:
    _held_writes(_io.hold(root, **_open_unnamed_kw(_io.open_unnamed_at, lane, seen)),
                 name, control, body)


def _held_new_seam(root: Path, name: PurePosixPath, control: PurePosixPath, body: str,
                   lane: str, seen: _Lane) -> None:
    held = _io.hold_new(root.parent, root.name,
                        **_open_unnamed_kw(_io.open_unnamed_at, lane, seen))
    _held_writes(held, name, control, body)


SEAMS: dict[str, Callable[..., None]] = {
    "path": _path_seam, "rooted": _rooted_seam, "held": _held_seam, "held_new": _held_new_seam}


def _mode(path: Path) -> int:
    return stat.S_IMODE(os.lstat(path).st_mode)


def _assert_pair_lands(root: Path, where: str, body: str, mask: int, want: int, how: str) -> None:
    """The create of `where`'s record and the replace beside it both land `want` under umask
    `mask`: whole, plain, single-named and the writer's, with nothing else beside them. `how`
    names the create in a failure."""
    name, control = NAMES[where]
    created, replaced = root / name, root / control
    assert sorted(os.listdir(created.parent)) == sorted([name.name, control.name]), (
        f"stray entries beside the records: {sorted(os.listdir(created.parent))}")
    assert_single_plain(replaced, want, body=body, why=(
        f"the control failed: under umask {mask:03o} {how}'s replace"))
    assert_single_plain(created, want, body=body, why=(
        f"under umask {mask:03o} {how} of {name}, where a replace from the same process landed "
        f"{oct(_mode(replaced))}: the create lane overrode the umask"))


def _create_lands_masked(tmp_path: Path, seen: _Lane, seam: str, lane: str, where: str,
                         body: str, mask: int, want: int) -> None:
    """Under umask `mask`, `seam`'s create of `where`'s record through `lane`, then its replace
    beside it; both land `want`, and the lane that ran is `lane`."""
    root = tmp_path / "records"
    root.mkdir()
    name, control = NAMES[where]
    with umask(mask):
        SEAMS[seam](root, name, control, body, lane, seen)

    if lane in UNNAMED_LANES:
        assert [_inode_of(fd) for fd in seen.unnamed] == [inode(root / name)], (
            f"the {seam} create's record is not the one unnamed file it opened (it opened "
            f"{len(seen.unnamed)}): the unnamed lane was not the one that ran")
    elif lane == "fallback":
        assert (seen.refusals, seen.unnamed) == (1, []), (
            f"the {seam} create met its unnamed-lane refusal {seen.refusals} times, not once")
    _assert_pair_lands(root, where, body, mask, want, f"the {seam} seam's {lane} create")


@pytest.mark.parametrize(("mask", "want"), UMASKS, ids=UMASK_IDS)
@pytest.mark.parametrize("where", list(NAMES))
@pytest.mark.parametrize("lane", LANES)
@pytest.mark.parametrize("seam", list(SEAMS))
def test_every_create_lane_lands_0644_masked_by_the_umask_as_replace_does(
        tmp_path, seen, no_unnamed_files_here, seam, lane, where, mask, want):
    _needs_the_unnamed_lane(no_unnamed_files_here, lane)
    _create_lands_masked(tmp_path, seen, seam, lane, where, BODY, mask, want)


@pytest.mark.parametrize("body", list(SMALL_BODIES.values()), ids=list(SMALL_BODIES))
@pytest.mark.parametrize("lane", LANES)
@pytest.mark.parametrize("seam", list(SEAMS))
def test_a_small_or_empty_create_lands_masked_too(tmp_path, seen, no_unnamed_files_here, seam,
                                                   lane, body):
    mask, want = TIGHT
    _needs_the_unnamed_lane(no_unnamed_files_here, lane)
    _create_lands_masked(tmp_path, seen, seam, lane, "nested", body, mask, want)


# -- the unnamed lane's other ways down ----------------------------------------------------------

class _NoProcPath:
    """`os.path` on a host with no `/proc`: `isdir` answers False under `/proc`; every other
    call is the real one."""

    def __getattr__(self, name: str) -> Any:
        return getattr(os.path, name)

    def isdir(self, path: Any) -> bool:
        return not os.fspath(path).startswith("/proc/") and os.path.isdir(path)


class _NoProc(PassThroughOs):
    """The real `os` on a host with no `/proc`, handed to a seam as its `os_`: the `link` from
    `/proc/self/fd/<N>` that names an unnamed file is `FileNotFoundError`, and `/proc/self/fd`
    is no folder. Each refused link is counted, and a duplicate of `<N>` kept, so the case can
    show the record is not the unnamed file the lane gave up."""

    def __init__(self, seen: _Lane) -> None:
        self._seen = seen
        self.path = _NoProcPath()

    def link(self, src: Any, dst: Any, *a: Any, **kw: Any) -> None:
        source = os.fspath(src)
        if source.startswith(PROC_FD):
            self._seen.refusals += 1
            self._seen.unnamed.append(os.dup(int(source[len(PROC_FD):])))
            raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), source)
        os.link(src, dst, *a, **kw)


def _rooted_no_proc(root: Path, name: PurePosixPath, control: PurePosixPath, seen: _Lane) -> None:
    os_ = _NoProc(seen)
    _io.rooted_mkdir(root, str(name.parent))
    _io.rooted_write(root, name, BODY, mode="create", os_=os_)
    _io.rooted_write(root, control, BODY, mode="replace", os_=os_)


def _held_no_proc(root: Path, name: PurePosixPath, control: PurePosixPath, seen: _Lane) -> None:
    _held_writes(_io.hold(root, os_=_NoProc(seen)), name, control, BODY)


#: The seams with an `os_=` seam to answer as a host with no `/proc` (the path seam has none).
NO_PROC_SEAMS: dict[str, Callable[..., None]] = {
    "rooted": _rooted_no_proc, "held": _held_no_proc}


@pytest.mark.parametrize(("mask", "want"), UMASKS, ids=UMASK_IDS)
@pytest.mark.parametrize("seam", list(NO_PROC_SEAMS))
def test_a_create_with_no_proc_to_link_through_falls_back_and_lands_masked(
        tmp_path, seen, no_unnamed_files_here, seam, mask, want):
    _needs_the_unnamed_lane(no_unnamed_files_here)
    root = tmp_path / "records"
    root.mkdir()
    name, control = NAMES["nested"]
    with umask(mask):
        NO_PROC_SEAMS[seam](root, name, control, seen)
    assert seen.refusals == 1, f"the {seam} create's /proc link was refused {seen.refusals} times"
    assert [_inode_of(fd) for fd in seen.unnamed] != [inode(root / name)], (
        f"the {seam} create's record is the unnamed file whose link was refused")
    _assert_pair_lands(root, "nested", BODY, mask, want, f"the {seam} seam's no-/proc create")


#: A `/proc/self/status` from a kernel before 4.7, which added its `Umask:` line.
STATUS_WITHOUT_UMASK = "Name:\tpython3\nState:\tR (running)\nTgid:\t4242\nPid:\t4242\n"


@pytest.mark.parametrize("status", ["absent", "no_umask_line"])
def test_the_unnamed_lane_stands_down_where_it_cannot_read_the_umask(
        tmp_path, no_unnamed_files_here, status):
    _needs_the_unnamed_lane(no_unnamed_files_here)
    folder = tmp_path / "records"
    folder.mkdir()
    status_file = tmp_path / "status"
    if status == "no_umask_line":
        status_file.write_text(STATUS_WITHOUT_UMASK, encoding="utf-8")
    fd = _io.open_unnamed(folder)
    dir_fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with umask(0o077):
            linked = _io._link_unnamed(fd, dir_fd, "rec.json", BODY, status=str(status_file))
    finally:
        os.close(dir_fd)
        os.close(fd)
    assert linked is False, f"the unnamed lane named its file with the umask unreadable ({status})"
    assert os.listdir(folder) == [], f"the stood-down lane left {os.listdir(folder)}"


@pytest.mark.parametrize("mask", [0o077, 0o027, 0o022, 0o002, 0o000],
                         ids=lambda m: f"umask{m:03o}")
def test_the_umask_reader_reports_what_os_umask_does_and_leaves_it_alone(mask):
    with umask(mask):
        read = _io._process_umask()
        reported = os.umask(mask)
    assert (read, reported) == (mask, mask), (
        f"under umask {mask:03o} the reader answered {read!r} and os.umask then reported "
        f"{reported:03o}")


# -- every other lane that makes a file -------------------------------------------------------

def _locked(cm: Any) -> None:
    with cm as f:
        f.write(BODY)


def _locked_fd(cm: Any) -> None:
    """A locked rewrite opener yields the record's descriptor and its `fstat` (#1174
    amendment 2), never a file object."""
    with cm as (fd, _st):
        os.write(fd, BODY.encode())


def _held_write(root: Path, name: str, **kw: Any) -> None:
    with _io.hold(root) as held:
        held.write(name, BODY, **kw)


#: Every other `_io` lane that makes a new file and asks for 0644, by seam, each writing `BODY`
#: to `name` under `root` (absent before the call).
OTHER_LANES: dict[str, Callable[[Path, str], None]] = {
    "path-replace": lambda root, name: _io.write_guarded(root / name, BODY, mode="replace"),
    "path-append": lambda root, name: _io.write_guarded(root / name, BODY, mode="append"),
    "path-update": lambda root, name: _io.write_guarded(root / name, BODY, mode="update"),
    "path-locked_for_rewrite": lambda root, name: _locked_fd(_io.locked_for_rewrite(root / name)),
    "path-open_guarded-append": lambda root, name: _locked(_io.open_guarded(root / name, "a")),
    "path-open_guarded-truncate": lambda root, name: _locked(_io.open_guarded(root / name, "w")),
    "path-append_jsonl": lambda root, name: _io.append_jsonl(root / name, BODY_ROWS),
    "rooted-replace": lambda root, name: _io.rooted_write(root, name, BODY, mode="replace"),
    "rooted-append": lambda root, name: _io.rooted_write(root, name, BODY, mode="append"),
    "rooted-append-durable": lambda root, name: _io.rooted_write(
        root, name, BODY, mode="append", durable=True),
    # (Its rooted twin's arm left with #1235, which deleted `_io.rooted_locked_for_rewrite`.)
    "held-replace": lambda root, name: _held_write(root, name, mode="replace"),
    "held-append": lambda root, name: _held_write(root, name, mode="append"),
    "held-append-durable": lambda root, name: _held_write(
        root, name, mode="append", durable=True),
}


@pytest.mark.parametrize(("mask", "want"), UMASKS, ids=UMASK_IDS)
@pytest.mark.parametrize("lane", list(OTHER_LANES))
def test_every_other_lane_that_makes_a_file_lands_0644_masked_by_the_umask(
        tmp_path, lane, mask, want):
    root = tmp_path / "records"
    root.mkdir()
    name = "rec.jsonl"
    with umask(mask):
        OTHER_LANES[lane](root, name)
    assert_single_plain(root / name, want, body=BODY, why=(
        f"under umask {mask:03o} the {lane} lane overrode the umask"))


# -- the one mode `_io` sets itself, and the umask it never sets -------------------------------
