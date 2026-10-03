"""#1144 — every `_io` writer lands 0644 masked by the process umask, whichever lane wrote it (O1).

Before #1144 the UNNAMED create lane (`O_TMPFILE`, then a link to the name) forced 0644 on its file
with `fchmod`, whatever the umask said. So under umask 077 one process wrote a create-lane record
0644 beside a replace-lane record 0600, and the same create landed 0644 on a host with `O_TMPFILE`
and 0600 on one without (NFS, virtiofs: the fallback). O1: no `_io` writer overrides the umask;
every lane lands `0644 & ~umask`, whichever seam wrote it.

The kernel cannot be left to mask the unnamed lane's file. Linux before 6.0 (ac6800e279a2, "fs: Add
missing umask strip in vfs_tmpfile", backported to the 4.19+ stable lines) did not apply the umask
to an `O_TMPFILE` open on a filesystem without POSIX ACLs, so a lane that only asked for 0644 still
landed 0644 there under umask 077. So the lane sets the mode itself, to `0644 & ~umask`, with the
umask read from `/proc/self/status` (Linux 4.7+). It never calls `os.umask(m)` and sets it back,
because every other thread would create files under `m` in between. Where that file or its
`Umask:` line is missing, the lane stands down to the named fallback, whose plain open every kernel
masks.

The create matrix is every create lane on every seam, under four umasks, at two depths:

* seams: the path seam `write_guarded(path, text, mode="create")`, the rooted seam
  `rooted_write(root, name, text, mode="create")`, and the held seam through both of its doors,
  `hold(root).write(...)` and `hold_new(parent, name).write(...)` (how `_episode_handle` writes an
  episode's records, `served/base.jsonl` included).
* lanes, each driven through the seam's own `open_unnamed=`:
  - `default`: the seam exactly as production calls it, nothing injected (no `open_unnamed=`,
    no `os_=`), so a lane that behaves only when its seams are left alone cannot hide;
  - `unnamed`: the unnamed lane, its real open passed through a recorder that proves it ran;
  - `old_kernel`: the unnamed lane on a kernel that does not mask the unnamed file. The real open,
    then the file set to 0644 outright, as such a kernel leaves it. This kernel masks it, so the
    seam puts back what the old one did, and the lane's own mode is what is left to judge;
  - `fallback`: the one named `O_CREAT|O_EXCL` open, reached by the unnamed open answering
    EOPNOTSUPP as a filesystem without `O_TMPFILE` does (`_create_lane.no_unnamed_files`).
* umasks: 077 -> 0600 and 027 -> 0640 are the obligation (027 also rules out a lane that picks
  between a hardcoded 0600 and 0644); 022 -> 0644 is #1078 J16's unchanged observable (O2) and
  the control no lane landing 0600 whatever the umask can pass; 002 -> 0644 pins that the umask
  only ever tightens the requested 0644, the one mask that tells a lane asking for 0644 from one
  asking for 0666.
* depths: a name at the top of the root, and `served/base.jsonl`, the record O1 names.

Each case also writes a `replace` record through the same seam, in the same process, under the
same umask, beside it: the same-process control. The create must land the replace's mode (O1's
"a create file and a replace file from the same process disagreeing"). A smaller matrix runs the
create with a small body and an empty one, so a lane keyed on the body's size cannot hide.
Further tests cover the unnamed lane's other way down (a host with no `/proc` to link through,
via the rooted and held seams' `os_=`), the lane standing down when it cannot read the umask, the
umask reader itself, and every OTHER lane that creates a file (replace, append, durable append,
update, the locked rewrites, the streaming open, `append_jsonl`) on every seam that has it.

Which lane ran is checked, not assumed. The unnamed and old-kernel cases keep a duplicate of the
descriptor the REAL unnamed open handed back (`_io.open_unnamed` / `_io.open_unnamed_at`) open until
the test is over, and require the record at the name to BE that file. Held open, its inode cannot
be freed and handed to a later file, so a lane that opened the unnamed file, dropped it and fell
back cannot pass for the unnamed lane. The fallback cases require their refusal to have been met
exactly once. Where tmp_path's filesystem cannot make an unnamed file at all (overlayfs before
Linux 6.6), the cases that need the unnamed lane are skipped, with that reason, not failed.

Behaviour cannot rule out a lane that learns the umask by setting it (`os.umask(0)` and back lands
the same mode, and races every other thread's creates meanwhile), nor tell a second, redundant
mode-setter from the one the old kernels need. A source check, resolved through
`scripts/lint/_astlib.py`, holds both lines: `_io` never reaches `os.umask`, and its one
mode-setting call is the unnamed lane's.

Fakes: the `open_unnamed=` seams (a pass-through recorder, the old-kernel opener and a refuser) and
the `os_=` seam (`_NoProc`, the real `os` with the `/proc` link refused). Nothing is patched.

Red before the #1144 fix (960ca44b's tests against the code before 8f36af5b): every `default` and
`unnamed` create under umask 077 and 027 (each landed 0644). Red before the review round's fix
(these tests against b9026530's code, which had dropped the `fchmod` and left the mode to the
kernel): every `old_kernel` path and rooted create under 077 and 027 (0644 kept), every held cell
that passes `open_unnamed=` (no such seam), `append_jsonl` under 002 (it asked for 0666), the
umask reader and the stand-down (no reader), and the source check (no mode set at all).
"""
from __future__ import annotations

import ast
import errno
import os
import stat
from collections.abc import Callable, Iterator
from pathlib import Path, PurePosixPath
from typing import Any

import pytest

from defender import _io
from defender.tests._by_path import import_lint_lib
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
    """Under umask M, a `create` through `seam`'s `lane`, at the top of the root or nested in
    `served/`, lands `0644 & ~M`: a plain, single-named regular file holding the whole body,
    owned by the writer, and the same mode a `replace` through the same seam lands beside it
    from the same process under the same umask. That holds on a kernel that leaves the unnamed
    file unmasked too (`old_kernel`). The lane that ran is the one named: an unnamed or
    old-kernel case's record IS the unnamed file the real open made, a fallback case's unnamed
    lane was refused once, and a default case injects nothing at all."""
    _needs_the_unnamed_lane(no_unnamed_files_here, lane)
    _create_lands_masked(tmp_path, seen, seam, lane, where, BODY, mask, want)


@pytest.mark.parametrize("body", list(SMALL_BODIES.values()), ids=list(SMALL_BODIES))
@pytest.mark.parametrize("lane", LANES)
@pytest.mark.parametrize("seam", list(SEAMS))
def test_a_small_or_empty_create_lands_masked_too(tmp_path, seen, no_unnamed_files_here, seam,
                                                   lane, body):
    """The create matrix's claim for a body far below `BODY`'s size: a few bytes, and none.
    Under umask 077 each lands 0600 on every seam and lane, nested in `served/`, as the replace
    beside it does."""
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
    """The unnamed lane's other documented way down: a host with no `/proc` to link the
    unnamed file through. The create gives the unnamed file up (its one link refused), falls
    back to the named open, and lands `0644 & ~M` beside the replace, like every other case."""
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
    """Where the process umask cannot be read without changing it (`/proc/self/status` absent,
    or a kernel before 4.7 whose status has no `Umask:` line), the unnamed lane names nothing
    and answers False, which sends its caller to the named fallback (the no-`/proc` cases above
    drive that fallback end to end). It neither guesses a mode nor sets the umask to learn
    it."""
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
    """The unnamed lane's umask reader answers the umask in force, the value `os.umask`
    reports, and leaves it in force: read, then reported by `os.umask` setting the same mask
    back, both are the mask pinned."""
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
    "rooted-locked_for_rewrite": lambda root, name: _locked_fd(
        _io.rooted_locked_for_rewrite(root, name)),
    "held-replace": lambda root, name: _held_write(root, name, mode="replace"),
    "held-append": lambda root, name: _held_write(root, name, mode="append"),
    "held-append-durable": lambda root, name: _held_write(
        root, name, mode="append", durable=True),
}


@pytest.mark.parametrize(("mask", "want"), UMASKS, ids=UMASK_IDS)
@pytest.mark.parametrize("lane", list(OTHER_LANES))
def test_every_other_lane_that_makes_a_file_lands_0644_masked_by_the_umask(
        tmp_path, lane, mask, want):
    """O1's other lanes: replace, append (plain and durable), update, the locked rewrite, the
    streaming open and the JSONL appender, on every seam that has each, make a new file of
    `0644 & ~M` under umask M: plain, single-named, owned by the writer, holding the whole
    body. Under umask 002 this is what tells a lane asking for 0644 from one asking for 0666."""
    root = tmp_path / "records"
    root.mkdir()
    name = "rec.jsonl"
    with umask(mask):
        OTHER_LANES[lane](root, name)
    assert_single_plain(root / name, want, body=BODY, why=(
        f"under umask {mask:03o} the {lane} lane overrode the umask"))


# -- the one mode `_io` sets itself, and the umask it never sets -------------------------------

#: What sets a file's mode outright, by the dotted origin `_astlib` resolves a name to.
MODE_SETTERS = frozenset({"os.chmod", "os.fchmod", "os.lchmod", "shutil.copymode",
                          "shutil.copystat"})
#: The same, called on a VALUE (the `os_` seam, `self._os`, a `Path`): `.<attr>`.
MODE_SETTER_METHODS = frozenset({".chmod", ".fchmod", ".lchmod"})
UMASK = ("os.umask", ".umask")


def _astlib() -> Any:
    """The gates' shared name resolver (`scripts/lint/_astlib.py`), imported the way the suites
    reach it."""
    return import_lint_lib("_astlib")


def _enclosing_defs(tree: ast.AST) -> dict[ast.AST, str]:
    """Every node's innermost enclosing `def`, by name (`<module>` at the top level)."""
    owner: dict[ast.AST, str] = {}

    def visit(node: ast.AST, fn: str) -> None:
        for child in ast.iter_child_nodes(node):
            inner = child.name if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) else fn
            owner[child] = inner
            visit(child, inner)
    visit(tree, "<module>")
    return owner


def _refers_to(node: ast.AST, env: Any, astlib: Any) -> str | None:
    """What `node` names, resolved through `_astlib`: the dotted origin of a name or attribute
    chain rooted in an import (`os.umask`, an `import os as o` alias, a `from os import fchmod`),
    `getattr(<x>, "<name>")` as `<x>.<name>` would resolve, and `.<attr>` for an attribute read
    off a value, which has no import origin to resolve."""
    if isinstance(node, (ast.Name, ast.Attribute)):
        found = astlib.origin(node, env)
        if found is not None or not isinstance(node, ast.Attribute):
            return found
        if astlib.origin(node.value, env) is None:
            # The receiver is a value: the `os_` seam, `self._os`, a `Path`. `_astlib` cannot
            # resolve a value, and its rule for that duck-typed case is to key on the attribute.
            return f".{node.attr}"  # lint-ast-resolve: ok — a value receiver (the os_ seam, self._os, a Path) has no import origin; per _astlib's duck-typed rule the attribute names the call, and the one setter it finds is then resolved to `os` through its parameter's default
        return None
    if isinstance(node, ast.Call) and astlib.callee(node, env) == "builtins.getattr" \
            and len(node.args) >= 2:
        attr = astlib.str_value(node.args[1], env)
        if attr is not None:
            receiver = astlib.origin(node.args[0], env)
            return f"{receiver}.{attr}" if receiver is not None else f".{attr}"
    return None


def test_io_never_sets_the_umask_and_sets_one_mode_itself_in_the_unnamed_lane():
    """`_io` reads the umask only from `/proc/self/status`: nothing in it reaches `os.umask` (a
    call, a reference, an alias, a `getattr`, or `.umask` on the `os_` seam), because setting the
    umask to learn it leaves every other thread creating files under the temporary mask. And
    its one mode-setting call (`os.chmod` / `fchmod` / `lchmod` or `shutil.copymode` /
    `copystat` by any spelling, or `.chmod` / `.fchmod` / `.lchmod` on a value) is the unnamed
    lane's `os_.fchmod` in `_link_unnamed`, where `os_` is the `os` seam: its default resolves
    to `os`. Every other lane leaves the mode to the kernel's masking of the 0644 it asks for."""
    astlib = _astlib()
    tree = ast.parse(Path(_io.__file__).read_text(encoding="utf-8"))
    env = astlib.module_env(tree)
    def_of = _enclosing_defs(tree)
    umasks: list[str] = []
    setters: list[tuple[str, str, ast.AST]] = []
    for node in ast.walk(tree):
        what = _refers_to(node, env, astlib)
        if what in UMASK:
            umasks.append(f"line {node.lineno}: {what} in {def_of[node]}")
        elif what in MODE_SETTERS or what in MODE_SETTER_METHODS:
            setters.append((def_of[node], what, node))
    assert umasks == [], (
        "defender/_io.py reaches os.umask (read the umask from /proc/self/status instead; "
        "setting it races every other thread's creates):\n" + "\n".join(umasks))
    assert [(fn, what) for fn, what, _ in setters] == [("_link_unnamed", ".fchmod")], (
        "defender/_io.py's mode-setting calls are not exactly the unnamed lane's one fchmod "
        "(every other lane leaves the mode to the kernel's umask):\n"
        + "\n".join(f"line {n.lineno}: {what} in {fn}" for fn, what, n in setters))
    (_fn, _what, call), = setters
    assert isinstance(call, ast.Attribute)
    assert isinstance(call.value, ast.Name), f"_link_unnamed's fchmod is called on {call.value}"
    link_unnamed = next(f for f in tree.body
                        if isinstance(f, ast.FunctionDef) and f.name == "_link_unnamed")
    seam_defaults = dict(zip((a.arg for a in link_unnamed.args.kwonlyargs),
                             link_unnamed.args.kw_defaults, strict=True))
    seam_default = seam_defaults.get(call.value.id)
    not_the_seam = (f"_link_unnamed's fchmod is called on {call.value.id!r}, which is not its "
                    "`os` seam (a keyword-only parameter defaulting to `os`)")
    assert seam_default is not None, not_the_seam
    assert astlib.origin(seam_default, env) == "os", not_the_seam
