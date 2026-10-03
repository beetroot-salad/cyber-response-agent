"""#1144 — every `_io` writer honours the process umask; none sets a mode of its own (O1, N2).

`_io`'s writers each ask the kernel for 0644 and let it mask that by the process umask, except,
before #1144, the UNNAMED create lane (`O_TMPFILE`, then a link to the name), which forced 0644 on
its file whatever the umask said. So under umask 077 one process wrote a create-lane record 0644
beside a replace-lane record 0600, and the same create landed 0644 on a host with `O_TMPFILE`
and 0600 on one without (NFS, virtiofs: the fallback). O1: no `_io` writer overrides the umask;
every lane lands `0644 & ~umask`, whichever seam wrote it.

The create matrix is every create lane on every seam, under four umasks, at two depths:

* seams: the path seam `write_guarded(path, text, mode="create")`, the rooted seam
  `rooted_write(root, name, text, mode="create")`, and the held seam
  `hold(root).write(name, text, mode="create")` (how `_episode_handle` writes an episode's
  records, `served/base.jsonl` included).
* lanes:
  - `default`: the seam exactly as production calls it, nothing injected (no `open_unnamed=`,
    no `os_=`), so a lane that behaves only when its seams are left alone cannot hide;
  - `unnamed`: the unnamed lane, its real open passed through a recorder that proves it ran;
  - `fallback`: the one named `O_CREAT|O_EXCL` open. The path and rooted seams reach it through
    their own `open_unnamed=` seam answering EOPNOTSUPP, as a filesystem without `O_TMPFILE`
    does (#1078's `_no_unnamed_files`). `Held.write` has NO `open_unnamed=` seam (its unnamed
    open is always the real one), so the EOPNOTSUPP trigger cannot reach it; its fallback is
    driven by the lane's other documented trigger, a host with no `/proc` to link the unnamed
    file through, via `hold(root, os_=)`: the `os_` fake answers the `/proc/self/fd/<N>` link
    with `FileNotFoundError` and reports no `/proc/self/fd` folder. The body that then runs is
    the same named create the rooted seam's EOPNOTSUPP reaches. (The held seam's EOPNOTSUPP
    trigger stays undriven: reaching it would need a production seam, and this is tests only.)
* umasks: 077 -> 0600 and 027 -> 0640 are the obligation (027 also rules out a lane that picks
  between a hardcoded 0600 and 0644); 022 -> 0644 is #1078 J16's unchanged observable (O2) and
  the control no lane landing 0600 whatever the umask can pass; 002 -> 0644 pins that the umask
  only ever tightens the requested 0644 (N2), the one mask that tells a lane asking for 0644 from
  one asking for 0666.
* depths: a name at the top of the root, and `served/base.jsonl`, the record O1 names.

Each case also writes a `replace` record through the same seam, in the same process, under the
same umask, beside it: the same-process control. The create must land the replace's mode (O1's
"a create file and a replace file from the same process disagreeing"). A smaller matrix runs the
create with a small body and an empty one, so a lane keyed on the body's size cannot hide; a
third runs every OTHER lane that creates a file (replace, append, durable append, update, the
locked rewrite, the streaming open) on every seam that has it.

Which lane ran is checked, not assumed. The unnamed cases keep a duplicate of the descriptor the
REAL unnamed open handed back (`_io.open_unnamed` / `_io.open_unnamed_at`; on the held seam, the
file the `/proc/self/fd/` link names) open until the test is over, and require the record at the
name to BE that file. Held open, its inode cannot be freed and handed to a later file, so a lane
that opened the unnamed file, dropped it and fell back cannot pass for the unnamed lane. The
fallback cases require their refusal to have been met exactly once.

Behaviour cannot rule out a writer that reads the umask and computes the masked mode itself
(`os.umask(0)` then `fchmod(0o644 & ~m)` lands the same mode, and races every other thread's
umask meanwhile). N2 forbids it: no explicit modes in `_io`. A source check holds that line: the
module names no chmod- or umask-family call.

Fakes: the `open_unnamed=` seams (a pass-through recorder and a refuser) and the held root's
`os_=` seam (`PassThroughOs`, the real `os` with `link` watched). Nothing is patched.

Red before #1144 landed: every `default` and `unnamed` create under umask 077 and 027 (each
landed 0644), and the source check (the forced `fchmod`). The rest held and must keep holding.
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
#: The sizes a lane keyed on the body's length would treat differently from `BODY`.
SMALL_BODIES = {"small": "{}\n", "empty": ""}

#: (umask, the mode every lane must land under it): `0o644 & ~umask`, spelled out.
UMASKS = [(0o077, 0o600), (0o027, 0o640), (0o022, 0o644), (0o002, 0o644)]
UMASK_IDS = [f"umask{m:03o}" for m, _ in UMASKS]
TIGHT = UMASKS[0]
LANES = ("default", "unnamed", "fallback")

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


def _inode_of(fd: int) -> tuple[int, int]:
    st = os.fstat(fd)
    return st.st_dev, st.st_ino


def _inode(path: Path) -> tuple[int, int]:
    st = os.lstat(path)
    return st.st_dev, st.st_ino


def _opener(real: Callable[[Any], int], lane: str, seen: _Lane) -> Callable[[Any], int]:
    """The `open_unnamed=` seam for `lane`, over the seam's real opener (`write_guarded`'s takes
    a folder path, `rooted_write`'s a folder descriptor). `unnamed`: pass through to `real` and
    keep a duplicate of the descriptor it returned. `fallback`: answer as a filesystem without
    `O_TMPFILE` does, and count the refusal."""
    def open_unnamed(where: Any) -> int:
        if lane == "fallback":
            seen.refusals += 1
            raise OSError(errno.EOPNOTSUPP, os.strerror(errno.EOPNOTSUPP))
        fd = real(where)
        seen.unnamed.append(os.dup(fd))
        return fd
    return open_unnamed


def _open_unnamed_kw(real: Callable[[Any], int], lane: str, seen: _Lane) -> dict[str, Any]:
    """The `open_unnamed=` keyword for `lane`: none at all for `default`."""
    return {} if lane == "default" else {"open_unnamed": _opener(real, lane, seen)}


class _NoProcPath:
    """`os.path` on a host with no `/proc`: `isdir` answers False under `/proc`; every other
    call is the real one."""

    def __getattr__(self, name: str) -> Any:
        return getattr(os.path, name)

    def isdir(self, path: Any) -> bool:
        return not os.fspath(path).startswith("/proc/") and os.path.isdir(path)


class _ProcFdLinks(PassThroughOs):
    """The real `os`, handed to the held root as its `os_`, watching the one call that names an
    unnamed file: `link` from `/proc/self/fd/<N>`. `unnamed`: keep a duplicate of `<N>`, then
    pass the link through. `fallback`: answer as a host with no `/proc` (the link is
    `FileNotFoundError` and `/proc/self/fd` is no folder), and count the refusal."""

    def __init__(self, lane: str, seen: _Lane) -> None:
        self._lane = lane
        self._seen = seen
        if lane == "fallback":
            self.path = _NoProcPath()

    def link(self, src: Any, dst: Any, *a: Any, **kw: Any) -> None:
        source = os.fspath(src)
        if source.startswith(PROC_FD):
            if self._lane == "fallback":
                self._seen.refusals += 1
                raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), source)
            self._seen.unnamed.append(os.dup(int(source[len(PROC_FD):])))
        os.link(src, dst, *a, **kw)


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


def _held_seam(root: Path, name: PurePosixPath, control: PurePosixPath, body: str, lane: str,
               seen: _Lane) -> None:
    held = _io.hold(root) if lane == "default" else _io.hold(root, os_=_ProcFdLinks(lane, seen))
    with held:
        held.write(name, body, mode="create")
        held.write(control, body, mode="replace")


SEAMS: dict[str, Callable[..., None]] = {
    "path": _path_seam, "rooted": _rooted_seam, "held": _held_seam}


def _mode(path: Path) -> int:
    return stat.S_IMODE(os.lstat(path).st_mode)


def _assert_whole_plain_record(path: Path, body: str) -> None:
    st = os.lstat(path)
    assert stat.S_ISREG(st.st_mode), f"{path.name} is not a regular file"
    assert st.st_nlink == 1, f"{path.name} has {st.st_nlink} names, not one"
    assert st.st_uid == os.geteuid(), f"{path.name} is not owned by the writing process"
    assert path.read_text(encoding="utf-8") == body, f"{path.name} does not hold the whole body"


def _create_lands_masked(tmp_path: Path, seen: _Lane, seam: str, lane: str, where: str,
                         body: str, mask: int, want: int) -> None:
    """Under umask `mask`, `seam`'s create of `where`'s record through `lane`, then its replace
    beside it; both land `want`, whole, plain and single-named, and the lane that ran is
    `lane`."""
    root = tmp_path / "records"
    root.mkdir()
    name, control = NAMES[where]
    with umask(mask):
        SEAMS[seam](root, name, control, body, lane, seen)
    created, replaced = root / name, root / control

    if lane == "unnamed":
        assert [_inode_of(fd) for fd in seen.unnamed] == [_inode(created)], (
            f"the {seam} create's record is not the one unnamed file it opened (it opened "
            f"{len(seen.unnamed)}): the unnamed lane was not the one that ran")
    elif lane == "fallback":
        assert (seen.refusals, seen.unnamed) == (1, []), (
            f"the {seam} create met its unnamed-lane refusal {seen.refusals} times, not once")
    assert sorted(os.listdir(created.parent)) == sorted([name.name, control.name]), (
        f"stray entries beside the records: {sorted(os.listdir(created.parent))}")
    _assert_whole_plain_record(created, body)
    _assert_whole_plain_record(replaced, body)
    assert _mode(replaced) == want, (
        f"the control failed: under umask {mask:03o} the {seam} seam's replace landed "
        f"{oct(_mode(replaced))}, not {oct(want)}")
    assert _mode(created) == want, (
        f"under umask {mask:03o} the {seam} seam's {lane} create of {name} landed "
        f"{oct(_mode(created))}, where a replace from the same process landed "
        f"{oct(_mode(replaced))}: the create lane overrode the umask")


@pytest.mark.parametrize(("mask", "want"), UMASKS, ids=UMASK_IDS)
@pytest.mark.parametrize("where", list(NAMES))
@pytest.mark.parametrize("lane", LANES)
@pytest.mark.parametrize("seam", list(SEAMS))
def test_every_create_lane_lands_0644_masked_by_the_umask_as_replace_does(
        tmp_path, seen, seam, lane, where, mask, want):
    """Under umask M, a `create` through `seam`'s `lane`, at the top of the root or nested in
    `served/`, lands `0644 & ~M`: a plain, single-named regular file holding the whole body,
    owned by the writer, and the same mode a `replace` through the same seam lands beside it
    from the same process under the same umask. The lane that ran is the one named: an unnamed
    case's record IS the unnamed file the real open made, a fallback case's unnamed lane was
    refused once, and a default case injects nothing at all."""
    _create_lands_masked(tmp_path, seen, seam, lane, where, BODY, mask, want)


@pytest.mark.parametrize("body", list(SMALL_BODIES.values()), ids=list(SMALL_BODIES))
@pytest.mark.parametrize("lane", LANES)
@pytest.mark.parametrize("seam", list(SEAMS))
def test_a_small_or_empty_create_lands_masked_too(tmp_path, seen, seam, lane, body):
    """The create matrix's claim for a body far below `BODY`'s size: a few bytes, and none.
    Under umask 077 each lands 0600 on every seam and lane, nested in `served/`, as the replace
    beside it does."""
    mask, want = TIGHT
    _create_lands_masked(tmp_path, seen, seam, lane, "nested", body, mask, want)


# -- every other lane that makes a file -------------------------------------------------------

def _locked(cm: Any) -> None:
    with cm as f:
        f.write(BODY)


def _held_write(root: Path, name: str, **kw: Any) -> None:
    with _io.hold(root) as held:
        held.write(name, BODY, **kw)


#: Every other `_io` lane that makes a new file and asks for 0644, by seam, each writing `BODY`
#: to `name` under `root` (absent before the call).
OTHER_LANES: dict[str, Callable[[Path, str], None]] = {
    "path-replace": lambda root, name: _io.write_guarded(root / name, BODY, mode="replace"),
    "path-append": lambda root, name: _io.write_guarded(root / name, BODY, mode="append"),
    "path-update": lambda root, name: _io.write_guarded(root / name, BODY, mode="update"),
    "path-locked_for_rewrite": lambda root, name: _locked(_io.locked_for_rewrite(root / name)),
    "path-open_guarded-append": lambda root, name: _locked(_io.open_guarded(root / name, "a")),
    "path-open_guarded-truncate": lambda root, name: _locked(_io.open_guarded(root / name, "w")),
    "rooted-replace": lambda root, name: _io.rooted_write(root, name, BODY, mode="replace"),
    "rooted-append": lambda root, name: _io.rooted_write(root, name, BODY, mode="append"),
    "rooted-append-durable": lambda root, name: _io.rooted_write(
        root, name, BODY, mode="append", durable=True),
    "rooted-locked_for_rewrite": lambda root, name: _locked(
        _io.rooted_locked_for_rewrite(root, name)),
    "held-replace": lambda root, name: _held_write(root, name, mode="replace"),
    "held-append": lambda root, name: _held_write(root, name, mode="append"),
    "held-append-durable": lambda root, name: _held_write(
        root, name, mode="append", durable=True),
}


@pytest.mark.parametrize(("mask", "want"), UMASKS[:3], ids=UMASK_IDS[:3])
@pytest.mark.parametrize("lane", list(OTHER_LANES))
def test_every_other_lane_that_makes_a_file_lands_0644_masked_by_the_umask(
        tmp_path, lane, mask, want):
    """O1's other lanes: replace, append (plain and durable), update, the locked rewrite and
    the streaming open, on every seam that has each, make a new file of `0644 & ~M` under
    umask M: plain, single-named, owned by the writer, holding the whole body."""
    root = tmp_path / "records"
    root.mkdir()
    name = "rec.jsonl"
    with umask(mask):
        OTHER_LANES[lane](root, name)
    _assert_whole_plain_record(root / name, BODY)
    assert _mode(root / name) == want, (
        f"under umask {mask:03o} the {lane} lane made {oct(_mode(root / name))}, "
        f"not {oct(want)}: it overrode the umask")


# -- N2: no explicit modes ---------------------------------------------------------------------

#: The calls that set a file's mode, or read or change the process umask, outright.
MODE_SETTERS = frozenset({"chmod", "fchmod", "lchmod", "umask", "copymode", "copystat"})


def _docstrings(tree: ast.Module) -> set[int]:
    """The `id`s of the module's, classes' and functions' docstring constants."""
    found: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = node.body
            if (body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)):
                found.add(id(body[0].value))
    return found


def test_io_sets_no_mode_and_reads_no_umask_of_its_own():
    """N2: `_io` leaves every mode to the kernel's masking of the 0644 it asks for. Its source
    names none of `MODE_SETTERS`: not as a call or a reference on any receiver (`os.fchmod`,
    `os_.fchmod`, `Path.chmod`), an import, a bare name, or a string (`getattr(os, "fchmod")`,
    a shell command). Read from the AST, so prose in docstrings and comments is not judged."""
    tree = ast.parse(Path(_io.__file__).read_text(encoding="utf-8"))
    docstrings = _docstrings(tree)
    found: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr in MODE_SETTERS:
            found.append(f"line {node.lineno}: .{node.attr}")
        elif isinstance(node, ast.Name) and node.id in MODE_SETTERS:
            found.append(f"line {node.lineno}: {node.id}")
        elif isinstance(node, ast.alias) and node.name.rsplit(".", 1)[-1] in MODE_SETTERS:
            found.append(f"line {node.lineno}: import {node.name}")
        elif (isinstance(node, ast.Constant) and isinstance(node.value, str)
              and id(node) not in docstrings
              and any(word in node.value for word in MODE_SETTERS)):
            found.append(f"line {node.lineno}: {node.value[:60]!r}")
    assert found == [], (
        "defender/_io.py sets a mode or reads the umask itself (N2: no explicit modes; every "
        "lane asks for 0644 and the kernel masks it):\n" + "\n".join(found))
