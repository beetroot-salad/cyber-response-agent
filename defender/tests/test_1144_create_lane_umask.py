"""#1144 — every create lane honours the process umask, as replace and append already do (O1).

`_io`'s writers each ask the kernel for 0644 and let it mask that by the process umask, except,
before #1144, the UNNAMED create lane (`O_TMPFILE`, then a link to the name), which forced 0644 on
its file whatever the umask said. So under umask 077 one process wrote a create-lane record 0644
beside a replace-lane record 0600, and the same create landed 0644 on a host with `O_TMPFILE`
and 0600 on one without (NFS, virtiofs: the fallback). O1: no `_io` writer overrides the umask;
every lane lands `0644 & ~umask`, whichever seam wrote it.

The matrix is every create lane on every seam, under four umasks:

* seams: the path seam `write_guarded(path, text, mode="create")`, the rooted seam
  `rooted_write(root, name, text, mode="create")`, and the held seam
  `hold(root).write(name, text, mode="create")` (how `_episode_handle` writes an episode's
  records, `served/base.jsonl` included).
* lanes: `unnamed` (the default on every host this suite runs on) and `fallback` (the one named
  `O_CREAT|O_EXCL` open). The path and rooted seams reach the fallback through their own
  `open_unnamed=` seam answering EOPNOTSUPP, as a filesystem without `O_TMPFILE` does (#1078's
  `_no_unnamed_files`). `Held.write` has NO `open_unnamed=` seam (its unnamed open is always the
  real one), so the EOPNOTSUPP trigger cannot reach it; its fallback is driven by the lane's other
  documented trigger, a host with no `/proc` to link the unnamed file through, via
  `hold(root, os_=)`: the `os_` fake answers the `/proc/self/fd/<N>` link with
  `FileNotFoundError` and reports no `/proc/self/fd` folder. The body that then runs is the same
  named create the rooted seam's EOPNOTSUPP reaches.
* umasks: 077 -> 0600 and 027 -> 0640 are the obligation (027 also rules out a lane that picks
  between a hardcoded 0600 and 0644); 022 -> 0644 is #1078 J16's unchanged observable (O2) and
  the control no lane landing 0600 whatever the umask can pass; 002 -> 0644 pins that the umask
  only ever tightens the requested 0644 (N2), the one mask that tells a lane asking for 0644 from
  one asking for 0666.

Each case also writes a `replace` record through the same seam, in the same process, under the
same umask: the same-process control. The create must land the replace's mode (O1's "a create
file and a replace file from the same process disagreeing").

Which lane ran is checked, not assumed. The unnamed cases record the inode of the file the REAL
unnamed open handed back (`_io.open_unnamed` / `_io.open_unnamed_at`; on the held seam, the file
the `/proc/self/fd/` link names) and require the record at the name to BE that file, so a host
that silently fell back cannot pass for the unnamed lane. The fallback cases require their
refusal to have been met exactly once.

Fakes: the `open_unnamed=` seams (a pass-through recorder and a refuser) and the held root's
`os_=` seam (`PassThroughOs`, the real `os` with `link` watched). Nothing is patched.

Red before #1144 lands: the unnamed lane on all three seams under umask 077 and 027 (each lands
0644). The rest holds today and must keep holding.
"""
from __future__ import annotations

import errno
import os
import stat
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from defender import _io
from defender.tests._umask import umask
from defender.tests.test_1111_rooted_io import PassThroughOs

#: The record each case creates, and the same-process control it replaces, both at the top of
#: one folder (a root-level name: the rooted seam walks folders but never makes them).
CREATED = "created.json"
REPLACED = "replaced.json"
#: More than one buffer's worth, so "the whole body" means something.
BODY = '{"record": "write-once"}\n' * 4096

#: (umask, the mode every lane must land under it): `0o644 & ~umask`, spelled out.
UMASKS = [(0o077, 0o600), (0o027, 0o640), (0o022, 0o644), (0o002, 0o644)]
LANES = ("unnamed", "fallback")

PROC_FD = "/proc/self/fd/"
#: What a fallback case's seam records when it refuses the unnamed lane.
REFUSED = "refused"


def _inode_of(fd: int) -> tuple[int, int]:
    st = os.fstat(fd)
    return st.st_dev, st.st_ino


def _inode(path: Path) -> tuple[int, int]:
    st = os.lstat(path)
    return st.st_dev, st.st_ino


def _opener(real: Callable[[Any], int], lane: str, seen: list) -> Callable[[Any], int]:
    """The `open_unnamed=` seam for `lane`, over the seam's real opener (`write_guarded`'s takes
    a folder path, `rooted_write`'s a folder descriptor). `unnamed`: pass through to `real` and
    record the inode of the file it opened. `fallback`: answer as a filesystem without
    `O_TMPFILE` does, and record the refusal."""
    def open_unnamed(where: Any) -> int:
        if lane == "fallback":
            seen.append(REFUSED)
            raise OSError(errno.EOPNOTSUPP, os.strerror(errno.EOPNOTSUPP))
        fd = real(where)
        seen.append(_inode_of(fd))
        return fd
    return open_unnamed


class _NoProcPath:
    """`os.path` on a host with no `/proc`: `isdir` answers False under `/proc`; every other
    call is the real one."""

    def __getattr__(self, name: str) -> Any:
        return getattr(os.path, name)

    def isdir(self, path: Any) -> bool:
        return not os.fspath(path).startswith("/proc/") and os.path.isdir(path)


class _ProcFdLinks(PassThroughOs):
    """The real `os`, handed to the held root as its `os_`, watching the one call that names an
    unnamed file: `link` from `/proc/self/fd/<N>`. `unnamed`: pass it through, recording the
    inode of the file it names. `fallback`: answer as a host with no `/proc` (the link is
    `FileNotFoundError` and `/proc/self/fd` is no folder), and record the refusal."""

    def __init__(self, lane: str, seen: list) -> None:
        self._lane = lane
        self._seen = seen
        if lane == "fallback":
            self.path = _NoProcPath()

    def link(self, src: Any, dst: Any, *a: Any, **kw: Any) -> None:
        source = os.fspath(src)
        if source.startswith(PROC_FD):
            if self._lane == "fallback":
                self._seen.append(REFUSED)
                raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), source)
            self._seen.append(_inode_of(int(source[len(PROC_FD):])))
        os.link(src, dst, *a, **kw)


def _path_seam(folder: Path, lane: str, seen: list) -> None:
    _io.write_guarded(folder / CREATED, BODY, mode="create",
                      open_unnamed=_opener(_io.open_unnamed, lane, seen))
    _io.write_guarded(folder / REPLACED, BODY, mode="replace")


def _rooted_seam(folder: Path, lane: str, seen: list) -> None:
    _io.rooted_write(folder, CREATED, BODY, mode="create",
                     open_unnamed=_opener(_io.open_unnamed_at, lane, seen))
    _io.rooted_write(folder, REPLACED, BODY, mode="replace")


def _held_seam(folder: Path, lane: str, seen: list) -> None:
    with _io.hold(folder, os_=_ProcFdLinks(lane, seen)) as held:
        held.write(CREATED, BODY, mode="create")
        held.write(REPLACED, BODY, mode="replace")


#: Each seam's create (through `lane`) then its replace control, in one folder.
SEAMS: dict[str, Callable[[Path, str, list], None]] = {
    "path": _path_seam, "rooted": _rooted_seam, "held": _held_seam}


def _mode(path: Path) -> int:
    return stat.S_IMODE(os.lstat(path).st_mode)


def _assert_whole_plain_record(path: Path) -> None:
    st = os.lstat(path)
    assert stat.S_ISREG(st.st_mode), f"{path.name} is not a regular file"
    assert st.st_nlink == 1, f"{path.name} has {st.st_nlink} names, not one"
    assert st.st_uid == os.geteuid(), f"{path.name} is not owned by the writing process"
    assert path.read_text(encoding="utf-8") == BODY, f"{path.name} does not hold the whole body"


@pytest.mark.parametrize(("mask", "want"), UMASKS, ids=[f"umask{m:03o}" for m, _ in UMASKS])
@pytest.mark.parametrize("lane", LANES)
@pytest.mark.parametrize("seam", list(SEAMS))
def test_every_create_lane_lands_0644_masked_by_the_umask_as_replace_does(
        tmp_path, seam, lane, mask, want):
    """Under umask M, a `create` through `seam`'s `lane` lands `0644 & ~M`: a plain,
    single-named regular file holding the whole body, owned by the writer, and the same mode a
    `replace` through the same seam lands from the same process under the same umask. The lane
    that ran is the one named: an unnamed case's record IS the unnamed file the real open made,
    a fallback case's unnamed lane was refused once."""
    folder = tmp_path / "records"
    folder.mkdir()
    seen: list = []
    with umask(mask):
        SEAMS[seam](folder, lane, seen)
    created, replaced = folder / CREATED, folder / REPLACED

    if lane == "unnamed":
        assert seen == [_inode(created)], (
            f"the {seam} create's record is not the one unnamed file it opened (saw {seen}): "
            "the unnamed lane was not the one that ran")
    else:
        assert seen == [REFUSED], (
            f"the {seam} create did not meet its unnamed-lane refusal exactly once: {seen}")
    assert sorted(os.listdir(folder)) == [CREATED, REPLACED], (
        f"stray entries beside the records: {sorted(os.listdir(folder))}")
    _assert_whole_plain_record(created)
    _assert_whole_plain_record(replaced)
    assert _mode(replaced) == want, (
        f"the control failed: under umask {mask:03o} the {seam} seam's replace landed "
        f"{oct(_mode(replaced))}, not {oct(want)}")
    assert _mode(created) == want, (
        f"under umask {mask:03o} the {seam} seam's {lane} create landed {oct(_mode(created))}, "
        f"where a replace from the same process landed {oct(_mode(replaced))}: the create "
        "lane overrode the umask")
