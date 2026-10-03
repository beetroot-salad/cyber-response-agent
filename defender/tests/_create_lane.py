"""The create lane's test helpers, one home each, for every suite that drives `_io`'s `create`.

`write_guarded(mode="create")`, `rooted_write(mode="create")` and `Held.write(mode="create")`
write the record to an unnamed (`O_TMPFILE`) file and link it to its name, or fall back to one
named `O_CREAT|O_EXCL` open where the filesystem cannot make an unnamed file (#1078 J16/J63).
The #1078, #1111 and #1144 suites each need the same three things around that lane: the seam
that forces the fallback, the judge of what a create left at the name, and the probe for
whether this filesystem can make an unnamed file at all.
"""
from __future__ import annotations

import errno
import os
import stat
from collections.abc import Callable
from pathlib import Path
from typing import Any

from defender import _io


def no_unnamed_files(errno_: int) -> Callable[[Any], int]:
    """An `open_unnamed=` seam answering as a filesystem without `O_TMPFILE` does (NFS,
    virtiofs: EOPNOTSUPP, EISDIR or EINVAL), or with a real failure (any other errno). It
    takes whatever the seam it is handed to passes: a folder path (`write_guarded`) or a folder
    descriptor (`rooted_write`, `hold`)."""
    def refuse(_where: Any) -> int:
        raise OSError(errno_, os.strerror(errno_))
    return refuse


def assert_single_plain(path: Path, mode: int, *, body: str | None = None,
                        why: str = "") -> None:
    """`path` is a plain regular file with one name, owned by this process, of exactly `mode`,
    and, given `body`, holding exactly that. `mode` is the mode under the umask the caller pinned
    around the write (`tests/_umask.py`): every lane honours the umask (#1144), so a mode means
    nothing without one. `why` is added to a wrong mode's message."""
    st = os.lstat(path)
    assert stat.S_ISREG(st.st_mode), f"{path} is not a regular file"
    assert st.st_nlink == 1, f"{path} has {st.st_nlink} names, not one"
    assert st.st_uid == os.geteuid(), f"{path} is not owned by the writing process"
    got = stat.S_IMODE(st.st_mode)
    assert got == mode, f"{path} has mode {oct(got)}, not {oct(mode)}" + (why and f" ({why})")
    if body is not None:
        assert path.read_text(encoding="utf-8") == body, f"{path} does not hold the whole body"


def unnamed_files_unsupported(directory: Path) -> str | None:
    """Why `directory`'s filesystem cannot make an unnamed (`O_TMPFILE`) file, or None when it
    can, from one real open. overlayfs before Linux 6.6 is the usual case. Every create there
    falls back to the named open, so a test that needs the unnamed lane to run has nothing to
    test, and its caller skips it rather than failing it with a message about the wrong thing."""
    flag = getattr(os, "O_TMPFILE", None)
    if flag is None:
        return "this platform has no O_TMPFILE, so no create here makes an unnamed file"
    try:
        fd = os.open(directory, flag | os.O_WRONLY, 0o600)
    except OSError as e:
        if e.errno not in _io._NO_UNNAMED_FILES:
            raise
        return (f"the filesystem holding {directory} cannot make an unnamed (O_TMPFILE) file "
                f"({errno.errorcode.get(e.errno, e.errno)}; overlayfs before Linux 6.6 is one), "
                "so every create there takes the named fallback and the unnamed lane never runs")
    os.close(fd)
    return None
