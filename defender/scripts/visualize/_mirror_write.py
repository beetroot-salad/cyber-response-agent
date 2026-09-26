"""The run-page mirror's one write, stdlib-only so it can run as the checkout's owner (#1084 D5).

`visualize_run.render_and_mirror` calls `write_page` in-process when nothing needs dropping,
and otherwise runs THIS FILE as a script in a child whose uid/gid are the checkout owner's, the
page bytes on stdin. Same code in both lanes; the child imports nothing from `defender`, so it
needs no access to the package's site-packages, and it runs under `-I`.

Why a child and not write-as-root-then-chown: the mirror lives in a folder the user owns, so
anything in it may be a link the user planted. A root writer that follows one writes (and a
chown hands over) a file the user could not touch. Written as the user, every link the child
follows reaches only what the user could already write — the kernel does the refusing.
"""
from __future__ import annotations

import errno
import os
import sys
import tempfile
from pathlib import Path

PAGE_MODE = 0o644


def write_page(dest: Path, data: bytes) -> None:
    """Create `dest`'s folders and put `data` at `dest` by stage-then-rename.

    A symlink AT `dest` is refused (`ELOOP`) rather than renamed over: a link sitting at the
    page name is not something this writer made, and replacing it silently would hide a plant.
    Links ABOVE `dest` are followed — as whoever runs this, which is the point (module doc).
    An existing plain page is replaced by a new inode, never written through, so a page that is
    a hard link to some other file leaves that file's bytes alone.
    """
    dest.parent.mkdir(parents=True, exist_ok=True)  # lint-unguarded-tree-write: ok — runs as the folder's owner (#1084 D5); guarded_mkdir trusts its base, which here is the user's
    if dest.is_symlink():
        raise OSError(errno.ELOOP, "refusing to replace a symlink at the mirror page", str(dest))
    fd, stage = tempfile.mkstemp(dir=dest.parent, prefix=f".{dest.name}.")
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(data)
            os.fchmod(out.fileno(), PAGE_MODE)
        os.replace(stage, dest)
    except BaseException:
        Path(stage).unlink(missing_ok=True)
        raise


if __name__ == "__main__":
    write_page(Path(sys.argv[1]), sys.stdin.buffer.read())
