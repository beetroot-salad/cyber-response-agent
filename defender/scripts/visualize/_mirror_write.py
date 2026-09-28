"""The run-page mirror's one write, stdlib-only so it can run as the checkout's owner.

`visualize_run.mirror_page` (via `_mirror`) calls `write_page` in-process when no privilege
drop is needed, and otherwise runs this file under `-I` in a child with the checkout owner's
uid/gid, page bytes on stdin. The child imports nothing from `defender`.

A child rather than write-as-root-then-chown: the mirror folder is user-owned, so anything in
it may be a planted link, and a root writer following one would write (and chown) a file the
user could not touch. Running as the user, the kernel refuses anything they could not write.
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

    A symlink at `dest` is refused (`ELOOP`) rather than silently replaced, since this writer
    did not make it. Links above `dest` are followed, as the user running this. An existing
    page is replaced by a new inode, so a hard-linked page leaves the other file untouched.
    """
    dest.parent.mkdir(parents=True, exist_ok=True)  # lint-unguarded-tree-write: ok — runs as the folder's owner; guarded_mkdir trusts its base, which here is the user's
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


if __name__ == "__main__":  # lint-log-setup: ok — a stdlib-only child that imports nothing from `defender` by design
    write_page(Path(sys.argv[1]), sys.stdin.buffer.read())
