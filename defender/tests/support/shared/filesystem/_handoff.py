"""The one spelling of "write a file another process may be reading" (#1410).

An in-place write (`Path.write_text`) truncates the file first and fills it after, so a reader
that polls the file, or a child launched alongside the write, can see it empty or half-written:
a test that fails rarely and passes on a rerun. `write_whole` writes the content beside the
target under a name no other writer uses, then renames it over the target, so a reader sees the
old file or the new one, never a part.

A write that nothing reads until it completes (setup before the run starts, a record read after
its writer exited) needs none of this; a plain write is fine there.

Writing whole does not stop a lost update: two processes that each read a file, change it and
write it back both start from the same old content, and the second write erases the first's
change. `updating` holds a lock across the read and the write for that.
"""
from __future__ import annotations

import contextlib
import fcntl
import os
import threading
import uuid
from collections.abc import Iterator
from pathlib import Path


def write_whole(path: str | os.PathLike[str], data: str | bytes, *, mode: int | None = None) -> Path:
    """Replace `path` with `data` (text is UTF-8) in one rename; `mode` chmods it before the
    rename, so the file is never visible without it. Safe against concurrent writers in other
    threads or processes: each stages under its own name, and the last rename wins whole."""
    path = Path(path)
    part = path.with_name(
        f".{path.name}.{os.getpid()}.{threading.get_ident()}.{uuid.uuid4().hex[:8]}.part")
    try:
        if isinstance(data, bytes):
            part.write_bytes(data)
        else:
            part.write_text(data, encoding="utf-8")
        if mode is not None:
            part.chmod(mode)
        os.replace(part, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            part.unlink()
        raise
    return path


_held = threading.local()


@contextlib.contextmanager
def updating(path: str | os.PathLike[str]) -> Iterator[None]:
    """Hold `path`'s update lock for the block: read it, change it and write it back inside, and
    no other thread or process holding the same lock can interleave. The lock is a file beside
    `path` (`.<name>.lock`), so it works across processes that share only the folder. Re-entrant
    in one thread: a block that calls another holding the same lock does not deadlock."""
    lock = Path(path).with_name(f".{Path(path).name}.lock")
    key = os.path.abspath(lock)
    depth: dict[str, int] = _held.__dict__.setdefault("depth", {})
    if depth.get(key):
        depth[key] += 1
        try:
            yield
        finally:
            depth[key] -= 1
        return
    with open(lock, "a") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)  # released when the handle closes
        depth[key] = 1
        try:
            yield
        finally:
            del depth[key]
