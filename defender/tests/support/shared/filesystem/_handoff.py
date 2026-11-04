"""The one spelling of "write a file another process may be reading" (#1410).

An in-place write (`Path.write_text`) truncates the file first and fills it after, so a reader
that polls the file, or a child launched alongside the write, can see it empty or half-written:
a test that fails rarely and passes on a rerun. `write_whole` writes the content beside the
target under a name no other writer uses, then renames it over the target, so a reader sees the
old file or the new one, never a part.

A write that nothing reads until it completes (setup before the run starts, a record read after
its writer exited) needs none of this; a plain write is fine there.
"""
from __future__ import annotations

import contextlib
import os
import threading
import uuid
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
