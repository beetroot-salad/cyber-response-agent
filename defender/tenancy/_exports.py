"""File reads and removals the delivery package and the run side share, with no link followed: no git, no network."""
from __future__ import annotations

import os
import shutil
import stat
from pathlib import Path

from defender import _io
from defender.records.formats import OID as OID  # run_knowledge's import (owed: from records.formats directly)


class DeliveryRefused(Exception):
    """The tenant cannot safely author or deliver this; the message names why."""


def regular_files(root: Path) -> dict[str, bytes]:
    """Every regular file below `root`, by POSIX relative path, with its bytes: walked and read
    with no link followed and no FIFO opened, each file under `READ_LIMIT` (`_io.bind`). Any
    other entry (a link, a symlinked folder, a FIFO, socket or device), an oversized file or one
    that cannot be read refuses the whole read, naming it: nothing is skipped."""
    files: dict[str, bytes] = {}
    with _io.bind(root) as bound:
        pending = [""]
        while pending:
            folder = pending.pop()
            listed = _io.stat_entries(bound.under(folder) if folder else bound)
            if listed.stats is None:
                raise DeliveryRefused(
                    f"{root / folder} could not be listed: "
                    f"{listed.refusal or 'it is absent'}"
                )
            for name, st in sorted(listed.stats.items()):
                rel = f"{folder}/{name}" if folder else name
                if stat.S_ISDIR(st.st_mode):
                    pending.append(rel)
                    continue
                if not stat.S_ISREG(st.st_mode):
                    raise DeliveryRefused(
                        f"{root / rel} is not a regular file or a folder "
                        f"(mode {stat.filemode(st.st_mode)}): refused whole"
                    )
                if st.st_size > _io.READ_LIMIT:
                    raise DeliveryRefused(
                        f"{root / rel} is larger than {_io.READ_LIMIT} bytes: "
                        "refused whole"
                    )
                read = bound.read_bytes(
                    rel
                )  # lint-whole-read: ok — `_io.Bound`, which enforces READ_LIMIT and the no-follow guards
                if read.data is None:
                    raise DeliveryRefused(
                        f"{root / rel} could not be read: "
                        f"{read.refusal or 'it vanished'}: refused whole"
                    )
                files[rel] = read.data
    return files


def remove_entry(folder: Path, name: str) -> None:
    """Remove `folder/name` as the entry it is (a folder with no link below it followed,
    anything else unlinked); nothing when it, or `folder`, is absent."""
    try:
        fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return
    try:
        try:
            st = os.stat(name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        if stat.S_ISDIR(st.st_mode):
            shutil.rmtree(name, dir_fd=fd)
        else:
            os.unlink(name, dir_fd=fd)
    finally:
        os.close(fd)
