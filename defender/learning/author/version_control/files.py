"""No-follow reads and in-place draft synchronization."""

from __future__ import annotations

import contextlib
import os
import shutil
import stat
from collections.abc import Iterable
from pathlib import Path

from defender import _io

from .model import DeliveryRefused


def _regular_files(root: Path) -> dict[str, bytes]:
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


def _folders_of(files: Iterable[str], extra: Iterable[str] = ()) -> frozenset[str]:
    """Every folder (POSIX relative path) holding one of `files` or named in `extra`, with its
    ancestors."""
    folders: set[str] = set()
    for rel in (*(f.rpartition("/")[0] for f in files), *extra):
        parts = [p for p in rel.split("/") if p]
        folders.update("/".join(parts[:n]) for n in range(1, len(parts) + 1))
    return frozenset(folders)


#: A folder opened to work below it: no link followed, never handed to a child.
_FOLDER_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _resync(root: Path, files: dict[str, bytes], folders: frozenset[str]) -> None:
    """Make the real folder `root` hold exactly `files` (as plain files with those bytes) and
    `folders`, in place: what matches stays, everything else is removed as the entry it is (a
    link unlinked, never followed; a FIFO unlinked, never opened; a folder removed with no link
    below it followed), and what is missing is created exclusively. Every step is relative to a
    held, no-follow folder descriptor, so an entry swapped mid-sync is never written through.
    In place, so a writable lane bound into a running box keeps its folder."""
    fd = os.open(root, _FOLDER_FLAGS)
    try:
        _resync_at(fd, "", files, folders)
    finally:
        os.close(fd)


def _resync_at(
    dir_fd: int, prefix: str, files: dict[str, bytes], folders: frozenset[str]
) -> None:
    here_files = {
        rel[len(prefix) :]: data
        for rel, data in files.items()
        if rel.startswith(prefix) and "/" not in rel[len(prefix) :]
    }
    here_folders = {
        rel[len(prefix) :]
        for rel in folders
        if rel.startswith(prefix) and "/" not in rel[len(prefix) :]
    }
    with os.scandir(dir_fd) as entries:
        present = {entry.name: entry.stat(follow_symlinks=False) for entry in entries}
    kept: set[str] = set()
    for name, st in present.items():
        if (name in here_folders and stat.S_ISDIR(st.st_mode)) or (
            name in here_files and _holds(dir_fd, name, here_files[name])
        ):
            kept.add(name)
        elif stat.S_ISDIR(st.st_mode):
            shutil.rmtree(name, dir_fd=dir_fd)
        else:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(name, dir_fd=dir_fd)
    for name in sorted(here_folders):
        if name not in kept:
            os.mkdir(
                name, 0o755, dir_fd=dir_fd
            )  # lint-unguarded-tree-write: ok — made relative to a held no-follow folder descriptor; an entry planted at the name fails it (EEXIST)
        child = os.open(name, _FOLDER_FLAGS, dir_fd=dir_fd)
        try:
            _resync_at(child, f"{prefix}{name}/", files, folders)
        finally:
            os.close(child)
    for name, data in sorted(here_files.items()):
        if name not in kept:
            _create_new_at(dir_fd, name, data)


def _holds(dir_fd: int, name: str, data: bytes) -> bool:
    """Is `name` a plain, single-linked regular file holding exactly `data`? Opened no-follow
    and non-blocking (a link or FIFO is not followed or waited on) and judged on the opened
    descriptor; any fault answers no, and the caller removes the entry."""
    try:
        fd = os.open(
            name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
            dir_fd=dir_fd,
        )
    except OSError:
        return False
    try:
        st = os.fstat(fd)
        if not _io.is_plain_entry(st) or st.st_size != len(data):
            return False
        with os.fdopen(os.dup(fd), "rb") as handle:
            return handle.read(len(data) + 1) == data
    except OSError:
        return False
    finally:
        os.close(fd)


def _create_new_at(dir_fd: int, name: str, data: bytes) -> None:
    """A new plain file `name` holding `data`, created exclusively relative to `dir_fd` with no
    link followed: an entry already at the name fails it."""
    fd = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o644,
        dir_fd=dir_fd,
    )
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)


def _sweep_temporaries(folder: Path, prefix: str) -> None:
    """Remove every entry of `folder` named with `prefix` (a build cut off left it), as the
    entry it is: a folder removed with no link below it followed, anything else unlinked.
    Called under the tenant's lock, so no live builder is writing one."""
    if not _io.entry_present(folder):
        return
    fd = os.open(folder, _FOLDER_FLAGS)
    try:
        with os.scandir(fd) as entries:
            stale = [
                (entry.name, entry.is_dir(follow_symlinks=False))
                for entry in entries
                if entry.name.startswith(prefix)
            ]
        for name, is_folder in stale:
            if is_folder:
                shutil.rmtree(name, dir_fd=fd)
            else:
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(name, dir_fd=fd)
    finally:
        os.close(fd)


def _remove_entry(folder: Path, name: str) -> None:
    """Remove `folder/name` as the entry it is (a folder with no link below it followed,
    anything else unlinked); nothing when it, or `folder`, is absent."""
    try:
        fd = os.open(folder, _FOLDER_FLAGS)
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


def _rename_new(folder: Path, source: str, name: str) -> None:
    """Rename `folder/source` to `folder/name`, refusing any entry already at `name` (a plain
    rename would replace an empty folder there). Both relative to one held, no-follow folder
    descriptor. The caller holds the tenant's lock, under which alone such names are made."""
    fd = os.open(folder, _FOLDER_FLAGS)
    try:
        try:
            os.stat(name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            os.rename(source, name, src_dir_fd=fd, dst_dir_fd=fd)
            return
        raise DeliveryRefused(
            f"{folder / name} already exists: a draft is never built over another entry"
        )
    finally:
        os.close(fd)
