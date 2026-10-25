"""Alias-refusing host writes and staged-file lifecycle."""
from __future__ import annotations

import contextlib



import errno

import fcntl



import os


import secrets

import stat



from collections.abc import Callable, Iterator

from pathlib import Path

from typing import Any




#: The mode every `_io` lane that makes a file asks for. The kernel masks it by the process umask,
#: so the file lands `0644 & ~umask`. The unnamed create lane applies that mask itself
#: (`_link_unnamed`), because kernels before 6.0 skipped it for an unnamed file (#1144).
_FILE_MODE = 0o644




def _rewrite_fd(os_: Any, fd: int, data: bytes) -> None:
    """Replace the whole content of the locked, open `fd` with `data`, in place: back to 0,
    truncate, then write until every byte is down."""
    os_.lseek(fd, 0, os.SEEK_SET)
    os_.ftruncate(fd, 0)
    view = memoryview(data)
    while view:
        view = view[os_.write(fd, view):]



class NotPlainEntry(OSError):  # noqa: N818 — named for what it reports, like `FileExistsError`'s siblings
    """The core's refusal of a link, hard link or other non-plain entry AT a name (left in place
    for the reap scan): ELOOP, or EMLINK for a hard link, carrying the `write_guarded_alias`
    mark. A linked or non-directory FOLDER on the way is a plain `OSError` / `NotADirectoryError`
    instead, so a caller that contains this refusal contains nothing else."""




# The alias-refusing write seam.
#
# Every host-side write into a shared box tree goes through `write_guarded` (or
# `guarded_mkdir` for directories). A planted symlink or hard link at the target is refused,
# never followed: `replace` stages under an unpredictable name and swaps it in, never opening
# the target; `append`/`update` open with O_NOFOLLOW. `_refuse_unless_plain` runs first in
# every mode and raises one exception type for symlink, hard link and directory alike, so
# callers handle them uniformly. The `.write_guarded_alias` attribute on the raised OSError
# lets a caller that must distinguish "aliased" from an ordinary occupied name do so.
def stage_name(path: Path) -> Path:
    """An unpredictable staged name in `path`'s own directory. Never a predictable
    `<name>.tmp`, so an occupied staged name is always hostile and `O_EXCL` failing on it is
    unambiguous."""
    path = Path(path)
    return path.with_name(staged_leaf(path.name))




def staged_leaf(leaf: str) -> str:
    """:func:`stage_name` for a bare leaf name: the name-source seam
    `rooted_write(stage_name=)` defaults to."""
    return f"{leaf}.staged-{secrets.token_hex(8)}"




def open_unnamed(directory: Path) -> int:
    """A write descriptor on a NEW, UNNAMED file in `directory` (`O_TMPFILE`): it has no name,
    and so no reader can see it, until `_link_unnamed` gives it one. `OSError(EOPNOTSUPP)`
    where the platform has no such open at all, the same answer a filesystem without it gives.
    The name-source seam `write_guarded(open_unnamed=)` defaults to."""
    flag = getattr(os, "O_TMPFILE", None)
    if flag is None:
        raise OSError(errno.EOPNOTSUPP, "no O_TMPFILE on this platform", str(directory))
    return os.open(directory, flag | os.O_WRONLY, _FILE_MODE)




#: What an unnamed open answers on a filesystem (NFS, virtiofs, FUSE) or kernel that cannot make
#: one — the create lane then falls back. Any other errno is a real failure of the write.
_NO_UNNAMED_FILES = frozenset({errno.EOPNOTSUPP, errno.EISDIR, errno.EINVAL})




def _create_unnamed(
    path: Path, text: str | bytes, open_unnamed: Callable[[Path], int],
) -> bool:
    """`create`'s complete-or-absent lane (#1078 J16/J63): the body is written in full and
    synced on an unnamed file, set to 0644 masked by the process umask (`_link_unnamed` says
    why it sets the mode itself), which is then given `path`'s name in one `linkat`. No
    reader ever sees the name absent-then-empty or partial, the file never has two names (its
    link count goes 0 -> 1), and a crash before the link leaves nothing in the directory."""
    try:
        fd = open_unnamed(path.parent)
    except OSError as e:
        if e.errno in _NO_UNNAMED_FILES:
            return False
        raise
    try:
        dir_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            return _link_unnamed(fd, dir_fd, path.name, text)
        finally:
            os.close(dir_fd)
    finally:
        os.close(fd)




#: Where Linux (4.7+) reports this process's umask without changing it, on its `Umask:` line.
_PROC_STATUS = "/proc/self/status"




def _process_umask(status: str = _PROC_STATUS) -> int | None:
    """The process umask, read without changing it: the octal `Umask:` line of `status`
    (`/proc/self/status`). None when the file cannot be read or has no such line (a kernel
    before 4.7). Never `os.umask(m)` and back: in between, every other thread would create its
    files under `m`."""
    try:
        with open(status, "rb") as f:
            lines = f.read().splitlines()
    except OSError:
        return None
    for line in lines:
        key, _, value = line.partition(b":")
        if key == b"Umask":
            try:
                return int(value.strip(), 8)
            except ValueError:
                return None
    return None




def _link_unnamed(
    fd: int, dir_fd: int, leaf: str, text: str | bytes, *, os_: Any = os,
    status: str = _PROC_STATUS,
) -> bool:
    """The body of `create`'s unnamed lane, shared by the path, rooted and held seams: set the
    unnamed `fd` to `_FILE_MODE` masked by the process umask, write `text` to it in full, sync
    it, then name it `leaf` in `dir_fd`. False, with nothing named, when the umask cannot be
    read from `status` or the host has no `/proc` to link through; the caller then falls back.
    The caller owns both descriptors."""
    mask = _process_umask(status)
    if mask is None:
        return False
    os_.fchmod(fd, _FILE_MODE & ~mask)
    data = text if isinstance(text, (bytes, bytearray)) else text.encode("utf-8")
    # Buffered: the file object loops over a short `os.write` until every byte has landed.
    with os_.fdopen(fd, "wb", closefd=False) as f:
        f.write(data)
    os_.fsync(fd)
    try:
        os_.link(f"/proc/self/fd/{fd}", leaf, dst_dir_fd=dir_fd, follow_symlinks=True)
    except FileNotFoundError:
        if not os_.path.isdir("/proc/self/fd"):
            return False
        raise
    return True




def _create_named(path: Path, text: str | bytes) -> None:
    """`create`'s fallback where no unnamed file can be made: ONE `O_CREAT|O_EXCL|O_NOFOLLOW`
    open of the target itself, then the write (see `write_guarded` for its residue)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, _FILE_MODE)
    try:
        _write_all(fd, text)
    except BaseException:
        # Ours to remove: the create succeeded, so the half-written entry is this call's.
        with contextlib.suppress(OSError):
            os.remove(path)
        raise




def _mark_alias(exc: OSError, *, is_alias: bool) -> OSError:
    exc.write_guarded_alias = is_alias  # type: ignore[attr-defined]
    return exc




def is_hard_linked(st: os.stat_result) -> bool:
    """A regular file with more than one name — the alias `O_NOFOLLOW` cannot refuse."""
    return stat.S_ISREG(st.st_mode) and st.st_nlink > 1




def is_plain_entry(st: os.stat_result) -> bool:
    """The rule for "a plain, single-linked regular file", shared by the guarded write and read
    seams and the archive's destination screen."""
    return stat.S_ISREG(st.st_mode) and not is_hard_linked(st)




def _refuse_unless_plain(path: Path) -> None:
    """Refuse unless `path` is absent or a plain, single-linked regular file. Symlinks, hard
    links, directories, FIFOs, sockets and devices all get the same refusal type."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return
    _refuse_unless_plain_stat(st, path)




def _refuse_unless_plain_stat(st: os.stat_result, where: object) -> None:
    """:func:`_refuse_unless_plain`'s judgement of an entry already `stat`ed without following
    it (by `lstat`, a no-follow `fstatat`, or `fstat` on a no-follow descriptor)."""
    is_hardlink = is_hard_linked(st)
    is_alias = stat.S_ISLNK(st.st_mode) or is_hardlink
    if not is_plain_entry(st):
        # The planted entry is left in place so the reap scan can still report it. EMLINK for
        # a hard link, ELOOP otherwise; both are plain `OSError`, so the type stays uniform.
        refusal_errno = errno.EMLINK if is_hardlink else errno.ELOOP
        raise _mark_alias(
            NotPlainEntry(refusal_errno, "refusing to write through a non-plain or aliased entry",
                          str(where)),
            is_alias=is_alias,
        )




def open_nofollow_fd(path: Path, flags: int, *, os_: Any = os) -> int:
    """`O_NOFOLLOW` open whose `ELOOP` is marked as an alias refusal: after
    `_refuse_unless_plain`, it means a symlink was planted in the race window, and must not
    count toward the accounting kill circuit as an ordinary failure."""
    try:
        return os_.open(path, flags | os.O_NOFOLLOW, _FILE_MODE)
    except OSError as e:
        raise _mark_alias(e, is_alias=e.errno == errno.ELOOP) from None




@contextlib.contextmanager
def locked_for_rewrite(path: Path, *, os_: Any = os) -> Iterator[tuple[int, os.stat_result]]:
    """The locked read-modify-write prefix: refuse a non-plain target, open with
    `O_NOFOLLOW` (creating it when absent), judge the descriptor plain on its own `fstat` (a
    hard link planted after the precheck, #1174 O11), then take the exclusive lock — in that
    order, so refusal precedes any lock or write. Yields the locked descriptor, at position 0,
    and that `fstat`; never a file object (callers get contents, #1174 amendment 2)."""
    path = Path(path)
    _refuse_unless_plain(path)
    fd = open_nofollow_fd(path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, os_=os_)
    try:
        st = os_.fstat(fd)
        _refuse_unless_plain_stat(st, path)
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield fd, st
    finally:
        os_.close(fd)




def write_guarded(
    path: Path, text: str | bytes, *, mode: str = "replace",
    stage_name: Callable[[Path], Path] = stage_name,
    open_unnamed: Callable[[Path], int] = open_unnamed, **kw: object,
) -> None:
    """The single write seam every shared-tree writer routes through."""
    unexpected = set(kw) - {"encoding"}
    if unexpected:
        raise TypeError(
            f"write_guarded() got unexpected keyword argument(s) {sorted(unexpected)} — "
            f"did you mean mode={mode!r}?"
        )
    path = Path(path)
    if mode == "replace":
        _refuse_unless_plain(path)
        staged = Path(stage_name(path))
        try:
            fd = os.open(staged, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         _FILE_MODE)
        except OSError as e:
            raise _mark_alias(e, is_alias=e.errno == errno.EEXIST) from None
        try:
            _write_all(fd, text)
            os.replace(staged, path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.remove(staged)
            raise
    elif mode == "create":
        # Precheck first so a planted entry is the marked alias refusal; an EEXIST from the
        # link (or the fallback's open) is then the ordinary create race, unmarked.
        _refuse_unless_plain(path)
        if not _create_unnamed(path, text, open_unnamed):
            _create_named(path, text)
    elif mode == "append":
        _refuse_unless_plain(path)
        fd = open_nofollow_fd(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND)
        if isinstance(text, (bytes, bytearray)):
            with os.fdopen(fd, "ab") as fb:
                fb.write(text)
        else:
            with os.fdopen(fd, "a", encoding="utf-8") as f:
                f.write(text)
    elif mode == "update":
        with locked_for_rewrite(path) as (fd, _st):
            _rewrite_fd(os, fd, text.encode("utf-8") if isinstance(text, str) else bytes(text))
    else:
        raise ValueError(f"unknown write_guarded mode: {mode!r}")




def _write_all(fd: int, text: str | bytes, *, os_: Any = os, sync: bool = False) -> None:
    """Write `text` (UTF-8 for a `str`) to a fresh descriptor this call now owns, and close it —
    on every exit, `fdopen` failing included. `sync` flushes and `fsync`s it before the close,
    for a record whose bytes must be on disk when the call returns."""
    try:
        fb = os_.fdopen(fd, "wb")
    except BaseException:
        os_.close(fd)  # `fdopen` failed to take the fd, so it is still ours to close
        raise
    with fb:
        fb.write(text if isinstance(text, (bytes, bytearray)) else text.encode("utf-8"))
        if sync:
            fb.flush()
            os_.fsync(fd)




def _ensure_dir_component(component: Path) -> None:
    try:
        st = os.lstat(component)
    except FileNotFoundError:
        try:
            os.mkdir(component)  # lint-unguarded-tree-write: ok — this is the guarded mkdir the gate points other callers at
            return
        except FileExistsError:
            # Something appeared since the lstat: re-judge it, since it may be a planted
            # symlink. If it vanished again, the FileNotFoundError propagates (fail closed).
            st = os.lstat(component)
    if stat.S_ISLNK(st.st_mode):
        raise OSError(
            errno.ELOOP, "refusing to create through a symlinked path component", str(component)
        )
    if not stat.S_ISDIR(st.st_mode):
        raise NotADirectoryError(
            errno.ENOTDIR, "path component is not a directory", str(component)
        )




def guarded_mkdir(path: Path, *, base: Path) -> None:
    """`mkdir(parents=True, exist_ok=True)`, refusing a symlinked component at any depth below
    `base` (a plain `mkdir(parents=True)` would silently traverse one).

    `base` is the trust root: it and everything above it are host-controlled, since the box's
    writable mounts start inside it. `base` itself is created following symlinks; every
    component below it is judged. Checking up to `/` instead would refuse common host setups
    (`/tmp` is a symlink on macOS) with no security gain. `base` is required so each call site
    names the tree it trusts. Containment is judged lexically; `resolve()` would collapse the
    very symlinks being refused. (An exclusive create of one folder is `_io.hold_new(parent,
    name, exclusive=True)`, which takes a name, not a path.)"""
    path = Path(path)
    base = Path(base)
    try:
        rest = path.relative_to(base)
    except ValueError:
        raise ValueError(
            f"guarded_mkdir: {str(path)!r} is not inside the tree root {str(base)!r} — the "
            f"anchor names the wrong tree, or the target reaches outside it"
        ) from None
    # `relative_to` is a prefix match, so `<base>/x/../../escaped` passes it. Refuse a target
    # whose lexically normalised form climbs out; a `..` that stays inside is still accepted.
    if rest.parts and os.path.normpath(str(rest)).split(os.sep)[0] == os.pardir:
        raise ValueError(
            f"guarded_mkdir: {str(path)!r} climbs out of the tree root {str(base)!r} through "
            f"'..' — the target reaches outside the tree the anchor names"
        )
    # Skip on the hot path once the root exists. `is_dir()` follows a link at `base` on
    # purpose: `base` is the caller's trust root. A runs folder is not a link-tolerant base: it
    # is held no-follow first (`run_repository.hold_runs_folder`, #1105 OP-2), which refuses a
    # link there before this runs; a bigger disk is reached by moving the data root.
    if not base.is_dir():
        os.makedirs(base, exist_ok=True)
    accum = base
    parts = rest.parts
    for part in parts:
        accum = accum / part
        _ensure_dir_component(accum)




#: The staged-name marker, matched loosely (not the exact `<name>.staged-<16 hex>` shape) so
#: the sweep also removes planted staged-looking names. Nothing else writes into this suffix
#: namespace.
_STAGED_MARKER = ".staged-"




def sweep_staged(tree: Path) -> list[Path]:
    """Remove every orphaned staged file under `tree` (unpredictable staged names mean crash
    orphans are never overwritten by name). Symlinks are removed as entries, never followed.

    Called from `box.stop_and_scrub` after the reap scan, so the sweep never deletes entries
    the scan should report."""
    tree = Path(tree)
    removed: list[Path] = []
    for dirpath, _dirs, files in os.walk(tree, followlinks=False):
        for name in files:
            if _STAGED_MARKER in name:
                p = Path(dirpath) / name
                with contextlib.suppress(OSError):
                    os.remove(p)
                    removed.append(p)
    return removed


def unnamed_files_unavailable(error: OSError) -> bool:
    """Whether the filesystem refused unnamed-file creation as unsupported."""
    return error.errno in _NO_UNNAMED_FILES
