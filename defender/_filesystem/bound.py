"""Descriptor-rooted filesystem views and refusal records."""
from __future__ import annotations

import contextlib

import dataclasses


import errno




import os



import stat


import threading

from collections.abc import Callable, Iterator

from pathlib import Path, PurePath

from typing import Any, Final, Literal

from defender._filesystem.write import NotPlainEntry as NotPlainEntry, _FILE_MODE as _FILE_MODE, _mark_alias as _mark_alias, _refuse_unless_plain_stat as _refuse_unless_plain_stat

from defender._filesystem.json import parse_jsonl_row as parse_jsonl_row



TEXT_READ_ERRORS: tuple[type[Exception], ...] = (OSError, UnicodeDecodeError)
"""What reading a text file can raise: unreadable (``OSError``) or undecodable
(``UnicodeDecodeError``, a ``ValueError``).

For callers that read and parse under one ``try``. To add a parse error, bind the composed
tuple first (mypy rejects a star-unpack in an ``except`` display)::

    malformed: tuple[type[BaseException], ...] = (SomeParseError, *TEXT_READ_ERRORS)
    try:
        ...
    except malformed as e:
"""





#: The most a whole-file read through `_io` takes in (#1174): a planted sparse file
#: (`truncate -s 1T`) would otherwise have CPython pre-size a buffer of `st_size + 1`. A caller's
#: `limit` can only lower it (#1188 D1): `_read_plain_fd` clamps every limit here, so no call,
#: however spelled, reads more. The wire log, the one file legitimately past it, streams
#: (`iter_plain_jsonl_rows`).
READ_LIMIT = 64 * 1024 * 1024




ALIAS_READ_REFUSAL = "refusing to read through a non-plain or aliased entry"




#: One `read(2)` of the read step: a typical record (investigation.md is capped at 64 KiB) is
#: one read plus the empty one that says EOF.
_READ_CHUNK = 256 * 1024



_VANISHED = "the file vanished while it was being read"


_NOT_A_PATH = "not an encodable path"




class _TooLarge(OSError):
    """The read step's own size refusal (`EFBIG`): over the limit by `fstat`, or grown past it
    while read. Its own type, so a caller that heals from oversize content (the run-state JSON
    update, #1174 amendment 2) never heals from an unrelated `EFBIG` a fault raised."""




def _too_large(limit: int) -> _TooLarge:
    return _TooLarge(errno.EFBIG, f"larger than the read limit ({limit} bytes)")




class _ReadVanished(OSError):
    """An `ENOENT` after the descriptor was opened and judged plain. A subclass is not mapped to
    `FileNotFoundError` the way `OSError(ENOENT, ...)` is, so no reader's `except
    FileNotFoundError` (absent) catches it: it is a refusal (#1174 O3)."""




def _read_cap(limit: int) -> int:
    """A caller's read limit, clamped to `READ_LIMIT`: it can only lower the cap (#1188 D1). A
    non-int (`None` included, the old "no bound") is a caller's bug, refused as a `TypeError`
    before any byte is read rather than compared or added to below."""
    if not isinstance(limit, int) or isinstance(limit, bool):
        raise TypeError(f"read limit must be an int, not {limit!r}")
    return min(limit, READ_LIMIT)




def _read_plain_fd(
    os_: Any, fd: int, size: int, *, binary: bool, errors: str = "strict",
    limit: int = READ_LIMIT, budget: int | None = None,
) -> str | bytes:
    """The one place a whole file's bytes are read (#1174): every whole-file read in `_io`
    comes here, the guarded readers, the canonical wrappers and the locked JSON routines."""
    limit = _read_cap(limit)
    if budget is not None:
        if budget <= limit:
            return _read_prefix(os_, fd, budget, binary=binary, errors=errors)
        data = _read_prefix(os_, fd, limit + 1, binary=True, errors=errors)
        if len(data) > limit:
            raise _too_large(limit)
        assert isinstance(data, bytes)
        return data if binary else data.decode("utf-8", errors)
    if size > limit:
        raise _too_large(limit)
    buf = bytearray()
    want = size + 1 if size > 0 else _READ_CHUNK
    try:
        while chunk := os_.read(fd, want):
            buf += chunk
            if len(buf) > limit:
                raise _too_large(limit)
            want = _READ_CHUNK
    except FileNotFoundError:
        raise _ReadVanished(errno.ENOENT, _VANISHED) from None
    if binary:
        return bytes(buf)
    text = buf.decode("utf-8", errors)
    if "\r" in text:
        text = text.replace("\r\n", "\n").replace("\r", "\n")
    return text




def _read_prefix(os_: Any, fd: int, budget: int, *, binary: bool, errors: str) -> str | bytes:
    """`_read_plain_fd`'s prefix mode: at most `budget` bytes, asked for a chunk at a time (a
    huge budget allocates nothing up front), `_ReadVanished` for an `ENOENT` from a `read`,
    text decoded as UTF-8 under `errors` with no newline translation."""
    buf = bytearray()
    try:
        while len(buf) < budget and (
                chunk := os_.read(fd, min(budget - len(buf), _READ_CHUNK))):
            buf += chunk
    except FileNotFoundError:
        raise _ReadVanished(errno.ENOENT, _VANISHED) from None
    return bytes(buf) if binary else buf.decode("utf-8", errors)




# Linux only (the bound reader, not this module): `bind` walks open the root and each step
# `O_PATH`, which needs only search permission, as path traversal does; `O_RDONLY` would need
# read permission on every directory. `bind()` refuses with `_PLATFORM_FAULT` elsewhere.
_O_PATH: int | None = getattr(os, "O_PATH", None)


_PLATFORM_FAULT = ("the episode-tree reader walks each directory step with O_PATH, which this "
                   "platform's os module does not offer — the reader is Linux-only")



#: One intermediate step. `O_PATH|O_NOFOLLOW` opens a symlink as the link itself (`fstat`
#: shows `S_ISLNK`), which is then refused as an alias rather than traversed.
_STEP_FLAGS = (_O_PATH or 0) | os.O_NOFOLLOW | os.O_CLOEXEC



#: The root's own open (`bind`): an `O_PATH` directory handle that follows the operator's
#: spelling; a listing (`Bound._listing`) opens `.` for reading off it only then.
_ROOT_FLAGS = (_O_PATH or 0) | os.O_DIRECTORY | os.O_CLOEXEC



#: `errors=` values `Bound.read` admits; anything else is refused before any open.
_ERRORS_VALUES = ("strict", "replace")



_NOT_A_NAME = "not a valid relative name — a name is a sequence of plain path components"




def _parse_name(name: str | PurePath) -> tuple[str, tuple[str, ...]]:
    """A `bind`ed reader's name grammar: a POSIX `str` or a `PurePath`, split on `/` into
    non-empty components that are never `.` or `..`. Absolute names, NULs, empty components and
    a spelling that does not encode raise `ValueError` (naming no path) before any open.
    """
    if isinstance(name, PurePath):
        spelling = name.as_posix()
    elif isinstance(name, str):
        spelling = name
    else:
        raise ValueError(_NOT_A_NAME)
    if not spelling or spelling.startswith("/") or "\x00" in spelling:
        raise ValueError(_NOT_A_NAME)
    try:
        os.fsencode(spelling)  # a lone surrogate (not an undecodable byte) is no name (#1174)
    except UnicodeEncodeError:
        raise ValueError(_NOT_A_NAME) from None
    parts = tuple(spelling.split("/"))
    if any(p in ("", ".", "..") for p in parts):
        raise ValueError(_NOT_A_NAME)
    return spelling, parts




@dataclasses.dataclass(frozen=True)
class _Read:
    """What every `bind`ed reader's answer carries: `name` as the caller spelled it (`""` for
    the root), `absent`, and `reason` when refused. `refusal` renders them as one sentence."""

    name: str
    absent: bool
    reason: str | None

    @property
    def refusal(self) -> str | None:
        if self.reason is None:
            return None
        return f"{self.name}: {self.reason}" if self.name else self.reason




#: What refused a `bind`ed read (`RecordRead.refused_by`): a link or hard link at the name or a
#: linked folder on the way (the alias refusal); something at the name, or on the way, that is
#: not a file or folder (a directory or FIFO at the name, a file used as a folder); bytes that
#: are not UTF-8; or anything else (an I/O fault, a size cap, a closed root).
RefusalKind = Literal["alias", "not_file", "undecodable", "fault"]


REFUSED_ALIAS: Final = "alias"


REFUSED_NOT_FILE: Final = "not_file"


REFUSED_UNDECODABLE: Final = "undecodable"


REFUSED_FAULT: Final = "fault"




@dataclasses.dataclass(frozen=True)
class RecordRead(_Read):
    """A `bind`ed reader's answer to a file, in exactly one of three states: present (`text` a
    `str`, possibly empty), absent (`absent=True`) or refused (`reason`, and `refused_by`
    saying what stopped it: one of the `REFUSED_*` kinds)."""

    text: str | None
    refused_by: RefusalKind | None = None

    def __post_init__(self) -> None:
        if (self.reason is None) != (self.refused_by is None):
            raise ValueError("a refused RecordRead names what refused it, and only a refused one")




@dataclasses.dataclass(frozen=True)
class BytesRead(_Read):
    """A bound file's original bytes, with the same absence/refusal states as `RecordRead`."""

    data: bytes | None
    refused_by: RefusalKind | None = None

    def __post_init__(self) -> None:
        if (self.reason is None) != (self.refused_by is None):
            raise ValueError("a refused BytesRead names what refused it, and only a refused one")




#: What one entry of a listed directory is, judged without following it: a regular file (hard
#: links included — `read` refuses those), a real directory, or anything else.
ENTRY_FILE, ENTRY_DIR, ENTRY_OTHER = "file", "dir", "other"




@dataclasses.dataclass(frozen=True)
class EntriesRead(_Read):
    """A `bind`ed reader's answer to "what is in this directory" (`Bound.entries`): present
    (`entries` maps each name to its `ENTRY_*` kind), absent, or refused."""

    entries: dict[str, str] | None

    def files(self) -> list[str]:
        """The names classified regular files, sorted; `[]` when absent or refused."""
        return sorted(n for n, k in (self.entries or {}).items() if k == ENTRY_FILE)

    def dirs(self) -> list[str]:
        """The names classified real directories, sorted; `[]` when absent or refused."""
        return sorted(n for n, k in (self.entries or {}).items() if k == ENTRY_DIR)

    def has_file(self, entry: str) -> bool:
        return (self.entries or {}).get(entry) == ENTRY_FILE




@dataclasses.dataclass(frozen=True)
class StatRead(_Read):
    """A `bind`ed reader's answer to "what stands at this name" (`stat_entry`): present (`st`
    the entry's own `stat`, a link judged as the link), absent, or refused."""

    st: os.stat_result | None




@dataclasses.dataclass(frozen=True)
class StatsRead(_Read):
    """A `bind`ed reader's answer to "what stands in this directory" (`stat_entries`): present
    (`stats` maps each name to its own no-follow `stat`), absent, or refused."""

    stats: dict[str, os.stat_result] | None




# -- the core: reaching a file below a trust root (#1111) -----------------------------------
#
# Every no-follow read and write in this module past the path seams (`Bound`, and the rooted
# seam the `Run` handle writes through) reaches its file through these steps, so each rule is
# written once:
#   * `_descend` walks the folders, each opened off the one above as an `O_PATH|O_NOFOLLOW`
#     handle: a link is an unmarked ELOOP, a non-directory an unmarked ENOTDIR, never traversed.
#   * `_open_leaf` opens the file no-follow and non-blocking (a planted FIFO cannot wedge it) and
#     judges the opened descriptor with the one plainness rule, `_refuse_unless_plain_stat` (a
#     regular file with at most one name: a file a concurrent replace just unnamed still counts).
#     A read lets the open decide and asks nothing of the name first (#1049 d-04). A write first
#     judges the name by a no-follow stat (`_leaf_present`), so a plant is refused before any
#     write open and left in place for the reap scan; `create` and `replace` never open the name
#     (they link or rename onto it), and `append` / `update` judge the opened descriptor again.
#   * `_open_refusal` is what a failed leaf open means, as one table.
# A link or hard link at the leaf is a marked alias refusal; any other non-plain leaf, a linked
# folder and a non-directory folder are unmarked (`hooks/budget_enforcer.py` keys on the mark).
# Reads fold every refusal into a reason with no path in it (`_read_reason`).

_NOT_PLAIN = "refusing to write through a non-plain or aliased entry"


_LINKED_FOLDER = "refusing to create through a symlinked path component"


_NOT_A_FOLDER = "path component is not a directory"




def _step(os_: Any, dir_fd: int, component: str, where: Path, *, create: bool) -> int:
    """One folder, opened off `dir_fd` (made first, off the same handle, when `create` and it is
    absent). An absent folder is `FileNotFoundError`. The caller owns the returned fd."""
    try:
        fd = os_.open(component, _STEP_FLAGS, dir_fd=dir_fd)
    except FileNotFoundError:
        if not create:
            raise
        with contextlib.suppress(FileExistsError):  # whatever won the race is judged below
            os_.mkdir(component, dir_fd=dir_fd)  # lint-unguarded-tree-write: ok — the rooted mkdir, relative to a no-follow handle
        fd = os_.open(component, _STEP_FLAGS, dir_fd=dir_fd)
    try:
        st = os_.fstat(fd)
    except BaseException:
        os_.close(fd)
        raise
    if stat.S_ISDIR(st.st_mode):
        return fd
    os_.close(fd)
    if stat.S_ISLNK(st.st_mode):
        raise OSError(errno.ELOOP, _LINKED_FOLDER, str(where))
    raise NotADirectoryError(errno.ENOTDIR, _NOT_A_FOLDER, str(where))




@contextlib.contextmanager
def _descend(
    os_: Any, start_fd: int, folders: tuple[str, ...], where: Path, *, create: bool = False,
) -> Iterator[int]:
    """A handle on `<start_fd>/<folders>`, each folder judged by `_step`. Yields `start_fd`
    itself when `folders` is empty; closes every handle it opened."""
    fd = start_fd
    try:
        for component in folders:
            where = where / component
            step = _step(os_, fd, component, where, create=create)
            # Hand over before closing: an interrupt between the two can leak `left`, but the
            # `finally` never closes it a second time (a number another open may now hold).
            left, fd = fd, step
            if left != start_fd:
                os_.close(left)
        yield fd
    finally:
        if fd != start_fd:
            os_.close(fd)




def _open_refusal(e: OSError, where: Path) -> OSError:
    """A failed leaf open, read as a refusal row: ELOOP is a link at the name (marked); ENXIO (a
    reader-less FIFO, a socket) and EISDIR (a directory) are the unmarked non-plain row; any
    other errno is the open's own failure, unmarked."""
    if e.errno == errno.ELOOP:
        return _mark_alias(NotPlainEntry(errno.ELOOP, _NOT_PLAIN, str(where)), is_alias=True)
    if e.errno in (errno.ENXIO, errno.EISDIR):
        return _mark_alias(NotPlainEntry(errno.ELOOP, _NOT_PLAIN, str(where)), is_alias=False)
    return _mark_alias(e, is_alias=False)




def _open_leaf_stat(
    os_: Any, dir_fd: int, leaf: str, flags: int, where: Path,
) -> tuple[int, os.stat_result]:
    """:func:`_open_leaf`, also answering the descriptor's one `fstat` (the plainness
    judgement), so a reader takes the size from it rather than asking again."""
    try:
        fd = os_.open(leaf, flags | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, _FILE_MODE,
                      dir_fd=dir_fd)
    except OSError as e:
        raise _open_refusal(e, where) from None
    try:
        st = os_.fstat(fd)
        _refuse_unless_plain_stat(st, where)
    except BaseException:
        os_.close(fd)
        raise
    return fd, st




def _read_leaf(
    os_: Any, dir_fd: int, leaf: str, where: Path, *, binary: bool, errors: str = "strict",
    max_bytes: int | None = None,
) -> str | bytes:
    """The whole of the plain file `leaf` (the open decides), or the exception that stopped it:
    `FileNotFoundError` when absent at the open, else a member of `TEXT_READ_ERRORS` (the read
    step's refusals among them, :func:`_read_plain_fd`). With `max_bytes`, the read step's
    byte-faithful prefix of at most that many bytes."""
    fd, st = _open_leaf_stat(os_, dir_fd, leaf, os.O_RDONLY, where)
    try:
        return _read_plain_fd(os_, fd, st.st_size, binary=binary, errors=errors,
                              budget=max_bytes)
    finally:
        os_.close(fd)




def _refused_by(e: BaseException) -> RefusalKind:
    """The `REFUSED_*` kind of a refused read's exception. The core already marks the cases
    apart: `NotPlainEntry` is an entry at the name, alias-marked for a link or hard link; a
    linked folder on the way is a bare `ELOOP`; a file used as a folder is
    `NotADirectoryError`."""
    if isinstance(e, UnicodeDecodeError):
        return REFUSED_UNDECODABLE
    if isinstance(e, NotPlainEntry):
        return REFUSED_ALIAS if getattr(e, "write_guarded_alias", False) else REFUSED_NOT_FILE
    if isinstance(e, NotADirectoryError):
        return REFUSED_NOT_FILE
    if isinstance(e, OSError) and e.errno == errno.ELOOP:
        return REFUSED_ALIAS
    return REFUSED_FAULT




def _read_reason(e: BaseException) -> str:
    """A refused read's reason, naming no path: the alias sentence for a link, hard link or
    other non-plain entry, else the error's own words."""
    if isinstance(e, _ReadVanished):
        return _VANISHED
    if isinstance(e, OSError) and e.errno:
        if e.errno in (errno.ELOOP, errno.EMLINK):
            return ALIAS_READ_REFUSAL
        if isinstance(e, _TooLarge) or (e.errno == errno.EINVAL and e.strerror == _NOT_A_PATH):
            return str(e.strerror)
        return os.strerror(e.errno)
    return str(e)




def _entry_kind(entry: Any) -> str:
    """One `os.DirEntry`'s kind, judged of the entry itself (`follow_symlinks=False`)."""
    if entry.is_symlink():
        return ENTRY_OTHER
    if entry.is_dir(follow_symlinks=False):
        return ENTRY_DIR
    if entry.is_file(follow_symlinks=False):
        return ENTRY_FILE
    return ENTRY_OTHER




class _Handle:
    """A held directory descriptor — a `bind`'s root, shared with its `under` derivations, or a
    `Held`'s, shared with its views — closed once: by its owner or, if unscoped, on collection.

    Every read and write off it works from a private `dup` taken under the handle's lock
    (`dup()`), and `close()` takes the same lock. So a caller after the close gets `EBADF` and
    touches nothing, and one already running keeps its own descriptor, never a number the
    process has since reused (the sibling's `Ledger.record` runs on worker threads that can
    outlive a cancelled task)."""

    __slots__ = ("_lock", "_os", "fd")

    def __init__(self, os_: Any, fd: int | None) -> None:
        self._os = os_
        self.fd = fd
        self._lock = threading.Lock()

    @contextlib.contextmanager
    def dup(self, where: object = None) -> Iterator[int]:
        """A private duplicate of the held descriptor for one operation, closed after it."""
        with self._lock:
            if self.fd is None:
                raise OSError(errno.EBADF, os.strerror(errno.EBADF),
                              None if where is None else str(where))
            fd = self._os.dup(self.fd)
        try:
            yield fd
        finally:
            self._os.close(fd)

    def close(self) -> None:
        with self._lock:
            if self.fd is not None:
                fd, self.fd = self.fd, None
                self._os.close(fd)

    def __del__(self) -> None:
        with contextlib.suppress(Exception):
            self.close()




class Bound:
    """An episode-tree reader bound to one root (`bind`) or a directory relative to it
    (`under`). It holds the root only as an open directory handle, never as a path a reader
    could format; every read is `openat`-style and no-follow from that handle.

    `under` opens nothing: each read walks the full relative name from the root at that moment.
    The root itself is opened once and not re-resolved, so a `Bound` is scoped to one grading or
    rendering pass.
    """

    def __init__(self, os_: Any, handle: _Handle, *, prefix: tuple[str, ...] = (),
                 absent: bool = False, error: str | None = None, owner: bool = False) -> None:
        self._os = os_
        self._handle = handle
        self._prefix = prefix
        self._absent = absent
        self._error = error
        self._owner = owner

    # -- lifetime: one handle per `bind` -------------------------------------------------------

    def close(self) -> None:
        """Release the root handle (derived readers then answer `Bad file descriptor`). A no-op
        on a derived reader. Idempotent."""
        if self._owner:
            self._handle.close()

    def __enter__(self) -> Bound:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # -- the reads ------------------------------------------------------------------------------

    def read(self, name: str | PurePath, *, errors: str = "strict",
             max_bytes: int | None = None) -> RecordRead:
        """The file at `name`, as a `RecordRead`. `max_bytes` bounds the bytes taken off the
        file (`_read_plain_fd`'s prefix mode): its text is the first `max_bytes` bytes decoded,
        newlines kept as they are. Without it the read is whole."""
        data, absent, reason, refused_by = self._read(
            name, binary=False, errors=errors, max_bytes=max_bytes)
        assert data is None or isinstance(data, str)
        return RecordRead(name=name.as_posix() if isinstance(name, PurePath) else name,
                          text=data, absent=absent, reason=reason, refused_by=refused_by)

    def read_bytes(self, name: str | PurePath) -> BytesRead:
        """Read original bytes whole, with the same size limit and path guards as `read`."""
        data, absent, reason, refused_by = self._read(name, binary=True)
        assert data is None or isinstance(data, bytes)
        return BytesRead(name=name.as_posix() if isinstance(name, PurePath) else name,
                         data=data, absent=absent, reason=reason, refused_by=refused_by)

    def _read(self, name: str | PurePath, *, binary: bool, errors: str = "strict",
              max_bytes: int | None = None,
              ) -> tuple[str | bytes | None, bool, str | None, RefusalKind | None]:
        _, parts = _parse_name(name)
        if errors not in _ERRORS_VALUES:
            raise ValueError("errors must be 'strict' or 'replace'")
        if max_bytes is not None and (isinstance(max_bytes, bool) or not isinstance(
                max_bytes, int) or max_bytes < 0):
            raise ValueError("max_bytes must be a non-negative int")
        if self._absent:
            return None, True, None, None
        if self._error is not None:
            return None, False, self._error, REFUSED_FAULT
        where = PurePath(*self._prefix, *parts)
        try:
            # A closed root is the dup's `EBADF`, answered as a refusal like any other.
            with self._handle.dup() as root_fd, _descend(
                    self._os, root_fd, self._prefix + parts[:-1], Path(".")) as dir_fd:
                data = _read_leaf(self._os, dir_fd, parts[-1], Path(where), binary=binary,
                                  errors=errors, max_bytes=max_bytes)
        except FileNotFoundError:
            return None, True, None, None
        except TEXT_READ_ERRORS as e:
            return None, False, _read_reason(e), _refused_by(e)
        return data, False, None, None

    def read_jsonl(self, name: str | PurePath) -> tuple[list[dict], int, RecordRead]:
        rec = self.read(name, errors="replace")
        if rec.text is None:
            return [], 0, rec
        rows, malformed = _jsonl_rows_of(rec.text)
        return rows, malformed, rec

    def entries(self) -> EntriesRead:
        """What is in the bound directory, each entry judged without following it. For an
        `under` derivation the walk is the same no-follow walk `read` makes."""
        absent, reason, listed = self._listing(_entry_kind, lambda e: e.strerror or str(e))
        return EntriesRead(name="/".join(self._prefix), entries=listed, absent=absent,
                           reason=reason)

    def _listing(
        self, judge: Callable[[Any], Any], reason_of: Callable[[OSError], str],
    ) -> tuple[bool, str | None, dict[str, Any] | None]:
        """The one listing step `entries()` and `stat_entries` share: `(absent, reason, rows)`,
        each row `judge(entry)` of one scanned entry, and a scan fault `reason_of(error)`."""
        if self._absent:
            return True, None, None
        if self._error is not None:
            return False, self._error, None
        try:
            with self._handle.dup() as root_fd:
                kind, payload = self._directory_fd(root_fd)
        except OSError as e:  # the root closed: the dup's `EBADF`
            return False, (e.strerror or str(e)), None
        if kind != "leaf":
            return kind == "absent", None if kind == "absent" else str(payload), None
        fd = payload
        try:
            try:
                with self._os.scandir(fd) as it:
                    rows = {entry.name: judge(entry) for entry in it}
            except OSError as fault:
                try:
                    dead = self._os.fstat(fd).st_nlink == 0
                except OSError:
                    dead = False
                return (True, None, None) if dead else (False, reason_of(fault), None)
            try:
                dead = self._os.fstat(fd).st_nlink == 0
            except OSError as e:
                return False, reason_of(e), None
        finally:
            self._os.close(fd)
        return (True, None, None) if dead else (False, None, rows)

    def _directory_fd(self, root_fd: int) -> tuple[str, Any]:
        """A read handle on the bound directory for `_listing`: the prefix walked as folders,
        then `.` reopened for reading off the last handle (the walk's handles are `O_PATH`)."""
        try:
            with _descend(self._os, root_fd, self._prefix, Path(".")) as dir_fd:
                fd = self._os.open(  # lint-text-io: ok — os.open of a DIRECTORY handle, no text mode
                    ".", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC, dir_fd=dir_fd)
        except FileNotFoundError:
            return "absent", None
        except OSError as e:
            return "refused", _read_reason(e)
        return "leaf", fd

    def under(self, name: str | PurePath) -> Bound:
        """A reader bound at `name` relative to this one — a name prefix over the same root
        handle. Owns no handle."""
        _spelling, parts = _parse_name(name)
        return Bound(self._os, self._handle, prefix=self._prefix + parts,
                     absent=self._absent, error=self._error)




def located(bound: Bound) -> str:
    """Where `bound`'s folder is, for a refusal to name: the kernel's name for the held
    descriptor (`/proc/self/fd`, as the `O_PATH` hold already assumes Linux) joined with the
    view's prefix; `""` when it cannot be told. Description only — nothing is opened, and
    nothing is trusted, by it. A function beside `Bound`, as `stat_entry` is (#1133 O3)."""
    try:
        with bound._handle.dup() as fd:
            root = os.readlink(f"/proc/self/fd/{fd}")
    except OSError:
        return ""
    return str(Path(root, *bound._prefix))




def stat_entry(bound: Bound, name: str | PurePath) -> StatRead:
    """What stands at `name` below `bound`, judged without following it: the folders on the
    way are walked as `Bound.read` walks them (a linked or non-directory folder is refused),
    and the leaf is `stat`ed no-follow, so a link there answers as the link itself. Opens
    nothing at the leaf — a FIFO cannot block it. A function beside `Bound`, not a method: the
    reader's own surface is pinned to its readers and `close` (#1133 O3)."""
    spelling, parts = _parse_name(name)
    if bound._absent:
        return StatRead(name=spelling, st=None, absent=True, reason=None)
    if bound._error is not None:
        return StatRead(name=spelling, st=None, absent=False, reason=bound._error)
    os_ = bound._os
    try:
        with bound._handle.dup() as root_fd, _descend(
                os_, root_fd, bound._prefix + parts[:-1], Path(".")) as dir_fd:
            st = os_.stat(parts[-1], dir_fd=dir_fd, follow_symlinks=False)
    except FileNotFoundError:
        return StatRead(name=spelling, st=None, absent=True, reason=None)
    except OSError as e:
        return StatRead(name=spelling, st=None, absent=False, reason=_read_reason(e))
    return StatRead(name=spelling, st=st, absent=False, reason=None)




def stat_entries(bound: Bound) -> StatsRead:
    """Every entry of the directory `bound` names, each judged without following it: the
    directory is reached and scanned by the listing step `Bound.entries` is built on
    (`Bound._listing`, once), and each entry is `stat`ed no-follow relative to it — one call
    per entry, where `entries()` plus a `stat_entry` per name would walk from the root again
    for every one. So a directory deleted under the listing is absent here as it is there
    (#1177). Opens no entry: a FIFO cannot block it. A function beside `Bound`, like
    `stat_entry`, for the same reason (#1133 O3)."""
    absent, reason, stats = bound._listing(
        lambda entry: entry.stat(follow_symlinks=False), _read_reason)
    return StatsRead(name="/".join(bound._prefix), stats=stats, absent=absent, reason=reason)




def bind(root: Path, *, os_: Any = os) -> Bound:  # lint-dup: ok — an unrelated `bind` (an AgentDeps builder) already lives at runtime/agent_definition.py:294; the shared word names two unrelated concepts, not one contract split in two
    """Open `root` once (following a symlinked root spelling, the operator's own; nothing below
    it is followed) and return a `Bound` that owns the handle: `with bind(root) as bound:`.

    An absent, non-directory or unreadable root does not raise here; every later read answers
    absent or refused, per name.
    """
    if _O_PATH is None:  # pragma: no cover — no CI box lacks it
        raise OSError(errno.ENOTSUP, _PLATFORM_FAULT)
    try:
        fd = os_.open(Path(root), _ROOT_FLAGS)
    except FileNotFoundError:
        return Bound(os_, _Handle(os_, None), absent=True)
    except OSError as e:
        return Bound(os_, _Handle(os_, None), error=(e.strerror or str(e)))
    return Bound(os_, _Handle(os_, fd), owner=True)




def _jsonl_rows_of(text: str) -> tuple[list[dict], int]:
    rows: list[dict] = []
    unreadable = 0
    for line in text.splitlines():
        if not line.strip():
            continue
        row = parse_jsonl_row(line)
        if row is None:
            unreadable += 1
        else:
            rows.append(row)
    return rows, unreadable
