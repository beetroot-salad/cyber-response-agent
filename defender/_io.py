from __future__ import annotations

import contextlib
import dataclasses
import datetime as _dt
import errno
import fcntl
import json
import math
import os
import re
import secrets
import stat
import sys
import threading
from collections.abc import Callable, Iterator, Mapping
from pathlib import Path, PurePath
from typing import Any, Literal, overload

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


def read_text_utf8(path: Path) -> str:
    return path.read_text(encoding="utf-8")  # lint-text-io: ok — the canonical pinned reader


def read_text_soft(path: Path) -> tuple[str | None, str | None]:
    try:
        return read_text_utf8(path), None
    except TEXT_READ_ERRORS as e:
        return None, str(e)


ALIAS_READ_REFUSAL = "refusing to read through a non-plain or aliased entry"


def entry_present(path: Path) -> bool:
    """Does anything stand at the name — a file, a link, a directory, a FIFO?

    Safe to ask ahead of a guarded read: it decides only whether a caller reports "absent" or
    "refused", never what is read. Not ``Path.exists()``, which follows links and on 3.11
    re-raises a permission fault from the parent. An entry that cannot be judged counts as
    present; the guarded read that follows names why it could not be read.
    """
    try:
        os.lstat(path)
    except FileNotFoundError:
        return False
    except OSError:
        return True
    return True


def read_guarded(path: Path, *, errors: str = "strict") -> tuple[str | None, str | None]:
    """:func:`write_guarded`'s READ-side twin: the text at ``path``, or a refusal reason.

    Same return shape as :func:`read_text_soft`, but anything other than a plain,
    single-linked regular file is refused rather than followed — trees a box has written into
    may hold planted entries. ``errors`` is ``open``'s decoding policy; tolerant line readers
    pass ``"replace"`` so one bad byte costs one row.

    Absence is also a refusal here (the reason string distinguishes it); a caller that must act
    on absence differently uses :func:`read_plain` and catches it.
    """
    try:
        return read_plain(path, errors=errors), None
    except TEXT_READ_ERRORS as e:
        return None, str(e)


def read_plain(path: Path, *, errors: str = "strict") -> str:
    """The guarded read as a RAISING primitive: the text of the plain, single-linked regular
    file at ``path``, read with universal newlines exactly as ``Path.read_text`` would — or the
    exception that stopped it, every one a member of :data:`TEXT_READ_ERRORS`:

      * ``FileNotFoundError`` — nothing at the name;
      * an ``OSError`` carrying :data:`ALIAS_READ_REFUSAL` — the entry is not a plain file: a
        symlink (refused at the open, ``ELOOP``), a hard link (``EMLINK``, the write side's
        own errno for the shape ``O_NOFOLLOW`` cannot refuse), a directory, fifo, socket or
        device (``ELOOP``, as the write side folds them);
      * any other ``OSError`` — the file is there and could not be read (``EACCES``, ``EIO``);
      * ``UnicodeDecodeError`` — its bytes are not UTF-8.

    Plainness is judged on the open descriptor (``O_NOFOLLOW`` then ``fstat``), not by
    ``lstat``-then-read, which leaves a race window for a plant.
    """
    # `_open_plain_fd` opens with `O_NONBLOCK`: a planted FIFO would otherwise block the open
    # forever before `fstat` could refuse it.
    fd = _open_plain_fd(path)
    try:
        with os.fdopen(fd, "r", encoding="utf-8", errors=errors) as fh:
            fd = -1  # `fdopen` owns it now; the finally below must not close it twice.
            return fh.read()
    finally:
        if fd >= 0:
            os.close(fd)


def read_plain_bytes(path: Path) -> bytes:
    """:func:`read_plain` without newline translation, for records whose exact bytes matter
    (e.g. the alert's content hash)."""
    fd = _open_plain_fd(path)
    try:
        with os.fdopen(fd, "rb") as fh:
            fd = -1
            return fh.read()
    finally:
        if fd >= 0:
            os.close(fd)


def read_bytes_guarded(path: Path) -> tuple[bytes | None, str | None]:
    """:func:`read_guarded`'s bytes twin — ``(data, None)`` or ``(None, reason)``."""
    try:
        return read_plain_bytes(path), None
    except TEXT_READ_ERRORS as e:
        return None, str(e)


def _open_plain_fd(path: Path) -> int:
    """The guarded open both plain readers share; the caller owns the returned fd."""
    try:
        fd = open_nofollow_fd(Path(path), os.O_RDONLY | os.O_NONBLOCK)
    except OSError as e:
        # Reword a symlink-at-the-leaf `ELOOP` as the alias refusal. An `ELOOP` from a looped
        # component higher up keeps its own strerror: the leaf is not the alias.
        if getattr(e, "write_guarded_alias", False) and _leaf_is_link(path):
            raise _mark_alias(OSError(errno.ELOOP, ALIAS_READ_REFUSAL, str(path)),
                              is_alias=True) from None
        raise
    try:
        st = os.fstat(fd)
        # `O_NOFOLLOW` cannot refuse a hard link, so check the link count; directories,
        # FIFOs, sockets and devices get the same refusal as a planted symlink.
        if not is_plain_entry(st):
            raise OSError(
                errno.EMLINK if is_hard_linked(st) else errno.ELOOP, ALIAS_READ_REFUSAL,
                str(path),
            )
    except BaseException:
        os.close(fd)
        raise
    return fd


def _leaf_is_link(path: Path) -> bool:
    """Is the entry at `path` itself a symlink? `False` if it cannot be `lstat`ed (a looped
    parent), where the leaf is not the alias."""
    try:
        return stat.S_ISLNK(os.lstat(path).st_mode)
    except OSError:
        return False


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
#: spelling; `Bound.entries()` opens `.` for reading off it only when listing.
_ROOT_FLAGS = (_O_PATH or 0) | os.O_DIRECTORY | os.O_CLOEXEC

#: `errors=` values `Bound.read` admits; anything else is refused before any open.
_ERRORS_VALUES = ("strict", "replace")

_NOT_A_NAME = "not a valid relative name — a name is a sequence of plain path components"


def _parse_name(name: str | PurePath) -> tuple[str, tuple[str, ...]]:
    """A `bind`ed reader's name grammar: a POSIX `str` or a `PurePath`, split on `/` into
    non-empty components that are never `.` or `..`. Absolute names, NULs and empty components
    raise `ValueError` (naming no path) before any open.
    """
    if isinstance(name, PurePath):
        spelling = name.as_posix()
    elif isinstance(name, str):
        spelling = name
    else:
        raise ValueError(_NOT_A_NAME)
    if not spelling or spelling.startswith("/") or "\x00" in spelling:
        raise ValueError(_NOT_A_NAME)
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


@dataclasses.dataclass(frozen=True)
class RecordRead(_Read):
    """A `bind`ed reader's answer to a file, in exactly one of three states: present (`text` a
    `str`, possibly empty), absent (`absent=True`) or refused (`reason`)."""

    text: str | None


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

class NotPlainEntry(OSError):  # noqa: N818 — named for what it reports, like `FileExistsError`'s siblings
    """The core's refusal of a link, hard link or other non-plain entry AT a name (left in place
    for the reap scan): ELOOP, or EMLINK for a hard link, carrying the `write_guarded_alias`
    mark. A linked or non-directory FOLDER on the way is a plain `OSError` / `NotADirectoryError`
    instead, so a caller that contains this refusal contains nothing else."""
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


@contextlib.contextmanager
def _rooted(
    os_: Any, root: Path, folders: tuple[str, ...], *, create: bool = False,
) -> Iterator[int]:
    """`_descend` from a trust root, opened following its spelling (host territory, as
    `guarded_mkdir`'s base is). A missing root is `FileNotFoundError`."""
    if _O_PATH is None:  # pragma: no cover — no CI box lacks it
        raise OSError(errno.ENOTSUP, _PLATFORM_FAULT)
    root_fd = os_.open(Path(root), _ROOT_FLAGS)
    try:
        with _descend(os_, root_fd, folders, Path(root), create=create) as fd:
            yield fd
    finally:
        os_.close(root_fd)


def _leaf_present(os_: Any, dir_fd: int, leaf: str, where: Path) -> bool:
    """Judge the entry at `leaf` by a no-follow stat: False when absent, True when a plain file
    stands there, else its refusal (left in place for the reap scan)."""
    try:
        st = os_.stat(leaf, dir_fd=dir_fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    _refuse_unless_plain_stat(st, where)
    return True


def _open_refusal(e: OSError, where: Path) -> OSError:
    """A failed leaf open, read as a refusal row: ELOOP is a link at the name (marked); ENXIO (a
    reader-less FIFO, a socket) and EISDIR (a directory) are the unmarked non-plain row; any
    other errno is the open's own failure, unmarked."""
    if e.errno == errno.ELOOP:
        return _mark_alias(NotPlainEntry(errno.ELOOP, _NOT_PLAIN, str(where)), is_alias=True)
    if e.errno in (errno.ENXIO, errno.EISDIR):
        return _mark_alias(NotPlainEntry(errno.ELOOP, _NOT_PLAIN, str(where)), is_alias=False)
    return _mark_alias(e, is_alias=False)


def _open_leaf(os_: Any, dir_fd: int, leaf: str, flags: int, where: Path) -> int:
    """Open `leaf` off `dir_fd` no-follow and non-blocking, then judge the descriptor. The
    caller owns the returned fd."""
    try:
        fd = os_.open(leaf, flags | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, 0o644,
                      dir_fd=dir_fd)
    except OSError as e:
        raise _open_refusal(e, where) from None
    try:
        _refuse_unless_plain_stat(os_.fstat(fd), where)
    except BaseException:
        os_.close(fd)
        raise
    return fd


def _read_leaf(
    os_: Any, dir_fd: int, leaf: str, where: Path, *, binary: bool, errors: str = "strict",
) -> str | bytes:
    """The whole of the plain file `leaf` (the open decides), or the exception that stopped it:
    `FileNotFoundError` when absent, else a member of `TEXT_READ_ERRORS`."""
    fd = _open_leaf(os_, dir_fd, leaf, os.O_RDONLY, where)
    try:
        fh = os_.fdopen(fd, "rb") if binary else os_.fdopen(
            fd, "r", encoding="utf-8", errors=errors)
    except BaseException:
        os_.close(fd)  # `fdopen` failed to take the fd, so it is still ours to close
        raise
    with fh:
        return fh.read()


def _read_reason(e: BaseException) -> str:
    """A refused read's reason, naming no path: the alias sentence for a link, hard link or
    other non-plain entry, else the error's own words."""
    if isinstance(e, OSError) and e.errno:
        if e.errno in (errno.ELOOP, errno.EMLINK):
            return ALIAS_READ_REFUSAL
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

    def read(self, name: str | PurePath, *, errors: str = "strict") -> RecordRead:
        spelling, parts = _parse_name(name)
        if errors not in _ERRORS_VALUES:
            raise ValueError("errors must be 'strict' or 'replace'")
        if self._absent:
            return RecordRead(name=spelling, text=None, absent=True, reason=None)
        if self._error is not None:
            return RecordRead(name=spelling, text=None, absent=False, reason=self._error)
        where = PurePath(*self._prefix, *parts)
        try:
            # A closed root is the dup's `EBADF`, answered as a refusal like any other.
            with self._handle.dup() as root_fd, _descend(
                    self._os, root_fd, self._prefix + parts[:-1], Path(".")) as dir_fd:
                text = _read_leaf(self._os, dir_fd, parts[-1], Path(where), binary=False,
                                  errors=errors)
        except FileNotFoundError:
            return RecordRead(name=spelling, text=None, absent=True, reason=None)
        except TEXT_READ_ERRORS as e:
            return RecordRead(name=spelling, text=None, absent=False, reason=_read_reason(e))
        assert isinstance(text, str)
        return RecordRead(name=spelling, text=text, absent=False, reason=None)

    def read_jsonl(self, name: str | PurePath) -> tuple[list[dict], int, RecordRead]:
        rec = self.read(name, errors="replace")
        if rec.text is None:
            return [], 0, rec
        rows, malformed = _jsonl_rows_of(rec.text)
        return rows, malformed, rec

    def entries(self) -> EntriesRead:
        """What is in the bound directory, each entry judged without following it. For an
        `under` derivation the walk is the same no-follow walk `read` makes."""
        spelling = "/".join(self._prefix)
        if self._absent:
            return EntriesRead(name=spelling, entries=None, absent=True, reason=None)
        if self._error is not None:
            return EntriesRead(name=spelling, entries=None, absent=False, reason=self._error)
        try:
            with self._handle.dup() as root_fd:
                kind, payload = self._directory_fd(root_fd)
        except OSError as e:  # the root closed: the dup's `EBADF`
            return EntriesRead(name=spelling, entries=None, absent=False,
                               reason=(e.strerror or str(e)))
        if kind != "leaf":
            return EntriesRead(name=spelling, entries=None, absent=kind == "absent",
                               reason=None if kind == "absent" else str(payload))
        fd = payload
        try:
            with self._os.scandir(fd) as it:
                listed = {entry.name: _entry_kind(entry) for entry in it}
        except OSError as e:
            return EntriesRead(name=spelling, entries=None, absent=False,
                               reason=(e.strerror or str(e)))
        finally:
            self._os.close(fd)
        return EntriesRead(name=spelling, entries=listed, absent=False, reason=None)

    def _directory_fd(self, root_fd: int) -> tuple[str, Any]:
        """A read handle on the bound directory for `entries`: the prefix walked as folders,
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


def use_utf8_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(encoding="utf-8", errors=getattr(stream, "errors", None) or "strict")


#: The deepest nesting a box-written JSON artifact may carry and still be readable, judged on
#: the bytes before decoding. `json.loads` recurses on the shared stack, so without this bound
#: the same line could decode from a shallow caller and hit `RecursionError` from a deep one,
#: and a writer and reader could disagree on whether it is a row. 100 is far past any real
#: artifact and far short of the stack budget.
JSON_NESTING_LIMIT = 100

#: A string literal or a bracket. A string with no closing quote runs to the end of the text:
#: the match can never fail, so the scan never backs up and restarts at a later quote, which on
#: an unclosed run of escaped quotes made the scan quadratic in the text's length.
_JSON_TOKEN = re.compile(r'"(?:[^"\\]|\\.)*"?|[\[\]{}]')


def json_nesting_depth(text: str) -> int:
    """The deepest container nesting in ``text``, judged without decoding it.

    Exact for valid JSON (brackets inside string literals are not counted); invalid JSON is
    refused by the decoder anyway. One pass, linear in the text's length whatever it holds, so
    it is safe on model- or box-written text of any size."""
    depth = deepest = 0
    for token in _JSON_TOKEN.finditer(text):
        bracket = text[token.start()]
        if bracket == '"':
            continue
        if bracket in "[{":
            depth += 1
            deepest = max(deepest, depth)
        elif depth:
            depth -= 1
    return deepest


# lint-parse: ok — returns `object`, not `Any`, so each caller must narrow the shape itself.
def load_json_artifact(text: str) -> tuple[object, str | None]:
    """Decode one JSON artifact a box could have written: ``(value, None)``, or ``(None,
    reason)`` when it is not one. Success is ``reason is None`` — ``null`` decodes to ``None``.

    The single place malformed-artifact tolerance is decided. Nesting is checked before
    decoding (see :data:`JSON_NESTING_LIMIT`) rather than catching ``RecursionError``, whose
    occurrence depends on the caller's stack depth."""
    if json_nesting_depth(text) > JSON_NESTING_LIMIT:
        return None, f"nested deeper than {JSON_NESTING_LIMIT}"
    try:
        return json.loads(text), None
    except ValueError as e:
        return None, str(e)


def parse_jsonl_row(line: str) -> dict | None:
    """One physical line as a JSONL row (a JSON object), or ``None``.

    Public because ``challenge_gate._write_trace_row`` must apply exactly the predicate the
    readers do, from any stack depth. Non-dict JSON is not a row, so consumers can call
    ``row.get(...)`` safely.
    """
    s = line.strip()
    if not s:
        return None
    obj, reason = load_json_artifact(s)
    return obj if reason is None and isinstance(obj, dict) else None


def read_jsonl_rows(path: Path) -> list[dict]:
    return read_jsonl_rows_report(path)[0]


def read_jsonl_rows_report(path: Path) -> tuple[list[dict], int]:
    """JSONL rows plus the number of non-blank lines that were not rows, for callers that must
    account for lost evidence.
    """
    if not path.is_file():
        return [], 0
    text = path.read_text(encoding="utf-8", errors="replace")  # lint-jsonl-io: ok — the canonical tolerant reader  # noqa: E501
    return _jsonl_rows_of(text)


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


class JsonTooDeep(ValueError):
    """`json_safe(..., deeper="refuse")` met a container past `max_depth`."""


def json_safe(value: Any, *, non_finite: Literal["text", "null"],
              max_depth: int | None = None, deeper: Literal["repr", "refuse"] = "repr",
              naive_is_utc: bool = False) -> Any:
    """`value` with only the parts the JSON encoder cannot carry replaced; text, numbers,
    booleans and null are left as the encoder would write them.

    A set becomes a list, ordered by each member's written JSON. A key is always text. A key
    or value JSON has no type for becomes text: a date or time in ISO 8601, a timestamp that
    knows its zone in UTC as `2026-01-01T10:00:00.000000Z` — one fixed width, so every
    timestamp in one output reads alike. `naive_is_utc` is for a caller whose zone-less
    timestamps are known to be UTC; any other zone-less one is written without a zone.

    A non-finite float goes the way the caller says: `"text"` keeps it, spelled as the
    Protocol Buffers JSON mapping and OpenTelemetry spell it (`"NaN"`, `"Infinity"`), for a
    reader diagnosing; `"null"` makes it missing, for a reader computing over the field.
    `max_depth` bounds the walk. By default a deeper value is cut to its repr, for a caller
    handed arbitrary objects (a log). `deeper="refuse"` instead raises `JsonTooDeep` at the
    first container that would sit deeper than `max_depth` levels, for a caller whose data must
    be stored whole or not at all. Either way the walk never recurses past `max_depth`, so a
    cyclic value ends too."""
    if non_finite not in ("text", "null"):
        raise ValueError(f"non_finite must be 'text' or 'null', not {non_finite!r}")
    if deeper not in ("repr", "refuse"):
        raise ValueError(f"deeper must be 'repr' or 'refuse', not {deeper!r}")
    rules = _JsonRules(non_finite, sys.maxsize if max_depth is None else max_depth,
                       deeper == "refuse", naive_is_utc)
    return _json_safe_walk(value, rules, 0)


@dataclasses.dataclass(frozen=True)
class _JsonRules:
    non_finite: str
    max_depth: int
    refuse_deeper: bool
    naive_is_utc: bool


def _json_safe_walk(v: Any, rules: _JsonRules, depth: int) -> Any:
    if v is None or isinstance(v, (bool, int, str)):
        return v
    if isinstance(v, float):
        if math.isfinite(v):
            return v
        return None if rules.non_finite == "null" else _non_finite_text(v)
    if depth >= rules.max_depth:
        if not rules.refuse_deeper:
            return repr(v)
        # Only a container adds a level; a date at the limit is still one text value.
        if isinstance(v, (Mapping, list, tuple, set, frozenset)):
            raise JsonTooDeep(f"a value nests deeper than {rules.max_depth} levels")
    if isinstance(v, Mapping):
        return {_json_key(k, rules): _json_safe_walk(x, rules, depth + 1) for k, x in v.items()}
    if isinstance(v, (list, tuple, set, frozenset)):
        items = [_json_safe_walk(x, rules, depth + 1) for x in v]
        if isinstance(v, (set, frozenset)):
            # By written JSON: text in text order, and `1` never ties `"1"`, so the order never
            # depends on how the set happens to iterate.
            items.sort(key=lambda x: json.dumps(x, ensure_ascii=False))
        return items
    return _json_text(v, rules)


def _json_key(k: Any, rules: _JsonRules) -> str:
    # Always text, so a caller that sorts keys never compares `1` with `"b"`; a key the encoder
    # carries is spelled as the encoder would write it (`true`, `null`, `1`, `NaN`).
    if k is None or isinstance(k, (bool, int, float)):
        return json.dumps(k)
    return _json_text(k, rules)


def _json_text(v: Any, rules: _JsonRules) -> str:
    if isinstance(v, _dt.datetime):
        if v.utcoffset() is None and rules.naive_is_utc:
            v = v.replace(tzinfo=_dt.UTC)
        if v.utcoffset() is None:
            return v.isoformat(timespec="microseconds")
        utc = v.astimezone(_dt.UTC).replace(tzinfo=None)
        return utc.isoformat(timespec="microseconds") + "Z"
    if isinstance(v, _dt.time):
        return v.isoformat(timespec="microseconds")
    return str(v)  # a date's text is already ISO 8601


def _non_finite_text(v: float) -> str:
    return "NaN" if math.isnan(v) else "Infinity" if v > 0 else "-Infinity"


def append_jsonl(path: Path, rows: list[dict]) -> int:
    if not rows:
        return 0
    path.parent.mkdir(parents=True, exist_ok=True)  # lint-unguarded-tree-write: ok — the unguarded primitive itself; the gate flags its callers  # noqa: E501
    with path.open("a", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")  # lint-jsonl-io: ok — the canonical JSONL appender
    return len(rows)


def write_atomic(path: Path, text: str) -> None:
    write_guarded(path, text, mode="replace")


# The alias-refusing write seam.
#
# Every host-side write into a shared box tree goes through `write_guarded` (or
# `guarded_mkdir` for directories). A planted symlink or hard link at the target is refused,
# never followed: `replace` stages under an unpredictable name and swaps it in, never opening
# the target; `append`/`update` open with O_NOFOLLOW. `_refuse_unless_plain` runs first in
# every mode and raises one exception type for symlink, hard link and directory alike, so
# callers handle them uniformly. The `.write_guarded_alias` attribute on the raised OSError
# lets a caller that must distinguish "aliased" from an ordinary occupied name (the budget
# accounting exemption) do so.
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
    return os.open(directory, flag | os.O_WRONLY, 0o644)


#: What an unnamed open answers on a filesystem (NFS, virtiofs, FUSE) or kernel that cannot make
#: one — the create lane then falls back. Any other errno is a real failure of the write.
_NO_UNNAMED_FILES = frozenset({errno.EOPNOTSUPP, errno.EISDIR, errno.EINVAL})


def _create_unnamed(
    path: Path, text: str | bytes, open_unnamed: Callable[[Path], int],
) -> bool:
    """`create`'s complete-or-absent lane (#1078 J16/J63): the body is written in full and
    synced on an unnamed file, which is then given `path`'s name in one `linkat`. No
    reader ever sees the name absent-then-empty or partial, the file never has two names (its
    link count goes 0 -> 1), and a crash before the link leaves nothing in the directory.

    The link passes the directory as a descriptor, so CPython calls `linkat(AT_SYMLINK_FOLLOW)`
    through `/proc/self/fd/N` — unprivileged. Without the descriptor it calls plain `link(2)`,
    which does not follow that magic link and fails `EXDEV` on every host.

    True when this lane wrote the file; False when this filesystem or host cannot make an
    unnamed file (or has no `/proc`), and the caller falls back. An occupied name raises
    `FileExistsError` (the ordinary create race); anything else propagates."""
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


def _link_unnamed(
    fd: int, dir_fd: int, leaf: str, text: str | bytes, *, os_: Any = os,
) -> bool:
    """The body of `create`'s unnamed lane, shared by the path and rooted seams: write `text`
    in full to the unnamed `fd`, sync it, then name it `leaf` in `dir_fd`. False when the host
    has no `/proc` to link through. The caller owns both descriptors. The file keeps the mode
    its open gave it, 0644 under the process umask, as every other lane's (#1144)."""
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
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
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


def open_nofollow_fd(path: Path, flags: int) -> int:
    """`O_NOFOLLOW` open whose `ELOOP` is marked as an alias refusal: after
    `_refuse_unless_plain`, it means a symlink was planted in the race window, and must not
    count toward the accounting kill circuit as an ordinary failure."""
    try:
        return os.open(path, flags | os.O_NOFOLLOW, 0o644)
    except OSError as e:
        raise _mark_alias(e, is_alias=e.errno == errno.ELOOP) from None


@contextlib.contextmanager
def locked_for_rewrite(path: Path, *, binary: bool = False) -> Iterator[Any]:
    """The locked read-modify-write prefix: refuse a non-plain target, open with
    `O_NOFOLLOW`, then take the exclusive lock — in that order, so refusal precedes any lock or
    write. Yields the locked handle at position 0."""
    path = Path(path)
    _refuse_unless_plain(path)
    fd = open_nofollow_fd(path, os.O_RDWR | os.O_CREAT)
    opener = os.fdopen(fd, "r+b") if binary else os.fdopen(fd, "r+", encoding="utf-8")
    with opener as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        yield f


def write_guarded(
    path: Path, text: str | bytes, *, mode: str = "replace",
    stage_name: Callable[[Path], Path] = stage_name,
    open_unnamed: Callable[[Path], int] = open_unnamed, **kw: object,
) -> None:
    """The single write seam every shared-tree writer routes through.

    Modes:
      * `replace` — stage under an unpredictable name, then `os.replace` into place (replaces
        a planted symlink without following it).
      * `create` — for write-once records; an occupied name raises `FileExistsError`. The body
        is written to an unnamed file and linked to the name in one step (`_create_unnamed`),
        so a reader sees the name absent or the file complete, and the file never has two
        names (a named stage hard-linked into place would, and guarded readers refuse that).
        Where the filesystem cannot make an unnamed file it falls back to one
        `O_CREAT|O_EXCL|O_NOFOLLOW` open: a reader racing the write can then see an empty
        record (and refuses it as corrupt), and a crash can leave a partial one.
      * `append` — the JSONL lane, `O_NOFOLLOW` at open.
      * `update` — locked read-modify-write via `locked_for_rewrite`.

    `text` may be `bytes`. `stage_name` and `open_unnamed` are the name and unnamed-open seams.
    `**kw` accepts only `encoding` (ignored; utf-8 is pinned): swallowing other keywords would
    let a misspelt `mode=` silently truncate a file meant for appending."""
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
            fd = os.open(staged, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
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
        with locked_for_rewrite(path, binary=isinstance(text, (bytes, bytearray))) as f:
            f.seek(0)
            f.truncate()
            f.write(text)
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


def open_guarded(path: Path, mode: str = "a"):
    """Open `path` for a streaming writer (`observe.RequestLogger`). The alias check runs once,
    at open. `os.devnull` is exempt, for the null logger."""
    path = Path(path)
    if str(path) != os.devnull:
        _refuse_unless_plain(path)
    flags = os.O_WRONLY | os.O_CREAT | (os.O_APPEND if mode == "a" else os.O_TRUNC)
    fd = open_nofollow_fd(path, flags)
    return os.fdopen(fd, mode, encoding="utf-8")


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
    very symlinks being refused."""
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
    # Skip on the hot path once the root exists. `is_dir()` follows symlinks on purpose: a
    # host-chosen symlinked runs base must keep working.
    if not base.is_dir():
        os.makedirs(base, exist_ok=True)
    accum = base
    for part in rest.parts:
        accum = accum / part
        _ensure_dir_component(accum)


# The rooted seam (#1111): what the `Run` handle reads and writes through, on the core above.
# Each call names a trust root (its spelling followed) and a record relative to it (never
# followed). `os_` is the `os` seam, as `bind`'s.

_ROOTED_MODES = ("create", "replace", "append")


def open_unnamed_at(dir_fd: int) -> int:
    """:func:`open_unnamed` off a folder descriptor: the name-source seam
    `rooted_write(open_unnamed=)` defaults to."""
    flag = getattr(os, "O_TMPFILE", None)
    if flag is None:
        raise OSError(errno.EOPNOTSUPP, "no O_TMPFILE on this platform")
    return os.open(".", flag | os.O_WRONLY | os.O_CLOEXEC, 0o644, dir_fd=dir_fd)


@overload
def rooted_read(
    root: Path, name: str | PurePath, *, binary: Literal[False] = False, os_: Any = os,
) -> tuple[str | None, str | None]: ...
@overload
def rooted_read(
    root: Path, name: str | PurePath, *, binary: Literal[True], os_: Any = os,
) -> tuple[bytes | None, str | None]: ...
def rooted_read(
    root: Path, name: str | PurePath, *, binary: bool = False, os_: Any = os,
) -> tuple[str | bytes | None, str | None]:
    """The text (or, with `binary`, the exact bytes) of the plain file at `name` under `root` —
    or `(None, reason)` when it is absent (the root included) or refused, as `read_guarded`
    answers. A name outside the relative-name grammar is `ValueError`."""
    spelling, parts = _parse_name(name)
    try:
        with _rooted(os_, root, parts[:-1]) as dir_fd:
            return _read_leaf(os_, dir_fd, parts[-1], Path(root, *parts), binary=binary), None
    except FileNotFoundError:
        return None, f"{spelling}: {os.strerror(errno.ENOENT)}"
    except TEXT_READ_ERRORS as e:
        return None, f"{spelling}: {_read_reason(e)}"


def rooted_mkdir(root: Path, folder_name: str | PurePath, *, os_: Any = os) -> None:
    """Make `root/<folder_name>`: the root itself if missing, following links (as
    :func:`guarded_mkdir` makes its base), then each missing folder below it, never through a
    link. `"."` names the root itself, the holding folder of a record at its top level."""
    folders = () if str(folder_name) in ("", ".") else _parse_name(folder_name)[1]
    try:
        with _rooted(os_, root, folders, create=True):
            return
    except FileNotFoundError:
        # Only the root can be missing here (`create` makes every folder below it).
        os_.makedirs(Path(root), exist_ok=True)
    with _rooted(os_, root, folders, create=True):
        pass


def rooted_write(
    root: Path, name: str | PurePath, text: str | bytes, *, mode: str,
    durable: bool = False, stage_name: Callable[[str], str] = staged_leaf,
    open_unnamed: Callable[[int], int] = open_unnamed_at, os_: Any = os,
) -> None:
    """:func:`write_guarded`'s `create` / `replace` / `append`, for `name` under `root`. The
    folders are walked, never made (:func:`rooted_mkdir` makes them): a missing one, or a
    missing root, is `FileNotFoundError`. `durable` (append only) flushes and `fsync`s the leaf
    before closing it, then the folder holding it, for a record whose rows must be on disk when
    the call returns.
    `stage_name` and `open_unnamed` are the leaf-name and unnamed-open seams."""
    _spelling, parts = _parse_name(name)
    _check_write(text, mode, durable)
    with _rooted(os_, root, parts[:-1]) as dir_fd:
        _write_at(os_, dir_fd, parts[-1], Path(root, *parts), text, mode=mode, durable=durable,
                  stage_name=stage_name, open_unnamed=open_unnamed)


def _check_write(text: object, mode: str, durable: bool) -> None:
    """A write's arguments, judged before any I/O: `text` is `str` or `bytes` (an iterable
    would be spent by the create lane's first attempt), `mode` one of `_ROOTED_MODES`, and
    `durable` only with `append`."""
    if not isinstance(text, (str, bytes)):
        raise TypeError(f"text must be str or bytes, not {type(text).__name__}")
    if mode not in _ROOTED_MODES:
        raise ValueError(f"unknown rooted_write mode: {mode!r}")
    if durable and mode != "append":
        raise ValueError(f"durable applies to the append mode only, not {mode!r}")


def _write_at(  # noqa: PLR0913 — `rooted_write`'s whole call, carried to the folder it resolved
    os_: Any, dir_fd: int, leaf: str, where: Path, text: str | bytes, *, mode: str,
    durable: bool = False, stage_name: Callable[[str], str] = staged_leaf,
    open_unnamed: Callable[[int], int] = open_unnamed_at,
) -> None:
    """One `create` / `replace` / `append` of `leaf` in the folder `dir_fd` holds. `durable`
    (append only) fsyncs the leaf, then that folder, so the record and its entry are both on
    disk when the call returns."""
    if mode == "create":
        _create_at(os_, dir_fd, leaf, where, text, open_unnamed)
    elif mode == "replace":
        _replace_at(os_, dir_fd, leaf, where, text, stage_name)
    else:
        _leaf_present(os_, dir_fd, leaf, where)
        fd = _open_leaf(os_, dir_fd, leaf, os.O_WRONLY | os.O_CREAT | os.O_APPEND, where)
        _write_all(fd, text, os_=os_, sync=durable)
        if durable:
            _fsync_folder(os_, dir_fd)


def _fsync_folder(os_: Any, dir_fd: int) -> None:
    """`fsync` the folder `dir_fd` holds, through `.` reopened `O_RDONLY|O_DIRECTORY` off it:
    an `O_PATH` handle cannot be synced (`EBADF`)."""
    fd = os_.open(".", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC, dir_fd=dir_fd)  # lint-text-io: ok — os.open of a DIRECTORY handle, no text mode
    try:
        os_.fsync(fd)
    finally:
        os_.close(fd)


def _unlink_at(os_: Any, dir_fd: int, leaf: str, where: Path) -> bool:
    """Remove the plain file `leaf` in the folder `dir_fd` holds: `True` when one was removed,
    `False` when nothing is there. The entry is judged by a no-follow stat before the unlink: a
    link, a hard link or any other non-plain entry is the core's refusal and is left in place
    for the reap scan. The stat and the unlink are two steps, so an entry swapped between them
    is removed as found."""
    if not _leaf_present(os_, dir_fd, leaf, where):
        return False
    try:
        os_.unlink(leaf, dir_fd=dir_fd)
    except FileNotFoundError:
        return False
    return True


def _create_at(
    os_: Any, dir_fd: int, leaf: str, where: Path, text: str | bytes,
    open_unnamed: Callable[[int], int],
) -> None:
    """`create`: #1078's complete-or-absent lane (an unnamed file, named once written), else one
    named `O_EXCL` create. An occupied name is the ordinary write-once collision,
    `FileExistsError`, unmarked, known before any body is written."""
    if _leaf_present(os_, dir_fd, leaf, where):
        raise FileExistsError(errno.EEXIST, os.strerror(errno.EEXIST), str(where))
    try:
        fd = open_unnamed(dir_fd)
    except OSError as e:
        if e.errno not in _NO_UNNAMED_FILES:
            raise
    else:
        try:
            if _link_unnamed(fd, dir_fd, leaf, text, os_=os_):
                return
        finally:
            os_.close(fd)
    fd = os_.open(leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                  0o644, dir_fd=dir_fd)
    try:
        _write_all(fd, text, os_=os_)
    except BaseException:
        # Ours to remove: the create succeeded, so the half-written entry is this call's.
        with contextlib.suppress(OSError):
            os_.unlink(leaf, dir_fd=dir_fd)
        raise


def _replace_at(
    os_: Any, dir_fd: int, leaf: str, where: Path, text: str | bytes,
    stage_name: Callable[[str], str],
) -> None:
    """`replace`: stage under an unpredictable name beside `leaf`, then rename onto it. The
    rename swaps the entry and never follows it."""
    _leaf_present(os_, dir_fd, leaf, where)
    staged = stage_name(leaf)
    try:
        fd = os_.open(staged, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                      0o644, dir_fd=dir_fd)
    except OSError as e:
        raise _mark_alias(e, is_alias=e.errno == errno.EEXIST) from None
    try:
        _write_all(fd, text, os_=os_)
        os_.rename(staged, leaf, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
    except BaseException:
        with contextlib.suppress(OSError):
            os_.unlink(staged, dir_fd=dir_fd)
        raise


@contextlib.contextmanager
def rooted_locked_for_rewrite(
    root: Path, name: str | PurePath, *, binary: bool = False, os_: Any = os,
) -> Iterator[Any]:
    """:func:`locked_for_rewrite` for `name` under `root`: the folders walked (never made), the
    record judged, opened (created when absent) and judged again on its descriptor, then the
    exclusive lock. Yields the locked handle at position 0."""
    _spelling, parts = _parse_name(name)
    where = Path(root, *parts)
    with _rooted(os_, root, parts[:-1]) as dir_fd:
        _leaf_present(os_, dir_fd, parts[-1], where)
        fd = _open_leaf(os_, dir_fd, parts[-1], os.O_RDWR | os.O_CREAT, where)
    try:
        opener = os_.fdopen(fd, "r+b") if binary else os_.fdopen(fd, "r+", encoding="utf-8")
    except BaseException:
        os_.close(fd)
        raise
    with opener as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        yield f


# The held root (#1133): an `Episode`'s one open handle on its episode dir. Every verb works
# `*at` off it, so the dir is resolved once, at the door, and never again by name.


class Held:
    """A folder held open by descriptor (:func:`hold`, :func:`hold_new`), and the rooted verbs
    relative to it. Nothing below the held folder is followed; the folder itself is never
    re-resolved, so a rename carries the handle with it and a removal fails every write.

    Each verb works off a private `dup` of the root (`_Handle.dup`, which its views share): a
    verb after `close` is `OSError(EBADF)` and touches nothing. Reads are the view's: this
    handle writes."""

    def __init__(self, os_: Any, fd: int, where: Path) -> None:
        self._os = os_
        self._root = _Handle(os_, fd)
        self._where = Path(where)

    # -- lifetime -------------------------------------------------------------------------------

    def close(self) -> None:
        """Release the root. Idempotent; the views then answer `Bad file descriptor`."""
        self._root.close()

    def __enter__(self) -> Held:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def _dup(self) -> contextlib.AbstractContextManager[int]:
        return self._root.dup(self._where)

    def view(self) -> Bound:
        """A reader over this same handle. It owns nothing: closing it is a no-op, and once this
        root is closed it answers `Bad file descriptor`."""
        return Bound(self._os, self._root)

    # -- the verbs ------------------------------------------------------------------------------

    def write(self, name: str | PurePath, text: str | bytes, *, mode: str,
              durable: bool = False) -> None:
        """:func:`rooted_write`'s modes, in one walk off the held root that makes each missing
        holding folder (no link followed) and writes the leaf in the last one. A durable write
        makes no folder: a missing one is `FileNotFoundError`."""
        _check_write(text, mode, durable)
        _spelling, parts = _parse_name(name)
        # A durable write makes no folder: every folder its record's entry depends on already
        # exists, so the chain it syncs is the whole chain.
        with self._dup() as root_fd, _descend(
                self._os, root_fd, parts[:-1], self._where, create=not durable) as dir_fd:
            _write_at(self._os, dir_fd, parts[-1], Path(self._where, *parts), text,
                      mode=mode, durable=durable)

    def mkdir(self, folder: str | PurePath) -> None:
        """Make each missing folder of `folder` below the held root, never through a link."""
        folders = () if str(folder) in ("", ".") else _parse_name(folder)[1]
        with self._dup() as root_fd, _descend(
                self._os, root_fd, folders, self._where, create=True):
            pass

    def unlink(self, name: str | PurePath) -> bool:
        """Remove the plain file at `name` below the held root (`_unlink_at`); `False` when it
        or a holding folder is absent."""
        _spelling, parts = _parse_name(name)
        with self._dup() as root_fd:
            try:
                with _descend(self._os, root_fd, parts[:-1], self._where) as dir_fd:
                    return _unlink_at(self._os, dir_fd, parts[-1], Path(self._where, *parts))
            except FileNotFoundError:
                return False


def hold(root: Path, *, os_: Any = os) -> Held:
    """Hold `root` open, following its spelling (the operator's, as :func:`bind`'s). A missing
    root is `FileNotFoundError`, a non-directory `NotADirectoryError`."""
    if _O_PATH is None:  # pragma: no cover — no CI box lacks it
        raise OSError(errno.ENOTSUP, _PLATFORM_FAULT)
    return Held(os_, os_.open(Path(root), _ROOT_FLAGS), Path(root))


def hold_new(parent: Path, name: str, *, os_: Any = os) -> Held:
    """Make (or adopt) the folder `name` in `parent` and hold it. `parent` is made if missing,
    following its spelling; `name` is judged off `parent`'s handle and never followed (a link,
    file or FIFO there is the core's folder refusal). The held descriptor is the one that
    judged it. `parent` is then fsynced, so the new folder's entry is durable."""
    if _O_PATH is None:  # pragma: no cover — no CI box lacks it
        raise OSError(errno.ENOTSUP, _PLATFORM_FAULT)
    if not isinstance(name, str) or len(_parse_name(name)[1]) != 1:
        raise ValueError(f"{name!r}: {_NOT_A_NAME}")
    parent = Path(parent)
    try:
        parent_fd = os_.open(parent, _ROOT_FLAGS)
    except FileNotFoundError:
        os_.makedirs(parent, exist_ok=True)
        parent_fd = os_.open(parent, _ROOT_FLAGS)
    try:
        fd = _step(os_, parent_fd, name, parent / name, create=True)
        try:
            _fsync_folder(os_, parent_fd)
        except BaseException:
            os_.close(fd)
            raise
    finally:
        os_.close(parent_fd)
    return Held(os_, fd, parent / name)


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
