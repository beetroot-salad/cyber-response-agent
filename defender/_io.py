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
from collections.abc import Callable, Iterator, Mapping
from pathlib import Path, PurePath
from typing import Any, Literal

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

#: The leaf: read, no-follow; `O_NONBLOCK` keeps a planted FIFO from wedging the open. Its
#: kind is judged by `fstat` on the opened handle (directory leaves use the same flags).
_WALK_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC

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

    def has_dir(self, entry: str) -> bool:
        return (self.entries or {}).get(entry) == ENTRY_DIR


def _walk_chain(os_: Any, start_fd: int | None, components: tuple[str, ...]) -> tuple[str, Any]:
    """The shared no-follow walk behind `Bound.read`/`read_jsonl`/`entries`: opens each
    component from the previous handle and requires every intermediate to be a real directory
    (a symlink step is the alias refusal).

    Answers `("absent", None)`, `("refused", reason)` or `("leaf", (fd, stat_result))`. The
    caller classifies and owns the leaf fd; intermediate fds are closed here on every path.
    """
    owned: int | None = None  # an intermediate fd THIS walk opened and still holds
    dir_fd = start_fd
    try:
        for index, component in enumerate(components):
            is_last = index == len(components) - 1
            try:
                fd = os_.open(component, _WALK_FLAGS if is_last else _STEP_FLAGS, dir_fd=dir_fd)
            except OSError as e:
                return _open_fault(e)
            try:
                st = os_.fstat(fd)
            except OSError as e:
                os_.close(fd)
                return "refused", (e.strerror or str(e))
            if is_last:
                return "leaf", (fd, st)
            if not stat.S_ISDIR(st.st_mode):
                os_.close(fd)
                return "refused", (ALIAS_READ_REFUSAL if stat.S_ISLNK(st.st_mode)
                                   else os.strerror(errno.ENOTDIR))
            if owned is not None:
                os_.close(owned)
            owned = fd
            dir_fd = fd
    finally:
        if owned is not None:
            os_.close(owned)  # the last intermediate, on every exit — the leaf is the caller's
    raise AssertionError("_walk_chain: empty component sequence")  # _parse_name never yields one


def _open_fault(e: OSError) -> tuple[str, Any]:
    """`_walk_chain`'s reading of a failed component open's errno."""
    if e.errno == errno.ENOENT:
        return "absent", None
    if e.errno == errno.ELOOP:
        return "refused", ALIAS_READ_REFUSAL
    return "refused", (e.strerror or str(e))


def _classify_leaf_file(fd: int, st: Any) -> bool:
    """Is the opened leaf a plain, single-linked regular file (judged on the descriptor)?"""
    return stat.S_ISREG(st.st_mode) and st.st_nlink == 1


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
    """The directory descriptor shared by a `bind` and its `under` derivations, closed once:
    by `Bound.close()` or, if unscoped, on collection."""

    __slots__ = ("_os", "fd")

    def __init__(self, os_: Any, fd: int | None) -> None:
        self._os = os_
        self.fd = fd

    def close(self) -> None:
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

    def _walk(self, parts: tuple[str, ...]) -> tuple[str, Any]:
        if self._absent:
            return "absent", None
        if self._error is not None:
            return "refused", self._error
        if self._handle.fd is None:
            return "refused", os.strerror(errno.EBADF)  # closed
        return _walk_chain(self._os, self._handle.fd, self._prefix + parts)

    def read(self, name: str | PurePath, *, errors: str = "strict") -> RecordRead:
        spelling, parts = _parse_name(name)
        if errors not in _ERRORS_VALUES:
            raise ValueError("errors must be 'strict' or 'replace'")
        kind, payload = self._walk(parts)
        if kind == "absent":
            return RecordRead(name=spelling, text=None, absent=True, reason=None)
        if kind == "refused":
            return RecordRead(name=spelling, text=None, absent=False, reason=str(payload))
        fd, st = payload
        if not _classify_leaf_file(fd, st):
            self._os.close(fd)
            return RecordRead(name=spelling, text=None, absent=False, reason=ALIAS_READ_REFUSAL)
        # The read can still fail after the open (EIO, stale network handle); fold into a refusal.
        try:
            fh = self._os.fdopen(fd, "r", encoding="utf-8", errors=errors)
        except OSError as e:
            self._os.close(fd)  # `fdopen` failed to take the fd, so it is still ours to close
            return RecordRead(name=spelling, text=None, absent=False, reason=str(e))
        try:
            with fh:
                text = fh.read()
        except TEXT_READ_ERRORS as e:
            return RecordRead(name=spelling, text=None, absent=False, reason=str(e))
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
        if self._handle.fd is None:
            return EntriesRead(name=spelling, entries=None, absent=False,
                               reason=os.strerror(errno.EBADF))
        kind, payload = self._directory_fd()
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

    def _directory_fd(self) -> tuple[str, Any]:
        """A read handle on the bound directory for `entries`. The root handle is `O_PATH`, so
        the root is reopened as `.` off it; a derivation walks its prefix."""
        if not self._prefix:
            try:
                fd = self._os.open(  # lint-text-io: ok — os.open of a DIRECTORY handle, no text mode
                    ".", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC, dir_fd=self._handle.fd)
            except OSError as e:
                return "refused", (e.strerror or str(e))
            return "leaf", fd
        kind, payload = _walk_chain(self._os, self._handle.fd, self._prefix)
        if kind != "leaf":
            return kind, payload
        fd, st = payload
        if not stat.S_ISDIR(st.st_mode):
            self._os.close(fd)
            return "refused", os.strerror(errno.ENOTDIR)
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

_JSON_STRING = re.compile(r'"(?:[^"\\]|\\.)*"')
_JSON_BRACKET = re.compile(r"[\[\]{}]")


def json_nesting_depth(text: str) -> int:
    """The deepest container nesting in ``text``, judged without decoding it.

    Exact for valid JSON (string literals are dropped first); invalid JSON is refused by the
    decoder anyway. Regex-driven so large payloads cost one pass over their brackets."""
    depth = deepest = 0
    for bracket in _JSON_BRACKET.finditer(_JSON_STRING.sub("", text)):
        if bracket.group() in "[{":
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


def json_safe(value: Any, *, non_finite: Literal["text", "null"],
              max_depth: int | None = None) -> Any:
    """`value` with only the parts the JSON encoder cannot carry replaced; text, numbers,
    booleans and null are left as the encoder would write them.

    A set becomes a list in a fixed order. A key or value JSON has no type for becomes text,
    a date or time in ISO 8601. A non-finite float goes the way the caller says: `"text"`
    keeps it, spelled as the Protocol Buffers JSON mapping and OpenTelemetry spell it (`"NaN"`,
    `"Infinity"`), for a reader diagnosing; `"null"` makes it missing, for a reader computing
    over the field. A key cannot be null, so a non-finite key is always spelled. `max_depth`
    cuts a deeper value to its repr, for a caller handed arbitrary objects."""
    if non_finite not in ("text", "null"):
        raise ValueError(f"non_finite must be 'text' or 'null', not {non_finite!r}")
    return _json_safe_walk(value, non_finite, max_depth, 0)


def _json_safe_walk(v: Any, non_finite: str, max_depth: int | None, depth: int) -> Any:
    if v is None or isinstance(v, (bool, int, str)):
        return v
    if isinstance(v, float):
        if math.isfinite(v):
            return v
        return None if non_finite == "null" else _non_finite_text(v)
    if max_depth is not None and depth >= max_depth:
        return repr(v)
    if isinstance(v, Mapping):
        return {_json_key(k): _json_safe_walk(x, non_finite, max_depth, depth + 1)
                for k, x in v.items()}
    if isinstance(v, (list, tuple, set, frozenset)):
        items = [_json_safe_walk(x, non_finite, max_depth, depth + 1) for x in v]
        # By repr, which no two set members share (`1` and `"1"` print alike), so the order
        # never depends on the hash seed.
        return sorted(items, key=repr) if isinstance(v, (set, frozenset)) else items
    return _json_text(v)


def _json_key(k: Any) -> str:
    # Always text, so a caller that sorts keys never compares `1` with `"b"`; a key the encoder
    # carries is spelled as the encoder would write it (`true`, `null`, `1`, `NaN`).
    if k is None or isinstance(k, (bool, int, float)):
        return json.dumps(k)
    return _json_text(k)


def _json_text(v: Any) -> str:
    return v.isoformat() if isinstance(v, (_dt.date, _dt.time)) else str(v)


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
    return path.with_name(f"{path.name}.staged-{secrets.token_hex(8)}")


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
    """`create`'s complete-or-absent lane (#1078 J16/J63): the body is written in full, synced
    and set to 0644 on an unnamed file, which is then given `path`'s name in one `linkat`. No
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
        os.fchmod(fd, 0o644)
        data = text if isinstance(text, (bytes, bytearray)) else text.encode("utf-8")
        # Buffered: the file object loops over a short `os.write` until every byte has landed.
        with os.fdopen(fd, "wb", closefd=False) as f:
            f.write(data)
        os.fsync(fd)
        dir_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.link(f"/proc/self/fd/{fd}", path.name, dst_dir_fd=dir_fd, follow_symlinks=True)
        except FileNotFoundError:
            if not os.path.isdir("/proc/self/fd"):
                return False
            raise
        finally:
            os.close(dir_fd)
    finally:
        os.close(fd)
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
    is_hardlink = is_hard_linked(st)
    is_alias = stat.S_ISLNK(st.st_mode) or is_hardlink
    if not is_plain_entry(st):
        # The planted entry is left in place so the reap scan can still report it. EMLINK for
        # a hard link, ELOOP otherwise; both are plain `OSError`, so the type stays uniform.
        refusal_errno = errno.EMLINK if is_hardlink else errno.ELOOP
        raise _mark_alias(
            OSError(refusal_errno, "refusing to write through a non-plain or aliased entry",
                     str(path)),
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


def _write_all(fd: int, text: str | bytes) -> None:
    """Write `text` to a fresh descriptor and close it (text or bytes to match)."""
    if isinstance(text, (bytes, bytearray)):
        with os.fdopen(fd, "wb") as fb:
            fb.write(text)
    else:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)


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
