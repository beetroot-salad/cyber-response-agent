from __future__ import annotations

import contextlib
import errno
import fcntl
import json
import os
import re
import secrets
import stat
import sys
from collections.abc import Callable, Iterator
from pathlib import Path, PurePath
from typing import Any

from defender._model import model

TEXT_READ_ERRORS: tuple[type[Exception], ...] = (OSError, UnicodeDecodeError)
"""What reading a text file can raise: unreadable (``OSError``) or undecodable
(``UnicodeDecodeError``, a ``ValueError``).

One exported name because a caller that reads AND parses under a single ``try``
(``iter_lessons``, the curators' yaml loads, the invlang companion walk) must write its own
``except`` — :func:`read_text_soft` only covers a pure read-skip — and that is where the next
wrong tuple gets written. To add a parse error, bind the composed tuple first; mypy rejects a
star-unpack in an ``except`` display::

    malformed: tuple[type[BaseException], ...] = (SomeParseError, *TEXT_READ_ERRORS)
    try:
        ...
    except malformed as e:

A grep for this name is then the audit of who guards a read correctly.
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
    """Does ANYTHING stand at the name — a file, a link, a directory, a FIFO?

    The one question a reader may ask AHEAD of a guarded read without opening a check-then-act
    window: it decides only what a caller SAYS about the name ("absent" versus "refused"), never
    what it reads. ``Path.exists()`` is not this: it follows a link, and on 3.11 it re-raises a
    permission fault from the directory above (only ``ENOENT``/``ENOTDIR``/``EBADF``/``ELOOP``
    are swallowed), so a mode-000 parent crashed a reader that had screened the parent itself
    with ``lstat``. An entry the caller cannot judge is PRESENT: the guarded read that follows
    is what names why it could not be read.

    NO PRODUCTION CALLER as of #1049: every episode-tree reader that used to ask this ahead of
    a read now asks nothing — the primitive's own open decides absent-vs-refused (`_io.bind`).
    Kept as the documented answer to the question for the readers #1049 left untouched (a
    run-dir lane could still want it) and because a committed test's docstring
    (`test_1025_page_contract.py:964`) explains a still-true design point by naming it; deleting
    the function would leave that citation dangling for no functional gain. `# lint-vulture: ok`
    in the baseline names this reason.
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

    ``errors`` is ``open``'s own decoding policy. The default refuses an undecodable byte
    like any other read fault; the tolerant line readers pass ``"replace"`` so one bad byte
    costs one row rather than the whole file (`Bound.read_jsonl`).

    Same return shape as :func:`read_text_soft` — ``(text, None)`` or ``(None, reason)`` — so it
    drops in wherever a reader already tolerates "could not read this". What it adds is that a
    path which is not a plain, single-linked regular file is a REFUSAL rather than a read of
    whatever the entry points at. The read itself is :func:`read_plain`; this is the fold.

    WHY A SEPARATE FUNCTION RATHER THAN A CHECK EACH CALLER WRITES. Every read of a path inside
    a run dir, an episode dir or the drain corpus is a read from a tree a live box is root on,
    so an entry at an expected artifact's name may be something the model planted. The write
    side has had one seam for this since M3; the read side had a per-module habit, and the
    habit was wrong in two different ways in one file — an ``S_ISREG`` screen that admitted a
    hard link, and before that no screen at all. Two guards on one path that do not match is
    not a bug you fix once.

    ABSENT is a refusal here, unlike on the write side where it is the ordinary case: a file
    that is not there is not a file to read, and folding it in with the alias refusal is right
    because no caller of THIS can act on the two differently — both mean "you have no content".
    The reason string tells them apart for a log. The one reader that does act on them
    differently — the companion reader, for which an unwritten document is turn 1's ordinary
    state — takes :func:`read_plain` and catches the absence itself.
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

    STRICTLY STRONGER THAN AN ``lstat`` THEN A READ, which is what the hand-written version was.
    The plainness question is asked of the OPEN DESCRIPTOR: ``O_NOFOLLOW`` refuses a symlink at
    the open itself, and ``fstat`` then judges the very object that was opened. A check-then-act
    pair answers about whatever the name meant a moment ago, and the window between them is
    exactly where a plant belongs.
    """
    # `O_NONBLOCK` IS NOT AN OPTIMISATION, it is the only thing standing between this and a
    # hang. An ordinary `O_RDONLY` open of a FIFO BLOCKS until some process opens the write
    # end — before any screen below can run — so a fifo planted at an artifact's name would
    # wedge the caller forever rather than be refused. Non-blocking makes the open return at
    # once; `fstat` then refuses it like any other non-regular entry. On a regular file the
    # flag does nothing at all, so the ordinary path is unchanged.
    try:
        fd = open_nofollow_fd(Path(path), os.O_RDONLY | os.O_NONBLOCK)
    except OSError as e:
        # A symlink AT THE NAME is refused BY THE OPEN (`ELOOP`, marked by `open_nofollow_fd`),
        # and it is the same refusal the hard-link and directory arms below spell — said in the
        # same words here, so a caller's log names an alias as an alias rather than as "too
        # many levels of symbolic links", and never has to prefix the sentence itself (which
        # one caller did, in front of a permission fault as well). Only when the LEAF is the
        # link, though: an `ELOOP` raised for a looped component higher up the path is the
        # OS's own finding about that directory, and relabelling it would blame the leaf for
        # an alias it is not (review of PR #1042) — that one keeps its own strerror.
        if getattr(e, "write_guarded_alias", False) and _leaf_is_link(path):
            raise _mark_alias(OSError(errno.ELOOP, ALIAS_READ_REFUSAL, str(path)),
                              is_alias=True) from None
        raise
    try:
        st = os.fstat(fd)
        # A hard link is the shape `O_NOFOLLOW` cannot refuse — the open SUCCEEDS (B9) — so the
        # link count is asked here rather than inferred from the open having worked. A
        # directory, fifo, socket or device lands in the same refusal for the reason
        # `_refuse_unless_plain` gives: a caller must not have to tell those apart from a
        # planted symlink to know it has no artifact.
        if not is_plain_entry(st):
            raise OSError(
                errno.EMLINK if is_hard_linked(st) else errno.ELOOP, ALIAS_READ_REFUSAL,
                str(path),
            )
        with os.fdopen(fd, "r", encoding="utf-8", errors=errors) as fh:
            fd = -1  # `fdopen` owns it now; the finally below must not close it twice.
            return fh.read()
    finally:
        if fd >= 0:
            os.close(fd)


def _leaf_is_link(path: Path) -> bool:
    """Is the entry AT `path` itself a symlink? `False` when the name cannot even be stat'ed
    without following a link (`lstat` raising `ELOOP` for a looped parent), which is exactly
    the case where the leaf is not the alias."""
    try:
        return stat.S_ISLNK(os.lstat(path).st_mode)
    except OSError:
        return False


# LINUX ONLY — the bound reader, not this module. The root and every intermediate step of a
# `bind` walk are opened `O_PATH`: a handle to the directory that is never read through, which
# the kernel grants on SEARCH permission alone — exactly what traversing a path by name always
# needed, so a `drwx--x--x` root or component traverses here as it did for the path-based
# reader this replaced. Opened `O_RDONLY` instead (the portable form) a step needed READ
# permission on every directory, and a search-only directory anywhere on the way refused every
# record beneath it. `O_PATH` is Linux-only; `bind()` refuses with the reason on a platform
# without it (`_PLATFORM_FAULT`) — the rest of this module, and the package that imports it,
# is untouched by the decision.
_O_PATH: int | None = getattr(os, "O_PATH", None)
_PLATFORM_FAULT = ("the episode-tree reader walks each directory step with O_PATH, which this "
                   "platform's os module does not offer — the reader is Linux-only")

#: One intermediate step (D-V3). `O_PATH|O_NOFOLLOW` never follows: a symlink at the step is
#: OPENED AS THE LINK ITSELF (the handle `fstat`s `S_ISLNK`) and refused as an alias off that
#: — never traversed, and never the kernel's own `ELOOP`. `O_CLOEXEC` is routine hygiene.
_STEP_FLAGS = (_O_PATH or 0) | os.O_NOFOLLOW | os.O_CLOEXEC

#: The root's own open (`bind`): an `O_PATH` directory handle that FOLLOWS the operator's
#: spelling (RF-R8) and needs search permission alone; `Bound.entries()` on the root opens
#: `.` for reading off it only when asked to list.
_ROOT_FLAGS = (_O_PATH or 0) | os.O_DIRECTORY | os.O_CLOEXEC

#: The leaf (D-V3): opened for reading, no-follow (`ELOOP` for a symlink at the leaf);
#: `O_NONBLOCK` keeps a FIFO at the leaf from wedging the walk open. No `O_DIRECTORY` —
#: plainness is judged by `fstat`-ing the opened handle, not by asking the open to enforce a
#: shape. A directory leaf (`Bound.entries` on a derivation) is opened with the same flags.
_WALK_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC

#: `errors=` values `Bound.read` admits. Anything else is a caller mistake, refused before any
#: open (D-06) — the codec's own `LookupError` for a bogus handler name never reaches a caller.
_ERRORS_VALUES = ("strict", "replace")

_NOT_A_NAME = "not a valid relative name — a name is a sequence of plain path components"


def _parse_name(name: str | PurePath) -> tuple[str, tuple[str, ...]]:
    """A `bind`ed reader's name grammar (D-J1): a `str` in POSIX spelling, or a `PurePath`
    rendered `as_posix()`, split on `/` into components that are each non-empty and never `.`
    or `..` — an absolute spelling, a NUL byte, an empty component (`a//b`, `a/`) or a `.`/`..`
    component (including the whole name) raises `ValueError` naming no path, before any open.
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


@model(frozen=True)
class _Read:
    """What every `bind`ed reader's answer carries: `name`, the relative name AS THE CALLER
    SPELLED IT (never the root; `""` for the root itself), `absent` (nothing at the name) and
    `reason` (a non-empty `str` when refused). `refusal` is the one sentence every consumer
    that wants a sentence gets — `f"{name}: {reason}"`, or the bare reason for the root; a
    consumer that wants the parts reads them, never the sentence."""

    name: str
    absent: bool
    reason: str | None

    @property
    def refusal(self) -> str | None:
        if self.reason is None:
            return None
        return f"{self.name}: {self.reason}" if self.name else self.reason


@model(frozen=True)
class RecordRead(_Read):
    """A `bind`ed reader's answer to a file, in exactly one of three states: present (`text` a
    `str`, possibly empty), absent (`absent=True`) or refused (`reason`)."""

    text: str | None


#: What one entry of a listed directory is, judged WITHOUT following it (`EntriesRead`): a
#: regular file (a hard link included — `read` is what refuses that, by its link count), a
#: real directory, or anything else (a symlink, a FIFO, a socket, a device).
ENTRY_FILE, ENTRY_DIR, ENTRY_OTHER = "file", "dir", "other"


@model(frozen=True)
class EntriesRead(_Read):
    """A `bind`ed reader's answer to "what is IN this directory" (`Bound.entries`), in the same
    three states `RecordRead` has: present (`entries` a mapping of each entry's own name to
    `ENTRY_FILE`/`ENTRY_DIR`/`ENTRY_OTHER`), absent (nothing at the bound name) or refused
    (`reason`). `name` is the bound directory's own relative spelling (`""` for the root)."""

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
    """The shared per-component walk `Bound.read`/`Bound.read_jsonl` (leaf wants a regular
    file) and `Bound.entries` (leaf wants a directory) build on: opens every component
    no-follow from the previous handle — each intermediate as an `O_PATH` step
    (`_STEP_FLAGS`), the leaf for reading (`_WALK_FLAGS`) — `fstat`-classifying each
    intermediate as a real directory (D-V3): a symlink at a step is the alias refusal, any
    other non-directory is 'Not a directory'. Answers `("absent", None)`, `("refused",
    reason)` or `("leaf", (fd, stat_result))` — the CALLER classifies the leaf's own `fstat`
    result and owns (reads or stores) the returned fd; every intermediate fd this walk opened
    is closed here, on every path, before it returns.
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
    """One component's own open failed — `_walk_chain`'s three-way reading of the errno,
    split out so the walk's own branch count stays legible (ruff C901)."""
    if e.errno == errno.ENOENT:
        return "absent", None
    if e.errno == errno.ELOOP:
        return "refused", ALIAS_READ_REFUSAL
    return "refused", (e.strerror or str(e))


def _classify_leaf_file(fd: int, st: Any) -> bool:
    """Is the leaf handle `fstat` classified a plain, single-linked regular file? A hard link
    (`S_ISREG` with `st_nlink > 1`), a directory, a FIFO, a socket or a device is not — the
    same fold `read_plain`'s alias refusal makes, judged off the open descriptor rather than a
    name that could have changed since."""
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
    """The one opened directory descriptor behind a `bind` and every `under` derived from it —
    shared by reference, so it lives while any of them does and is closed exactly once: by
    `Bound.close()` (the `with bind(...)` form) or, for a bind nobody scoped, on collection."""

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
    """An episode-tree reader bound to one root (`bind`) or one directory named relative to it
    (`Bound.under`) — the ONLY value that ever held the root's own spelling, and it holds it
    as an opened directory HANDLE, never as a `str`/`bytes`/`os.PathLike` a reader body could
    format (D-V2). Every read is `os.openat`-style, no-follow, from that handle down. A
    derivation (`under`) opens NOTHING: it is the same root handle plus a name prefix, so
    every `read`/`read_jsonl`/`entries` walks the whole relative name from the root at that
    moment (a name renamed, replaced or removed between two reads is answered fresh on the
    second), and there is exactly one handle per `bind`, closed by `close()` — `bind` is a
    context manager, and a handle nobody scoped is closed when its last reader is collected.
    The root ITSELF is not re-resolved: `bind` opens it once, and if the operator deletes and
    recreates an entry at that same path during this `Bound`'s lifetime, reads through it keep
    answering off the original (now unlinked) directory rather than the replacement — a
    `Bound` is scoped to one grading or rendering pass, never held across such a window.
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
        """Release the root handle — the reader `bind` returned owns it; every reader derived
        from it (`under`) answers `Bad file descriptor` from then on. On a derived reader this
        is a no-op: it owns nothing. Idempotent."""
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
        # `UnicodeDecodeError` AND `OSError` — the read itself can fail after the open (EIO, a
        # stale handle on a network mount); the reader it replaced folded both into a refusal
        # (`TEXT_READ_ERRORS`), and a refusal is what every caller already handles.
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
        """What is IN the bound directory, each entry judged of itself (never followed): the
        answer to "is this directory there, and what real files and real directories does it
        hold" for a caller that used to `lstat` a name ahead of a read. The root's own listing
        for a `bind`; for an `under` derivation, the walk to the named directory is the same
        no-follow walk `read` makes, and a symlinked, file-squatted or unreadable component is
        that walk's own refusal."""
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
        """A READ handle on the bound directory for `entries` — `("leaf", fd)`, or the walk's
        own `("absent", None)` / `("refused", reason)`. The root handle is `O_PATH` (search
        permission alone), so the root is opened as `.` off it; a derivation walks its prefix,
        and a leaf that is not a directory is 'Not a directory'."""
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
        """A reader bound at `name` relative to this one — a NAME PREFIX over the same root
        handle, opened only when a read through it walks. It owns no handle; closing it is a
        no-op, and it answers off the root handle's lifetime."""
        _spelling, parts = _parse_name(name)
        return Bound(self._os, self._handle, prefix=self._prefix + parts,
                     absent=self._absent, error=self._error)


def bind(root: Path, *, os_: Any = os) -> Bound:  # lint-dup: ok — an unrelated `bind` (an AgentDeps builder) already lives at runtime/agent_definition.py:294; the shared word names two unrelated concepts, not one contract split in two
    """The one operation in this module that takes a path (D-V2): opens `root` ONCE — its own
    open FOLLOWS a symlinked spelling (the operator's own, RF-R8; a `Bound.under` derived
    below it never does) — and hands back a `Bound` reader that holds only the resulting
    handle, and OWNS it: use `with bind(root) as bound:` (or `close()`), one handle per pass.
    `root` absent, not a directory, or unreadable does not raise here: every subsequent
    `.read`/`.read_jsonl`/`.entries` call answers absent, or refuses `f"{name}: {reason}"`
    independently per name (F-C — the fault is the bind's, the observable is per name).
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


#: The deepest nesting a JSON artifact a box wrote may carry and still be READABLE. A property
#: of the bytes, judged by :func:`json_nesting_depth` before the decoder sees them — never of
#: the caller. `json.loads` recurses once per nested container on the interpreter's shared
#: stack budget (3.11: the `sys.getrecursionlimit()` one), so without a bound the same line
#: decoded from a deep call and a shallow one gives two different answers, and the two sides of
#: a "this line is / is not a row" agreement (`challenge_gate._is_row_shaped` deep in the gate,
#: `read_jsonl_rows` from the top) could disagree about one line. 100 is an order of magnitude
#: past the deepest artifact any adapter or model writes here, and an order of magnitude short
#: of the budget a caller could plausibly have left.
JSON_NESTING_LIMIT = 100

_JSON_STRING = re.compile(r'"(?:[^"\\]|\\.)*"')
_JSON_BRACKET = re.compile(r"[\[\]{}]")


def json_nesting_depth(text: str) -> int:
    """The deepest container nesting in ``text``, judged WITHOUT decoding it.

    Exact for valid JSON: string literals are dropped first (escapes honoured), so a bracket
    inside a value does not count, and each remaining ``[``/``{`` opens a level. For text that
    is not JSON the answer is whatever the brackets say — the decoder refuses it either way,
    so only valid text needs the number to be right. Iterative and regex-driven so a payload
    of megabytes costs a pass over its brackets, not a Python loop over its characters."""
    depth = deepest = 0
    for bracket in _JSON_BRACKET.finditer(_JSON_STRING.sub("", text)):
        if bracket.group() in "[{":
            depth += 1
            deepest = max(deepest, depth)
        elif depth:
            depth -= 1
    return deepest


# lint-parse: ok — the decoder is the seam every reader narrows AT, not one that narrows for
# them: it returns `object`, never `Any`, so a caller cannot read a key or index a list without
# its own `isinstance` — the shape check stays beside the code that knows the shape.
def load_json_artifact(text: str) -> tuple[object, str | None]:
    """Decode one JSON artifact a box could have written: ``(value, None)``, or ``(None,
    reason)`` when it is not one. Success is ``reason is None`` — ``null`` decodes to ``None``.

    THE ONE PLACE the tolerance for a malformed artifact is decided. Every reader of a run
    dir's content (a lead file, a table row, a payload, an alert) used to spell its own
    ``except`` around ``json.loads``, each with a different list, and each new malformed shape
    had to be discovered once per reader — the deeply nested one was, four times over
    (``lead_repository.load_leads``, ``branch/capture``, ``_provenance``, ``query_tool``),
    with the table's row reader the one that had not yet paid. Decode errors are a
    ``ValueError``; nesting is judged ahead of the decoder by :func:`json_nesting_depth`, for
    the reason :data:`JSON_NESTING_LIMIT` gives — a ``RecursionError`` out of ``json.loads``
    is a fact about the caller's stack, and catching it would make the answer depend on who
    asked."""
    if json_nesting_depth(text) > JSON_NESTING_LIMIT:
        return None, f"nested deeper than {JSON_NESTING_LIMIT}"
    try:
        return json.loads(text), None
    except ValueError as e:
        return None, str(e)


def parse_jsonl_row(line: str) -> dict | None:
    """One physical line as a JSONL ROW, or ``None`` if it is not one.

    THE definition of what counts as a row, published rather than kept inside
    :func:`read_jsonl_rows`, because a second reader must agree with it exactly:
    ``challenge_gate._write_trace_row`` decides whether a stage's framed reply may stand as its
    own physical line, which is only safe while "a line every reader skips" is the SAME
    predicate the reader applies — and the same from ANY stack depth, which is what
    :func:`load_json_artifact`'s nesting bound buys: the writer asks from deep inside the
    gate, the readers from the top, and one line must not be a row to one and not the other.

    A row is a line that parses AND parses to a dict: ``"x"``, ``3`` and ``[...]`` are all
    valid JSON and none of them is one. Without that half the declared ``list[dict]`` is a lie
    and every consumer's ``row.get(...)`` raises ``AttributeError`` — a class no drain guard
    names, so it crashes the worker every tick.
    """
    s = line.strip()
    if not s:
        return None
    obj, reason = load_json_artifact(s)
    return obj if reason is None and isinstance(obj, dict) else None


def read_jsonl_rows(path: Path) -> list[dict]:
    return read_jsonl_rows_report(path)[0]


def read_jsonl_rows_report(path: Path) -> tuple[list[dict], int]:
    """JSONL rows plus the number of non-blank physical lines that were not rows.

    Most artifact readers are deliberately tolerant and need only :func:`read_jsonl_rows`.
    Boundaries that must account for lost evidence, however, cannot recover malformed lines
    after that tolerant reader has discarded them. Keeping the accounting beside
    :func:`parse_jsonl_row` makes both readers agree on exactly what a row is.
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


def append_jsonl(path: Path, rows: list[dict]) -> int:
    if not rows:
        return 0
    path.parent.mkdir(parents=True, exist_ok=True)  # lint-unguarded-tree-write: ok — the pre-#771 primitive itself; its own callers are what the gate flags  # noqa: E501
    with path.open("a", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")  # lint-jsonl-io: ok — the canonical JSONL appender
    return len(rows)


def write_atomic(path: Path, text: str) -> None:
    write_guarded(path, text, mode="replace")


# The alias-refusing write backstop (M3).
#
# Every host-side write into a shared box tree routes through `write_guarded` (or
# `guarded_mkdir` for the directory-component half). A planted symlink or hard link at the
# write's target name is refused rather than followed: `replace` stages under an unpredictable
# name (D1) and only ever swaps the *staged* file into place, never opens the existing target
# for writing; `append`/`update` open the existing target with O_NOFOLLOW. `_refuse_unless_plain`
# is the shared precheck all three modes run first, and it keeps the refusal's exception TYPE
# uniform across "target is a symlink", "target is a hard-linked regular file" and "target is a
# directory" — three causes a caller must not tell apart from the exception class alone (F1's
# per-call-site posture parity depends on exactly one type here). `.write_guarded_alias` is a
# non-standard attribute set on the raised OSError so a caller that DOES need to tell "aliased"
# from "ordinary occupied name" (D3's accounting exemption) can, without weakening that.
def stage_name(path: Path) -> Path:
    """An unpredictable staged name in `path`'s own directory (§7 D1).

    Never the deterministic `<name>.tmp` B4 was planted at, and never repeats: our staged names
    collide with nothing we wrote, so an occupied staged name is always hostile and
    `O_CREAT|O_EXCL` failing closed on it is unambiguous."""
    path = Path(path)
    return path.with_name(f"{path.name}.staged-{secrets.token_hex(8)}")


def _mark_alias(exc: OSError, *, is_alias: bool) -> OSError:
    exc.write_guarded_alias = is_alias  # type: ignore[attr-defined]
    return exc


def is_hard_linked(st: os.stat_result) -> bool:
    """A regular file with more than one name — the alias `O_NOFOLLOW` cannot refuse (B9)."""
    return stat.S_ISREG(st.st_mode) and st.st_nlink > 1


def is_plain_entry(st: os.stat_result) -> bool:
    """THE rule for "a plain, single-linked regular file" — what a guarded write may replace,
    what a guarded read may open, and what an archive copy may land on. One predicate over
    an `lstat`/`fstat` result, so the write seam, the read seam and the archive's destination
    screen cannot drift on what counts as plain: not a symlink, not a hard link, not a
    directory, fifo, socket or device."""
    return stat.S_ISREG(st.st_mode) and not is_hard_linked(st)


def _refuse_unless_plain(path: Path) -> None:
    """Refuse unless `path` is absent or a plain, single-linked regular file.

    A symlink and a hard-linked regular file are both aliases (B9: `O_NOFOLLOW` alone does not
    stop a hard link). A directory, fifo, socket or device is not something any of the three
    write modes below can safely replace/append/update either — and folding it into the same
    refusal, with the same exception type, is what keeps a directory squatting an artifact's
    name from reading as a DIFFERENT posture than a planted symlink at the identical name."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return
    is_hardlink = is_hard_linked(st)
    is_alias = stat.S_ISLNK(st.st_mode) or is_hardlink
    if not is_plain_entry(st):
        # D1: the refusal LEAVES the planted entry in place, symlink or hard link alike —
        # removal is sanitizing, and an entry the writer deletes is one the reap scan can
        # never report.
        # ELOOP for everything except a hard link (B9: `O_NOFOLLOW` never fires for one — the
        # open would SUCCEED — so ELOOP would claim a reason a hard-link plant cannot
        # produce); EMLINK for a hard link. Neither errno has a dedicated `OSError` subclass,
        # so both raise the same TYPE (what `posture_class` compares) while the errno stays an
        # honest description of which shape was refused.
        refusal_errno = errno.EMLINK if is_hardlink else errno.ELOOP
        raise _mark_alias(
            OSError(refusal_errno, "refusing to write through a non-plain or aliased entry",
                     str(path)),
            is_alias=is_alias,
        )


def open_nofollow_fd(path: Path, flags: int) -> int:
    """`O_NOFOLLOW` open whose `ELOOP` is MARKED as an alias refusal.

    Every caller runs `_refuse_unless_plain` first, so an `ELOOP` out of the open itself means
    a symlink appeared in the window between the two checks — the same attack, one race later.
    Without the mark that refusal reaches D3's accounting exemption as an ordinary write
    failure and counts toward the very kill circuit the exemption exists to keep an alias out
    of."""
    try:
        return os.open(path, flags | os.O_NOFOLLOW, 0o644)
    except OSError as e:
        raise _mark_alias(e, is_alias=e.errno == errno.ELOOP) from None


@contextlib.contextmanager
def locked_for_rewrite(path: Path, *, binary: bool = False) -> Iterator[Any]:
    """The locked read-modify-write lane's dangerous prefix, in ONE place: refuse a non-plain
    or aliased target, open the survivor with `O_NOFOLLOW`, then take the exclusive lock —
    strictly in that order, so the refusal happens before anything is locked or written.

    Yields the open, locked handle positioned at 0; the caller reads, decides, seeks and
    truncates. Two callers hold that sequence — `write_guarded(mode="update")` and
    `hooks/_run_dir.update_json_locked` — and share this one copy so the refusal contract
    cannot be changed for only one of them."""
    path = Path(path)
    _refuse_unless_plain(path)
    fd = open_nofollow_fd(path, os.O_RDWR | os.O_CREAT)
    opener = os.fdopen(fd, "r+b") if binary else os.fdopen(fd, "r+", encoding="utf-8")
    with opener as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        yield f


def write_guarded(
    path: Path, text: str | bytes, *, mode: str = "replace",
    stage_name: Callable[[Path], Path] = stage_name, **kw: object,
) -> None:
    """The single write seam every shared-tree writer routes through (M3).

    `mode` names the idiom the caller had: `replace` (the truncating/atomic lane — D1: stages
    under an unpredictable name, then `os.replace`s into place, which replaces a planted
    symlink rather than following it and never opens the existing target at all), `append`
    (the JSONL lane — `O_NOFOLLOW` at open) and `update` (the locked read-modify-write lane —
    `O_NOFOLLOW` at open, before the lock is taken). `text` may be `bytes` (the drain lane's
    corpus restore); the fd is opened binary or text to match. `stage_name` is the name-source
    seam. `**kw` absorbs a mode-irrelevant `encoding` (every mode already pins utf-8) rather
    than raising `TypeError` on it — and NOTHING ELSE: a swallowed unknown keyword is how a
    misspelt `mode=` (`moode="append"`) silently falls back to `replace` and TRUNCATES the
    file the caller meant to append to."""
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
            if isinstance(text, (bytes, bytearray)):
                with os.fdopen(fd, "wb") as fb:
                    fb.write(text)
            else:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    f.write(text)
            os.replace(staged, path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.remove(staged)
            raise
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


def open_guarded(path: Path, mode: str = "a"):
    """Open `path` for a STREAMING writer that holds the handle open across many individual
    writes (`observe.RequestLogger`), unlike `write_guarded`'s one-shot modes. The alias check
    runs once, at open — there is no per-write re-check, matching every other writer's
    contract (a refusal happens before anything is written, never mid-stream). `os.devnull` is
    exempt: it is not a regular file and never will be, and refusing it would break the
    null-logger path that legitimately opens it."""
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
            os.mkdir(component)  # lint-unguarded-tree-write: ok — THIS is the guarded mkdir the gate points every other caller at
            return
        except FileExistsError:
            # Something appeared between the lstat and the mkdir. Re-judge what is ACTUALLY
            # there rather than assuming it is the directory we meant to create: a symlink
            # planted in exactly that window is the hole this function exists to close (B8),
            # and swallowing the EEXIST would traverse it. A second FileNotFoundError (it
            # raced away again) propagates, which is the fail-closed side.
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
    """`mkdir(parents=True, exist_ok=True)`, refusing a symlinked component at any depth
    BELOW `base` (B8: `O_NOFOLLOW` on the leaf alone does not protect a swapped component;
    B10: `mkdir(parents=True, exist_ok=True)` over one succeeds silently).

    `base` IS THE TRUST ROOT — the shared tree's own root, not the filesystem's. It and
    everything above it are host-controlled: the box's writable mounts start at the tree, so
    the box can plant a component INSIDE `base` and nowhere above it. `base` is therefore
    created with a plain `parents=True` mkdir that follows symlinks, and only the components
    strictly below it are judged.

    WHY THE ANCHOR IS REQUIRED, AND NOT A CONVENIENCE. Walking to the filesystem root instead
    refuses on any symlinked ANCESTOR — a host configuration the box cannot influence, and a
    common one (`/tmp` is a symlink on macOS, where the default runs base lives; a symlinked
    `/data` or `/var/run` does the same on Linux). That refusal lands on every mkdir in the
    process: no session store, so no run starts, and the sidecar persistence paths degrade to
    permanent silent no-ops. Anchoring costs no coverage, because the region it stops checking
    is the region the box cannot reach.

    Depth-agnosticism is preserved WITHIN the tree: every component from `base` down is
    checked, not only the last one created. `base` is keyword-only and required so a new call
    site has to name the tree it trusts; a default would silently re-adopt whichever anchor
    was convenient, which is how the walk reached `/` to begin with. Containment is judged
    LEXICALLY: `resolve()` here would collapse the very symlink the walk exists to refuse."""
    path = Path(path)
    base = Path(base)
    try:
        rest = path.relative_to(base)
    except ValueError:
        raise ValueError(
            f"guarded_mkdir: {str(path)!r} is not inside the tree root {str(base)!r} — the "
            f"anchor names the wrong tree, or the target reaches outside it"
        ) from None
    # `relative_to` is a PREFIX match over path parts, so it happily accepts a target that
    # climbs back out with `..` (`<base>/x/../../escaped` is "inside" `<base>` by that test).
    # The walk below would then `lstat`/`mkdir` components the kernel resolves OUTSIDE the
    # trust root — the containment claim inverted. Normalising is purely lexical (it collapses
    # no symlink), and a `..` that stays inside — `<base>/x/../y` — normalises to `y` and is
    # still accepted, so only the escaping shape is refused.
    if rest.parts and os.path.normpath(str(rest)).split(os.sep)[0] == os.pardir:
        raise ValueError(
            f"guarded_mkdir: {str(path)!r} climbs out of the tree root {str(base)!r} through "
            f"'..' — the target reaches outside the tree the anchor names"
        )
    # Short-circuited, not unconditional: this runs on the per-tool-call hot path and the tree
    # root is created before any box starts, so the syscall is pure overhead after the first.
    # `is_dir()` follows symlinks deliberately — a host-chosen symlinked runs base is the
    # configuration the anchor exists to keep working.
    if not base.is_dir():
        os.makedirs(base, exist_ok=True)
    accum = base
    for part in rest.parts:
        accum = accum / part
        _ensure_dir_component(accum)


#: The staged NAME CLASS, matched loosely on purpose — deliberately NOT the exact
#: `<name>.staged-<16 hex>` shape `stage_name` mints. The sweep must also remove an entry an
#: attacker planted at a staged-looking name (e.g. `report.md.staged-hostile`), and a plant by
#: construction carries no hex of ours. The cost is that a legitimate artifact whose name
#: contains this literal would be swept — accepted, because `.staged-` is a suffix namespace
#: this module owns and nothing else in any tree writes into it.
_STAGED_MARKER = ".staged-"


def sweep_staged(tree: Path) -> list[Path]:
    """Remove every orphaned staged file under `tree` (§7 D1's accepted cost: unpredictable
    staged names mean no later write ever replaces a crash-orphaned one by name, so orphans
    accumulate and need a sweep). `os.walk(..., followlinks=False)` never descends into a
    symlinked directory, and removing a symlink entry never touches what it points at — so a
    staged NAME planted as an alias is removed as an entry, never followed.

    Called from `box.stop_and_scrub` — AFTER the reap scan has judged the tree, never before:
    sweeping first would delete entries the scan exists to report. Sweeping after costs
    nothing, because the scan permits any regular file and an orphaned staged file is one."""
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
