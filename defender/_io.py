from __future__ import annotations

import contextlib
import errno
import fcntl
import json
import os
import stat
import sys
from collections.abc import Callable, Iterator
from pathlib import Path, PurePath
from typing import IO, Any, Literal, overload

from defender._filesystem.bound import (
    ALIAS_READ_REFUSAL as ALIAS_READ_REFUSAL,
    Bound as Bound,
    BytesRead as BytesRead,
    ENTRY_DIR as ENTRY_DIR,
    ENTRY_FILE as ENTRY_FILE,
    ENTRY_OTHER as ENTRY_OTHER,
    EntriesRead as EntriesRead,
    READ_LIMIT as READ_LIMIT,
    REFUSED_ALIAS as REFUSED_ALIAS,
    REFUSED_FAULT as REFUSED_FAULT,
    REFUSED_NOT_FILE as REFUSED_NOT_FILE,
    REFUSED_UNDECODABLE as REFUSED_UNDECODABLE,
    RecordRead as RecordRead,
    RefusalKind as RefusalKind,
    StatRead as StatRead,
    StatsRead as StatsRead,
    TEXT_READ_ERRORS as TEXT_READ_ERRORS,
    _ERRORS_VALUES as _ERRORS_VALUES,
    _Handle as _Handle,
    _LINKED_FOLDER as _LINKED_FOLDER,
    _NOT_A_FOLDER as _NOT_A_FOLDER,
    _NOT_A_NAME as _NOT_A_NAME,
    _NOT_A_PATH as _NOT_A_PATH,
    _NOT_PLAIN as _NOT_PLAIN,
    _O_PATH as _O_PATH,
    _PLATFORM_FAULT as _PLATFORM_FAULT,
    _READ_CHUNK as _READ_CHUNK,
    _ROOT_FLAGS as _ROOT_FLAGS,
    _Read as _Read,
    _ReadVanished as _ReadVanished,
    _STEP_FLAGS as _STEP_FLAGS,
    _TooLarge as _TooLarge,
    _VANISHED as _VANISHED,
    _descend as _descend,
    _entry_kind as _entry_kind,
    _jsonl_rows_of as _jsonl_rows_of,
    _open_leaf_stat as _open_leaf_stat,
    _open_refusal as _open_refusal,
    _parse_name as _parse_name,
    _read_cap as _read_cap,
    _read_leaf as _read_leaf,
    _read_plain_fd as _read_plain_fd,
    _read_prefix as _read_prefix,
    _read_reason as _read_reason,
    _refused_by as _refused_by,
    _step as _step,
    _too_large as _too_large,
    bind as bind,
    located as located,
    stat_entries as stat_entries,
    stat_entry as stat_entry,
)


from defender._filesystem.write import (
    unnamed_files_unavailable,
    NotPlainEntry as NotPlainEntry,
    _FILE_MODE as _FILE_MODE,
    _NO_UNNAMED_FILES as _NO_UNNAMED_FILES,
    _PROC_STATUS as _PROC_STATUS,
    _STAGED_MARKER as _STAGED_MARKER,
    _create_named as _create_named,
    _create_unnamed as _create_unnamed,
    _ensure_dir_component as _ensure_dir_component,
    _link_unnamed as _link_unnamed,
    _mark_alias as _mark_alias,
    _process_umask as _process_umask,
    _refuse_unless_plain as _refuse_unless_plain,
    _refuse_unless_plain_stat as _refuse_unless_plain_stat,
    _rewrite_fd as _rewrite_fd,
    _write_all as _write_all,
    guarded_mkdir as guarded_mkdir,
    is_hard_linked as is_hard_linked,
    is_plain_entry as is_plain_entry,
    locked_for_rewrite as locked_for_rewrite,
    open_nofollow_fd as open_nofollow_fd,
    open_unnamed as open_unnamed,
    stage_name as stage_name,
    staged_leaf as staged_leaf,
    sweep_staged as sweep_staged,
    write_guarded as write_guarded,
)


def read_text_utf8(path: Path, *, limit: int = READ_LIMIT) -> str:
    """The canonical text read: UTF-8 with universal newlines, as `Path.read_text` reads, and
    opened as it opens (following links, blocking). Bounded (#1174): a file over `limit`
    (at most `READ_LIMIT`) raises an `OSError`, before reading or once it grows past it."""
    return _read_followed_text(path, limit=_read_cap(limit), errors="strict")


def read_bytes_capped(path: Path, *, limit: int = READ_LIMIT) -> bytes:
    """`Path.read_bytes`, capped: the exact bytes (no newline translation), opened as it opens
    (following links, blocking). A file over `limit` (at most `READ_LIMIT`) raises an `OSError`,
    before reading or once it grows past it (#1188 amendment 3)."""
    data = _read_followed(path, limit=_read_cap(limit), binary=True)
    assert isinstance(data, bytes)
    return data


def read_text_soft(
    path: Path, *, limit: int = READ_LIMIT,
) -> tuple[str | None, str | None]:
    try:
        return read_text_utf8(path, limit=limit), None
    except TEXT_READ_ERRORS as e:
        return None, str(e)


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


def read_guarded(
    path: Path, *, errors: str = "strict", os_: Any = os,
) -> tuple[str | None, str | None]:
    """:func:`write_guarded`'s READ-side twin: the text at ``path``, or a refusal reason.

    Same return shape as :func:`read_text_soft`, but anything other than a plain,
    single-linked regular file is refused rather than followed — trees a box has written into
    may hold planted entries. ``errors`` is ``open``'s decoding policy; tolerant line readers
    pass ``"replace"`` so one bad byte costs one row.

    Absence is also a refusal here (the reason string distinguishes it); a caller that must act
    on absence differently uses :func:`read_plain` and catches it.
    """
    try:
        return read_plain(path, errors=errors, os_=os_), None
    except TEXT_READ_ERRORS as e:
        return None, str(e)


def read_plain(path: Path, *, errors: str = "strict", os_: Any = os) -> str:
    """The guarded read as a RAISING primitive: the text of the plain, single-linked regular
    file at ``path``, read with universal newlines exactly as ``Path.read_text`` would — or the
    exception that stopped it, every one a member of :data:`TEXT_READ_ERRORS`:

      * ``FileNotFoundError`` — nothing at the name;
      * an ``OSError`` carrying :data:`ALIAS_READ_REFUSAL` — the entry is not a plain file: a
        symlink (refused at the open, ``ELOOP``), a hard link (``EMLINK``, the write side's
        own errno for the shape ``O_NOFOLLOW`` cannot refuse), a directory, fifo, socket or
        device (``ELOOP``, as the write side folds them);
      * any other ``OSError`` — the file is there and could not be read (``EACCES``, ``EIO``),
        including the read step's refusals (:func:`_read_plain_fd`): larger than
        :data:`READ_LIMIT` (``EFBIG``), no data yet on the non-blocking descriptor
        (``EAGAIN``), gone while it was read (an ``ENOENT`` that is NOT a
        ``FileNotFoundError``), and a path that does not encode (``EINVAL``);
      * ``UnicodeDecodeError`` — its bytes are not UTF-8.

    Plainness is judged on the open descriptor (``O_NOFOLLOW`` then ``fstat``), not by
    ``lstat``-then-read, which leaves a race window for a plant.
    """
    # `_open_plain_fd` opens with `O_NONBLOCK`: a planted FIFO would otherwise block the open
    # forever before `fstat` could refuse it.
    fd, st = _open_plain_fd(path, os_)
    try:
        text = _read_plain_fd(os_, fd, st.st_size, binary=False, errors=errors)
    finally:
        os_.close(fd)
    assert isinstance(text, str)
    return text


def read_plain_bytes(path: Path, *, os_: Any = os) -> bytes:
    """:func:`read_plain` without newline translation, for records whose exact bytes matter
    (e.g. the alert's content hash)."""
    fd, st = _open_plain_fd(path, os_)
    try:
        data = _read_plain_fd(os_, fd, st.st_size, binary=True)
    finally:
        os_.close(fd)
    assert isinstance(data, bytes)
    return data


def read_bytes_guarded(path: Path, *, os_: Any = os) -> tuple[bytes | None, str | None]:
    """:func:`read_guarded`'s bytes twin — ``(data, None)`` or ``(None, reason)``."""
    try:
        return read_plain_bytes(path, os_=os_), None
    except TEXT_READ_ERRORS as e:
        return None, str(e)


def _read_followed(path: Path, *, limit: int, errors: str = "strict",
                   binary: bool = False) -> str | bytes:
    """The canonical wrappers' read: opened as `Path.read_text`/`read_bytes` open (following
    links, blocking, #1174 O9), then the shared step with the wrapper's `limit`."""
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    try:
        return _read_plain_fd(os, fd, os.fstat(fd).st_size, binary=binary, errors=errors,
                              limit=limit)
    finally:
        os.close(fd)


def _read_followed_text(path: Path, *, limit: int, errors: str) -> str:
    text = _read_followed(path, limit=limit, errors=errors)
    assert isinstance(text, str)
    return text


def _json_object(raw: bytes) -> dict | None:
    """`raw` as a JSON object, or `None` when it is not usable as one: undecodable, not JSON,
    nested past :data:`JSON_NESTING_LIMIT` (judged before decoding, :func:`load_json_artifact`),
    or not an object."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    doc, reason = load_json_artifact(text)
    return doc if reason is None and isinstance(doc, dict) else None


def locked_json_update(
    open_locked: Any, mutate: Callable[[dict], Any], *,
    default: Callable[[], dict] = dict, os_: Any = os,
) -> dict:
    """The locked read-modify-write of a run-state JSON object (#1174 amendment 2): callers get
    contents, never a handle to read.

    `open_locked` is a context manager yielding the locked record's descriptor and its `fstat`
    (:func:`locked_for_rewrite`). The whole record is read through the shared step; content
    unusable as state (over :data:`READ_LIMIT`, undecodable, not JSON, too deep, not an
    object) starts over from `default()` (O6). Any other read fault
    propagates and nothing is written (O7). `mutate` changes the state in place; it is written
    back whole, and returned."""
    with open_locked as (fd, st):
        try:
            raw = _read_plain_fd(os_, fd, st.st_size, binary=True)
        except _TooLarge:
            state = None
        else:
            assert isinstance(raw, bytes)
            state = _json_object(raw)
        if state is None:
            state = default()
        mutate(state)
        _rewrite_fd(os_, fd, json.dumps(state, indent=2).encode())
    return state


def locked_json_read(open_locked: Any, *, os_: Any = os) -> dict:
    """The locked read of a run-state JSON object (#1174 O8): `open_locked` is
    :func:`locked_for_read`'s context manager. `{}` when the record is absent, refused, or
    unreadable (every `TEXT_READ_ERRORS` member, the size limit among them), and when its
    content is unusable as state."""
    try:
        with open_locked as (fd, st):
            raw = _read_plain_fd(os_, fd, st.st_size, binary=True)
    except TEXT_READ_ERRORS:
        return {}
    assert isinstance(raw, bytes)
    return _json_object(raw) or {}


def _open_plain_fd(path: Path, os_: Any = os) -> tuple[int, os.stat_result]:
    """The guarded open both plain readers share, and the descriptor's one `fstat`; the caller
    owns the returned fd. A path that does not encode is refused (`EINVAL`) before any open
    (#1174 O4)."""
    try:
        os.fsencode(path)
    except UnicodeEncodeError:
        raise OSError(errno.EINVAL, _NOT_A_PATH) from None
    try:
        fd = open_nofollow_fd(Path(path), os.O_RDONLY | os.O_NONBLOCK, os_=os_)
    except OSError as e:
        # Reword a symlink-at-the-leaf `ELOOP` as the alias refusal. An `ELOOP` from a looped
        # component higher up keeps its own strerror: the leaf is not the alias.
        if getattr(e, "write_guarded_alias", False) and _leaf_is_link(path, os_):
            raise _mark_alias(OSError(errno.ELOOP, ALIAS_READ_REFUSAL, str(path)),
                              is_alias=True) from None
        raise
    try:
        st = os_.fstat(fd)
        # `O_NOFOLLOW` cannot refuse a hard link, so check the link count; directories,
        # FIFOs, sockets and devices get the same refusal as a planted symlink.
        if not is_plain_entry(st):
            raise OSError(
                errno.EMLINK if is_hard_linked(st) else errno.ELOOP, ALIAS_READ_REFUSAL,
                str(path),
            )
    except BaseException:
        os_.close(fd)
        raise
    return fd, st


def _leaf_is_link(path: Path, os_: Any = os) -> bool:
    """Is the entry at `path` itself a symlink? `False` if it cannot be `lstat`ed (a looped
    parent), where the leaf is not the alias."""
    try:
        return stat.S_ISLNK(os_.lstat(path).st_mode)
    except OSError:
        return False


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


def _open_leaf(os_: Any, dir_fd: int, leaf: str, flags: int, where: Path) -> int:
    """Open `leaf` off `dir_fd` no-follow and non-blocking, then judge the descriptor. The
    caller owns the returned fd."""
    return _open_leaf_stat(os_, dir_fd, leaf, flags, where)[0]


def use_utf8_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(encoding="utf-8", errors=getattr(stream, "errors", None) or "strict")

from defender._filesystem.json import (
    JSON_NESTING_LIMIT as JSON_NESTING_LIMIT,
    JsonTooDeep as JsonTooDeep,
    _JSON_TOKEN as _JSON_TOKEN,
    _JsonRules as _JsonRules,
    _json_key as _json_key,
    _json_safe_walk as _json_safe_walk,
    _json_text as _json_text,
    _non_finite_text as _non_finite_text,
    json_nesting_depth as json_nesting_depth,
    json_safe as json_safe,
    load_json_artifact as load_json_artifact,
    parse_jsonl_row as parse_jsonl_row,
)



def read_jsonl_rows(path: Path, *, limit: int = READ_LIMIT) -> list[dict]:
    return read_jsonl_rows_report(path, limit=limit)[0]


def read_jsonl_rows_report(
    path: Path, *, limit: int = READ_LIMIT,
) -> tuple[list[dict], int]:
    """JSONL rows plus the number of non-blank lines that were not rows, for callers that must
    account for lost evidence. Bounded like :func:`read_text_utf8` (`limit`, #1174): a file
    over it raises an `OSError`.
    """
    limit = _read_cap(limit)  # before the absent-file answer: `None` is refused either way
    if not path.is_file():
        return [], 0
    return _jsonl_rows_of(_read_followed_text(path, limit=limit, errors="replace"))


def iter_plain_jsonl_rows(path: Path) -> Iterator[dict]:
    """The JSONL rows of a log too large to read whole (the wire log runs past 100 MB), streamed
    one line at a time (#1188 D2). Nothing at `path` yields nothing; a line that is not a row is
    skipped, and so is a line longer than `READ_LIMIT`, which is never held whole. Opened as
    :func:`read_plain` opens it: a symlink, hard link, FIFO or device is refused with
    :data:`ALIAS_READ_REFUSAL`, so a planted alias cannot point the stream at a file (or
    `/dev/zero`) the host never wrote."""
    try:
        fd, _ = _open_plain_fd(path)
    except FileNotFoundError:
        return
    try:
        handle = os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise
    with handle:
        while raw := handle.readline(READ_LIMIT + 1):
            if len(raw) > READ_LIMIT and not raw.endswith(b"\n"):
                # A newline-free stretch past the cap is not a row: drop it a chunk at a time,
                # never holding more than the cap (#1188 amendment 3).
                while (tail := handle.readline(_READ_CHUNK)) and not tail.endswith(b"\n"):
                    pass
                continue
            row = parse_jsonl_row(raw.decode("utf-8", "replace"))
            if row is not None:
                yield row


def append_jsonl(path: Path, rows: list[dict]) -> int:
    """Append `rows` to `path` as JSONL, one row per line, making the file (and its folder)
    when absent. A new file asks for `_FILE_MODE`, as every other lane's, so the umask masks
    0644, not `open("a")`'s 0666 (#1144). Returns how many rows it wrote."""
    if not rows:
        return 0
    path.parent.mkdir(parents=True, exist_ok=True)  # lint-unguarded-tree-write: ok — the unguarded primitive itself; the gate flags its callers  # noqa: E501
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, _FILE_MODE)
    try:
        fh = os.fdopen(fd, "a", encoding="utf-8")
    except BaseException:
        os.close(fd)  # `fdopen` failed to take the fd, so it is still ours to close
        raise
    with fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")  # lint-jsonl-io: ok — the canonical JSONL appender
    return len(rows)


@contextlib.contextmanager
def locked_for_read(path: Path, *, os_: Any = os) -> Iterator[tuple[int, os.stat_result]]:
    """The locked read's opener (#1174 O8): no-follow, non-blocking, read-only — it creates
    nothing — judged plain on its descriptor, under a shared lock. Yields the descriptor and
    its `fstat`. An absent record raises `FileNotFoundError`; a link or other non-plain entry,
    its refusal."""
    path = Path(path)
    try:
        fd = os_.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError as e:
        raise _mark_alias(e, is_alias=e.errno == errno.ELOOP) from None
    try:
        st = os_.fstat(fd)
        _refuse_unless_plain_stat(st, path)
        fcntl.flock(fd, fcntl.LOCK_SH)
        yield fd, st
    finally:
        os_.close(fd)


def open_guarded(path: Path, mode: str = "a"):
    """Open `path` for a streaming writer (`observe.RequestLogger`). The alias check runs once,
    at open. `os.devnull` is exempt, for the null logger."""
    path = Path(path)
    if str(path) != os.devnull:
        _refuse_unless_plain(path)
    flags = os.O_WRONLY | os.O_CREAT | (os.O_APPEND if mode == "a" else os.O_TRUNC)
    fd = open_nofollow_fd(path, flags)
    return os.fdopen(fd, mode, encoding="utf-8")


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
    return os.open(".", flag | os.O_WRONLY | os.O_CLOEXEC, _FILE_MODE, dir_fd=dir_fd)


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


def rooted_unlink(root: Path, name: str | PurePath, *, os_: Any = os) -> None:
    """Unlink a leaf, including a leaf symlink, without following its holding folders."""
    _spelling, parts = _parse_name(name)
    try:
        with _rooted(os_, root, parts[:-1]) as dir_fd:
            os_.unlink(parts[-1], dir_fd=dir_fd)
    except FileNotFoundError:
        pass


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
        if not unnamed_files_unavailable(e):
            raise
    else:
        try:
            if _link_unnamed(fd, dir_fd, leaf, text, os_=os_):
                return
        finally:
            os_.close(fd)
    fd = os_.open(leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                  _FILE_MODE, dir_fd=dir_fd)
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
                      _FILE_MODE, dir_fd=dir_fd)
    except OSError as e:
        raise _mark_alias(e, is_alias=e.errno == errno.EEXIST) from None
    try:
        _write_all(fd, text, os_=os_)
        os_.rename(staged, leaf, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
    except BaseException:
        with contextlib.suppress(OSError):
            os_.unlink(staged, dir_fd=dir_fd)
        raise


# The held root (#1133): an `Episode`'s one open handle on its episode dir. Every verb works
# `*at` off it, so the dir is resolved once, at the door, and never again by name.


class Held:
    """A folder held open by descriptor (:func:`hold`, :func:`hold_new`), and the rooted verbs
    relative to it. Nothing below the held folder is followed; the folder itself is never
    re-resolved, so a rename carries the handle with it and a removal fails every write.

    Each verb works off a private `dup` of the root (`_Handle.dup`, which its views share): a
    verb after `close` is `OSError(EBADF)` and touches nothing. Reads are the view's: this
    handle writes. `open_unnamed` is the unnamed-open seam every `create` takes, as
    `rooted_write`'s is."""

    def __init__(self, os_: Any, fd: int, where: Path, *,
                 open_unnamed: Callable[[int], int]) -> None:
        self._os = os_
        self._open_unnamed = open_unnamed
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
                      mode=mode, durable=durable, open_unnamed=self._open_unnamed)

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


def hold(root: Path, *, os_: Any = os, follow: bool = True,
         open_unnamed: Callable[[int], int] = open_unnamed_at) -> Held:
    """Hold `root` open, following its spelling (the operator's, as :func:`bind`'s). A missing
    root is `FileNotFoundError`, a non-directory `NotADirectoryError`. `open_unnamed` is the
    unnamed-open seam the held root's creates take (`rooted_write(open_unnamed=)`'s).

    `follow=False` opens `root` itself no-follow and judges the descriptor as `_step` judges
    each folder below a root: a link at `root`, dangling or not, is `OSError(ELOOP)` (the
    linked-folder refusal), anything but a directory `NotADirectoryError`. Its ancestors are
    still followed, as host configuration. The runs repository holds a tenant's runs folder
    this way, so a link there is refused rather than listed (#1105 H1)."""
    if _O_PATH is None:  # pragma: no cover — no CI box lacks it
        raise OSError(errno.ENOTSUP, _PLATFORM_FAULT)
    root = Path(root)
    if follow:
        return Held(os_, os_.open(root, _ROOT_FLAGS), root, open_unnamed=open_unnamed)
    fd = os_.open(root, _STEP_FLAGS)
    try:
        st = os_.fstat(fd)
    except BaseException:
        os_.close(fd)
        raise
    if not stat.S_ISDIR(st.st_mode):
        os_.close(fd)
        if stat.S_ISLNK(st.st_mode):
            raise OSError(errno.ELOOP, _LINKED_FOLDER, str(root))
        raise NotADirectoryError(errno.ENOTDIR, _NOT_A_FOLDER, str(root))
    return Held(os_, fd, root, open_unnamed=open_unnamed)


def hold_new(parent: Path, name: str, *, os_: Any = os,
             open_unnamed: Callable[[int], int] = open_unnamed_at,
             exclusive: bool = False) -> Held:
    """Make (or adopt) the folder `name` in `parent` and hold it. `parent` is made if missing,
    following its spelling; `name` is judged off `parent`'s handle and never followed (a link,
    file or FIFO there is the core's folder refusal). The held descriptor is the one that
    judged it. `parent` is then fsynced, so the new folder's entry is durable. `open_unnamed`
    is the unnamed-open seam, as :func:`hold`'s.

    `exclusive` adopts nothing: any entry already at `name` (a folder, a link, anything) is
    `FileExistsError`, so of two callers racing for one name exactly one wins it."""
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
        if exclusive:
            os_.mkdir(name, dir_fd=parent_fd)  # lint-unguarded-tree-write: ok — the rooted mkdir, relative to a no-follow handle; EEXIST is the caller's answer
        fd = _step(os_, parent_fd, name, parent / name, create=True)
        try:
            _fsync_folder(os_, parent_fd)
        except BaseException:
            os_.close(fd)
            raise
    finally:
        os_.close(parent_fd)
    return Held(os_, fd, parent / name, open_unnamed=open_unnamed)


def move_at(held: Held, src: str | PurePath, dst: str | PurePath) -> None:
    """Rename the plain file `src` to `dst`, both below the held root, by `renameat` between the
    two holding folders' descriptors. A function beside `Held`, not a method: the handle's own
    surface is pinned to its verbs (#1133).

    Both folder chains are walked with no link followed (`dst`'s are made). Both leaves are
    judged by `_leaf_present`: the source must be a plain file (`FileNotFoundError` when absent),
    the destination absent or a plain file, which is replaced as `os.replace` does. A link, hard
    link, FIFO or folder at either is the core's refusal and is left in place. The judgement and
    the rename are two steps, with the swap caveat `_unlink_at` documents."""
    os_ = held._os
    _s_spelling, s_parts = _parse_name(src)
    _d_spelling, d_parts = _parse_name(dst)
    with held._dup() as root_fd, _descend(
            os_, root_fd, s_parts[:-1], held._where) as src_fd:
        if not _leaf_present(os_, src_fd, s_parts[-1], Path(held._where, *s_parts)):
            raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT),
                                    str(Path(held._where, *s_parts)))
        with _descend(os_, root_fd, d_parts[:-1], held._where, create=True) as dst_fd:
            _leaf_present(os_, dst_fd, d_parts[-1], Path(held._where, *d_parts))
            os_.rename(s_parts[-1], d_parts[-1], src_dir_fd=src_fd, dst_dir_fd=dst_fd)


def open_lock_at(held: Held, name: str | PurePath) -> IO[str]:
    """An open file at `name` below the held root, for `flock`: the holding folders walked and
    made with no link followed, the name judged by a no-follow stat (a link, hard link, FIFO or
    folder there is the core's refusal, before any open), then opened `O_RDWR|O_CREAT` through
    `_open_leaf` (no-follow, non-blocking, close-on-exec, the descriptor judged plain). Created
    `0644` (umask applied), never truncated. Timing stays in `_flock.take` / `release`; the
    caller closes the file."""
    os_ = held._os
    _spelling, parts = _parse_name(name)
    where = Path(held._where, *parts)
    with held._dup() as root_fd, _descend(
            os_, root_fd, parts[:-1], held._where, create=True) as dir_fd:
        _leaf_present(os_, dir_fd, parts[-1], where)
        fd = _open_leaf(os_, dir_fd, parts[-1], os.O_RDWR | os.O_CREAT, where)
    try:
        return os_.fdopen(fd, "a+", encoding="utf-8")
    except BaseException:
        os_.close(fd)
        raise
