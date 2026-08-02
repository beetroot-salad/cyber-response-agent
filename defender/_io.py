from __future__ import annotations

import contextlib
import errno
import fcntl
import json
import os
import secrets
import stat
import sys
from collections.abc import Callable
from pathlib import Path

TEXT_READ_ERRORS: tuple[type[Exception], ...] = (OSError, UnicodeDecodeError)
"""What reading a text file can raise: unreadable (``OSError``) or undecodable
(``UnicodeDecodeError``, a ``ValueError``).

Exported as one name because the *guard* half of the bug is not fixable by a reader function.
A caller whose whole response to a bad file is "skip it" can use :func:`read_text_soft` — but a
caller that reads AND parses under one ``try`` (``iter_lessons``, the curators' yaml loads, the
invlang companion walk) must still write its own ``except``, and that is precisely where the
next wrong tuple gets written. A pure read-skip is ``except TEXT_READ_ERRORS``; to add a parse
error, bind the composed tuple first — mypy rejects a star-unpack in an ``except`` display::

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


def use_utf8_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(encoding="utf-8", errors=getattr(stream, "errors", None) or "strict")


def read_jsonl_rows(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    rows: list[dict] = []
    text = path.read_text(encoding="utf-8", errors="replace")  # lint-jsonl-io: ok — the canonical tolerant reader  # noqa: E501
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        try:
            obj = json.loads(s)
        except json.JSONDecodeError:
            continue
        # A JSONL line is a ROW: `"x"`, `3` and `[...]` are all valid JSON and none of them
        # is one. Without this the declared `list[dict]` was a lie and every consumer's
        # `row.get(...)` raised AttributeError on the first such line — a class no drain
        # guard names, so it crashed the worker every tick, which is exactly the failure
        # the tolerant reader exists to prevent.
        if isinstance(obj, dict):
            rows.append(obj)
    return rows


def append_jsonl(path: Path, rows: list[dict]) -> int:
    if not rows:
        return 0
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")  # lint-jsonl-io: ok — the canonical JSONL appender
    return len(rows)


def write_atomic(path: Path, text: str) -> None:
    write_guarded(path, text, mode="replace")


# --------------------------------------------------------------------------- #
# #771 M3 — the alias-refusing write backstop.
#
# Every host-side write into a shared box tree routes through `write_guarded` (or
# `guarded_mkdir` for the directory-component half). A planted symlink or hard link at the
# write's target name is refused rather than followed: `replace` stages under an unpredictable
# name (D1) and only ever swaps the *staged* file into place, never opens the existing target
# for writing; `append`/`update` open the existing target with O_NOFOLLOW. `_refuse_unless_plain`
# is the shared precheck all three modes run first, and it is what keeps the refusal's exception
# TYPE uniform across "the target is a symlink", "the target is a hard-linked regular file" and
# "the target is a directory" — three causes a caller must not be able to tell apart from the
# exception class alone (F1's per-call-site posture parity depends on exactly one type here).
# `.write_guarded_alias` is a non-standard attribute this module sets on the raised OSError so a
# caller that DOES need to tell "aliased" apart from "ordinary occupied name" (D3's accounting
# exemption) can, without weakening that uniformity.
# --------------------------------------------------------------------------- #
def stage_name(path: Path) -> Path:
    """An unpredictable staged name in `path`'s own directory (§7 D1).

    Never the deterministic `<name>.tmp` B4 was planted at, and never repeats: our own staged
    names collide with nothing we ever wrote, so an occupied staged name is always hostile and
    `O_CREAT|O_EXCL` failing closed on it is unambiguous."""
    path = Path(path)
    return path.with_name(f"{path.name}.staged-{secrets.token_hex(8)}")


def _mark_alias(exc: OSError, *, is_alias: bool) -> OSError:
    exc.write_guarded_alias = is_alias  # type: ignore[attr-defined]
    return exc


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
    is_hardlink = stat.S_ISREG(st.st_mode) and st.st_nlink > 1
    is_alias = stat.S_ISLNK(st.st_mode) or is_hardlink
    if is_alias or not stat.S_ISREG(st.st_mode):
        # D1: the refusal LEAVES the planted entry in place, symlink or hard link alike —
        # removal is sanitizing, and an entry the writer deletes is one the reap scan can
        # never report (pinned explicitly for the hard-link shape by
        # test_a_planted_hard_link_still_refuses_the_guarded_write).
        # ELOOP for everything except a hard link (B9: `O_NOFOLLOW` never fires for one — the
        # open would SUCCEED — so ELOOP here would claim a refusal reason a hard-link plant
        # cannot produce). EMLINK for a hard link instead: neither errno has a dedicated
        # `OSError` subclass, so both still raise the same TYPE (plain `OSError`) — the thing
        # `posture_class` compares — while the errno itself stays an honest description of
        # which shape was refused.
        refusal_errno = errno.EMLINK if is_hardlink else errno.ELOOP
        raise _mark_alias(
            OSError(refusal_errno, "refusing to write through a non-plain or aliased entry",
                     str(path)),
            is_alias=is_alias,
        )


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
    seam (pinned by `test_atomic_write_refuses_a_planted_temp_name`); `**kw` is unused and
    absorbs a caller supplying a mode-irrelevant keyword rather than raising `TypeError` on it."""
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
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o644)
        if isinstance(text, (bytes, bytearray)):
            with os.fdopen(fd, "ab") as fb:
                fb.write(text)
        else:
            with os.fdopen(fd, "a", encoding="utf-8") as f:
                f.write(text)
    elif mode == "update":
        _refuse_unless_plain(path)
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o644)
        if isinstance(text, (bytes, bytearray)):
            with os.fdopen(fd, "r+b") as fb:
                fcntl.flock(fb, fcntl.LOCK_EX)
                fb.seek(0)
                fb.truncate()
                fb.write(text)
        else:
            with os.fdopen(fd, "r+", encoding="utf-8") as f:
                fcntl.flock(f, fcntl.LOCK_EX)
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
    flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | (os.O_APPEND if mode == "a" else os.O_TRUNC)
    fd = os.open(path, flags, 0o644)
    return os.fdopen(fd, mode, encoding="utf-8")


def _ensure_dir_component(component: Path) -> None:
    try:
        st = os.lstat(component)
    except FileNotFoundError:
        with contextlib.suppress(FileExistsError):
            os.mkdir(component)
        return
    if stat.S_ISLNK(st.st_mode):
        raise OSError(
            errno.ELOOP, "refusing to create through a symlinked path component", str(component)
        )
    if not stat.S_ISDIR(st.st_mode):
        raise NotADirectoryError(
            errno.ENOTDIR, "path component is not a directory", str(component)
        )


def guarded_mkdir(path: Path) -> None:
    """`mkdir(parents=True, exist_ok=True)`, refusing a symlinked component at ANY depth (B8:
    `O_NOFOLLOW` on the leaf alone does not protect a swapped component; B10:
    `mkdir(parents=True, exist_ok=True)` over one succeeds silently). Depth-agnostic: every
    component from the root down is checked, not only the last one created."""
    path = Path(path)
    parts = path.parts
    if not parts:
        return
    accum = Path(parts[0])
    _ensure_dir_component(accum)
    for part in parts[1:]:
        accum = accum / part
        _ensure_dir_component(accum)


def sweep_staged(tree: Path) -> list[Path]:
    """Remove every orphaned staged file under `tree` (§7 D1's accepted cost: unpredictable
    staged names mean no later write ever replaces a crash-orphaned one by name, so orphans
    accumulate and need a sweep). `os.walk(..., followlinks=False)` never descends into a
    symlinked directory, and removing a symlink entry never touches what it points at — so a
    staged NAME planted as an alias is removed as an entry, never followed."""
    tree = Path(tree)
    removed: list[Path] = []
    for dirpath, _dirs, files in os.walk(tree, followlinks=False):
        for name in files:
            if ".staged-" in name:
                p = Path(dirpath) / name
                with contextlib.suppress(OSError):
                    os.remove(p)
                    removed.append(p)
    return removed
