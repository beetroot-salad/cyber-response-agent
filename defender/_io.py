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
from pathlib import Path
from typing import Any

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
    path.parent.mkdir(parents=True, exist_ok=True)  # lint-unguarded-tree-write: ok — the pre-#771 primitive itself; its own callers are what the gate flags  # noqa: E501
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
    `hooks/_run_dir.update_json_locked` — and before this they each carried their own copy of
    it, only one of which ran in production. A change to the refusal contract then had to be
    made twice, with the dead copy the one the spec covered."""
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
    seam (pinned by `test_atomic_write_refuses_a_planted_temp_name`); `**kw` is unused and
    absorbs a caller supplying a mode-irrelevant keyword (`encoding`, which every mode already
    pins to utf-8) rather than raising `TypeError` on it. It absorbs NOTHING ELSE: a swallowed
    unknown keyword is how a misspelt `mode=` (`moode="append"`) silently falls back to
    `replace` and TRUNCATES the file the caller meant to append to."""
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
    refuses on any symlinked ANCESTOR, which is a configuration the host chose and the box
    cannot influence — and those are common: `/tmp` is itself a symlink on macOS, which is
    where the default runs base lives, and a symlinked `/data` or `/var/run` does the same on
    Linux. The refusal then lands on every mkdir in the process: the session store cannot be
    created, so no run starts at all, and the three sidecar persistence paths degrade to
    permanent silent no-ops. Anchoring costs no coverage, because the region it stops checking
    is the region the box cannot reach.

    Depth-agnosticism (firm consensus #13) is preserved WITHIN the tree: every component from
    `base` down is checked, at any depth, not only the last one created. `base` is required
    keyword-only rather than defaulted so that a new call site has to name the tree it trusts —
    a default would silently re-adopt whichever anchor happened to be convenient, which is how
    the walk reached `/` to begin with. Containment is judged LEXICALLY: `resolve()` here would
    collapse the very symlink the walk exists to refuse."""
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
    # Short-circuited, not unconditional: this runs on the per-tool-call hot path (every
    # model-facing write/edit, every captured query payload), and the tree root is created
    # before any box starts — so the syscall is pure overhead in every case but the first.
    # `is_dir()` follows symlinks deliberately: `base` and everything above it are
    # host-controlled (see above), and a host-chosen symlinked runs base is the configuration
    # the anchor exists to keep working.
    if not base.is_dir():
        os.makedirs(base, exist_ok=True)
    accum = base
    for part in rest.parts:
        accum = accum / part
        _ensure_dir_component(accum)


#: The staged NAME CLASS, matched loosely on purpose — deliberately NOT the exact
#: `<name>.staged-<16 hex>` shape `stage_name` mints. The sweep's obligation is not only to
#: collect our own crash-orphans: it also has to remove an entry an attacker planted at a
#: staged-looking name (`test_orphaned_staged_files_are_swept_through_the_same_primitive` plants
#: `report.md.staged-hostile` as a symlink and requires it gone), and a plant by construction
#: carries no hex of ours. The cost is that a legitimate artifact whose name contains this
#: literal would be swept — accepted, because `.staged-` is a suffix namespace this module owns
#: and nothing else in any tree writes into it.
_STAGED_MARKER = ".staged-"


def sweep_staged(tree: Path) -> list[Path]:
    """Remove every orphaned staged file under `tree` (§7 D1's accepted cost: unpredictable
    staged names mean no later write ever replaces a crash-orphaned one by name, so orphans
    accumulate and need a sweep). `os.walk(..., followlinks=False)` never descends into a
    symlinked directory, and removing a symlink entry never touches what it points at — so a
    staged NAME planted as an alias is removed as an entry, never followed.

    Called from `box.stop_and_scrub` — AFTER the reap scan has judged the tree, never before.
    Sweeping first would delete entries the scan exists to report, which is the sanitizing move
    the design refuses everywhere else; sweeping after costs nothing, because the scan permits
    any regular file and an orphaned staged file is one."""
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
