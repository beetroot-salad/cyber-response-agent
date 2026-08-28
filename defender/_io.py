from __future__ import annotations

import contextlib
import errno
import fcntl
import json
import os
import secrets
import stat
import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

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


def use_utf8_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(encoding="utf-8", errors=getattr(stream, "errors", None) or "strict")


def parse_jsonl_row(line: str) -> dict | None:
    """One physical line as a JSONL ROW, or ``None`` if it is not one.

    THE definition of what counts as a row, published rather than kept inside
    :func:`read_jsonl_rows`, because a second reader must agree with it exactly:
    ``challenge_gate._write_trace_row`` decides whether a stage's framed reply may stand as its
    own physical line, which is only safe while "a line every reader skips" is the SAME
    predicate the reader applies.

    A row is a line that parses AND parses to a dict: ``"x"``, ``3`` and ``[...]`` are all
    valid JSON and none of them is one. Without that half the declared ``list[dict]`` is a lie
    and every consumer's ``row.get(...)`` raises ``AttributeError`` — a class no drain guard
    names, so it crashes the worker every tick.
    """
    s = line.strip()
    if not s:
        return None
    try:
        obj = json.loads(s)
    except ValueError:
        # `JSONDecodeError` IS a `ValueError`; the broader guard costs nothing and spares the
        # two callers from agreeing on which to name.
        return None
    return obj if isinstance(obj, dict) else None


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


# --------------------------------------------------------------------------- #
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
# --------------------------------------------------------------------------- #
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


def plain_unaliased_file(path: Path) -> bool:
    """True iff `path` is a present, plain, SINGLE-LINKED regular file.

    The predicate half of `_refuse_unless_plain`, split out so a READER can ask the same
    question the write seam answers. `_run_paths.artifact_file` is the weaker screen — it is an
    `S_ISREG` lstat, so it accepts a hard link, the one alias shape `O_NOFOLLOW` cannot refuse
    (B9) — and a reader that pairs itself with a `write_guarded` write needs THIS one, or the
    two guards admit different sets while a comment claims they are twins.

    Note the asymmetry with the refusal below, and it is deliberate: ABSENT is plain enough to
    write (that is the ordinary case) and is not a file to read, so this answers False where
    `_refuse_unless_plain` returns without raising."""
    try:
        st = os.lstat(path)
    except (OSError, ValueError):
        # Fails closed, like `_run_paths._lstat_is`: an entry the caller cannot judge is not
        # one it may read through.
        return False
    return stat.S_ISREG(st.st_mode) and st.st_nlink == 1


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
