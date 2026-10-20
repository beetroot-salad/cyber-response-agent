"""Shared machinery for #1133's Episode-handle spec, rev 3. It defines NO tests."""
from __future__ import annotations

from defender.tests.support.shared._fixture_uuid import fixture_uuid

import dataclasses
import errno
import fcntl
import importlib
import inspect
import logging
import os
import shutil
import stat
import threading
from collections.abc import Callable
from pathlib import Path, PurePosixPath
from typing import Any

from defender import _io
from defender.episodes._episode_paths import LAYOUT
from defender.run_repository import WIRE_LOG_NAMES
from defender.tests.shared.filesystem.test_1111_rooted_io import (  # noqa: F401 — re-exported for the #1133 suite
    DEADLINE,
    HOST_BYTES,
    O6_ROWS,
    PassThroughOs,
    census,
    in_time,
    raised_by,
)

HANDLE_MODULE = "defender.episodes._episode_handle"

#: The world, token, wire-log name and draw index the composing records are addressed with.
WORLD_ID = fixture_uuid("world:1133:b")
WIRE_NAME = WIRE_LOG_NAMES.agent_framed_trace(f"judge:{WORLD_ID}:0")
DRAW_N = 0

#: D1's record table (kept by D2'), row for row: address -> the verbs that row grants. Rev 3
#: (R1): records are write-only, so `family` and `review` lose `read`; reading a record is the
#: view's `read(LAYOUT.<record>)`.
RECORD_VERBS: dict[str, tuple[str, ...]] = {
    "family": ("create",),
    "family_stamp": ("write",),
    "review": ("write",),
    "samples": ("write",),
    "judge": ("write",),
    "timing": ("write",),
    "learning_html": ("write",),
    "served_base": ("create",),
    "served_world": ("append",),
    "priming_lock": ("create", "delete"),
    "wire_log": ("write",),
    "world.draw": ("write", "delete"),
    "family_draw": ("write", "delete"),
    # #1187 R8 (declared change 12): the archive pointer `world.run_dir_pointer` is retired with
    # its write — nothing reads it, and the arm roster supersedes it — so the row is gone.
    # #1224: the episode outcome and each world's own record, both created once.
    "world_record": ("create",),
    "outcome": ("create",),
    # PR #1232 round 7: why `verify_family` withheld the family stamp, replaced like the stamp.
    "not_comparable": ("write",),
    # #1255 D6 (owner decision, 2026-10-16): the primer's skip record — the source's pre-fork
    # calls that left no recording (the call failed, the payload was unreadable) — created
    # once beside the capture.
    "served_unrecorded": ("create",),
}

#: D1's folders (kept by D2'): `served`, `runs`, `worlds`, `world(label).dir`,
#: `world(label).draws`. `runs` is the handle's PRIVATE `_runs` since #1105 PR 2 (F-13): the
#: container and its arms are the runs repository's episode view, built on this handle, and
#: the one public hand-out of its path is `box_mounted_container` (`PRIVATE_FOLDERS`).
FOLDERS: tuple[str, ...] = ("served", "runs", "worlds", "world.dir", "world.draws", "family_draws")
#: The folders the handle serves under a private attribute (the key's name, `_`-prefixed).
PRIVATE_FOLDERS: tuple[str, ...] = ("runs",)

#: Every verb name a record could answer. `read` stays listed although rev 3 grants it to no
#: record, so the class and surface pins check its ABSENCE on every record. (#1224 removed the
#: last record granting `append_durable`, the staging record, and the verb with it.)
ALL_VERBS = ("read", "write", "create", "append", "delete")

#: The write verbs, and the `Held.write` mode each is (D2': one `held.write` per write verb).
WRITE_MODE = {"write": "replace", "create": "create", "append": "append"}

#: The components each composing record is addressed with.
RECORD_ARGS: dict[str, tuple[Any, ...]] = {
    "family_draw": (DRAW_N,),
    "served_world": (WORLD_ID,),
    "wire_log": (WIRE_NAME,),
    "world.draw": (DRAW_N,),
    "world_record": (WORLD_ID,),
}


# ---------------------------------------------------------------------------------------
# Lazy access to the rev-2 names
# ---------------------------------------------------------------------------------------

def handle() -> Any:
    """`defender.episodes._episode_handle`, imported per call."""
    return importlib.import_module(HANDLE_MODULE)


def Episode() -> Any:  # noqa: N802 — names the class it hands back
    """The `Episode` class, looked up per call."""
    return handle().Episode


def open_episode(episode_dir: Path, io: Any = _io) -> Any:
    """`Episode.open(episode_dir, io=io)`."""
    return Episode().open(Path(episode_dir), io=io)


def create_episode(episode_dir: Path, io: Any = _io) -> Any:
    """`Episode.create(episode_dir, io=io)`."""
    return Episode().create(Path(episode_dir), io=io)


def hold(root: Path, **kw: Any) -> Any:
    """`_io.hold(root, **kw)`, resolved at call time so a missing core fails the calling test."""
    return _io.hold(root, **kw)  # type: ignore[attr-defined]


def hold_new(parent: Path, name: str, **kw: Any) -> Any:
    return _io.hold_new(parent, name, **kw)  # type: ignore[attr-defined]


def mod(dotted: str) -> Any:
    return importlib.import_module(f"defender.{dotted}")


# ---------------------------------------------------------------------------------------
# Addresses
# ---------------------------------------------------------------------------------------

def expected_record_rel(key: str) -> PurePosixPath:
    """The record's name relative to the episode dir, from `_episode_paths.LAYOUT` (the only
    place names are spelled)."""
    world = LAYOUT.world(WORLD_ID)
    return {
        "family": lambda: LAYOUT.family,
        "family_stamp": lambda: LAYOUT.family_stamp,
        "review": lambda: LAYOUT.review,
        "samples": lambda: LAYOUT.samples,
        "judge": lambda: LAYOUT.judge,
        "timing": lambda: LAYOUT.timing,
        "learning_html": lambda: LAYOUT.learning_html,
        "served_base": lambda: LAYOUT.served_base,
        "served_world": lambda: LAYOUT.served_world(WORLD_ID),
        "priming_lock": lambda: LAYOUT.priming_lock,
        "wire_log": lambda: LAYOUT.wire_log(WIRE_NAME),
        "world.draw": lambda: world.draw(DRAW_N),
        "family_draw": lambda: LAYOUT.family_draw(DRAW_N),
        "world_record": lambda: LAYOUT.world_record(WORLD_ID),
        "outcome": lambda: LAYOUT.outcome,
        "not_comparable": lambda: LAYOUT.not_comparable,
        "served_unrecorded": lambda: LAYOUT.served_unrecorded,
    }[key]()


def expected_folder_rel(key: str) -> PurePosixPath:
    world = LAYOUT.world(WORLD_ID)
    return {
        "served": LAYOUT.served, "runs": LAYOUT.runs, "worlds": LAYOUT.worlds,
        "world.dir": world.dir, "world.draws": world.draws,
        "family_draws": LAYOUT.family_draws,
    }[key]


def resolve(episode: Any, key: str) -> Any:
    """The record or folder at `key` on `episode` (the address grammar in the docstring)."""
    head, dot, rest = key.partition(".")
    owner, attr = (episode.world(WORLD_ID), rest) if (head == "world" and dot) else (episode, key)
    if owner is episode and attr in PRIVATE_FOLDERS:
        attr = f"_{attr}"
    got = getattr(owner, attr)
    if inspect.ismethod(got) or inspect.isfunction(got):
        return got(*RECORD_ARGS[key])
    return got


def holding_folders(rel: PurePosixPath) -> tuple[PurePosixPath, ...]:
    """Every folder strictly between the episode dir and `rel`, outermost first."""
    return tuple(reversed(rel.parents[:-1]))


def folder_and_parents(rel: PurePosixPath) -> tuple[PurePosixPath, ...]:
    """`rel` and every folder above it below the episode dir, outermost first."""
    return (*holding_folders(rel), rel)


def as_rel(name: Any) -> PurePosixPath:
    """A name as a `Held` verb received it (a `str` or a `PurePath`), normalised."""
    return PurePosixPath(Path(name).as_posix() if isinstance(name, os.PathLike) else str(name))


# ---------------------------------------------------------------------------------------
# Plants: every one a real filesystem entry
# ---------------------------------------------------------------------------------------

#: What a plant can put AT a record's name. `dangling` is a symlink whose target does not
#: exist, so a write that followed it would CREATE a file outside the episode.
LEAF_PLANTS = ("symlink", "dangling", "hardlink", "fifo", "directory")
#: What a plant can put at a holding folder (or, for a folder, at the folder itself).
FOLDER_PLANTS = ("folder_link_outside", "folder_link_inside", "folder_file", "folder_fifo")

#: What an owner's name check or the core's name grammar says.
NAME_REFUSAL = (r"not a valid path component|not a valid world id|not a non-negative integer|is not case-stable|"
                r"not a valid relative name")
#: What the core's refusals say: a non-plain or aliased leaf, a symlinked folder, a
#: non-directory folder.
CORE_REFUSAL = r"aliased|symlinked|not a directory"

#: The core's fault table for each plant (`test_1111_rooted_io.O6_ROWS`): exception type,
#: errno, and whether it carries the alias mark. A dangling link is a symlink.
ROWS = {**O6_ROWS, "dangling": O6_ROWS["symlink"]}

#: The plants that sit at a FOLDER on the way (or at a folder's own name): the walk's refusal, a
#: plain `OSError(ELOOP)` or `NotADirectoryError`, never the leaf class (R2). Every other row of
#: `ROWS` is a plant AT the name: the core's leaf refusal, `_io.NotPlainEntry`.
FOLDER_ROWS = frozenset({"folder_link_inside", "folder_link_outside", "folder_file",
                         "folder_fifo"})


def not_plain_entry() -> type[OSError]:
    """`_io.NotPlainEntry` (rev 3, R2), looked up per call: its absence fails the calling test,
    never the suite's collection."""
    cls = getattr(_io, "NotPlainEntry", None)
    assert isinstance(cls, type), (
        "defender._io has no `NotPlainEntry` — rev 3 (R2) gives the core's refusal of a "
        "non-plain entry at a name its own exception class")
    assert issubclass(cls, OSError), "`_io.NotPlainEntry` is not an OSError"
    return cls


def assert_refusal(exc: BaseException | None, kind: str, *, where: str) -> None:
    """`exc` is the core's refusal row for a `kind` plant: its type, its errno and its alias
    mark (`write_guarded_alias`; absent and False are both unmarked). Rev 3 (R2): a plant AT the
    name is the leaf class `_io.NotPlainEntry`; a plant at a folder on the way is not."""
    typ, code, marked = ROWS[kind]
    assert exc is not None, f"{where}: a {kind} plant was not refused"
    want = f"the core's {typ.__name__} {errno.errorcode[code]}"
    assert isinstance(exc, typ), f"{where}: a {kind} plant raised {exc!r}, not {want}"
    assert getattr(exc, "errno", None) == code, f"{where}: a {kind} plant raised {exc!r}, not {want}"
    assert bool(getattr(exc, "write_guarded_alias", False)) is marked, (
        f"{where}: a {kind} plant's refusal is {'un' if marked else ''}marked as an alias; the "
        f"core's table says {'marked' if marked else 'unmarked'}")
    if kind in FOLDER_ROWS:
        leaf = getattr(_io, "NotPlainEntry", None)
        if isinstance(leaf, type):
            assert not isinstance(exc, leaf), (
                f"{where}: a {kind} plant is a folder on the way, but its refusal is the leaf "
                f"class NotPlainEntry ({exc!r}) — a containment keyed on the class would read a "
                "linked folder as a planted leaf")
    else:
        assert isinstance(exc, not_plain_entry()), (
            f"{where}: a {kind} plant at the name raised {exc!r}, not the core's leaf refusal "
            "`_io.NotPlainEntry`")


def refusal_in(exc: BaseException | None) -> OSError | None:
    """The first `OSError` carrying an errno in `exc`'s cause chain, or `None`."""
    seen: set[int] = set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        if isinstance(exc, OSError) and exc.errno is not None:
            return exc
        exc = exc.__cause__ or exc.__context__
    return None


@dataclasses.dataclass(frozen=True)
class Planted:
    kind: str
    at: Path

    @property
    def fifo(self) -> Path | None:
        return self.at if self.kind in ("fifo", "folder_fifo") else None

    def remove(self) -> None:
        if self.at.is_symlink() or not self.at.is_dir():
            self.at.unlink()
        else:
            shutil.rmtree(self.at)


def plant_leaf(record: Path, kind: str, *, host: Path, body: bytes = HOST_BYTES) -> Planted:
    """Plant `kind` at the record's own name; its holding folders are made real first."""
    record.parent.mkdir(parents=True, exist_ok=True)
    if kind == "symlink":
        target = host / f"link-target-of-{record.name}"
        target.write_bytes(body)
        record.symlink_to(target)
    elif kind == "dangling":
        record.symlink_to(host / f"dangling-target-of-{record.name}")
    elif kind == "hardlink":
        other = host / f"other-name-of-{record.name}"
        other.write_bytes(body)
        os.link(other, record)
    elif kind == "fifo":
        os.mkfifo(record)
    elif kind == "directory":
        record.mkdir()
        (record / "keep").write_bytes(body)
    else:
        raise AssertionError(kind)
    return Planted(kind, record)


def plant_folder(root: Path, rel: PurePosixPath, at: PurePosixPath, kind: str, *, host: Path,
                 body: bytes = HOST_BYTES) -> Planted:
    """Plant `kind` at `at`, `rel` itself or one of its holding folders; the folders above `at`
    are made real. A link points at a real folder that already holds the rest of `rel` (the
    record's bytes, or a `keep` file when `at` is `rel`), so a walk that followed it would find
    something real there, and a write through it would visibly change that folder."""
    where = root / at
    where.parent.mkdir(parents=True, exist_ok=True)
    if kind == "folder_file":
        where.write_bytes(body)
        return Planted(kind, where)
    if kind == "folder_fifo":
        os.mkfifo(where)
        return Planted(kind, where)
    base = host if kind == "folder_link_outside" else root
    elsewhere = base / f"elsewhere-{'-'.join(at.parts)}"
    elsewhere.mkdir(parents=True, exist_ok=True)
    rest = PurePosixPath(*rel.parts[len(at.parts):])
    if rest.parts:
        reached = elsewhere / rest
        reached.parent.mkdir(parents=True, exist_ok=True)
        reached.write_bytes(body)
    else:
        (elsewhere / "keep").write_bytes(body)
    where.symlink_to(elsewhere, target_is_directory=True)
    return Planted(kind, where)


def plant(root: Path, rel: PurePosixPath, site: PurePosixPath | None, kind: str, *,
          host: Path) -> Planted:
    if site is None:
        return plant_leaf(root / rel, kind, host=host)
    return plant_folder(root, rel, site, kind, host=host)


def open_fds_on(path: Path) -> list[int]:
    """This process's open descriptors that refer to `path`'s inode (Linux `/proc`)."""
    want = os.lstat(path)
    out = []
    for name in os.listdir("/proc/self/fd"):
        try:
            st = os.stat(f"/proc/self/fd/{name}")
        except OSError:
            continue
        if (st.st_dev, st.st_ino) == (want.st_dev, want.st_ino):
            out.append(int(name))
    return sorted(out)


def public_names(obj: Any) -> set[str]:
    """Every name `obj` answers that does not start with `_` (`dir`, so inherited ones too)."""
    return {n for n in dir(obj) if not n.startswith("_")}


def warned(caplog: Any, *needles: str) -> list[str]:
    """Messages logged at WARNING or above that mention any of `needles`."""
    return [r.getMessage() for r in caplog.records
            if r.levelno >= logging.WARNING and any(n in r.getMessage() for n in needles)]


# ---------------------------------------------------------------------------------------
# The io= seam: a recording stand-in for `_io` that offers only `hold` / `hold_new`
# ---------------------------------------------------------------------------------------

@dataclasses.dataclass
class HeldCall:
    """One call a `RecordingHeld` saw: the method, and its arguments as passed."""

    method: str
    args: tuple[Any, ...]
    kwargs: dict[str, Any]

    @property
    def name(self) -> PurePosixPath:
        """The first argument (the record or folder name) normalised, however it was passed."""
        if self.args:
            return as_rel(self.args[0])
        for key in ("name", "folder"):
            if key in self.kwargs:
                return as_rel(self.kwargs[key])
        raise AssertionError(f"{self.method} was called with no name: {self.kwargs}")

    @property
    def text(self) -> Any:
        """A `write`'s payload, however it was passed."""
        return self.args[1] if len(self.args) > 1 else self.kwargs.get("text")


#: `(method, args, kwargs) -> None`, run before a `RecordingHeld` delegates: a plant, a raise.
Before = Callable[[str, tuple[Any, ...], dict[str, Any]], None]


class RecordingHeld:
    """A pass-through over a real `Held`: every verb and lifetime call is recorded, then
    `before(...)` (if given) runs, then the real `Held` answers."""

    def __init__(self, inner: Any, *, before: Before | None = None) -> None:
        self._inner = inner
        self._before = before
        self.calls: list[HeldCall] = []

    def _call(self, method: str, *args: Any, **kwargs: Any) -> Any:
        self.calls.append(HeldCall(method, args, dict(kwargs)))
        if self._before is not None:
            self._before(method, args, kwargs)
        return getattr(self._inner, method)(*args, **kwargs)

    # No `read`: rev 3's `Held` has none, so a handle that reaches for it shows up in `calls` as
    # `getattr:read` and fails on the real `Held`.

    def write(self, *args: Any, **kwargs: Any) -> Any:
        return self._call("write", *args, **kwargs)

    def mkdir(self, *args: Any, **kwargs: Any) -> Any:
        return self._call("mkdir", *args, **kwargs)

    def unlink(self, *args: Any, **kwargs: Any) -> Any:
        return self._call("unlink", *args, **kwargs)

    def view(self, *args: Any, **kwargs: Any) -> Any:
        return self._call("view", *args, **kwargs)

    def close(self, *args: Any, **kwargs: Any) -> Any:
        return self._call("close", *args, **kwargs)

    def __enter__(self) -> RecordingHeld:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def __getattr__(self, name: str) -> Any:
        # Anything else the handle reaches for on its `Held` is recorded too, so an unexpected
        # use shows up in `calls` rather than passing silently.
        self.calls.append(HeldCall(f"getattr:{name}", (), {}))
        return getattr(self._inner, name)


class RecordingIo:
    """The handle's `io=` seam, offering ONLY `hold` and `hold_new` (D2'): an `Episode` that
    reaches for anything else (`rooted_write`, `bind`, ...) fails with `AttributeError`. Each
    call is recorded and answered by the real core (with `os_` when given), wrapped in a
    `RecordingHeld`."""

    def __init__(self, *, os_: Any = None, before: Before | None = None) -> None:
        self.os_ = os_
        self.before = before
        self.opened: list[tuple[str, tuple[Any, ...]]] = []
        self.helds: list[RecordingHeld] = []

    def _kw(self) -> dict[str, Any]:
        return {} if self.os_ is None else {"os_": self.os_}

    def hold(self, root: Path, **kw: Any) -> RecordingHeld:
        self.opened.append(("hold", (Path(root),)))
        held = RecordingHeld(hold(Path(root), **{**self._kw(), **kw}), before=self.before)
        self.helds.append(held)
        return held

    def hold_new(self, parent: Path, name: str, **kw: Any) -> RecordingHeld:
        self.opened.append(("hold_new", (Path(parent), str(name))))
        held = RecordingHeld(hold_new(Path(parent), str(name), **{**self._kw(), **kw}),
                             before=self.before)
        self.helds.append(held)
        return held

    @property
    def calls(self) -> list[HeldCall]:
        """Every call on every `Held` this seam handed out, in order."""
        return [c for h in self.helds for c in h.calls]


# ---------------------------------------------------------------------------------------
# The os_= seam: a spy over the real `os`
# ---------------------------------------------------------------------------------------

def fd_flags(fd: int) -> int:
    return fcntl.fcntl(fd, fcntl.F_GETFL)


def fd_cloexec(fd: int) -> bool:
    return bool(fcntl.fcntl(fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC)


O_PATH = getattr(os, "O_PATH", 0)


@dataclasses.dataclass
class Opened:
    """One `os_.open` the spy saw: what was asked, and what came back (or the errno)."""

    path: str
    flags: int
    dir_fd: int | None
    fd: int | None
    errno: int | None
    cloexec: bool | None


@dataclasses.dataclass
class Synced:
    """One `os_.fsync`: the descriptor's inode and kind at that moment, its open flags (as the
    spy saw them passed, when it saw the open), `F_GETFL`, and what the watched file held then
    (`None` when this descriptor is not the watched file)."""

    fd: int
    ino: tuple[int, int]
    is_dir: bool
    open_flags: int | None
    getfl: int
    watched_bytes: bytes | None


class OsSpy(PassThroughOs):
    """The real `os`, handed in as `os_`: records every `open` (its flags, its `dir_fd`, the
    descriptor it returned and whether that descriptor is `FD_CLOEXEC`), every `fsync`, `mkdir`,
    `close`, `dup` and `unlink`. `hook(op, args, kwargs)` runs before a relative (`dir_fd=`)
    `open` / `stat` / `mkdir` / `unlink` is delegated; `after_open(path, dir_fd, fd)` after a
    successful `open` returns; `before_dup(fd)` once, just before the next `dup(fd)` is
    delegated (then it is cleared)."""

    def __init__(self, *, watch: Path | None = None) -> None:
        self.watch = watch
        self.opens: list[Opened] = []
        self.fsyncs: list[Synced] = []
        self.mkdirs: list[str] = []
        self.closes: list[int] = []
        self.dups: list[int] = []
        self.unlinks: list[str] = []
        self.hook: Callable[[str, tuple[Any, ...], dict[str, Any]], None] | None = None
        #: `(path, dir_fd, fd)`, run after a successful `open` returns (before the caller sees it).
        self.after_open: Callable[[str, int | None, int], None] | None = None
        #: `(fd)`, run once just before the next `dup(fd)` is delegated, then cleared.
        self.before_dup: Callable[[int], None] | None = None
        self._flags: dict[int, int] = {}

    def _relative(self, op: str, args: tuple[Any, ...], kwargs: dict[str, Any]) -> None:
        if kwargs.get("dir_fd") is not None and self.hook is not None:
            self.hook(op, args, kwargs)

    def open(self, path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        self._relative("open", (path, flags, *args), kwargs)
        try:
            fd = os.open(path, flags, *args, **kwargs)
        except OSError as e:
            self.opens.append(Opened(str(path), flags, kwargs.get("dir_fd"), None, e.errno, None))
            raise
        self._flags[fd] = flags
        self.opens.append(Opened(str(path), flags, kwargs.get("dir_fd"), fd, None,
                                 fd_cloexec(fd)))
        if self.after_open is not None:
            self.after_open(str(path), kwargs.get("dir_fd"), fd)
        return fd

    def stat(self, path: Any, *args: Any, **kwargs: Any) -> Any:
        self._relative("stat", (path, *args), kwargs)
        return os.stat(path, *args, **kwargs)

    def mkdir(self, path: Any, *args: Any, **kwargs: Any) -> None:
        self._relative("mkdir", (path, *args), kwargs)
        self.mkdirs.append(str(path))
        os.mkdir(path, *args, **kwargs)

    def unlink(self, path: Any, *args: Any, **kwargs: Any) -> None:
        self._relative("unlink", (path, *args), kwargs)
        self.unlinks.append(str(path))
        os.unlink(path, *args, **kwargs)

    def dup(self, fd: int) -> int:
        if self.before_dup is not None:
            hook, self.before_dup = self.before_dup, None
            hook(fd)
        new = os.dup(fd)
        self.dups.append(new)
        return new

    def close(self, fd: int) -> None:
        self._flags.pop(fd, None)
        self.closes.append(fd)
        os.close(fd)

    def fsync(self, fd: int) -> None:
        st = os.fstat(fd)
        ino = (st.st_dev, st.st_ino)
        watched = None
        if self.watch is not None and os.path.lexists(self.watch) and inode(self.watch) == ino:
            watched = self.watch.read_bytes()
        self.fsyncs.append(Synced(fd, ino, stat.S_ISDIR(st.st_mode), self._flags.get(fd),
                                  fd_flags(fd), watched))
        os.fsync(fd)


def inode(path: Path) -> tuple[int, int]:
    st = os.lstat(path)
    return st.st_dev, st.st_ino


def run_in_thread(fn: Callable[[], Any], *, timeout: float = DEADLINE) -> bool:
    """Run `fn` on another thread; True when it returned within `timeout`."""
    worker = threading.Thread(target=fn, daemon=True)
    worker.start()
    worker.join(timeout)
    return not worker.is_alive()


def held_verb(held: Any, verb: str, name: Any, payload: str | bytes = "held row\n") -> Any:
    """One `Held` verb by the name the suite parametrizes over: the write modes (`create`,
    `replace`, `append`, `durable_append`), `mkdir`, `unlink`. (Rev 3 has no `Held.read`; a
    read is the view's.)"""
    if verb == "durable_append":
        return held.write(name, payload, mode="append", durable=True)
    if verb in ("create", "replace", "append"):
        return held.write(name, payload, mode=verb)
    if verb == "mkdir":
        return held.mkdir(name)
    if verb == "unlink":
        return held.unlink(name)
    raise AssertionError(verb)


#: `Held`'s whole public surface in rev 3 (R1: no `read`).
HELD_SURFACE = frozenset({"write", "mkdir", "unlink", "view", "close"})
#: The view's (`Bound`'s) whole public surface (O3).
VIEW_SURFACE = frozenset({"read", "read_bytes", "read_jsonl", "entries", "under", "close"})
