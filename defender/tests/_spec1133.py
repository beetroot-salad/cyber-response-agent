"""Shared machinery for #1133's Episode-handle spec, rev 2. It defines NO tests.

The contract is issue #1133's intent+design doc as amended by rev 2 (O2, O3 replaced, O4.1-O4.8,
O5, O6, N-a..N-h, D1'-D7', S1-S5). The implementation must expose exactly these names; every
test in the ``test_1133_*`` suite reaches them lazily, per test, so a missing one fails its own
tests and never a whole file at collection.

Core, ``defender._io`` (D1'):

* ``hold(root: Path, *, os_=os) -> Held`` -- opens ``root`` following its spelling; a missing
  root is ``FileNotFoundError``, a non-directory ``NotADirectoryError``;
* ``hold_new(parent: Path, name: str, *, os_=os) -> Held`` -- makes ``parent`` if missing
  (following its spelling), makes or adopts ``name`` off the parent's handle without following
  it (a link, file or FIFO there is the core's folder refusal), holds THAT descriptor, then
  fsyncs ``parent`` reopened ``O_RDONLY|O_DIRECTORY``; ``name`` is one path component;
* ``class Held``: ``read(name, *, binary=False) -> (text | bytes | None, reason | None)``;
  ``write(name, text, *, mode, durable=False) -> None`` (``mode`` in ``create`` / ``replace`` /
  ``append``; ``text`` is ``str | bytes``, anything else a ``TypeError`` before any I/O;
  ``durable`` is append-only, a ``ValueError`` otherwise); ``mkdir(folder) -> None``;
  ``unlink(name) -> bool``; ``view() -> Bound`` (sharing the handle, owning nothing);
  ``close()``; context-manager use. Every descriptor it opens is ``O_CLOEXEC``; each verb works
  off a private ``dup`` of the root; a verb after ``close()`` raises ``OSError(EBADF)``.

Handle, ``defender._episode_handle`` (D2'):

* ``Episode.open(episode_dir, *, io=_io)`` -> an ``Episode`` (one ``io.hold(episode_dir)``);
* ``Episode.create(episode_dir, *, io=_io)`` -> an ``Episode`` (one
  ``io.hold_new(episode_dir.parent, episode_dir.name)``);
* the ``Episode`` IS the context manager (``with Episode.open(d) as ep`` binds the same object),
  with ``.dir``, ``.view()``, ``.close()``; ``Episode(<path>)`` is a ``TypeError`` (no public bare
  constructor);
* ``RECORD_VERBS: dict[str, tuple[str, ...]]`` and ``FOLDERS: tuple[str, ...]`` -- exactly the
  tables below (rev 2 keeps rev 1's records and folders, names and verbs unchanged);
* records answer ``.path`` plus exactly the verbs their row grants, as CLASS attributes (one
  class per verb set); folders answer ``.path`` and ``.ensure()``. Each record verb is ONE call
  on the held root: ``read`` -> ``Held.read(rel)``; ``write`` -> ``Held.write(rel, text,
  mode="replace")``; ``create`` -> ``mode="create"``; ``append`` -> ``mode="append"``;
  ``append_durable`` -> ``mode="append", durable=True``; ``delete`` -> ``Held.unlink(rel)``;
  ``ensure`` -> ``Held.mkdir(rel)``.

Address grammar: an address is an attribute path on an ``Episode``. A bare name (``family``,
``served_world``) is an attribute of the episode; ``world.<name>`` one of
``episode.world(label)``. A method takes the record's components (``served_world(token)``,
``wire_log(name)``, ``world(label).draw(n)``); anything else is a property.

Entry points, with the rev-2 signatures the suite calls (D3'):

* ``cli.prepare_episode(episode_id, source_run_dir, *, tenant, prime=)`` -> the ``Episode``
  (closed by ``prepare_episode`` itself on its own exception); ``prime(source_run_dir, episode)``;
* ``cli.start_family(episode, labels, *, spawn=, tenant_id=, tenants_root=)``;
  ``cli.verify_family(episode, run_dirs, *, source=)``;
  ``archive.archive_episode(episode, run_dirs)``;
* ``staging.record_staged(episode, row)``; ``staging.merge_review(episode, key, block)``;
* ``capture.prime_base(source_run_dir, episode)``;
* ``ledger.Ledger.for_world(episode, world_id)`` (``LedgerError`` at construction for a bad or
  non-case-stable id); ``review.scratch_ledger(scratch_episode, *, world_label=)``;
* ``_family.load_family(episode, ...)``, ``manifest_digest(episode)``,
  ``check_manifest_digest(episode, recorded)``;
* ``enqueue.draws_on_disk(view, label)`` / ``draws_on_disk_report(view, label)``;
* ``judge._run_world_draws(episode, label, *, judge, draws, model, effort, prompt)`` (S1);
* the path doors ``judge.grade_episode(episode_dir, ...)``, ``visualize_episode.render_episode(
  episode_dir)``, ``run.main([... "--resume", <manifest>, ...], ...)`` and ``cli.main`` keep
  their signatures.

Underscore-prefixed so pytest does not collect it.
"""
from __future__ import annotations

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
from defender._episode_paths import LAYOUT
from defender._run_paths import WIRE_LOG_NAMES
from defender.tests.test_1111_rooted_io import (  # noqa: F401 — re-exported for the #1133 suite
    DEADLINE,
    HOST_BYTES,
    O6_ROWS,
    PassThroughOs,
    census,
    in_time,
    raised_by,
)

HANDLE_MODULE = "defender._episode_handle"

#: The world, token, wire-log name and draw index the composing records are addressed with.
LABEL = "b"
TOKEN = "e1133.b"
WIRE_NAME = WIRE_LOG_NAMES.agent_framed_trace("judge:b:0")
DRAW_N = 0

#: D1's record table (kept by D2'), row for row: address -> the verbs that row grants.
RECORD_VERBS: dict[str, tuple[str, ...]] = {
    "family": ("read", "write"),
    "family_stamp": ("write",),
    "review": ("read", "write"),
    "samples": ("write",),
    "judge": ("write",),
    "timing": ("write",),
    "staged": ("create", "append_durable"),
    "learning_html": ("write",),
    "served_base": ("create",),
    "served_world": ("append",),
    "priming_lock": ("create", "delete"),
    "wire_log": ("write",),
    "world.draw": ("write", "delete"),
    "world.run_dir_pointer": ("write",),
}

#: D1's folders (kept by D2'): `served`, `runs`, `worlds`, `world(label).dir`,
#: `world(label).draws`.
FOLDERS: tuple[str, ...] = ("served", "runs", "worlds", "world.dir", "world.draws")

#: Every verb a record can be granted.
ALL_VERBS = ("read", "write", "create", "append", "append_durable", "delete")

#: The write verbs, and the `Held.write` mode each is (D2': one `held.write` per write verb).
WRITE_MODE = {"write": "replace", "create": "create", "append": "append",
              "append_durable": "append"}

#: The components each composing record is addressed with.
RECORD_ARGS: dict[str, tuple[Any, ...]] = {
    "served_world": (TOKEN,),
    "wire_log": (WIRE_NAME,),
    "world.draw": (DRAW_N,),
}


# ---------------------------------------------------------------------------------------
# Lazy access to the rev-2 names
# ---------------------------------------------------------------------------------------

def handle() -> Any:
    """`defender._episode_handle`, imported per call."""
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
    world = LAYOUT.world(LABEL)
    return {
        "family": lambda: LAYOUT.family,
        "family_stamp": lambda: LAYOUT.family_stamp,
        "review": lambda: LAYOUT.review,
        "samples": lambda: LAYOUT.samples,
        "judge": lambda: LAYOUT.judge,
        "timing": lambda: LAYOUT.timing,
        "staged": lambda: LAYOUT.staged,
        "learning_html": lambda: LAYOUT.learning_html,
        "served_base": lambda: LAYOUT.served_base,
        "served_world": lambda: LAYOUT.served_world(TOKEN),
        "priming_lock": lambda: LAYOUT.priming_lock,
        "wire_log": lambda: LAYOUT.wire_log(WIRE_NAME),
        "world.draw": lambda: world.draw(DRAW_N),
        "world.run_dir_pointer": lambda: world.run_dir_pointer,
    }[key]()


def expected_folder_rel(key: str) -> PurePosixPath:
    world = LAYOUT.world(LABEL)
    return {
        "served": LAYOUT.served, "runs": LAYOUT.runs, "worlds": LAYOUT.worlds,
        "world.dir": world.dir, "world.draws": world.draws,
    }[key]


def resolve(episode: Any, key: str) -> Any:
    """The record or folder at `key` on `episode` (the address grammar in the docstring)."""
    head, dot, rest = key.partition(".")
    owner, attr = (episode.world(LABEL), rest) if (head == "world" and dot) else (episode, key)
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
NAME_REFUSAL = (r"not a valid path component|not a non-negative integer|is not case-stable|"
                r"not a valid relative name")
#: What the core's refusals say: a non-plain or aliased leaf, a symlinked folder, a
#: non-directory folder.
CORE_REFUSAL = r"aliased|symlinked|not a directory"

#: The core's fault table for each plant (`test_1111_rooted_io.O6_ROWS`): exception type,
#: errno, and whether it carries the alias mark. A dangling link is a symlink.
ROWS = {**O6_ROWS, "dangling": O6_ROWS["symlink"]}


def assert_refusal(exc: BaseException | None, kind: str, *, where: str) -> None:
    """`exc` is the core's refusal row for a `kind` plant: its type, its errno and its alias
    mark (`write_guarded_alias`; absent and False are both unmarked)."""
    typ, code, marked = ROWS[kind]
    assert exc is not None, f"{where}: a {kind} plant was not refused"
    want = f"the core's {typ.__name__} {errno.errorcode[code]}"
    assert isinstance(exc, typ), f"{where}: a {kind} plant raised {exc!r}, not {want}"
    assert getattr(exc, "errno", None) == code, f"{where}: a {kind} plant raised {exc!r}, not {want}"
    assert bool(getattr(exc, "write_guarded_alias", False)) is marked, (
        f"{where}: a {kind} plant's refusal is {'un' if marked else ''}marked as an alias; the "
        f"core's table says {'marked' if marked else 'unmarked'}")


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

    def read(self, *args: Any, **kwargs: Any) -> Any:
        return self._call("read", *args, **kwargs)

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
    successful `open` returns."""

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
    `replace`, `append`, `append_durable`), `mkdir`, `unlink`, `read`."""
    if verb == "append_durable":
        return held.write(name, payload, mode="append", durable=True)
    if verb in ("create", "replace", "append"):
        return held.write(name, payload, mode=verb)
    if verb == "mkdir":
        return held.mkdir(name)
    if verb == "unlink":
        return held.unlink(name)
    if verb == "read":
        return held.read(name)
    raise AssertionError(verb)
