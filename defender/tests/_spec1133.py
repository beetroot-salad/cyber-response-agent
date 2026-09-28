"""Shared machinery for #1133's Episode-handle spec. It defines NO tests.

The contract is issue #1133's intent+design doc (O1-O4, N-a..N-g, D1-D7). This module holds
the spec's OWN copy of the handle's tables and the names the suite builds against. The
implementation must expose exactly these:

* module ``defender._episode_handle``;
* class ``Episode(episode_dir, *, io=_io)`` with ``.dir`` and ``.create_dir()``;
* ``RECORD_VERBS: dict[str, tuple[str, ...]]`` -- every record the handle hands out, keyed by
  its ADDRESS (below), mapped to the verbs its row grants, as ``_run_handle.MEMBER_VERB`` is;
* ``FOLDERS: tuple[str, ...]`` -- every folder the handle hands out, keyed the same way.

An address is an attribute path on an ``Episode``. A bare name (``family``, ``served_world``)
is an attribute of the episode. ``world.<name>`` is an attribute of ``episode.world(label)``.
An attribute that is a method takes the record's components (``served_world(token)``,
``wire_log(name)``, ``world(label).draw(n)``); anything else is a property. Records answer
``.path`` plus only the verbs their row grants (``read``, ``write``, ``create``, ``append``,
``append_durable``, ``delete``); folders answer ``.path`` and ``.ensure()``.

The matrices in ``test_1133_episode_handle.py`` are parametrized over the UNION of the shipped
tables and the copy below, so a record the shipped table drops is still exercised (and fails),
and a record it adds joins every matrix with no code here (O2).

Underscore-prefixed so pytest does not collect it.
"""
from __future__ import annotations

import dataclasses
import errno
import importlib
import inspect
import os
import shutil
from pathlib import Path, PurePosixPath
from typing import Any

from defender._episode_paths import LAYOUT
from defender._run_paths import WIRE_LOG_DIR, WIRE_LOG_NAMES
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

#: D1's record table, row for row: address -> the verbs that row grants.
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

#: D1's folders: `served`, `runs`, `worlds`, `world(label).dir`, `world(label).draws`.
FOLDERS: tuple[str, ...] = ("served", "runs", "worlds", "world.dir", "world.draws")

#: Every verb a record can be granted (D1 "Verb semantics").
ALL_VERBS = ("read", "write", "create", "append", "append_durable", "delete")

#: The components each composing record is addressed with.
RECORD_ARGS: dict[str, tuple[Any, ...]] = {
    "served_world": (TOKEN,),
    "wire_log": (WIRE_NAME,),
    "world.draw": (DRAW_N,),
}


def handle() -> Any:
    """`defender._episode_handle`, imported per call so a missing module fails each test on
    its own rather than the whole file at collection."""
    return importlib.import_module(HANDLE_MODULE)


def shipped_tables() -> tuple[dict[str, tuple[str, ...]], tuple[str, ...]]:
    """The handle's own `RECORD_VERBS` and `FOLDERS` when it is importable, else empty (the
    matrices then run over the spec's copy alone and each case fails on the missing module).
    Only the handle's OWN absence is tolerated; any other import error surfaces."""
    try:
        mod = importlib.import_module(HANDLE_MODULE)
    except ModuleNotFoundError as e:
        if e.name != HANDLE_MODULE:
            raise
        return {}, ()
    return dict(getattr(mod, "RECORD_VERBS", {}) or {}), tuple(getattr(mod, "FOLDERS", ()) or ())


def record_cases() -> dict[str, tuple[str, ...]]:
    """Every record address in the spec or the shipped table, with the union of the verbs
    either grants it, spec order first."""
    shipped, _ = shipped_tables()
    out: dict[str, tuple[str, ...]] = {}
    for key in (*RECORD_VERBS, *[k for k in shipped if k not in RECORD_VERBS]):
        verbs = list(RECORD_VERBS.get(key, ()))
        verbs += [v for v in shipped.get(key, ()) if v not in verbs]
        out[key] = tuple(verbs)
    return out


def folder_cases() -> tuple[str, ...]:
    _, shipped = shipped_tables()
    return (*FOLDERS, *[f for f in shipped if f not in FOLDERS])


def expected_record_rel(key: str) -> PurePosixPath | None:
    """The record's name relative to the episode dir, from `_episode_paths.LAYOUT` (the only
    place names are spelled). `None` for a record the spec does not know."""
    world = LAYOUT.world(LABEL)
    table = {
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
        # D1's one owner addition; resolved lazily so its absence fails the cases that need it.
        "wire_log": lambda: LAYOUT.wire_log(WIRE_NAME),
        "world.draw": lambda: world.draw(DRAW_N),
        "world.run_dir_pointer": lambda: world.run_dir_pointer,
    }
    thunk = table.get(key)
    return None if thunk is None else thunk()


def expected_folder_rel(key: str) -> PurePosixPath | None:
    world = LAYOUT.world(LABEL)
    return {
        "served": LAYOUT.served, "runs": LAYOUT.runs, "worlds": LAYOUT.worlds,
        "world.dir": world.dir, "world.draws": world.draws,
    }.get(key)


def resolve(episode: Any, key: str) -> Any:
    """The record or folder at `key` on `episode` (the address grammar in the docstring)."""
    head, dot, rest = key.partition(".")
    owner, attr = (episode.world(LABEL), rest) if (head == "world" and dot) else (episode, key)
    got = getattr(owner, attr)
    if inspect.ismethod(got) or inspect.isfunction(got):
        if key not in RECORD_ARGS:
            raise AssertionError(
                f"{key} is a composing accessor the spec gives no components for — add its "
                "arguments to `_spec1133.RECORD_ARGS` so it joins the matrices")
        return got(*RECORD_ARGS[key])
    return got


def rel_of(episode_dir: Path, key: str, thing: Any, *, folder: bool = False) -> PurePosixPath:
    """The address to plant at: the spec's LAYOUT name when the spec knows `key`, else the
    one the handle's own `.path` gives."""
    want = expected_folder_rel(key) if folder else expected_record_rel(key)
    if want is not None:
        return want
    return PurePosixPath(Path(thing.path).relative_to(episode_dir).as_posix())


_PROBE_EPISODE = Path("/nonexistent-1133/episodes/ep-1133")


def collection_rel(key: str, *, folder: bool = False) -> PurePosixPath | None:
    """`rel_of` at COLLECTION time, when the handle may not exist yet: the spec's name for a
    key it knows (the wire log spelled from `WIRE_LOG_DIR`, since `LAYOUT.wire_log` is itself
    new), else the handle's own `.path` on a probe episode, else `None`."""
    if key == "wire_log" and not folder:
        return PurePosixPath(WIRE_LOG_DIR) / WIRE_NAME
    want = expected_folder_rel(key) if folder else expected_record_rel(key)
    if want is not None:
        return want
    try:
        thing = resolve(handle().Episode(_PROBE_EPISODE), key)
        return PurePosixPath(Path(thing.path).relative_to(_PROBE_EPISODE).as_posix())
    except Exception:  # noqa: BLE001 — collection must not die; the case itself will fail
        return None


def holding_folders(rel: PurePosixPath) -> tuple[PurePosixPath, ...]:
    """Every folder strictly between the episode dir and `rel`, outermost first."""
    return tuple(reversed(rel.parents[:-1]))


def folder_and_parents(rel: PurePosixPath) -> tuple[PurePosixPath, ...]:
    """`rel` and every folder above it below the episode dir, outermost first."""
    return (*holding_folders(rel), rel)


# ---------------------------------------------------------------------------------------
# Plants: every one a real filesystem entry
# ---------------------------------------------------------------------------------------

#: What a plant can put AT a record's name. `dangling` is a symlink whose target does not
#: exist, so a write that followed it would CREATE a file outside the episode.
LEAF_PLANTS = ("symlink", "dangling", "hardlink", "fifo", "directory")
#: What a plant can put at a holding folder (or, for a folder, at the folder itself).
FOLDER_PLANTS = ("folder_link_outside", "folder_link_inside", "folder_file", "folder_fifo")

#: What an owner's name check says (`_check_component`, `_check_index`, the case-stable rule,
#: the rooted name grammar) — a `ValueError` carrying one of these is a name refusal, not some
#: other fault.
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
    mark (`write_guarded_alias`, which `hooks/budget_enforcer.py` reads with
    `getattr(e, "write_guarded_alias", False)`, so absent and False are both unmarked)."""
    typ, code, marked = ROWS[kind]
    assert exc is not None, f"{where}: a {kind} plant was not refused"
    want = f"the core's {typ.__name__} {errno.errorcode[code]}"
    assert isinstance(exc, typ), f"{where}: a {kind} plant raised {exc!r}, not {want}"
    assert getattr(exc, "errno", None) == code, f"{where}: a {kind} plant raised {exc!r}, not {want}"
    assert bool(getattr(exc, "write_guarded_alias", False)) is marked, (
        f"{where}: a {kind} plant's refusal is {'un' if marked else ''}marked as an alias; the "
        f"core's table says {'marked' if marked else 'unmarked'}")


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
    return out
