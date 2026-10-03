"""The drain's held trees (#1134 A3): one `Held` per writable mount of a drain batch, and the
lexical map from a working-copy path to the held mount that contains it.

A drain box mounts a few folders of the drain working copy writable. While the batch runs,
every host touch of those folders goes through a handle rooted at the mount point itself
(never at a folder inside it, which the box could replace with a link) and held open by
descriptor, so nothing below it is followed and the mount is resolved once, at `open`.
"""
from __future__ import annotations

import contextlib
import errno
import os
from collections.abc import Callable
from pathlib import Path
from types import TracebackType
from typing import TYPE_CHECKING, Any, TypeAlias

from defender._io import ENTRY_DIR, ENTRY_FILE, ENTRY_OTHER, Bound, Held, hold, read_text_soft
from defender._tree_listing import entry_kind

if TYPE_CHECKING:
    from defender.learning.core.config import DrainLabel, LoopPaths


def _absolute(path: Path | str) -> Path:
    """`path` as a `Path`, refused unless absolute and anchored at one `/`. A relative path has
    no honest base here: the holder knows its mounts, not the working copy's root, and cwd is
    nobody's root."""
    p = Path(path)
    if not p.is_absolute():
        raise ValueError(f"{str(path)!r} is not absolute; join it to its working-copy root first")
    if p.anchor != "/":
        # `//x` is its own anchor to pathlib, so it would match no mount and fall to a plain path.
        raise ValueError(f"{str(path)!r} is not anchored at a single '/'")
    return p


def _checked_mounts(mounts: tuple[Path | str, ...]) -> tuple[Path, ...]:
    """The mount points as `Path`s, refused (before anything is opened) unless each is
    absolute (one `/` anchor) with no `..` and no NUL, and no two are the same or nested, so a
    path has at most one containing mount."""
    points = tuple(_absolute(m) for m in mounts)
    for i, p in enumerate(points):
        if ".." in p.parts:
            raise ValueError(f"mount {str(p)!r} has a '..' component")
        if "\0" in str(p):
            raise ValueError(f"mount {str(p)!r} has a NUL byte")
        for q in points[:i]:
            if p.is_relative_to(q) or q.is_relative_to(p):
                raise ValueError(f"mounts {str(q)!r} and {str(p)!r} are the same or nested")
    return points


class DrainTrees:
    """The held roots of one drain batch's writable mounts: one :func:`hold` per mount, taken
    at :meth:`open` and released together by :meth:`close` (or the `with` block's exit).

    Every handle is the real :class:`Held`; writes go through it and reads through its
    `view()`. After `close`, each answers as a closed `Held` does (`EBADF`).

    Paths are matched lexically and must be absolute (see :meth:`tree_for`).
    """

    def __init__(self, held: tuple[tuple[Path, Held], ...], stack: contextlib.ExitStack) -> None:
        """Use :meth:`open`."""
        self._held = held
        self._stack = stack

    @classmethod
    def open(cls, mounts: tuple[Path, ...], *, os_: Any = os) -> DrainTrees:
        """Hold each of `mounts` (absolute mount points; no `..` or NUL, none the same as or
        nested in another, else `ValueError` before anything is opened), in order, following each
        mount's own spelling as `hold` does. If one `hold` fails, the handles already taken are
        closed and its exception propagates unchanged. An empty tuple holds nothing."""
        points = _checked_mounts(tuple(mounts))
        with contextlib.ExitStack() as stack:
            held = tuple((p, stack.enter_context(hold(p, os_=os_))) for p in points)
            return cls(held, stack.pop_all())

    @property
    def mounts(self) -> tuple[Path, ...]:
        """The mount points, as given to `open` and in that order."""
        return tuple(p for p, _held in self._held)

    def tree_for(self, path: Path | str) -> tuple[Held, str] | None:
        """The held mount containing `path`, and `path`'s POSIX name below it (`"."` for the
        mount point itself), or `None` when no mount contains it.

        Lexical: no `resolve()` and no filesystem access, so a link anywhere neither moves a
        path into a mount nor out of one; containment is by whole path components (a
        `lessons-questioner/` path is never under `lessons/`). `path` must be absolute and
        anchored at one `/` (`ValueError` otherwise: never `None`, which would send the caller
        to a plain path). A `..` component below a mount is `ValueError`: lexically
        inside, it may name something outside. A `..` above every mount is not collapsed, so
        such a path is `None` even when it would collapse into a mount."""
        p = _absolute(path)
        for mount, held in self._held:
            try:
                rel = p.relative_to(mount)
            except ValueError:
                continue
            if ".." in rel.parts:
                raise ValueError(f"{str(path)!r} has a '..' component below the mount {mount}")
            return held, rel.as_posix()
        return None

    def mount(self, path: Path | str) -> Held:
        """The held root for the mount point `path` exactly (compared lexically, as
        :meth:`tree_for` does); `ValueError` for any other path."""
        p = _absolute(path)
        for mount, held in self._held:
            if p == mount:
                return held
        raise ValueError(f"{str(path)!r} is not a held mount point")

    # -- lifetime -------------------------------------------------------------------------------

    def close(self) -> None:
        """Close every held root, each once, even if an earlier one's close raises (the last
        such fault propagates). Idempotent."""
        self._stack.close()

    def __enter__(self) -> DrainTrees:
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None,
                 tb: TracebackType | None) -> None:
        # The stack's own exit, handed the exception unwinding through the `with`: every root is
        # still closed, and a close fault then carries that exception as its `__context__`
        # instead of dropping it (`close()` would hand the stack `None` and cut the chain).
        # Nothing is suppressed.
        self._stack.__exit__(exc_type, exc, tb)


def open_drain_trees(wt_paths: LoopPaths, label: DrainLabel) -> DrainTrees:
    """The held roots of a `label` drain batch's writable mounts: :meth:`DrainTrees.open` over
    exactly `wt_paths.drain_writable_trees(label)` (the drain working copy's paths), the list
    `_drain_box_request` mounts read-write, so the held roots are the box's rw mounts (#1134
    O4). Nothing is derived here: an unknown label holds nothing.

    The mounts must be absolute (`ValueError` before anything is held otherwise), so a
    `wt_paths` with a relative `repo_root` is refused, never joined to the cwd. Use it as a
    context manager inside the lane's work step."""
    return DrainTrees.open(wt_paths.drain_writable_trees(label))


#: :meth:`DrainTrees.tree_for`, bound: a working-copy path to the held mount containing it and its
#: name below that mount, or `None` outside the lane's mounts.
TreeFor: TypeAlias = Callable[[Path | str], tuple[Held, str] | None]


def view_at(held: Held, name: str) -> Bound:
    """A reader over `held` bound at its folder `name` (`"."` is the held root itself): a name
    prefix over the same held handle, nothing opened."""
    view = held.view()
    return view if name == "." else view.under(name)


#: :func:`kind_at`'s answer when nothing stands at the path.
KIND_ABSENT = "absent"


def kind_at(repo_root: Path, tree_for: TreeFor, path: Path | str) -> str:
    """What stands at the working-copy `path` (absolute, or relative to `repo_root` as git
    status spells it): `"absent"`, `"file"`, `"dir"` or `"other"`.

    Asked of the held mount when `tree_for` places `path` inside one: its folder's listing
    judges it (`entry_kind`), so nothing below the mount point is followed and a hard link is
    `"file"` here (refused by :func:`read_at`). A holding folder whose listing is refused —
    linked, not a directory, unreadable — answers `"other"` (#1134 O2): something stands in the
    way, and it is not the plain entry. Never raises for a plant or a refusal. A path outside
    the lane's mounts keeps its plain path: it lies in the box's read-only area (#1134 D3)."""
    full = repo_root / path
    hit = tree_for(full)
    if hit is not None:
        held, name = hit
        if name == ".":  # the mount point itself, which has no listed parent below the mount
            top = held.view().entries()
            if top.reason is not None:
                return ENTRY_OTHER
            return KIND_ABSENT if top.absent else ENTRY_DIR
        got = entry_kind(held.view(), name)
        if got.reason is not None:
            return ENTRY_OTHER
        return KIND_ABSENT if got.absent else str(got.kind)
    if full.is_file():
        return ENTRY_FILE
    if full.is_dir():
        return ENTRY_DIR
    return ENTRY_OTHER if os.path.lexists(full) else KIND_ABSENT


def read_at(repo_root: Path, tree_for: TreeFor, path: Path | str) -> tuple[str | None, str | None]:
    """The text of the plain file at the working-copy `path`, as `(text, None)`, or `(None,
    reason)`; placed as :func:`kind_at` places it. Through a held mount nothing but a plain file
    is read (a link, a hard link, a FIFO, a folder is refused with the view's reason)."""
    full = repo_root / path
    hit = tree_for(full)
    if hit is None:
        return read_text_soft(full)
    held, name = hit
    rec = held.view().read(name)
    if rec.text is not None:
        return rec.text, None
    return None, rec.reason or os.strerror(errno.ENOENT)
