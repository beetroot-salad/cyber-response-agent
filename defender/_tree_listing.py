"""Fixed-shape listings of a held tree, built only from `Bound.entries()` and `Bound.under()`
(#1134, design addendum 2, B2).

The trees the learning drains read have known, shallow shapes: a lesson corpus is flat (depth
1), the query catalog is at most `<sys>/_draft/<file>.md` (depth 3). So nothing here walks a
tree of unknown depth, and nothing holds a descriptor: every folder is listed by its own
`entries()` call, which re-walks the folder's name from the held root, no-follow, and closes
what it opened before answering. A folder swapped or removed after its parent was listed is
therefore that folder's own refusal or absence, never an empty folder (`entries()` answers a
folder removed while it is listed absent).

Neither helper opens anything itself, and neither catches anything: every refusal is the
reason `entries()` gave, verbatim. `under()` validates a name and opens nothing.
"""
from __future__ import annotations

import dataclasses
from pathlib import PurePath

from defender._io import ENTRY_DIR, Bound


@dataclasses.dataclass(frozen=True)
class EntryKind:
    """`entry_kind`'s answer, in exactly one of three states: present (`kind` an `ENTRY_*`),
    absent (`absent`), or refused (`reason`, the listing of `folder` refused)."""

    #: The entry's name as the caller spelled it (POSIX), relative to the view.
    name: str
    #: The folder whose listing answered: the name's parent, relative to the view (`""` is the
    #: view's own folder).
    folder: str
    kind: str | None
    absent: bool
    reason: str | None


def entry_kind(view: Bound, name: str | PurePath) -> EntryKind:
    """What stands at `name` below `view`, as its folder's listing judges it (`entries()`:
    a link of any sort, a FIFO, socket or device is `ENTRY_OTHER`, a hard link `ENTRY_FILE`).

    One listing: `view.entries()` for a one-component name, else `view.under(<parent>)
    .entries()`. Absent when that folder is absent or has no row for the leaf; refused, with
    the listing's reason, when the listing was refused — a linked or non-directory holding
    folder among them (a caller that needs O2's "other" for that maps the refusal to it).

    `name` follows `Bound.read`'s grammar, checked by `under` before any I/O (`ValueError`);
    `""` and `"."` are refused too, since the view's own folder has no listed parent here
    (ask `view.entries()`). Never raises for a plant or a refusal."""
    spelling = name.as_posix() if isinstance(name, PurePath) else name
    view.under(name)  # the grammar check: opens nothing, raises ValueError for a bad name
    folder, _sep, leaf = spelling.rpartition("/")
    listing = (view.under(folder) if folder else view).entries()
    if listing.reason is not None:
        return EntryKind(name=spelling, folder=folder, kind=None, absent=False,
                         reason=listing.reason)
    kind = None if listing.entries is None else listing.entries.get(leaf)
    return EntryKind(name=spelling, folder=folder, kind=kind, absent=kind is None,
                     reason=None)


@dataclasses.dataclass(frozen=True)
class TreeListing:
    """`list_tree`'s answer. The view's own folder is present (`entries` set), absent
    (`absent`) or refused (`reason`). When present, `entries` maps every entry within the
    depth, by its view-relative name, to its `ENTRY_*` kind, in path-parts order; `refused`
    maps each folder below whose own listing was refused to its reason, and `gone` names each
    folder its parent listed as a directory whose own listing found nothing there. Such a
    folder keeps its `ENTRY_DIR` row, and nothing below it is listed: every directory row above
    the last level is exactly one of listed, refused or gone."""

    absent: bool
    reason: str | None
    entries: dict[str, str] | None
    refused: dict[str, str]
    gone: tuple[str, ...]


def _parts_order(name: str) -> tuple[str, ...]:
    return tuple(name.split("/"))


def list_tree(view: Bound, *, depth: int) -> TreeListing:
    """Every entry of `view`'s folder down to `depth` levels (`1`: the folder's own entries,
    exactly `view.entries()`), named relative to the view.

    Each directory row above the last level is listed by its own `view.under(<name>)
    .entries()`, so it is judged afresh, from the held root, without following links; a
    directory at the last level is reported and never listed. A folder whose listing is refused
    is in `refused` with its reason, one found gone since its parent's listing is in `gone`,
    and the rest of the shape is still listed. It stops at the first level that holds no folder
    to list, so a depth deeper than the tree costs nothing. `depth` is required: an `int` of at
    least 1, else `ValueError` before any I/O. Never raises for a plant or a refusal; holds
    nothing open."""
    if isinstance(depth, bool) or not isinstance(depth, int) or depth < 1:
        raise ValueError(f"depth must be an int of at least 1, not {depth!r}")
    top = view.entries()
    if top.entries is None:
        return TreeListing(absent=top.absent, reason=top.reason, entries=None, refused={},
                           gone=())
    found: dict[str, str] = dict(top.entries)
    refused: dict[str, str] = {}
    gone: list[str] = []
    level = [n for n, k in top.entries.items() if k == ENTRY_DIR]
    for _ in range(depth - 1):
        if not level:
            break
        below: list[str] = []
        for folder in sorted(level, key=_parts_order):
            listing = view.under(folder).entries()
            if listing.reason is not None:
                refused[folder] = listing.reason
            elif listing.entries is None:
                gone.append(folder)
            else:
                for entry, kind in listing.entries.items():
                    found[f"{folder}/{entry}"] = kind
                    if kind == ENTRY_DIR:
                        below.append(f"{folder}/{entry}")
        level = below
    return TreeListing(
        absent=False, reason=None,
        entries={n: found[n] for n in sorted(found, key=_parts_order)},
        refused={n: refused[n] for n in sorted(refused, key=_parts_order)},
        gone=tuple(sorted(gone, key=_parts_order)),
    )
