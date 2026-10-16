"""The walk below a tenant's folder, and the runs folder's entries (#1105 H1–H4, #1187 S-iso):
the bottom layer every lookup works through, and the argument checks the lookups share.

`walk_from_tenant(tenant, io, names)` holds `<data root>/<T>` no-follow (the data root itself is
followed, as configuration), then each folder of `names` OFF ITS PARENT'S HANDLE, never followed
(`_io.hold_under`), and hands back the last one held. So a link at `<T>`, `<T>/runs`,
`<T>/episodes`, `<ep>` or `<ep>/runs` is refused at its own level, naming it, and nothing of
another tenant's is reached through one (#1187 R1: where a folder is says whose it is, so no
record restates it). Every refusal of a level is `TenantRefused`; an absent level is
`FileNotFoundError`, which each caller reads as its own expected state.

`listing(view, folder, tenant_id, io=)` judges every entry of a natural runs folder from its
directory entry, never followed (H4): a UUID run folder and a known sidecar file of one are the
only entries it serves. Anything else — a pre-#1187 run, an old sidecar, `_tenant.json`,
`_episodes`, a link, a stray file — refuses the whole listing with `RunRefused` naming the entry
and the one-time command that moves such entries aside (#1187 O6).

`plan_retire(tenant, old_episodes_root, io=)` is the one-time command's plan (#1187 Flow 6):
the entries `listing` refuses, and the old shared episodes root's, each bound for a legacy folder
below `<T>`, every reason to move nothing listed before anything moves (S-move).

This module is the package's bottom layer: `_lookup` imports it, and it imports nothing of the
package's but its errors and `RunId`.
"""
from __future__ import annotations

import contextlib
import errno
import os
import stat
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from defender import _io
from defender._run_id import run_id_fault
from defender._shown import quoted, shown
from defender._tenant import Tenant, TenantRefused
from defender.run_repository._errors import RunRefused
from defender.run_repository._id import RunId
from defender.run_repository._layout import _SIDECAR_SUFFIXES, _STAGED_TAIL

#: The one-time command every refusal of a pre-#1187 entry sends the operator to (#1187 O6,
#: Flow 7), as the operator runs it from the checkout's root.
RETIRE_COMMAND = "defender/ops/retire_legacy_runs.py"

# -- the arguments ----------------------------------------------------------------------------


def require_accepted_tenant(tenant: object) -> Tenant:
    """`tenant`, when it is an accepted `Tenant`; else `TypeError` (S2: the tenant is never a
    bare id, a path or a carrier the repository would have to trust or re-accept)."""
    if not isinstance(tenant, Tenant):
        raise TypeError(f"the runs repository takes an accepted Tenant, not "
                        f"{type(tenant).__name__}")
    return tenant


def require_run_id(run_id: object, *, what: str = "run id") -> RunId:
    """`run_id`, when it is a `RunId`; else `TypeError` (a `str` included: callers convert at
    their own edge with `RunId.parse`)."""
    if not isinstance(run_id, RunId):
        raise TypeError(f"the {what} must be a RunId, not {type(run_id).__name__}")
    return run_id


def sidecar_owner(name: str) -> str | None:
    """The run id a sidecar file named `name` belongs to — `<id>` of `<id><suffix>`, or of the
    staged `<id><suffix>.staged-<hex>` a sidecar write creates first — or `None` when `name` is
    not shaped like a sidecar. The one statement of the sidecar clause (#1105 D2.1, MF-21): run
    setup and `open_run` refuse an id it answers for, and the listings take a regular file it
    answers for as a known sidecar when `RunId.parse` admits the owner (any other such file is
    refused). It judges a name, not a path; outside the package it is asked through
    `run_name_fault`."""
    bare = name[: m.start()] if (m := _STAGED_TAIL.search(name)) else name
    for suffix in _SIDECAR_SUFFIXES:
        if bare.endswith(suffix) and len(bare) > len(suffix):
            return bare[: -len(suffix)]
    return None


def run_name_fault(text: str) -> str | None:
    """Why `text` cannot name a run folder, or `None`: the run-id rule (`run_id_fault`: canonical
    lowercase UUID text) and the sidecar clause (D2.1, MF-21: a name shaped like a host-only
    sidecar file, or the staged file a sidecar write makes first, never names a run). Judged on
    the name alone, before anything is read. The one answer to "may this text name a run?": run
    setup admits a run id by it, and the one-time command keeps a run folder by it."""
    if (why := run_id_fault(text)) is not None:
        return why
    if sidecar_owner(text) is not None:
        return (f"{quoted(text)} is shaped like a host-only sidecar file beside a run folder, "
                "not a run")
    return None


def refuse_sidecar_id(run_id: RunId) -> None:
    """`run_name_fault` on a `RunId` (whose run-id rule already holds), as `RunRefused`."""
    if (why := run_name_fault(str(run_id))) is not None:
        raise RunRefused(why)


def entry_path(folder: Path | str, name: str) -> str:
    """`<folder>/<name>` as a refusal shows it: a hostile name read off disk is quoted."""
    return f"{folder}/{shown(name)}"


# -- the folder's entries (H4) -------------------------------------------------------------------


@dataclass(frozen=True)
class Listing:
    """What a held runs folder holds, every entry judged: its runs (sorted by text), and the
    known sidecar files beside them, by name and by the run id each belongs to."""

    runs: tuple[RunId, ...]
    sidecars: frozenset[str]
    sidecar_ids: frozenset[RunId]


def _parses(text: str) -> RunId | None:
    try:
        return RunId.parse(text)
    except RunRefused:
        return None


def retire_remedy(tenant_id: str) -> str:
    """What a refusal of a pre-#1187 entry tells the operator to do: run the one-time command
    for the tenant (no run, fork or drain in flight on the data root; its help says so)."""
    return (f"run {RETIRE_COMMAND} --tenant {tenant_id} to move pre-#1187 entries aside "
            "(nothing is deleted)")


def _as_run(name: str, kind: str, io: Any) -> RunId | None:
    """The run a runs-folder entry is: a real directory whose name `RunId.parse` admits and the
    sidecar clause passes."""
    return _parses(name) if kind == io.ENTRY_DIR and sidecar_owner(name) is None else None


def _as_sidecar(name: str, kind: str, io: Any) -> RunId | None:
    """The run a runs-folder entry is a known sidecar file of: a REGULAR file `<id><suffix>`
    (or its staged twin) whose `<id>` `RunId.parse` admits."""
    owner = sidecar_owner(name)
    return _parses(owner) if kind == io.ENTRY_FILE and owner is not None else None


def served_entry(name: str, kind: str, *, io: Any) -> bool:
    """Whether the natural runs folder's entry `name`, of `kind` (an `ENTRY_*`, judged from its
    directory entry and never followed), is one the listing serves: a run folder or a known
    sidecar file of one. The one rule both ways (#1187 Flow 6, Flow 7): `listing` refuses every
    other entry, naming the one-time command, and that command moves every other entry aside."""
    return _as_run(name, kind, io) is not None or _as_sidecar(name, kind, io) is not None


def listing(view: _io.Bound, folder: Path, tenant_id: str, *, io: Any) -> Listing:
    """Every entry of the held natural runs folder, judged from its directory entry and never
    followed (D2.4, H4). Served (`served_entry`): a run (a real directory whose name
    `RunId.parse` admits and the sidecar clause passes) and a known sidecar file — a REGULAR
    file `<id><suffix>` whose `<id>` `RunId.parse` admits. Nothing else is: any other entry — a
    pre-#1187 run folder or sidecar, `_tenant.json`, `_episodes`, a link, a stray file — is
    `RunRefused` naming it and the one-time command (#1187 O6, O10). A folder that cannot be
    listed is `TenantRefused`."""
    answer = view.entries()
    if answer.entries is None:
        why = "it is gone" if answer.absent else answer.reason
        raise TenantRefused(f"the runs folder {folder} could not be listed: {why}")
    runs: list[RunId] = []
    sidecars: set[str] = set()
    sidecar_ids: set[RunId] = set()
    for name in sorted(answer.entries):
        kind = answer.entries[name]
        if (run_id := _as_run(name, kind, io)) is not None:
            runs.append(run_id)
        elif (owned := _as_sidecar(name, kind, io)) is not None:
            sidecars.add(name)
            sidecar_ids.add(owned)
        else:
            raise RunRefused(
                f"{entry_path(folder, name)} is not a run folder or a sidecar file of one (a "
                "run id is canonical lowercase UUID text; a link or any other entry is never "
                f"followed) — {retire_remedy(tenant_id)}")
    return Listing(tuple(runs), frozenset(sidecars), frozenset(sidecar_ids))


# -- the walk below the tenant (#1187 S-iso) -----------------------------------------------------


def level_fault(exc: OSError) -> str:
    """Why one level of a walk could not be held, from the step's own refusal: the step opened
    that level alone, off its parent's handle, so its errno is the level's."""
    if exc.errno == errno.ELOOP:
        return "is a link, which is never followed"
    if exc.errno == errno.ENOTDIR:
        return "is not a directory"
    return f"cannot be opened ({exc.strerror or exc})"


def hold_tenant_folder(tenant: Tenant, io: Any) -> _io.Held:
    """`<data root>/<T>` held no-follow — the top of every walk (#1187 S-iso): its ancestors are
    the data root, followed as configuration; `<T>` itself never is. A link there (one swapped
    in after acceptance), something other than a directory, or a folder that is gone is
    `TenantRefused` naming `<T>`. Held afresh by every call: no descriptor outlives a lookup."""
    folder = Path(tenant.dir)
    try:
        return io.hold(folder, follow=False)
    except OSError as exc:
        raise TenantRefused(f"the tenant folder {folder} {level_fault(exc)}") from None


def hold_level(parent: _io.Held, name: str, where: Path, *, io: Any, create: bool = False,
               what: str = "the folder") -> _io.Held:
    """`name`, one folder below `parent`, held off its handle and never followed
    (`_io.hold_under`; made first when `create`). Absent is `FileNotFoundError`; a link, a
    non-directory or a folder that cannot be opened is `TenantRefused` naming `where`."""
    try:
        return io.hold_under(parent, name, create=create)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise TenantRefused(f"{what} {where} {level_fault(exc)}") from None


def walk_from_tenant(tenant: Tenant, io: Any, names: tuple[str, ...], *,
                     create: bool = False) -> _io.Held:
    """`<T>/<names...>` held, every level off its parent's handle and no-follow (see the module
    docstring); each parent is closed once its child is held, and the caller closes what this
    returns. `create` makes each missing level. An absent level is `FileNotFoundError`; any
    other fault of a level is `TenantRefused` naming it."""
    held = hold_tenant_folder(tenant, io)
    where = Path(tenant.dir)
    try:
        for name in names:
            where = where / name
            child = hold_level(held, name, where, io=io, create=create)
            held.close()
            held = child
    except BaseException:
        held.close()
        raise
    return held


def tenant_levels(tenant: Tenant, folder: Path) -> tuple[str, ...]:
    """`folder`'s names below `<T>` (`tenant.runs` is `("runs",)`), so a walk takes every name
    from the tenant's own layout and spells none."""
    return Path(folder).relative_to(tenant.dir).parts


# -- a runs folder held by its path (#1105 H1) ---------------------------------------------------


def _hold_fault(folder: Path, exc: OSError) -> str:
    """Why `folder` could not be held, judged from the folder's own entry (a no-follow `lstat`,
    description only) rather than from the errno, which an ancestor's fault shares: a link at
    the folder, something other than a directory there, else the hold's own reason — a folder
    above it that cannot be walked included."""
    try:
        st = os.lstat(folder)
    except OSError:
        st = None
    if st is not None and stat.S_ISLNK(st.st_mode):
        return "is a link, which is never followed"
    if st is not None and not stat.S_ISDIR(st.st_mode):
        return "is not a directory"
    return f"cannot be opened ({exc.strerror or exc})"


def hold_runs_folder(folder: Path, *, create: bool = False, io: Any = _io) -> _io.Held:
    """`folder` — a runs folder — held open no-follow, the one way the package and run setup
    open one (#1105 H1, OP-2). An absent folder is `FileNotFoundError`, or with `create` is made
    first (`guarded_mkdir`: the runs folder is the host-controlled trust root, nothing above it
    is judged) and then held. Every other failure — a link (dangling or not) or a non-directory
    at the folder, a folder above it that cannot be walked, a create that fails — is
    `TenantRefused` naming the folder and the fault."""
    folder = Path(folder)
    try:
        return io.hold(folder, follow=False)
    except FileNotFoundError:
        if not create:
            raise
    except OSError as exc:
        raise TenantRefused(f"the runs folder {folder} {_hold_fault(folder, exc)}") from None
    try:
        io.guarded_mkdir(folder, base=folder)
        return io.hold(folder, follow=False)
    except OSError as exc:
        raise TenantRefused(f"the runs folder {folder} could not be created and held: "
                            f"{_hold_fault(folder, exc)}") from None


# -- the one-time command's move (#1187 Flow 6, S-move) ------------------------------------------


def _stat_kind(st: os.stat_result, io: Any) -> str:
    """An entry's `ENTRY_*` kind from its own no-follow `stat`, as a listing judges it."""
    if stat.S_ISDIR(st.st_mode):
        return io.ENTRY_DIR
    if stat.S_ISREG(st.st_mode):
        return io.ENTRY_FILE
    return io.ENTRY_OTHER


def _within(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


@dataclass
class _Lane:
    """One source folder's share of the move: every entry of `names`, out of the held `source`
    (`source_path` in messages) into the folder `destination` below `<T>`."""

    source: _io.Held | None
    source_path: Path
    destination: Path
    names: list[str] = field(default_factory=list)


class RetirePlan:
    """The one-time command's plan (#1187 Flow 6): what moves where, and every reason found to
    move nothing (`faults`). Built by `plan_retire` before anything moves; `act` runs it only
    when `faults` is empty. Holds `<T>` and each source folder until closed (a context
    manager)."""

    def __init__(self, tenant_held: _io.Held, tenant_dev: int, io: Any) -> None:
        self._tenant_held = tenant_held
        self._tenant_dev = tenant_dev
        self._io = io
        self.lanes: list[_Lane] = []
        self.faults: list[str] = []

    def close(self) -> None:
        for lane in self.lanes:
            if lane.source is not None:
                lane.source.close()
        self._tenant_held.close()

    def __enter__(self) -> RetirePlan:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def act(self, report: Callable[[str], None]) -> int:
        """Move every planned entry, natural entries first, each by ONE rename between held
        handles (`_io.rename_into`, which judges both names again just before it): a folder for
        a lane is made off the held `<T>` (an existing real one adopted). Each move is reported
        through `report` as it lands; returns how many moved. A rename that fails — the
        destination name taken since the plan, the entry changed, `EXDEV` across two mounts of
        one filesystem — stops the command with `TenantRefused` naming both paths; the moves
        before it stand, nothing was copied, and a re-run finishes the rest."""
        if self.faults:
            raise TenantRefused("the plan has faults; nothing is moved")
        moved = 0
        for lane in self.lanes:
            if not lane.names:
                continue
            assert lane.source is not None  # a lane with names was held
            destination = hold_level(self._tenant_held, lane.destination.name, lane.destination,
                                     io=self._io, create=True)
            try:
                for name in lane.names:
                    src, dst = lane.source_path / name, lane.destination / name
                    try:
                        self._io.rename_into(lane.source, name, destination)
                    except OSError as exc:
                        why = ("they are on two mounts (EXDEV), so a rename cannot join them "
                               "and nothing is copied" if exc.errno == errno.EXDEV
                               else (exc.strerror or str(exc)))
                        raise TenantRefused(
                            f"{entry_path(lane.source_path, name)} could not be renamed to "
                            f"{entry_path(lane.destination, name)}: {why} — {moved} entr"
                            f"{'y' if moved == 1 else 'ies'} moved before it stay moved; fix "
                            "this and run the command again to move the rest") from None
                    moved += 1
                    report(f"moved {src} -> {dst}")
            finally:
                destination.close()
        return moved


def _judge_entries(plan: RetirePlan, lane: _Lane, stats: dict[str, os.stat_result],
                   keep: Callable[[str, os.stat_result], bool]) -> None:
    """Put every entry of `stats` that `keep` does not keep into `lane`, and record a fault for
    any of them a rename would not move whole: a link or anything but a folder or regular file
    (the operator removes it by hand), or an entry on another filesystem than `<T>`."""
    for name in sorted(stats):
        st = stats[name]
        if keep(name, st):
            continue
        lane.names.append(name)
        where = entry_path(lane.source_path, name)
        if stat.S_ISLNK(st.st_mode):
            plan.faults.append(f"{where} is a link — remove it by hand (`rm` the link; a link "
                               "is never followed or moved)")
        elif not (stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode)):
            plan.faults.append(f"{where} is neither a folder nor a regular file (a FIFO, socket "
                               "or device) — remove it by hand")
        elif st.st_dev != plan._tenant_dev:
            plan.faults.append(f"{where} is on another filesystem than {lane.destination.parent} "
                               "(a mount point): a rename cannot move it")


def _judge_destination(plan: RetirePlan, lane: _Lane, io: Any) -> None:
    """The lane's destination below `<T>`, judged off the held `<T>` without following it:
    absent (made at `act`), or a real folder on `<T>`'s filesystem in which no planned name is
    taken — a rename replaces a file or an empty folder (R2-22), so a taken name refuses here.
    A link or anything but a folder refuses."""
    folder = lane.destination
    found = io.stat_entry(plan._tenant_held.view(), folder.name)
    if found.absent:
        return
    if found.st is None or not stat.S_ISDIR(found.st.st_mode):
        why = found.reason if found.st is None else (
            "a link, which is never followed" if stat.S_ISLNK(found.st.st_mode)
            else "not a folder")
        plan.faults.append(f"the destination {folder} is {why} — remove it by hand; the "
                           "command makes the folder itself")
        return
    if found.st.st_dev != plan._tenant_dev:
        plan.faults.append(f"the destination {folder} is on another filesystem than "
                           f"{folder.parent} (a mount point): a rename cannot reach it")
        return
    if not lane.names:
        return
    held = hold_level(plan._tenant_held, folder.name, folder, io=io, what="the destination")
    try:
        view = held.view()
        for name in lane.names:
            if not io.stat_entry(view, name).absent:
                plan.faults.append(f"{entry_path(folder, name)} is already taken — a rename "
                                   "would replace it; move one of the two aside by hand")
    finally:
        held.close()


def plan_retire(tenant: Tenant, old_episodes_root: Path | None, *, io: Any) -> RetirePlan:
    """The one-time command's plan (#1187 Flow 6 steps 1-2, S-move), with nothing moved.

    `<T>` is held no-follow and `<T>/runs` listed off that hold (a link there is
    `TenantRefused`, naming it; absent, nothing to move): every entry the listing would not
    serve (`served_entry` — old run folders and their sidecars, `_tenant.json`, `_episodes`, a
    link, a stray file) goes to `<T>/runs-legacy/`. With `old_episodes_root` — the operator's,
    held FOLLOWING its spelling, as configuration; absent is nothing to move — every entry of
    it goes to `<T>/episodes-legacy/`. Each entry is judged from its own directory entry, never
    followed. `faults` lists every reason to move nothing: a link or special file in the move
    set, a destination that is not a real folder, a destination name already taken, a source
    (or an entry, or a destination) on another filesystem than `<T>`, and an old episodes root
    inside the data root (it would move this tenant's live episodes) or holding it."""
    tenant_held = hold_tenant_folder(tenant, io)
    try:
        plan = RetirePlan(tenant_held, io.held_stat(tenant_held).st_dev, io)
    except BaseException:
        tenant_held.close()
        raise
    try:
        natural = _Lane(None, Path(tenant.runs), Path(tenant.runs_legacy))
        plan.lanes.append(natural)
        with contextlib.suppress(FileNotFoundError):
            natural.source = hold_level(tenant_held, tenant.runs.name, tenant.runs, io=io,
                                        what="the runs folder")
        if natural.source is not None:
            listed = io.stat_entries(natural.source.view())
            if listed.stats is None:
                raise TenantRefused(f"the runs folder {tenant.runs} could not be listed: "
                                    f"{listed.reason}")
            _judge_entries(plan, natural, listed.stats,
                           lambda name, st: served_entry(name, _stat_kind(st, io), io=io))
        if old_episodes_root is not None:
            _plan_old_episodes(plan, tenant, Path(old_episodes_root), io)
        for lane in plan.lanes:
            _judge_destination(plan, lane, io)
    except BaseException:
        plan.close()
        raise
    return plan


def _plan_old_episodes(plan: RetirePlan, tenant: Tenant, root: Path, io: Any) -> None:
    lane = _Lane(None, root, Path(tenant.episodes_legacy))
    plan.lanes.append(lane)
    real = root.resolve()
    data_root = Path(tenant.data_root).resolve()
    if _within(real, data_root) or _within(data_root, real):
        plan.faults.append(f"the old episodes root {root} is inside the data root {data_root}, "
                           "or holds it — the retired episodes root sat outside every data root, "
                           "and moving this would move live entries")
        return
    try:
        lane.source = io.hold(root)
    except FileNotFoundError:
        return
    except OSError as exc:
        plan.faults.append(f"the old episodes root {root} cannot be held: "
                           f"{exc.strerror or exc}")
        return
    if io.held_stat(lane.source).st_dev != plan._tenant_dev:
        plan.faults.append(f"the old episodes root {root} is on another filesystem than "
                           f"{tenant.dir}: the command only renames, and a rename cannot cross "
                           "filesystems — move it onto the data root's filesystem first")
        return
    listed = io.stat_entries(lane.source.view())
    if listed.stats is None:
        plan.faults.append(f"the old episodes root {root} could not be listed: {listed.reason}")
        return
    _judge_entries(plan, lane, listed.stats, lambda _name, _st: False)
