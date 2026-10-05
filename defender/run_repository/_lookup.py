"""Run lookup (#1105 D2): `open_run`, `list_run_ids`, `bound_runs` and `run_exists`, and the
held runs folder every lookup and record function works through.

Each function takes an accepted `Tenant` (anything else is a `TypeError`, before any read) and,
where it names a run, a `RunId`. The runs folder is always `tenant.runs`: no function takes a
folder from its caller, reads the environment, or re-runs acceptance. Each opens that folder
ONCE, no-follow (`_io.hold(tenant.runs, follow=False)`), and does every read relative to that
handle, closing it before it returns (`bound_runs` holds it for its block). One held handle is
how a link at `tenant.runs` itself is refused, and how one call's listing, tenant record and
claims all come from one folder; it is not race protection (P1: the host is not malicious).

P2: an unexpected state raises one named error — `TenantRefused` for the runs folder and its
`_tenant.json`, `RunRefused` for everything else — naming the path and the fault, at the first
failed check, before any write. The expected states, and only these, answer normally: an absent
runs folder (empty answers), an absent `_episodes` (no claims), and the known sidecar files
beside run folders, a sidecar write's staged file included. Each function judges what it reads:
`open_run` and `run_exists` do not read `_episodes`, so its state does not refuse them.
"""
from __future__ import annotations

import errno
import stat
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from defender import _io
from defender._tenant import TENANT_RECORD_NAME, Tenant, TenantRefused, read_tenant, record_path
from defender.run_repository import _record
from defender.run_repository._errors import RunRefused, escaped, quoted, shown
from defender.run_repository._handle import Run
from defender.run_repository._id import RunId
from defender.run_repository._layout import RunPaths

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


def refuse_sidecar_id(run_id: RunId) -> None:
    """The sidecar clause (D2.1, MF-21) on an id: one shaped like a host-only sidecar file, or
    like the staged file a sidecar write makes first, never names a run. Judged on the name
    alone, before anything is read."""
    if RunPaths.sidecar_owner(str(run_id)) is not None:
        raise RunRefused(f"{quoted(str(run_id))} is shaped like a host-only sidecar file beside "
                         "a run folder, not a run")


# -- the held runs folder (H1, H2) -------------------------------------------------------------


def _hold_fault(exc: OSError) -> str:
    if exc.errno == errno.ELOOP:
        return f"is a link, which is never followed ({exc.strerror})"
    if exc.errno == errno.ENOTDIR:
        return "is not a directory"
    return f"cannot be opened ({exc.strerror or exc})"


@contextmanager
def held_runs(tenant: Tenant, io: Any) -> Iterator[_io.Held | None]:
    """`tenant.runs`, held open no-follow for the block, or `None` when it is absent (the one
    expected state of the folder itself). Any other refusal of the open is `TenantRefused`
    naming the folder; the handle is closed when the block ends, however it ends."""
    runs = Path(tenant.runs)
    try:
        held = io.hold(runs, follow=False)
    except FileNotFoundError:
        yield None
        return
    except OSError as exc:
        raise TenantRefused(f"the runs folder {escaped(runs)} {_hold_fault(exc)}") from None
    try:
        yield held
    finally:
        held.close()


def refuse_absent(tenant: Tenant) -> TenantRefused:
    """The refusal for a function that needs the runs folder to exist (`open_run`, the
    writer): run setup creates it, with its tenant record, and nothing here does."""
    return TenantRefused(f"the runs folder {escaped(tenant.runs)} is absent — run setup creates it, "
                         "with its tenant record")


class _HeldRecordIO:
    """`read_tenant`'s `io=` seam served through the held view (H3): the record is read off
    the held handle, never by path, so its verdict is about the folder this call holds."""

    def __init__(self, view: _io.Bound) -> None:
        self._view = view

    def read_guarded(self, _path: Path, **_kwargs: Any) -> tuple[str | None, str | None]:
        answer = self._view.read(TENANT_RECORD_NAME)
        if answer.text is not None:
            return answer.text, None
        return None, "absent" if answer.absent else answer.reason


def check_tenant_record(view: _io.Bound, tenant: Tenant) -> None:
    """`read_tenant`'s verdict on the held folder's `_tenant.json`, then an exact compare of
    its `tenant_id` with `tenant.id`. Every failure is `TenantRefused` naming the record, never
    a raw error, and never carrying a run id of the folder (NF-8)."""
    path = escaped(record_path(Path(tenant.runs)))
    try:
        record = read_tenant(Path(tenant.runs), io=_HeldRecordIO(view))
    except TenantRefused as exc:
        raise type(exc)(escaped(exc)) from None
    except (RecursionError, ValueError, TypeError, OSError) as exc:
        raise TenantRefused(f"{path} could not be judged: {escaped(exc)}") from None
    if record.tenant_id != tenant.id:
        raise TenantRefused(f"{path} names the tenant {quoted(record.tenant_id)}, not "
                            f"{quoted(tenant.id)}")


# -- the folder's entries (H4) -------------------------------------------------------------------


@dataclass(frozen=True)
class Listing:
    """What a held runs folder holds, every entry judged: its runs (sorted by text), and the
    known sidecar files beside them, by name and by the run id each belongs to."""

    runs: tuple[RunId, ...]
    sidecars: frozenset[str]
    sidecar_ids: frozenset[RunId]


def entry_path(folder: Path | str, name: str) -> str:
    """`<folder>/<name>` as a refusal shows it: a hostile name read off disk is quoted."""
    return f"{escaped(folder)}/{shown(name)}"


def _parses(text: str) -> RunId | None:
    try:
        return RunId.parse(text)
    except RunRefused:
        return None


def list_entries(view: _io.Bound, folder: Path, *, io: Any) -> Listing:
    """Every entry of the held runs folder, judged from its directory entry and never followed
    (D2.4, H4). Accepted: a run (a real directory whose name `RunId.parse` admits and the
    sidecar clause passes), `_tenant.json` and `_episodes` (each judged where it is read), and a
    known sidecar file. Any other entry is `RunRefused` naming it, a legacy run folder off the
    id rules included; a folder that cannot be listed is `TenantRefused`."""
    answer = view.entries()
    if answer.entries is None:
        why = "it is gone" if answer.absent else answer.reason
        raise TenantRefused(f"the runs folder {escaped(folder)} could not be listed: {escaped(why)}")
    runs: list[RunId] = []
    sidecars: set[str] = set()
    sidecar_ids: set[RunId] = set()
    for name in sorted(answer.entries):
        kind = answer.entries[name]
        if name in (TENANT_RECORD_NAME, _record.EPISODES_DIRNAME):
            continue
        owner = RunPaths.sidecar_owner(name)
        if kind == io.ENTRY_DIR:
            run_id = _parses(name) if owner is None else None
            if run_id is None:
                raise RunRefused(
                    f"{entry_path(folder, name)} is a directory that is not a run: its name is "
                    "off the run-id rules or shaped like a sidecar file — rename or move it")
            runs.append(run_id)
        elif kind == io.ENTRY_FILE and owner is not None and (owned := _parses(owner)):
            sidecars.add(name)
            sidecar_ids.add(owned)
        else:
            raise RunRefused(
                f"{entry_path(folder, name)} is not a run, a known sidecar file, "
                f"{TENANT_RECORD_NAME} or {_record.EPISODES_DIRNAME} (a link, a stray file or "
                "another entry) — move it out of the runs folder")
    return Listing(tuple(runs), frozenset(sidecars), frozenset(sidecar_ids))


def unclaimed_runs(view: _io.Bound, tenant: Tenant, *, io: Any) -> list[RunId]:
    """The held folder's runs minus every id a good episode record claims (D2's listings)."""
    listing = list_entries(view, tenant.runs, io=io)
    claimed = _record.claimed_ids(view, tenant, io=io)
    return [run_id for run_id in listing.runs if run_id not in claimed]


# -- the lookups (H6) ----------------------------------------------------------------------------


def open_run(tenant: Tenant, run_id: RunId, *, io: Any = _io) -> Run:
    """The tenant's run `run_id`, as a `Run` addressed `(tenant.id, run_id)` under
    `tenant.runs`.

    In order: the argument types; the sidecar clause; the held folder (absent is
    `TenantRefused`); its tenant record; the entry `tenant.runs/<run_id>`, which must be a real
    directory (anything else, absent included, is `RunRefused` naming the path). The handle is
    built by `Run.under` (DV-2): the record was judged through the held folder, and
    `Run.for_tenant` would read it a second time, by path. A handed-out `Run` is not checked
    again (NF-12). `_episodes` is not read: whether a sibling may be opened is its caller's."""
    tenant = require_accepted_tenant(tenant)
    run_id = require_run_id(run_id)
    refuse_sidecar_id(run_id)
    name = str(run_id)
    with held_runs(tenant, io) as held:
        if held is None:
            raise refuse_absent(tenant)
        view = held.view()
        check_tenant_record(view, tenant)
        entry = io.stat_entry(view, name)
        path = escaped(Path(tenant.runs) / name)
        if entry.st is None:
            raise RunRefused(f"{path} is absent" if entry.absent
                             else f"{path} could not be judged: {entry.reason}")
        if not stat.S_ISDIR(entry.st.st_mode):
            raise RunRefused(f"{path} is not a real directory (a link, a file or another "
                             "entry) — it is never followed or opened as a run")
    return Run.under(tenant.runs, name, io=io, tenant_id=tenant.id)


def list_run_ids(tenant: Tenant, *, io: Any = _io) -> list[RunId]:
    """The tenant's runs, sorted by text, minus every id a good episode record claims; `[]`
    when the runs folder is absent."""
    tenant = require_accepted_tenant(tenant)
    with held_runs(tenant, io) as held:
        if held is None:
            return []
        view = held.view()
        check_tenant_record(view, tenant)
        return unclaimed_runs(view, tenant, io=io)


def run_exists(tenant: Tenant, run_id: RunId, *, io: Any = _io) -> bool:
    """Whether a run or a known sidecar file stands at `run_id` in the tenant's runs folder:
    an occupancy answer, so the sidecar clause is not applied to `run_id`. `False` when the
    folder is absent. The whole listing is judged, so an unexpected entry refuses, save
    `_tenant.json` and `_episodes`, whose kind is judged only where they are read: `_episodes`
    is not read here."""
    tenant = require_accepted_tenant(tenant)
    run_id = require_run_id(run_id)
    with held_runs(tenant, io) as held:
        if held is None:
            return False
        view = held.view()
        check_tenant_record(view, tenant)
        listing = list_entries(view, tenant.runs, io=io)
        return run_id in listing.runs or str(run_id) in listing.sidecars


class RunRow:
    """One row of `bound_runs`: a run's members, read off the block's held handle when each
    read is made, its name walked no-follow (`Bound.under`, which opens nothing). Where a bare
    `Bound` would answer a `reason` — a refused read, or any read after the block, where it
    answers `Bad file descriptor` without raising (R41-12) — this raises `RunRefused`. A
    member's content is run content: whoever reads it validates it (P1)."""

    def __init__(self, rows: BoundRuns, run_id: RunId, bound: _io.Bound, path: Path) -> None:
        self._rows = rows
        self._run_id = run_id
        self._bound = bound
        self._path = path

    def _answer(self, answer: Any, what: str) -> Any:
        if answer.reason is not None:
            raise RunRefused(f"{self._path}: {what} refused: {answer.reason}")
        return answer

    def read(self, name: str, **kwargs: Any) -> _io.RecordRead:
        self._rows.require_open(f"reading {shown(name)} of {self._run_id}")
        return self._answer(self._bound.read(name, **kwargs), f"reading {shown(name)}")

    def entries(self) -> _io.EntriesRead:
        self._rows.require_open(f"listing {self._run_id}")
        return self._answer(self._bound.entries(), "listing")


class BoundRuns:
    """`bound_runs(tenant)`: the tenant's runs as `(RunId, RunRow)` rows, over one held
    descriptor for the `with` block. Listed once, on entry, in `list_run_ids`' order; `absent`
    is true when the runs folder is absent (no rows). Single use: a second entry, or iterating
    an object never entered or already left, raises `RunRefused`."""

    def __init__(self, tenant: Tenant, io: Any) -> None:
        self._tenant = tenant
        self._io = io
        self._state = "new"
        self._stack = ExitStack()
        self._rows: list[tuple[RunId, RunRow]] = []
        self.absent = False

    def require_open(self, doing: str) -> None:
        if self._state != "open":
            raise RunRefused(f"bound_runs over {escaped(self._tenant.runs)}: {doing} outside its "
                             "with block")

    def __enter__(self) -> BoundRuns:
        if self._state != "new":
            raise RunRefused(f"bound_runs over {escaped(self._tenant.runs)} is single use; enter a "
                             "fresh one")
        self._state = "open"
        try:
            held = self._stack.enter_context(held_runs(self._tenant, self._io))
            if held is None:
                self.absent = True
                return self
            view = held.view()
            check_tenant_record(view, self._tenant)
            runs = Path(self._tenant.runs)
            self._rows = [(run_id, RunRow(self, run_id, view.under(str(run_id)),
                                          runs / str(run_id)))
                          for run_id in unclaimed_runs(view, self._tenant, io=self._io)]
        except BaseException:
            self.__exit__()
            raise
        return self

    def __exit__(self, *_exc: object) -> None:
        self._state = "closed"
        self._stack.close()

    def __iter__(self) -> Iterator[tuple[RunId, RunRow]]:
        self.require_open("iterating its rows")
        return iter(list(self._rows))


def bound_runs(tenant: Tenant, *, io: Any = _io) -> BoundRuns:
    """The tenant's runs as rows over one held handle: `with bound_runs(t) as runs: for
    run_id, row in runs: row.read(name)`. See `BoundRuns`."""
    return BoundRuns(require_accepted_tenant(tenant), io)
