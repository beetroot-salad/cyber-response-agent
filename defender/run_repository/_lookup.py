"""Run lookup (#1105 D2): `open_run`, `list_run_ids`, `bound_runs` and `run_exists`, each over
one `_held.HeldRuns` (the held runs folder every lookup and record function works through).

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

import stat
from collections.abc import Iterator
from contextlib import ExitStack
from pathlib import Path
from typing import Any

from defender import _io
from defender._shown import shown
from defender._tenant import Tenant
from defender.run_repository import _record
from defender.run_repository._errors import RunRefused
from defender.run_repository._handle import Run
from defender.run_repository._held import (
    HeldRuns, hold_runs, refuse_sidecar_id, require_accepted_tenant, require_run_id,
)
from defender.run_repository._id import RunId

# -- the lookups (H6) ----------------------------------------------------------------------------


def _unclaimed(runs: HeldRuns) -> list[RunId]:
    """The held folder's runs minus every id a good episode record claims (D2's listings)."""
    claimed = _record.claimed_ids(runs)
    return [run_id for run_id in runs.listing().runs if run_id not in claimed]


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
    with hold_runs(tenant, io) as runs:
        entry = io.stat_entry(runs.require_present().view, name)
        path = runs.folder / name
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
    with hold_runs(tenant, io) as runs:
        return [] if runs.absent else _unclaimed(runs)


def run_exists(tenant: Tenant, run_id: RunId, *, io: Any = _io) -> bool:
    """Whether `run_id` is taken in the tenant's runs folder (`Listing.holds`, the record
    writer's definition too): a run stands there, sidecar files owned by that id stand beside
    it (its folder gone or not), or a sidecar file is named exactly `run_id`. An occupancy
    answer, so the sidecar clause is not applied to `run_id`. `False` when the
    folder is absent. The whole listing is judged, so an unexpected entry refuses, save
    `_tenant.json` and `_episodes`, whose kind is judged only where they are read: `_episodes`
    is not read here."""
    tenant = require_accepted_tenant(tenant)
    run_id = require_run_id(run_id)
    with hold_runs(tenant, io) as runs:
        if runs.absent:
            return False
        return runs.listing().holds(run_id)


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
            raise RunRefused(f"bound_runs over {self._tenant.runs}: {doing} outside its "
                             "with block")

    def __enter__(self) -> BoundRuns:
        if self._state != "new":
            raise RunRefused(f"bound_runs over {self._tenant.runs} is single use; enter a "
                             "fresh one")
        self._state = "open"
        try:
            runs = self._stack.enter_context(hold_runs(self._tenant, self._io))
            if runs.absent:
                self.absent = True
                return self
            self._rows = [(run_id, RunRow(self, run_id, runs.view.under(str(run_id)),
                                          runs.folder / str(run_id)))
                          for run_id in _unclaimed(runs)]
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
