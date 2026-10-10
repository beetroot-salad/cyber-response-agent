"""The tenant-scoped runs repository (#1105 PR 2, decision C) and run lookup (#1105 D2).

The accepted `Tenant` hands out its repository — `runs = tenant.runs_repository()` — bound to
that tenant; below it everything is ids. No method takes a `Tenant`, a folder or a path from its
caller, and none reads the environment (rev 4 S2): the natural container is always
`tenant.runs`, and an episode's container is reached only through `runs.episode(episode_id)`,
which asks the episode owner (the one reader of `DEFENDER_EPISODES_BASE`) for the episode.

* natural container: `runs.open(run_id) -> Run`, `runs.list() -> Listed`,
  `runs.exists(run_id)`, `runs.create(run_id)`, `runs.resolve(address) -> Run`;
* the episode view `runs.episode(episode_id) -> EpisodeRuns`: `open`, `list`, `create`,
  `create_container`, `base_world_id`, `arm_id`, and `episode`, the owner's handle;
* `runs.episode_files(episode_id) -> Episode`: the owner's handle alone (the judge's door);
* `RunAddress(tenant_id, run_id, episode_id | None)`: the stored and transported address.

Each lookup opens its container ONCE, no-follow (`_held.hold_runs`), and does every read
relative to that handle, closing it before it returns. One held handle is how a link at the
container itself is refused, and how one call's listing, tenant record and claims all come from
one folder; it is not race protection (P1: the host is not malicious).

P2: an unexpected state raises one named error — `TenantRefused` for a container and its
`_tenant.json`, `RunRefused` for everything else (`RunAbsent`, its subclass, for nothing at a
run's name) — naming the path and the fault, at the first failed check, before any write. The
expected states, and only these, answer normally: an absent container (empty answers), an
absent `_episodes` (no claims), and the known sidecar files beside run folders, a sidecar
write's staged file included. Each method judges what it reads: `open` and `exists` do not read
`_episodes`, so its state does not refuse them.
"""
from __future__ import annotations

import dataclasses
import stat
from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING, Any

from defender import _io
from defender._shown import quoted
from defender._tenant import (
    Tenant, TenantId, TenantRecord, TenantRefused, ensure_runs_base_record,
)
from defender.run_repository import _record
from defender.run_repository._errors import RunAbsent, RunRefused
from defender.run_repository._handle import Run
from defender.run_repository._held import (
    HeldRuns, hold_runs, hold_runs_folder, refuse_sidecar_id, require_accepted_tenant,
    require_run_id,
)
from defender.run_repository._id import RunId

if TYPE_CHECKING:
    from defender._episode_handle import Episode

# -- the rules, over one container (H1–H6) -------------------------------------------------------


def _unclaimed(runs: HeldRuns) -> list[RunId]:
    """The held folder's runs minus every id a good episode record claims (D2's listings)."""
    claimed = _record.claimed_ids(runs)
    return [run_id for run_id in runs.listing().runs if run_id not in claimed]


def _open(tenant: Tenant, folder: Path, run_id: RunId, io: Any) -> Run:
    """The run `run_id` of `tenant` in the container `folder`, as a `Run` addressed
    `(tenant.id, run_id)`.

    In order: the id's type; the sidecar clause; the held folder (absent is `TenantRefused`);
    its tenant record; the entry `<folder>/<run_id>`, which must be a real directory — nothing
    there is `RunAbsent`, anything else `RunRefused`, each naming the path. The handle is built
    by `Run.under` (DV-2): the record was judged through the held folder, and `Run.for_tenant`
    would read it a second time, by path. A handed-out `Run` is not checked again (NF-12).
    `_episodes` is not read: whether a sibling may be opened is its caller's."""
    run_id = require_run_id(run_id)
    refuse_sidecar_id(run_id)
    name = str(run_id)
    with hold_runs(tenant, io, folder=folder) as runs:
        entry = io.stat_entry(runs.require_present().view, name)
        path = runs.folder / name
        if entry.st is None:
            if entry.absent:
                raise RunAbsent(f"{path} is absent")
            raise RunRefused(f"{path} could not be judged: {entry.reason}")
        if not stat.S_ISDIR(entry.st.st_mode):
            raise RunRefused(f"{path} is not a real directory (a link, a file or another "
                             "entry) — it is never followed or opened as a run")
    return Run.under(folder, name, io=io, tenant_id=tenant.id)


@dataclasses.dataclass(frozen=True)
class Listed:
    """A container's runs, as a listing answers them: the run ids in text order (iterate the
    value), `absent` when the container does not exist — an empty one is not absent (R51-05) —
    and, from an episode view, `unreadable`: why a container that is there (a link, a
    non-directory) could not be held, `None` when it could."""

    ids: tuple[RunId, ...] = ()
    absent: bool = False
    unreadable: str | None = None

    def __iter__(self) -> Iterator[RunId]:
        return iter(self.ids)

    def __len__(self) -> int:
        return len(self.ids)


def _list(tenant: Tenant, folder: Path, io: Any, *, record_unreadable: bool) -> Listed:
    """The container's runs, sorted by text, minus every id a good episode record claims.
    Every entry is judged (rev 4.1 H4): a stray refuses the listing, naming it. An absent
    container is `Listed(absent=True)`; one that cannot be held raises `TenantRefused`, or with
    `record_unreadable` (an episode's container) answers `Listed(unreadable=<why>)`."""
    try:
        held = hold_runs_folder(folder, io=io)
    except FileNotFoundError:
        return Listed(absent=True)
    except TenantRefused as unholdable:
        if not record_unreadable:
            raise
        return Listed(unreadable=str(unholdable))
    try:
        return Listed(tuple(_unclaimed(HeldRuns(tenant, held, io, folder=folder))))
    finally:
        held.close()


def _exists(tenant: Tenant, run_id: RunId, io: Any) -> bool:
    """Whether `run_id` is taken in the tenant's runs folder (`Listing.holds`, the record
    writer's definition too): a run stands there, sidecar files owned by that id stand beside
    it (its folder gone or not), or a sidecar file is named exactly `run_id`. An occupancy
    answer, so the sidecar clause is not applied to `run_id`. `False` when the folder is
    absent. The whole listing is judged, so an unexpected entry refuses, save `_tenant.json`
    and `_episodes`, whose kind is judged only where they are read: `_episodes` is not read
    here."""
    run_id = require_run_id(run_id)
    with hold_runs(tenant, io) as runs:
        if runs.absent:
            return False
        return runs.listing().holds(run_id)


def _refuse_claimed(view: _io.Bound, folder: Path, run_id: RunId, io: Any) -> None:
    """Refuse a pinned `run_id` an episode record in the held runs folder claims: that id names
    a sibling, not a run of its own (#1105 D3.7, moved here from run setup unchanged). No
    tenant compare (the record step has already judged `_tenant.json`), so a record naming
    another tenant still claims — the fail-safe direction. A corrupt record, or anything else in
    `_episodes` that is not a record, refuses every pinned id."""
    claimed = _record.episode_sibling_ids(view, where=str(folder), io=io)
    if run_id in claimed:
        raise RunRefused(f"run id {str(run_id)!r} is claimed by an episode record in "
                         f"{folder} — it names an episode's sibling run; pick a fresh id")


# -- the stored address --------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class RunAddress:
    """Where a run lives, as it is stored or transported (curation rows, the sibling's argv):
    the tenant, the run, and the episode for an arm (`None` for a natural run). Every field is
    checked at construction — `TenantId`'s grammar, `RunId`'s rules, the episode owner's id rule
    — so a bad stored field never reaches a lookup; and it is frozen. To rehydrate one: accept
    its `tenant_id`, then `tenant.runs_repository().resolve(address)`."""

    tenant_id: TenantId
    run_id: RunId
    episode_id: str | None = None

    def __post_init__(self) -> None:
        from defender._episode_handle import refuse_bad_episode_id

        object.__setattr__(self, "tenant_id", TenantId(self.tenant_id))
        run_id: object = self.run_id
        object.__setattr__(self, "run_id",
                           run_id if isinstance(run_id, RunId) else RunId.parse(run_id))
        if self.episode_id is not None:
            object.__setattr__(self, "episode_id", refuse_bad_episode_id(self.episode_id))


# -- the repository ------------------------------------------------------------------------------


class RunsRepository:
    """The runs of ONE accepted tenant, by id — built only by `Tenant.runs_repository()` (the
    constructor is gated outside the package; anything but an accepted `Tenant` is a
    `TypeError`). It holds that tenant and reads no environment; see the module docstring."""

    def __init__(self, tenant: Tenant, *, io: Any = _io) -> None:
        self._tenant = require_accepted_tenant(tenant)
        self._io = io
        #: The natural container's record as `create` ensured it under its hold: write-once,
        #: so `base_world_id` answers from it without holding the container a second time.
        self._created: TenantRecord | None = None

    @property
    def tenant_id(self) -> TenantId:
        return self._tenant.id

    def open(self, run_id: RunId) -> Run:
        """The tenant's run `run_id` in its natural container (PR 1's `open_run` rule)."""
        return _open(self._tenant, Path(self._tenant.runs), run_id, self._io)

    def list(self) -> Listed:
        """The tenant's natural runs (PR 1's `list_run_ids` rule), telling an absent container
        from an empty one. A container that cannot be held refuses (`TenantRefused`)."""
        return _list(self._tenant, Path(self._tenant.runs), self._io, record_unreadable=False)

    def exists(self, run_id: RunId) -> bool:
        """Whether `run_id` is taken in the tenant's natural container (PR 1's `run_exists`)."""
        return _exists(self._tenant, run_id, self._io)

    def create(self, run_id: RunId, *, pinned: bool = False) -> Run:
        """The `Run` run setup builds at `run_id` in the tenant's natural container (D-create
        (a)), in today's order: the container held no-follow — made when absent, a link or a
        non-directory refused (`TenantRefused`); its `_tenant.json` ensured naming the tenant
        (minted when absent, refused when it names another); for a `pinned` id, the claimed-id
        check (`RunRefused`); then the handle, whose record compare is the race backstop. The
        run folder itself is not made here."""
        run_id = require_run_id(run_id)
        folder = Path(self._tenant.runs)
        with hold_runs_folder(folder, create=True, io=self._io) as held:
            record = ensure_runs_base_record(folder, self._tenant.id, io=self._io)
            if pinned:
                _refuse_claimed(held.view(), folder, run_id, self._io)
        self._created = record
        return Run.for_tenant(record.tenant_id, run_id, runs_base=folder, io=self._io)

    def base_world_id(self) -> str:
        """The natural container record's `base_world_id` — the world a natural run is stamped
        with. After a `create`, the record that create ensured (run setup holds the container
        once); otherwise read through the held container once its tenant is judged. An absent
        container refuses (`TenantRefused`): `create` makes it first."""
        if self._created is not None:
            return self._created.base_world_id
        with hold_runs(self._tenant, self._io) as held:
            return held.require_present().record().base_world_id

    def resolve(self, address: RunAddress) -> Run:
        """The run a stored `address` names, in this repository. An address naming another
        tenant is refused (`TenantRefused`, G22) before anything is read — the caller accepts
        the address's own tenant and resolves there. An arm's address (one carrying an episode
        id) is refused: no stored or transported address carries one (#1105 F-13)."""
        if not isinstance(address, RunAddress):
            raise TypeError(f"resolve takes a RunAddress, not {type(address).__name__}")
        if address.tenant_id != self._tenant.id:
            raise TenantRefused(
                f"the address of run {quoted(str(address.run_id))} names the tenant "
                f"{quoted(address.tenant_id)}, not this repository's "
                f"{quoted(self._tenant.id)} — accept its own tenant to resolve it")
        if address.episode_id is not None:
            raise RunRefused(
                f"the address of run {quoted(str(address.run_id))} names episode "
                f"{quoted(address.episode_id)}: an arm is opened through its episode "
                "(runs.episode(episode_id).open), never from a stored address")
        return self.open(address.run_id)

    def episode(self, episode_id: str, *, held: Episode | None = None,
                container_required: bool = False) -> EpisodeRuns:
        """The episode `episode_id`'s view: its container `runs/` and the arms in it, under this
        tenant. The episode is opened through the episode owner from `(tenant.data_root,
        episode_id)` — a bad id or an unusable episodes root is `EpisodeRefused`, a missing
        episode `FileNotFoundError` — or `held`, the handle the owner already handed this same
        request (the launcher's claim, the sibling's open before acceptance), is adopted.

        A PRESENT container's `_tenant.json` is judged at once, before anything else of the
        episode is read: one naming another tenant is `TenantRecordMismatch`, a missing or
        corrupt one `TenantRefused` (old episodes, launched before #1078, are not supported).
        An ABSENT container has nothing to judge; an UNREADABLE one (a link, a non-directory) is
        recorded, not raised — unless `container_required` (a sibling), where either refuses
        with `TenantRefused`."""
        return EpisodeRuns(self._tenant, episode_id, held=held,
                           container_required=container_required, io=self._io)

    def episode_files(self, episode_id: str) -> Episode:
        """The episode owner's handle on `episode_id` alone, opened under the tenant's data
        root and reading nothing in `runs/` (C-26): the judge's door. Refusals are the owner's
        (`EpisodeRefused`, `FileNotFoundError`, `NotADirectoryError`); nothing is created. The
        caller closes it."""
        from defender._episode_handle import Episode

        return Episode.open_in(self._tenant.data_root, episode_id)


#: An episode container's states, as the view records them when it opens.
PRESENT, ABSENT, UNREADABLE = "present", "absent", "unreadable"


class EpisodeRuns:
    """One episode's container and its arms, under one tenant: the narrower scope
    `RunsRepository.episode` hands out (see there). Built on the episode owner's handle
    (`episode`), which has the episode folder's own files; this view has `runs/`.

    The container is re-held, no-follow, by every call that reads or writes it, so a view
    opened before the container exists serves it once `create_container()` has made it. `state`
    is what the view found when it opened (or made): `present`, `absent` or `unreadable` (and
    then `unreadable_reason`). A context manager: leaving it closes the episode handle when the
    view opened it (an adopted handle stays its owner's to close)."""

    def __init__(self, tenant: Tenant, episode_id: str, *, held: Episode | None,
                 container_required: bool, io: Any) -> None:
        from defender._episode_handle import Episode, refuse_bad_episode_id
        from defender._episode_paths import LAYOUT

        self._tenant = tenant
        self._io = io
        self.episode_id = refuse_bad_episode_id(episode_id)
        if held is None:
            self.episode = Episode.open_in(tenant.data_root, self.episode_id)
            self._owns = True
        else:
            if not isinstance(held, Episode) or held.dir.name != self.episode_id:
                raise TypeError(f"the adopted episode handle is not episode "
                                f"{quoted(self.episode_id)}'s")
            self.episode = held
            self._owns = False
        self._folder = Path(self.episode.dir) / LAYOUT.runs
        self.state = PRESENT
        self.unreadable_reason: str | None = None
        try:
            self._judge(container_required=container_required)
        except BaseException:
            self.close()
            raise

    def _judge(self, *, container_required: bool) -> None:
        """Record the container's state, judging a present one's `_tenant.json` (G20)."""
        try:
            held = hold_runs_folder(self._folder, io=self._io)
        except FileNotFoundError:
            self.state = ABSENT
        except TenantRefused as unholdable:
            self.state, self.unreadable_reason = UNREADABLE, str(unholdable)
        else:
            try:
                HeldRuns(self._tenant, held, self._io, folder=self._folder).judged()
            finally:
                held.close()
        if container_required and self.state != PRESENT:
            why = (self.unreadable_reason if self.state == UNREADABLE
                   else f"{self._folder} is absent")
            raise TenantRefused(
                f"episode {quoted(self.episode_id)} has no container its tenant record binds "
                f"to {quoted(self._tenant.id)} ({why}) — an arm runs only in a container the "
                "launcher made for its tenant before the first sibling")

    @property
    def present(self) -> bool:
        """Was the container there, and judged, when the view opened (or made it)?"""
        return self.state == PRESENT

    def close(self) -> None:
        if self._owns:
            self.episode.close()

    def __enter__(self) -> EpisodeRuns:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def arm_id(self, label: str) -> RunId:
        """The arm `label`'s run id, `<episode_id>-<label>` — the one arm-id composition the
        repository makes, temporary until #1187. A label `RunId.parse` refuses is
        `RunRefused`."""
        return RunId.parse(f"{self.episode_id}-{label}")

    def open(self, arm_id: RunId) -> Run:
        """The arm `arm_id`, as `RunsRepository.open` answers in the natural container. An
        absent or unreadable container refuses (`TenantRefused`)."""
        return _open(self._tenant, self._folder, arm_id, self._io)

    def list(self) -> Listed:
        """The container's arms (every entry judged, H4); `absent` or `unreadable` (recorded,
        not raised) when the container is either."""
        return _list(self._tenant, self._folder, self._io, record_unreadable=True)

    def create(self, arm_id: RunId) -> Run:
        """The `Run` run setup builds for arm `arm_id` (D-create (a)). The container must
        already be there and name the tenant — an arm is never made in a container nobody
        bound (G5): absent, unreadable, recordless or foreign refuses (`TenantRefused`) and
        nothing is made. The run folder itself is not made here."""
        arm_id = require_run_id(arm_id)
        with hold_runs(self._tenant, self._io, folder=self._folder) as held:
            held.require_present().judged()
        return Run.for_tenant(self._tenant.id, arm_id, runs_base=self._folder, io=self._io)

    def create_container(self) -> None:
        """Make the container with the tenant's record (D-create (b)), as the launcher does at
        RUNS before the first arm: `runs/` made through the held episode — a link or a
        non-directory there refused before any record is minted (G25) — then its
        `_tenant.json` ensured naming the tenant (a record naming another is refused). A
        container already there is adopted (C-19)."""
        try:
            self.episode._runs.ensure()  # noqa: SLF001 — the view is built on the owner's handle; its container folder is the view's alone
        except OSError as refused:
            raise TenantRefused(f"the episode container {self._folder} could not be made: "
                                f"{refused}") from refused
        ensure_runs_base_record(self._folder, self._tenant.id, io=self._io)
        self.state, self.unreadable_reason = PRESENT, None

    def base_world_id(self) -> str:
        """The container record's own `base_world_id` (P5-02), read through the held container
        once its tenant is judged. An absent or unreadable container refuses."""
        with hold_runs(self._tenant, self._io, folder=self._folder) as held:
            return held.require_present().record().base_world_id
