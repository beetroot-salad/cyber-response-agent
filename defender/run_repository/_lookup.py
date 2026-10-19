"""The tenant-scoped runs repository (#1105 PR 2, decision C) and run lookup (#1105 D2).

The accepted `Tenant` hands out its repository — `runs = tenant.runs_repository()` — bound to
that tenant; below it everything is ids. No method takes a `Tenant`, a folder or a path from its
caller, and none reads the environment (rev 4 S2): the natural container is always
`tenant.runs`, and an episode's container is reached only through `runs.episode(episode_id)`,
which asks the episode owner (the one reader of `DEFENDER_EPISODES_BASE`) for the episode.

* natural container: `runs.open(run_id) -> Run`, `runs.list() -> Listed`,
  `runs.all_runs() -> list[Run]`, `runs.create(run_id)`, `runs.resolve(address) -> Run`;
* the episode view `runs.episode(episode_id) -> EpisodeRuns`: `open`, `arms`, `create`,
  `create_container`, `base_world_id`, `arm_id`, and `episode`, the owner's handle;
* `open_requested_run(data_root, tenant, run_id)`: a command line's `--tenant T <run_id>`,
  opened, or its refusal as text;
* `runs.episode_files(episode_id) -> Episode`: the owner's handle, its container's tenant
  record judged as `episode` judges it (the judge's door);
* `RunAddress(tenant_id, run_id, episode_id | None)`: the stored and transported address.

Each lookup opens its container ONCE, no-follow (`_hand_out`, `_held.hold_runs`), and does
every read relative to that handle, closing it before it returns. One held handle is how a link at the
container itself is refused, and how one call's listing, tenant record and claims all come from
one folder; it is not race protection (P1: the host is not malicious).

P2: an unexpected state raises one named error — `TenantRefused` for a container and its
`_tenant.json`, `RunRefused` for everything else — naming the path and the fault, at the first
failed check, before any write. Opening a run is the exception: `open` (natural and episode)
and `resolve` answer one family, `RunRefused`, of three kinds — `RunAbsent` when the run is
gone (nothing at its name, or no container), `RunUnreachable` (raised from the container's
`TenantRefused`) when the container cannot be trusted or read right now (a link, a
non-directory, a `_tenant.json` missing, corrupt or another tenant's), and a plain `RunRefused`
when the entry itself is refused (a link or a file at the name, a bad id) — so a caller handles
one family and cannot forget the other (#1105 PR 2 review). `resolve`'s refusal of another
tenant's address stays `TenantRefused`: that is a caller's bug, not a state of the run. `list`,
`runs`, `create`, `base_world_id` and `create_container` keep `TenantRefused` for the container.
The expected states, and only these, answer normally: an absent container (empty answers), an
absent `_episodes` (no claims), and the known sidecar files beside run folders, a sidecar
write's staged file included. Each method judges what it reads: `open` does not read
`_episodes`, so its state does not refuse it.
"""
from __future__ import annotations

import builtins
import contextlib
import dataclasses
import stat
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from defender import _io
from defender._shown import escaped, quoted
from defender.tenancy._tenant import (
    Tenant, TenantId, TenantRecord, TenantRefused, ensure_runs_base_record,
)
from defender.run_repository import _record
from defender.run_repository._errors import RunAbsent, RunRefused, RunUnreachable
from defender.run_repository._handle import Run
from defender.run_repository._held import (
    HeldRuns, hold_runs, hold_runs_folder, refuse_sidecar_id, require_accepted_tenant,
    require_run_id,
)
from defender.run_repository._id import RunId

if TYPE_CHECKING:
    from defender.episodes._episode_handle import Episode

# -- the rules, over one container (H1–H6) -------------------------------------------------------


def _unclaimed(runs: HeldRuns) -> list[RunId]:
    """The held folder's runs minus every id a good episode record claims (D2's listings)."""
    claimed = _record.claimed_ids(runs)
    return [run_id for run_id in runs.listing().runs if run_id not in claimed]


def _unreachable_run(folder: Path, run_id: RunId, fault: TenantRefused) -> RunUnreachable:
    """Run `run_id`'s refusal when its container cannot be held or its record does not name
    the tenant: `RunUnreachable`, raised from (here: caused by) the container's refusal."""
    refused = RunUnreachable(f"{Path(folder) / str(run_id)} cannot be reached: {fault}")
    refused.__cause__ = fault
    return refused


def _at_entry(runs: HeldRuns, run_id: RunId, io: Any) -> Run | RunRefused:
    """The run at `<folder>/<run_id>` of the held, judged folder, judged from its own entry
    (never followed): a real directory is the `Run` (built by `Run.under`: the record was
    judged through the held folder, and `Run.for_tenant` would read it again, by path);
    nothing there is `RunAbsent`; anything else a `RunRefused` naming the path."""
    name = str(run_id)
    path = runs.folder / name
    entry = io.stat_entry(runs.view, name)
    if entry.st is None:
        if entry.absent:
            return RunAbsent(f"{path} is absent")
        return RunRefused(f"{path} could not be judged: {entry.reason}")
    if not stat.S_ISDIR(entry.st.st_mode):
        return RunRefused(f"{path} is not a real directory (a link, a file or another entry) "
                          "— it is never followed or opened as a run")
    return Run.under(runs.folder, name, io=io, tenant_id=runs.tenant.id)


class Handout:
    """One hold's answer (`_hand_out`): a `Run`, or that id's `RunRefused`, per id in order,
    and — for the block only — a no-follow reader over each run handed out, walked from the
    held folder (no second hold). `absent` when the container was not there."""

    def __init__(self, answers: dict[RunId, Run | RunRefused], *, absent: bool = False,
                 view: _io.Bound | None = None) -> None:
        self._answers = answers
        self.absent = absent
        self._view = view

    def __getitem__(self, run_id: RunId) -> Run | RunRefused:
        return self._answers[run_id]

    def ids(self) -> builtins.list[RunId]:
        return builtins.list(self._answers)

    def values(self) -> builtins.list[Run | RunRefused]:
        return builtins.list(self._answers.values())

    def reader(self, run_id: RunId) -> _io.Bound:
        """A no-follow reader over the run `run_id` this hold handed out, as `Run.reader()`
        gives one but walked from the held folder (valid inside the `with` block only). An id
        that was refused, or a hold that judged nothing, refuses (`RunRefused`)."""
        answer = self._answers[run_id]
        if isinstance(answer, RunRefused):
            raise answer
        if self._view is None:
            raise RunRefused(f"run {quoted(str(run_id))} was not handed out by a held folder")
        return self._view.under(str(run_id))


@contextlib.contextmanager
def _hand_out(tenant: Tenant, folder: Path, io: Any,
              run_ids: Sequence[RunId] | None = None) -> Iterator[Handout]:
    """The one single-hold routine (#1105 PR 2 review): `folder` held ONCE, no-follow, its
    `_tenant.json` judged ONCE through that hold, and a `Run` handed out per id — every lookup
    of runs (`open`, `list`, `all_runs`, an episode view's `open` and `arms`) goes through it.

    * `run_ids` `None` — the listing: every run the held folder holds, minus the ids a good
      episode record claims, sorted by text. The listing judges every entry (a stray refuses
      it, `RunRefused`); a container that cannot be held or judged raises `TenantRefused`; an
      absent one is `absent` with no runs.
    * `run_ids` given — each id judged at its own entry (`_at_entry`), so one arm's entry
      never spoils another's; a sidecar-shaped id is that id's `RunRefused`. The container's
      own faults are every id's: absent is `RunAbsent` (the run is gone with it), one that
      cannot be held or whose record does not name the tenant `RunUnreachable`.

    The handle is closed when the block ends; the handed-out `Run`s outlive it."""
    folder = Path(folder)
    asked = None if run_ids is None else [require_run_id(r) for r in run_ids]
    held: _io.Held | None = None
    unholdable: TenantRefused | None = None
    try:
        held = hold_runs_folder(folder, io=io)
    except FileNotFoundError:
        pass
    except TenantRefused as fault:
        if asked is None:
            raise
        unholdable = fault
    if held is None:
        if asked is None:
            yield Handout({}, absent=True)
        elif unholdable is not None:
            yield Handout({r: _unreachable_run(folder, r, unholdable) for r in asked})
        else:
            yield Handout({r: RunAbsent(f"{folder / str(r)} is absent: its runs folder "
                                        f"{folder} is absent") for r in asked}, absent=True)
        return
    try:
        runs = HeldRuns(tenant, held, io, folder=folder)
        answers: dict[RunId, Run | RunRefused]
        view: _io.Bound | None = None
        if asked is None:
            answers = {r: Run.under(folder, str(r), io=io, tenant_id=tenant.id)
                       for r in _unclaimed(runs)}
            view = runs.view
        else:
            try:
                view = runs.judged()
            except TenantRefused as fault:
                answers = {r: _unreachable_run(folder, r, fault) for r in asked}
            else:
                answers = {r: refused if (refused := _id_refusal(r)) is not None
                           else _at_entry(runs, r, io) for r in asked}
        yield Handout(answers, view=view)
    finally:
        held.close()


def _id_refusal(run_id: RunId) -> RunRefused | None:
    """`refuse_sidecar_id`'s refusal of `run_id` as a value, or `None`."""
    try:
        refuse_sidecar_id(run_id)
    except RunRefused as refused:
        return refused
    return None


def _open(tenant: Tenant, folder: Path, run_id: RunId, io: Any) -> Run:
    """The run `run_id` of `tenant` in the container `folder`, as a `Run` addressed
    `(tenant.id, run_id)` — `_hand_out` over the one id, its refusal raised.

    In order: the id's type; the sidecar clause; the held folder — absent is `RunAbsent` (the
    run is gone with it), one that cannot be held or whose tenant record does not name the
    tenant is `RunUnreachable`, raised from the `TenantRefused` that judged it; the entry
    `<folder>/<run_id>`, which must be a real directory — nothing there is `RunAbsent`,
    anything else `RunRefused`, each naming the path. So the only refusal is `RunRefused` (see
    the module docstring). A handed-out `Run` is not checked again (NF-12). `_episodes` is not
    read: whether a sibling may be opened is its caller's."""
    run_id = require_run_id(run_id)
    refuse_sidecar_id(run_id)
    with _hand_out(tenant, folder, io, [run_id]) as out:
        answer = out[run_id]
    if isinstance(answer, RunRefused):
        raise answer
    return answer


@dataclasses.dataclass(frozen=True)
class Listed:
    """A container's runs, as a listing answers them: the run ids in text order (iterate the
    value), and `absent` when the container does not exist — an empty one is not absent
    (R51-05)."""

    ids: tuple[RunId, ...] = ()
    absent: bool = False

    def __iter__(self) -> Iterator[RunId]:
        return iter(self.ids)

    def __len__(self) -> int:
        return len(self.ids)


def _list_container(tenant: Tenant, folder: Path, io: Any) -> Listed:
    """The container's runs, sorted by text, minus every id a good episode record claims
    (`_hand_out`'s listing). Every entry is judged (rev 4.1 H4): a stray refuses the listing,
    naming it. An absent container is `Listed(absent=True)`; one that cannot be held raises
    `TenantRefused`."""
    with _hand_out(tenant, folder, io) as out:
        return Listed(absent=True) if out.absent else Listed(tuple(out.ids()))


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
        from defender.episodes._episode_handle import refuse_bad_episode_id

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
        """The tenant's run `run_id` in its natural container (PR 1's `open_run` rule). Every
        refusal is a `RunRefused`: `RunAbsent`, `RunUnreachable` or a refused entry (see the
        module docstring)."""
        return _open(self._tenant, Path(self._tenant.runs), run_id, self._io)

    def list(self) -> Listed:
        """The tenant's natural runs (PR 1's `list_run_ids` rule), telling an absent container
        from an empty one. A container that cannot be held refuses (`TenantRefused`)."""
        return _list_container(self._tenant, Path(self._tenant.runs), self._io)

    def all_runs(self) -> builtins.list[Run]:
        """Every run `list()` answers, as a `Run` addressed `(tenant, run_id)`, in the same
        order — from ONE hold of the container, whose `_tenant.json` is judged once
        (`_hand_out`'s listing), rather than a hold and a record read per run. The listing
        judged every entry (a run is a real directory there), so each handle is built with no
        further read: the listing is the snapshot (P1), and a run removed after it is still
        handed out, its records then reading as absent — nothing here raises for it, as a
        per-id `open` would. An absent container holds none; one that cannot be held, or whose
        record does not name the tenant, refuses (`TenantRefused`), as `list` does."""
        with _hand_out(self._tenant, Path(self._tenant.runs), self._io) as out:
            return [cast(Run, run) for run in out.values()]

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
        with hold_runs(self._tenant, self._io, folder=Path(self._tenant.runs)) as held:
            return held.require_present().record().base_world_id

    def resolve(self, address: RunAddress) -> Run:
        """The run a stored `address` names, in this repository, refused as `open` refuses
        (`RunRefused`). An address naming another tenant is refused (`TenantRefused`, G22)
        before anything is read — a caller's bug, not a state of the run: the caller accepts
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
        """The episode owner's handle on `episode_id`, opened under the tenant's data root:
        the judge's door. Its container is judged as `episode` judges it (the same view's
        judgement, G20): a PRESENT container whose `_tenant.json` names another tenant is
        `TenantRecordMismatch`, a missing or corrupt one `TenantRefused`; an absent or
        unreadable container is not this door's to refuse. Nothing else in `runs/` is read.
        The owner's refusals are its own (`EpisodeRefused`, `FileNotFoundError`,
        `NotADirectoryError`); nothing is created. The caller closes the handle."""
        view = EpisodeRuns(self._tenant, episode_id, held=None, container_required=False,
                           io=self._io)
        # The view's one resource is the episode handle, handed to the caller to close.
        return view.episode


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
        from defender.episodes._episode_handle import Episode, episode_dir, refuse_bad_episode_id
        from defender.episodes._episode_paths import LAYOUT

        self._tenant = tenant
        self._io = io
        self.episode_id = refuse_bad_episode_id(episode_id)
        if held is None:
            self.episode = Episode.open(episode_dir(tenant.data_root, self.episode_id))
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
        """Record the container's state, judging a present one's `_tenant.json` (G20). A
        container that cannot be held (a link, a non-directory) or, held, cannot be listed (its
        permissions) is recorded unreadable — read as absent by the page (rev 5.1 S1) — and its
        record is never read; a listable one with no record, or another tenant's, refuses."""
        try:
            held = hold_runs_folder(self._folder, io=self._io)
        except FileNotFoundError:
            self.state = ABSENT
        except TenantRefused as unholdable:
            self.state, self.unreadable_reason = UNREADABLE, str(unholdable)
        else:
            try:
                listed = held.view().entries()
                if listed.absent:
                    self.state = ABSENT
                elif listed.entries is None:
                    self.state = UNREADABLE
                    self.unreadable_reason = (f"the container {self._folder} cannot be listed: "
                                              f"{listed.reason}")
                else:
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

    def arm_id(self, label: str, *, episode_id: str | None = None) -> RunId:
        """The arm `label`'s run id, `<episode_id>-<label>` — the one arm-id composition the
        repository makes, temporary until #1187. A label `RunId.parse` refuses is
        `RunRefused`. `episode_id` is the id the arms were launched under when the caller holds
        the episode's own record of it and the view was opened by another name for the same
        folder (the page's `episodes/latest` link, #1025 J4); default: the view's id."""
        return RunId.parse(f"{self.episode_id if episode_id is None else episode_id}-{label}")

    def open(self, arm_id: RunId) -> Run:
        """The arm `arm_id`, as `RunsRepository.open` answers in the natural container: an
        absent container is `RunAbsent`, one that cannot be held or whose record does not name
        the tenant `RunUnreachable`."""
        return _open(self._tenant, self._folder, arm_id, self._io)

    @contextlib.contextmanager
    def arms(self, arm_ids: Sequence[RunId]) -> Iterator[Handout]:
        """Every arm of `arm_ids` from ONE hold of the container, its `_tenant.json` judged
        once (`_hand_out`): `handout[arm_id]` is the arm's `Run`, or the refusal `open` would
        raise for it — each arm judged at its own entry, the container's faults every arm's
        (`RunAbsent` when it is gone, `RunUnreachable` when it cannot be held or judged) — and
        `handout.reader(arm_id)` a no-follow reader over a handed-out arm, walked from the held
        container, for the block only."""
        with _hand_out(self._tenant, self._folder, self._io, arm_ids) as out:
            yield out

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


# -- a command line's request --------------------------------------------------------------------


def open_requested_run(data_root: Path, raw_tenant: str, raw_run_id: str, *,
                       episode_id: str | None = None) -> Run | str:
    """The run a command line's `--tenant T [--episode E] <run_id>` names — T accepted under
    `data_root` (the root its entry point resolved), then the run opened by id through T's
    repository: `runs.open`, or with `episode_id` the episode view's `open` (an arm). Neither
    follows a link at the run's name.

    The one opener those command lines share (#1105 PR 2 review). A refusal — the tenant's
    (`TenantRefused`), the run's (`RunRefused`), the episode's (`EpisodeRefused`, or the
    `OSError` of an episode folder that is not there) — is RETURNED as one line of text naming
    the request, never raised or logged: the command line prints it on stderr and exits with its
    own status (defender/CLAUDE.md: a refusal is a value, not a diagnostic)."""
    from defender.episodes._episode_handle import EpisodeRefused
    from defender.tenancy._tenant import requested_tenant

    try:
        tenant = requested_tenant(data_root, raw_tenant)
        runs = tenant.runs_repository()
        run_id = RunId.parse(raw_run_id)
        if episode_id is None:
            return runs.open(run_id)
        with runs.episode(episode_id) as view:
            return view.open(run_id)
    except (TenantRefused, RunRefused, EpisodeRefused, OSError) as refused:
        where = f" of episode {quoted(episode_id)}" if episode_id is not None else ""
        return (f"run {quoted(raw_run_id)}{where} of tenant {quoted(raw_tenant)} cannot be "
                f"opened: {escaped(refused)}")
