"""The tenant-scoped runs repository (#1105 PR 2, decision C) and run lookup (#1105 D2)."""
from __future__ import annotations

from defender.records._locations import DataRoot

from defender.records._locations import (RunsBase, _unwrap_episodes_root, _unwrap_runs_base)

import builtins
import contextlib
import dataclasses
import errno
import json
import stat
from collections.abc import Callable, Iterator, Mapping, Sequence
from pathlib import Path
from typing import Any, cast

from defender import _io
from defender.records._episode_handle import Episode, EpisodeRefused, refuse_bad_episode_id
from defender.records._episode_paths import LAYOUT
from defender.records._run_id import mint_uuid, uuid_id_fault
from defender._shown import escaped, quoted
from defender.tenancy._tenant import Tenant, TenantId, TenantRefused
from defender.records._errors import RunAbsent, RunRefused, RunUnreachable
from defender.records._handle import Run
from defender.records._held import (
    RetirePlan, hold_level, listing, plan_retire, refuse_sidecar_id, require_accepted_tenant,
    require_run_id, tenant_levels, walk_from_tenant,
)
from defender.records._id import RunId

#: A container's opener: the folder held (the caller closes it), `FileNotFoundError` when a
#: level is absent, `TenantRefused` when one cannot be held.
_Hold = Callable[[], _io.Held]

# -- the rules, over one container (H1–H6) -------------------------------------------------------


def _unreachable_run(folder: Path, run_id: RunId, fault: TenantRefused) -> RunUnreachable:
    """Run `run_id`'s refusal when its container cannot be held: `RunUnreachable`, raised from
    (here: caused by) the level's refusal."""
    refused = RunUnreachable(f"{Path(folder) / str(run_id)} cannot be reached: {fault}")
    refused.__cause__ = fault
    return refused


def _at_entry(view: _io.Bound, folder: Path, tenant_id: TenantId, run_id: RunId,
              io: Any) -> Run | RunRefused:
    """The run at `<folder>/<run_id>` of the held folder `view` reads, judged from its own entry
    (never followed): a real directory is the `Run` (built by `Run.under`, with no further
    read); nothing there is `RunAbsent`; anything else a `RunRefused` naming the path."""
    name = str(run_id)
    path = Path(folder) / name
    entry = io.stat_entry(view, name)
    if entry.st is None:
        if entry.absent:
            return RunAbsent(f"{path} is absent")
        return RunRefused(f"{path} could not be judged: {entry.reason}")
    if not stat.S_ISDIR(entry.st.st_mode):
        return RunRefused(f"{path} is not a real directory (a link, a file or another entry) "
                          "— it is never followed or opened as a run")
    return Run.under(RunsBase(folder), name, io=io, tenant_id=tenant_id)


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
def _hand_out(tenant_id: TenantId, folder: Path, io: Any, hold: _Hold,
              run_ids: Sequence[RunId] | None = None) -> Iterator[Handout]:
    """The one single-hold routine (#1105 PR 2 review): the container `folder` held ONCE by
    `hold` (the walk, every level no-follow), and a `Run` handed out per id — every lookup of
    runs (`open`, `list`, `all_runs`, an episode view's `open` and `arms`) goes through it."""
    folder = Path(folder)
    asked = None if run_ids is None else [require_run_id(r) for r in run_ids]
    held: _io.Held | None = None
    unholdable: TenantRefused | None = None
    try:
        held = hold()
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
        view = held.view()
        answers: dict[RunId, Run | RunRefused]
        if asked is None:
            answers = {r: Run.under(RunsBase(folder), str(r), io=io, tenant_id=tenant_id)
                       for r in listing(view, folder, tenant_id, io=io).runs}
        else:
            answers = {r: refused if (refused := _id_refusal(r)) is not None
                       else _at_entry(view, folder, tenant_id, r, io) for r in asked}
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


def _open(tenant_id: TenantId, folder: Path, hold: _Hold, run_id: RunId, io: Any) -> Run:
    """The run `run_id` in the container `folder` (held by `hold`), as a `Run` addressed
    `(tenant_id, run_id)` — `_hand_out` over the one id, its refusal raised.

    In order: the id's type; the sidecar clause; the held folder — absent is `RunAbsent` (the
    run is gone with it), one that cannot be held is `RunUnreachable`, raised from the
    `TenantRefused` that judged it; the entry `<folder>/<run_id>`, which must be a real
    directory — nothing there is `RunAbsent`, anything else `RunRefused`, each naming the path.
    So the only refusal is `RunRefused` (see the module docstring). A handed-out `Run` is not
    checked again (NF-12)."""
    run_id = require_run_id(run_id)
    refuse_sidecar_id(run_id)
    with _hand_out(tenant_id, folder, io, hold, [run_id]) as out:
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

    @property
    def tenant(self) -> Tenant:
        """The accepted identity this repository carries, including its data-root layout."""
        return self._tenant

    @property
    def tenant_id(self) -> TenantId:
        return self._tenant.id

    def _natural(self, *, create: bool = False) -> _io.Held:
        """`<T>/runs`, walked from the tenant's folder (made when `create`)."""
        return walk_from_tenant(self._tenant, self._io,
                                tenant_levels(self._tenant, _unwrap_runs_base(self._tenant.runs)), create=create)

    def open(self, run_id: RunId) -> Run:
        """The tenant's run `run_id` in its natural container (PR 1's `open_run` rule). Every
        refusal is a `RunRefused`: `RunAbsent`, `RunUnreachable` or a refused entry (see the
        module docstring)."""
        return _open(self._tenant.id, Path(_unwrap_runs_base(self._tenant.runs)), self._natural, run_id, self._io)

    def list(self) -> Listed:
        """The tenant's natural runs (PR 1's `list_run_ids` rule), telling an absent container
        from an empty one. A container that cannot be held refuses (`TenantRefused`); an entry
        that is not a UUID run folder or a sidecar of one refuses (`RunRefused`, naming the
        one-time command that moves pre-#1187 entries aside)."""
        with _hand_out(self._tenant.id, Path(_unwrap_runs_base(self._tenant.runs)), self._io, self._natural) as out:
            return Listed(absent=True) if out.absent else Listed(tuple(out.ids()))

    def all_runs(self) -> builtins.list[Run]:
        """Every run `list()` answers, as a `Run` addressed `(tenant, run_id)`, in the same
        order — from ONE walk to the container (`_hand_out`'s listing), rather than a walk per
        run. The listing judged every entry (a run is a real directory there), so each handle
        is built with no further read: the listing is the snapshot (P1), and a run removed
        after it is still handed out, its records then reading as absent — nothing here raises
        for it, as a per-id `open` would. An absent container holds none; one that cannot be
        held refuses (`TenantRefused`), and a stray entry (`RunRefused`), as `list` does."""
        with _hand_out(self._tenant.id, Path(_unwrap_runs_base(self._tenant.runs)), self._io, self._natural) as out:
            return [cast(Run, run) for run in out.values()]

    def create(self) -> Run:
        """The `Run` run setup builds at a freshly minted id in the tenant's natural container
        (D-create (a)): `<T>/runs` walked from the tenant's folder no-follow and made when absent
        (a link or a non-directory at any level refuses, `TenantRefused`), then the handle. The
        id is minted here and never named by a caller (#1279 A3). No record is written (#1187
        R1) and no claim is read. The run folder itself is not made here."""
        self._natural(create=True).close()
        return Run.under(self._tenant.runs, RunId.mint(), io=self._io, tenant_id=self._tenant.id)

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

    # -- episodes -------------------------------------------------------------------------------

    def _walk_episode(self, episode_id: str) -> Episode:
        """`<T>/episodes/<episode_id>`, walked from the tenant's folder no-follow and wrapped in
        the owner's handle. Absent is `FileNotFoundError` naming the episode; a link or a
        non-directory at any level is `TenantRefused` naming that level."""
        path = Path(_unwrap_episodes_root(self._tenant.episodes)) / episode_id
        try:
            return Episode.open(path, io=_EpisodeWalk(self._tenant, self._io))
        except FileNotFoundError:
            raise FileNotFoundError(
                errno.ENOENT, f"tenant {quoted(self._tenant.id)} has no episode "
                f"{quoted(episode_id)}", str(path)) from None

    def create_episode(self) -> EpisodeRuns:
        """Claim a fresh episode: mint a UUID and make `<T>/episodes/<uuid>` with ONE exclusive
        create off the held `<T>/episodes` (itself made first when absent), every level walked
        from the tenant's folder no-follow (#1187 dc 3, O9). An entry already at the minted
        name refuses (`RunRefused`): a fresh UUID is never taken, so a collision means
        something is wrong, and nothing is retried. The view owns the episode handle; leaving
        it closes it."""
        episode_id = mint_uuid()
        path = Path(_unwrap_episodes_root(self._tenant.episodes)) / episode_id
        try:
            episode = Episode.create(path, io=_EpisodeWalk(self._tenant, self._io),
                                     exclusive=True)
        except FileExistsError:
            raise RunRefused(
                f"{path} already exists — a freshly minted episode id names nothing, so "
                "something else is wrong there; nothing is retried") from None
        except OSError as exc:
            raise TenantRefused(f"the episode folder {path} could not be made: "
                                f"{exc.strerror or exc}") from None
        return EpisodeRuns(self._tenant, episode_id, episode, owns=True, require_roster=False,
                           io=self._io)

    def episode(self, episode_id: str, *, held: Episode | None = None,
                require_roster: bool = False) -> EpisodeRuns:
        """The episode `episode_id`'s view: its arm container `runs/`, its arm roster and the
        arms, under this tenant. The id is judged first (`EpisodeRefused`: canonical UUID text
        only, before any path is built); then `<T>/episodes/<episode_id>` is walked from the
        tenant's folder no-follow — a link at any level is `TenantRefused` naming it, a missing
        episode `FileNotFoundError` (G23) — or `held`, the handle a caller already holds on
        this same episode, is adopted."""
        episode_id = refuse_bad_episode_id(episode_id)
        if held is None:
            return EpisodeRuns(self._tenant, episode_id, self._walk_episode(episode_id),
                               owns=True, require_roster=require_roster, io=self._io)
        if not isinstance(held, Episode) or held.dir.name != episode_id:
            raise TypeError(f"the adopted episode handle is not episode "
                            f"{quoted(episode_id)}'s")
        return EpisodeRuns(self._tenant, episode_id, held, owns=False,
                           require_roster=require_roster, io=self._io)

    def episode_files(self, episode_id: str) -> Episode:
        """The episode owner's handle on `episode_id` — the judge's door: the same walk as
        `episode`, and nothing in `runs/` read. A bad id is `EpisodeRefused`, a missing episode
        `FileNotFoundError`, a link or a non-directory at any level `TenantRefused`; nothing is
        created. The caller closes the handle."""
        return self._walk_episode(refuse_bad_episode_id(episode_id))

    def retire_plan(self, old_episodes_root: Path | None) -> RetirePlan:
        """The one-time command's plan for this tenant (#1187 Flow 6, `_held.plan_retire`):
        `runs/`'s pre-#1187 entries, and with `old_episodes_root` that folder's entries, each
        with its destination below `<T>`, and every fault found — nothing moved. A link at
        `<T>` or `<T>/runs` is `TenantRefused`. The caller closes the plan."""
        return plan_retire(self._tenant, old_episodes_root, io=self._io)


class _EpisodeWalk:
    """The episode doors' `io` seam as the repository hands it (#1187 S-iso): `Episode.open` /
    `Episode.create` take a folder handed down from the held `<T>`, never a path they resolve.
    `hold(folder)` walks `folder`'s levels from the tenant's folder, every one off its parent's
    handle and no-follow (`walk_from_tenant`); `hold_new(parent, name, exclusive=)` walks
    `parent` the same way (each missing level made) and then makes `name` off it, never
    followed — with `exclusive`, ONE mkdir that refuses any entry already there
    (`FileExistsError`), adopting nothing. A folder outside `<T>` is `ValueError`."""

    def __init__(self, tenant: Tenant, io: Any) -> None:
        self._tenant = tenant
        self._io = io

    def hold(self, root: Path) -> _io.Held:
        return walk_from_tenant(self._tenant, self._io, tenant_levels(self._tenant, root))

    def hold_new(self, parent: Path, name: str, *, exclusive: bool = False) -> _io.Held:
        held = walk_from_tenant(self._tenant, self._io, tenant_levels(self._tenant, parent),
                                create=True)
        try:
            if exclusive:
                return self._io.hold_under(held, name, exclusive=True)
            return hold_level(held, name, Path(parent) / name, io=self._io, create=True)
        finally:
            held.close()


# -- the episode view and its arm roster ---------------------------------------------------------

#: An episode container's states, as the view records them when it opens.
PRESENT, ABSENT, UNREADABLE = "present", "absent", "unreadable"

#: The largest roster the reader accepts, in bytes: one world UUID and one arm UUID per world.
_ROSTER_CAP = 65536


def _no_duplicate_keys(pairs: builtins.list[tuple[str, Any]]) -> dict[str, Any]:
    doc: dict[str, Any] = {}
    for key, value in pairs:
        if key in doc:
            raise ValueError(f"the world UUID {quoted(key)} appears twice")
        doc[key] = value
    return doc


def _encode_roster(arm_ids: Mapping[str, RunId]) -> str:
    """@owns arm roster text — canonical UUID-to-UUID JSON, sorted and newline-terminated."""
    return json.dumps({world_id: str(arm) for world_id, arm in arm_ids.items()},
                      indent=2, sort_keys=True) + "\n"


def _check_roster_size(size: int) -> None:
    if size > _ROSTER_CAP:
        raise RunRefused(f"the arm roster would be {size} bytes, over its {_ROSTER_CAP}-byte "
                         "reader budget")


def check_arm_roster_capacity(world_count: int) -> None:
    """Refuse a family whose future arm roster cannot fit the reader's byte budget.

    Every admitted key and value is canonical UUID text: the wire size depends only on
    world count. Derive entry width from the same encoder publication uses, without minting
    any identity or touching the filesystem. The nil UUID here is a sizing sample only.
    """
    if not isinstance(world_count, int) or isinstance(world_count, bool) or world_count < 1:
        raise RunRefused("an arm roster needs a positive integer world count")
    sample = RunId.parse("00000000-0000-0000-0000-000000000000")
    framing = len(_encode_roster({}).encode("utf-8"))
    entry = len(_encode_roster({str(sample): sample}).encode("utf-8")) - framing
    _check_roster_size(framing + world_count * entry)


def _roster_text(arm_ids: Mapping[str, RunId]) -> str:
    text = _encode_roster(arm_ids)
    _check_roster_size(len(text.encode("utf-8")))
    return text


class EpisodeRuns:
    """One episode's arm container, arm roster and arms, under one tenant: the narrower scope
    `RunsRepository.episode` hands out (see there). Built on the episode owner's handle
    (`episode`), which has the episode folder's own files; this view has `runs/` and
    `arms.json` (`LAYOUT.arm_roster`).

    The container is re-held off the episode's handle, no-follow, by every call that reads or
    writes it. `state` is what the view found when it opened: `present`, `absent` or
    `unreadable` (and then `unreadable_reason`). A context manager: leaving it closes the
    episode handle when the view opened it (an adopted handle stays its owner's to close)."""

    def __init__(self, tenant: Tenant, episode_id: str, episode: Episode, *, owns: bool,
                 require_roster: bool, io: Any) -> None:
        self._tenant = tenant
        self._io = io
        self.episode_id = episode_id
        self.episode = episode
        self._owns = owns
        self._folder = RunsBase(Path(episode.dir) / LAYOUT.runs)
        self._roster_path = Path(episode.dir) / LAYOUT.arm_roster
        self.state = PRESENT
        self.unreadable_reason: str | None = None
        try:
            self._judge()
            if require_roster:
                self._require_started()
        except BaseException:
            self.close()
            raise

    def _hold_container(self, *, create: bool = False) -> _io.Held:
        """`runs/` held off the episode's handle, never followed; absent is
        `FileNotFoundError`, a link or a non-directory `TenantRefused` naming it."""
        return hold_level(self.episode._held_folder(), LAYOUT.runs.as_posix(), _unwrap_runs_base(self._folder),  # noqa: SLF001 — the view is built on the owner's handle; its container is the view's alone
                          io=self._io, create=create, what="the arm container")

    def _judge(self) -> None:
        """Record the container's state. A container that cannot be held (a link, a
        non-directory) or, held, cannot be listed (its permissions) is recorded unreadable —
        read as absent by the page (rev 5.1 S1)."""
        try:
            held = self._hold_container()
        except FileNotFoundError:
            self.state = ABSENT
            return
        except TenantRefused as unholdable:
            self.state, self.unreadable_reason = UNREADABLE, str(unholdable)
            return
        try:
            listed = held.view().entries()
        finally:
            held.close()
        if listed.absent:
            self.state = ABSENT
        elif listed.entries is None:
            self.state = UNREADABLE
            self.unreadable_reason = (f"the arm container {_unwrap_runs_base(self._folder)} cannot be listed: "
                                      f"{listed.reason}")

    @property
    def present(self) -> bool:
        """Was the container there when the view opened?"""
        return self.state == PRESENT

    def close(self) -> None:
        if self._owns:
            self.episode.close()

    def __enter__(self) -> EpisodeRuns:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # -- the arm roster (#1187 R2) ---------------------------------------------------------------

    def _roster_refused(self, why: str) -> RunRefused:
        return RunRefused(f"episode {quoted(self.episode_id)}: the arm roster {self._roster_path} "
                          f"is refused ({why}) — it fails closed until an operator repairs or "
                          "removes it")

    def _roster_document(self) -> dict[str, RunId] | None:
        """Strict UUID-to-UUID roster, or `None` when RUNS has not published one.

        Validate syntax and uniqueness before any manifest read; membership belongs to
        `arm_ids`. Duplicate JSON keys are refused by the decoder, never collapsed.
        """
        text = self._read_roster_text()
        if text is None:
            return None
        doc, reason = _io.load_json_artifact(text, object_pairs_hook=_no_duplicate_keys)
        if reason is not None:
            raise self._roster_refused(f"not one strict JSON document: {reason}")
        if not isinstance(doc, dict) or not doc:
            raise self._roster_refused("not a non-empty JSON object of world UUID to arm UUID")
        arms: dict[str, RunId] = {}
        owners: dict[RunId, str] = {}
        for world_id, value in doc.items():
            if (why := uuid_id_fault(world_id, "world")) is not None:
                raise self._roster_refused(why)
            try:
                arm = RunId.parse(value)
            except RunRefused:
                raise self._roster_refused(
                    f"the arm id of world {quoted(world_id)} is not a run id: {quoted(value)}") from None
            if arm in owners:
                raise self._roster_refused(
                    f"worlds {quoted(owners[arm])} and {quoted(world_id)} share one arm id")
            owners[arm] = world_id
            arms[world_id] = arm
        return arms

    def _read_roster_text(self) -> str | None:
        """The roster's strict UTF-8 text, or `None` when it is absent. Read through the held
        episode, never followed: a link, or anything but a regular file, is refused, and so is
        a file over `_ROSTER_CAP` (judged on its size before anything is read, and read no
        further than the cap plus one byte)."""
        name = LAYOUT.arm_roster.as_posix()
        view = self.episode.view()
        entry = self._io.stat_entry(view, name)
        if entry.absent:
            return None
        if entry.st is None:
            raise self._roster_refused(f"it cannot be judged: {entry.reason}")
        if not stat.S_ISREG(entry.st.st_mode):
            raise self._roster_refused("it is not a regular file; a link or any other entry is "
                                       "never followed")
        if entry.st.st_size > _ROSTER_CAP:
            raise self._roster_refused(f"it is over {_ROSTER_CAP} bytes")
        answer = view.read(name, max_bytes=_ROSTER_CAP + 1)
        if answer.text is None:
            raise self._roster_refused(
                "it vanished as it was read" if answer.absent
                else f"it cannot be read as UTF-8 text: {answer.reason}")
        if len(answer.text.encode("utf-8")) > _ROSTER_CAP:
            raise self._roster_refused(f"it is over {_ROSTER_CAP} bytes")
        return answer.text

    def _require_started(self) -> None:
        """Refuse absent or malformed RUNS publication before reading a manifest."""
        if self._roster_document() is None:
            raise TenantRefused(
                f"episode {quoted(self.episode_id)} has no arm roster ({self._roster_path} is "
                "absent): it never reached RUNS, and an arm runs only in an episode its "
                "launcher started")

    def arm_ids(self) -> dict[str, RunId] | None:
        """The complete `{world UUID: RunId}` mapping, or `None` before RUNS.

        Syntax, byte budget and uniqueness are checked before manifest loading. Its UUID set
        must then exactly match this episode's validated manifest: no partial or foreign arm
        mapping can be used. Descriptive labels never participate in roster identity.
        """
        from defender.records._family import manifest_world_ids

        arms = self._roster_document()
        if arms is None:
            return None
        worlds = set(manifest_world_ids(self.episode.view(), expected_episode_id=self.episode_id))
        if set(arms) != worlds:
            missing = sorted(worlds - set(arms))
            extra = sorted(set(arms) - worlds)
            raise self._roster_refused(
                "its world UUIDs are not exactly the manifest's worlds (missing "
                f"{[quoted(m) for m in missing]}, not in the manifest "
                f"{[quoted(e) for e in extra]})")
        return arms

    def arm_id(self, world_id: str) -> RunId:
        """One declared world's arm, by persisted world UUID; absent before RUNS."""
        arms = self.arm_ids()
        if arms is None:
            raise RunAbsent(f"episode {quoted(self.episode_id)} has no arm roster "
                            f"({self._roster_path} is absent): it never reached RUNS, so it has "
                            f"no arm for world {quoted(world_id)}")
        if not isinstance(world_id, str) or world_id not in arms:
            raise RunAbsent(f"episode {quoted(self.episode_id)}: the arm roster {self._roster_path} "
                            f"names no world {quoted(world_id)}")
        return arms[world_id]

    def start_runs(self, world_ids: Sequence[str]) -> dict[str, RunId]:
        """Publish RUNS once: every declared world UUID maps to one fresh arm UUID.

        Validate UUIDs, capacity and complete manifest membership before creating anything.
        Then make `runs/` no-follow and publish the roster complete-or-absent; a crash between
        those steps leaves no roster. Labels are resolved at operator-facing boundaries.
        """
        from defender.records._family import manifest_world_ids

        world_ids = builtins.list(world_ids)
        check_arm_roster_capacity(len(world_ids))
        for world_id in world_ids:
            if (why := uuid_id_fault(world_id, "world")) is not None:
                raise RunRefused(why)
        if len(set(world_ids)) != len(world_ids):
            raise RunRefused("start_runs was given a world UUID twice")
        declared = manifest_world_ids(self.episode.view(), expected_episode_id=self.episode_id)
        if set(world_ids) != set(declared):
            raise RunRefused("start_runs needs exactly the manifest's world UUIDs")
        self._hold_container(create=True).close()
        self.state, self.unreadable_reason = PRESENT, None
        arms = {world_id: RunId.mint() for world_id in world_ids}
        if len(set(arms.values())) != len(arms):
            raise RunRefused("two freshly minted arm ids are one; the roster is not written")
        try:
            self._io.create_complete(self.episode._held_folder(), LAYOUT.arm_roster,  # noqa: SLF001 — the view writes the roster through the owner's held folder
                                     _roster_text(arms))
        except FileExistsError:
            raise RunRefused(
                f"the arm roster {self._roster_path} is already written: it is written once, at "
                "the start of RUNS") from None
        except OSError as exc:
            raise RunRefused(f"the arm roster {self._roster_path} could not be written: "
                             f"{exc.strerror or exc}") from None
        return arms

    # -- the arms --------------------------------------------------------------------------------

    def open(self, arm_id: RunId) -> Run:
        """The arm `arm_id`, as `RunsRepository.open` answers in the natural container: an
        absent container is `RunAbsent`, one that cannot be held `RunUnreachable`."""
        return _open(self._tenant.id, _unwrap_runs_base(self._folder), self._hold_container, arm_id, self._io)

    @contextlib.contextmanager
    def arms(self, arm_ids: Sequence[RunId]) -> Iterator[Handout]:
        """Every arm of `arm_ids` from ONE hold of the container (`_hand_out`):
        `handout[arm_id]` is the arm's `Run`, or the refusal `open` would raise for it — each
        arm judged at its own entry, the container's faults every arm's (`RunAbsent` when it is
        gone, `RunUnreachable` when it cannot be held) — and `handout.reader(arm_id)` a
        no-follow reader over a handed-out arm, walked from the held container, for the block
        only."""
        with _hand_out(self._tenant.id, _unwrap_runs_base(self._folder), self._io, self._hold_container,
                       arm_ids) as out:
            yield out

    def create(self, arm_id: RunId) -> Run:
        """The `Run` run setup builds for arm `arm_id` (D-create (a)). The roster must hold the
        id — an arm is never made for an id its launcher did not mint (G5): no roster is
        `RunAbsent`, an id it does not hold `RunRefused` — and the container must be there, a
        real directory (absent or unreadable refuses, `TenantRefused`). Nothing is made; the
        run folder itself is made by run setup."""
        arm_id = require_run_id(arm_id)
        arms = self.arm_ids()
        if arms is None:
            raise RunAbsent(f"episode {quoted(self.episode_id)} has no arm roster "
                            f"({self._roster_path} is absent): no arm is made before RUNS")
        if arm_id not in arms.values():
            raise RunRefused(f"the arm roster {self._roster_path} holds no arm id "
                             f"{quoted(str(arm_id))} — an arm is made only at an id its "
                             "launcher minted")
        try:
            self._hold_container().close()
        except FileNotFoundError:
            raise TenantRefused(f"the arm container {_unwrap_runs_base(self._folder)} is absent — RUNS makes it "
                                "before the roster") from None
        return Run.under(self._folder, arm_id, io=self._io, tenant_id=self._tenant.id)


# -- a command line's request --------------------------------------------------------------------


def open_requested_run(data_root: DataRoot, raw_tenant: str, raw_run_id: str, *,
                       episode_id: str | None = None) -> tuple[Tenant, Run] | str:
    """The run a command line's `--tenant T [--episode E] <run_id>` names, beside T as accepted
    — T accepted under `data_root` (the root its entry point resolved), then the run opened by
    id through T's repository: `runs.open`, or with `episode_id` the episode view's `open` (an
    arm). Neither follows a link at any level below the tenant's folder. The caller gets the
    accepted `Tenant` too, so it never accepts T again (#1279 A4)."""
    from defender.tenancy._tenant import requested_tenant

    try:
        tenant = requested_tenant(data_root, raw_tenant)
        runs = tenant.runs_repository()
        run_id = RunId.parse(raw_run_id)
        if episode_id is None:
            return tenant, runs.open(run_id)
        with runs.episode(episode_id) as view:
            return tenant, view.open(run_id)
    except (TenantRefused, RunRefused, EpisodeRefused, OSError) as refused:
        where = f" of episode {quoted(episode_id)}" if episode_id is not None else ""
        return (f"run {quoted(raw_run_id)}{where} of tenant {quoted(raw_tenant)} cannot be "
                f"opened: {escaped(refused)}")
