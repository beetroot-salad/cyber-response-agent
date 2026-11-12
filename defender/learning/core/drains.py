from __future__ import annotations

import contextlib
import functools
import importlib
import logging
import subprocess
from typing import TYPE_CHECKING, Any
from collections.abc import Callable, Iterator

from defender.learning.core.config import (
    AUTHOR_DRAIN_LABEL,
    DrainLabel,
    FatalConfigError,
    LEAD_AUTHOR_DRAIN_LABEL,
    LoopPaths,
    merge_mode,
    repo_lock_wait_seconds,
)
from defender import box as box_mod
from defender._paths import process_defender_dir
from defender._text import one_line
from defender.learning.author import drain
from defender.learning.core.faults import SYSTEMIC_FAULTS
from defender.learning.core.lane_trees import open_drain_trees
from defender.learning.author._config import GIT_TIMEOUT_SECONDS
from defender.learning.core.pitfalls_disposition import PitfallsDisposition
# A runtime import: the store lead work tells a run from the refusal opening it.
from defender.records import Run
from defender.records.formats import TenantRefused
from defender.learning.core.store_tick import (
    AUTHOR_LANE,
    FEEDBACK_LANE,
    LEAD_LANE,
    Refused,
    Tick,
    classified_refusal,
    lane_waiting,
    opened_store,
)
from defender.learning.store import Stop

if TYPE_CHECKING:
    import datetime

    import httpx

    from defender.learning.author.version_control import Batch, TenantDelivery
    from defender.learning.author.version_control.auth import ForgeCredential
    from defender.systems.catalog import Catalog, TenantSystems
    from defender.systems.run_tenant import Admitted
    from defender.tenancy import Tenant, TenantDirectory

_logger = logging.getLogger(__name__)


class _LeadAuthorRetry(Exception):
    pass


def _invoke_lead_author(  # noqa: PLR0913 — the lead step's call shape, plus its bound label and the claim's items
    paths: LoopPaths, state: Any, run: Run, *, label: DrainLabel,  # noqa: ARG001 — `state`: the seam's call shape, `None` over the store
    batch: Batch | None = None, box: Any = None, on_done: Callable[[str | None], None],
    git_timeout: float = GIT_TIMEOUT_SECONDS, items: list[Any] | None = None, feedback: str | None = None,
    outcomes: dict[tuple[str, str], Any] | None = None, make_model: Callable[..., Any] | None = None,
    systems: TenantSystems | Catalog,
) -> None:
    """The lead-author lane's default work step for one claimed curation request. `label` is the lane's
    (bound in by `lead_author_drain`): the held roots of its writable mounts — the lanes of `batch`'s
    draft — are opened here, with the batch's box stopped, and closed when the request's serve returns
    or raises (#1134 A3, #1108 P4). A fault holding them propagates as itself, never as a swallowed
    transient. Over the store (#1278) the claim's `items`, the framed `feedback` of a replacement and
    the `outcomes` the curator decides are handed through to the curator's entry. With no `batch` (a
    checkout-shaped scene), the label's trees over `paths` are held, and the curator refuses at its
    commit (it commits only into a batch). The lane's systems are handed (#1366 R16): the tenant's, read once
    per claiming tick right before its claim (`_tick_systems`), or the whole `Catalog` from a caller with no tenant."""
    from defender.learning.leads.lead_extraction import LeadAuthorError

    _logger.info("step=lead-author")
    with open_drain_trees(paths, label, batch=batch) as trees:
        rc = _run_curator_module(
            "lead_author",  # lint-run-records: ok — the lead-author role/drain/module's own name, not the `lead_author/` record dir
            lambda mod: mod.run_under_held_queue_lock(
                run, paths=paths, trees=trees, box=box, on_done=on_done,
                git_timeout=git_timeout, batch=batch, systems=systems,
                **_store_kw(items, feedback, outcomes, make_model),
            ),
        )
    if rc not in (0, None):
        raise LeadAuthorError(f"lead-author for {run.id} returned rc={rc}")
    if rc is None:
        raise _LeadAuthorRetry("lead-author hit a swallowed transient (rc=None)")


def _store_kw(items: list[Any] | None, feedback: str | None, outcomes: dict[tuple[str, str], Any] | None,
              make_model: Callable[..., Any] | None) -> dict[str, Any]:
    """What a default work step hands its curator over a store claim (#1278): the claim's items of the
    curator's kind, the framed feedback (a replacement's), the outcomes map it fills, and the model
    seam when one is given. Nothing outside a claim."""
    kw: dict[str, Any] = {}
    if items is not None:
        kw.update(items=items, feedback=feedback, outcomes=outcomes)
    if make_model is not None:
        kw["make_model"] = make_model
    return kw


def _maybe_trigger_author(  # noqa: PLR0913 — the trigger seam's call shape, plus its bound label and the tick's claim
    paths: LoopPaths,
    state: Any,  # noqa: ARG001 — the seam's call shape, `None` over the store
    kind: str,
    threshold_env: str,
    module_name: str,
    pending_label: str,
    *,
    label: DrainLabel,
    batch: Batch | None = None,
    box: Any = None,
    items: list[Any] | None = None,
    feedback: str | None = None,
    outcomes: dict[tuple[str, str], Any] | None = None,
    make_model: Callable[..., Any] | None = None,
) -> None:
    """The author lane's default work step for one curator over a store claim (#1278). `label` is the
    lane's (bound in by `author_drain`): the held roots of the lane's writable mounts — the lanes of
    `batch`'s draft — are opened here, with the batch's box stopped, and closed when the curator's
    batch returns or raises (#1134 A3, #1108 P4). The claim already decided there is work (its wake
    count, `threshold_env`, is the store's claim threshold): the curator is handed the claim's `items`
    of its `kind`, the framed `feedback` of a replacement, and the `outcomes` it decides. Each curator
    opens its own trees and is one claim of the batch. A fault holding them propagates out of this
    step, never as a swallowed crash. With no `batch` (a checkout-shaped scene), the label's trees over
    `paths` are held instead, and the curator refuses any commit."""
    _logger.info(f"step={module_name} kind={kind} {pending_label}={len(items or ())} ({threshold_env})")
    with open_drain_trees(paths, label, batch=batch) as trees:
        rc = _run_curator_module(
            module_name,
            lambda mod: mod.run_batch(
                paths=paths, trees=trees, box=box,
                batch=batch, **_store_kw(items, feedback, outcomes, make_model)),
        )
    if rc not in (0, None):
        _logger.warning(f"{module_name} returned rc={rc} (its items take what the batch's commits show)")


_CURATOR_MODULES = {
    "lead_author": "defender.learning.leads.lead_author",  # lint-run-records: ok — the lead-author role/drain/module's own name, not the `lead_author/` record dir
    "pitfalls_curator": "defender.learning.leads.pitfalls_curator",
    "author": "defender.learning.author.lessons.run",
    # Runs as one unit with `author` — same tick, batch, box, branch and PR lease — with its
    # own channel, corpus, claim and consumption.
    "questioner_curator": "defender.learning.author.questioner.run",
    # The same, for a person's feedback instructions (#1414 D11, #1278 A4): the lessons corpus, its own
    # kind (`feedback_instruction`), prompt and claim.
    "feedback_curator": "defender.learning.author.feedback.run",
}


def _run_curator_module(module_name: str, call: Callable[[Any], int]):
    mod = importlib.import_module(_CURATOR_MODULES[module_name])
    try:
        return call(mod)
    except (subprocess.SubprocessError, OSError) as e:
        _logger.error(f"{module_name} crashed: {e!r} (continuing)")
        return None










#: The faults `_drain_one_curator` lets out of a curator rather than containing to its channel:
#: a `RETIRE_SET` fault; a `BoxFault` or `RunTainted`, since a box that won't start or stop (or a tainted tree) halts the batch as it
#: halts the lead-author lane (#1195 O4, O5); and an interrupt, since swallowing it would record
#: Ctrl-C as a curator fault, run the sibling curator, and go on to commit, push and open a PR
#: for the batch the operator asked to stop.
_HALTING: tuple[type[BaseException], ...] = (
    *drain.RETIRE_SET, box_mod.BoxFault, box_mod.RunTainted, KeyboardInterrupt, Stop,
)

#: What the lead-author lane's steps let out rather than contain to the claim's items: the systemic faults (no
#: item caused them, so none is charged: a misconfigured step, a box that will not run, a tainted tree), an
#: interrupt and the store's stop. A `RETIRE_SET` fault (an `AuthorError`) is one claim's failure: contained,
#: its items take what the batch's commits show.
_LEAD_HALTING: tuple[type[BaseException], ...] = (*SYSTEMIC_FAULTS, KeyboardInterrupt, Stop)








@contextlib.contextmanager
def _batch_claim(batch: Batch | None):
    """One claim of the batch: on every exit the draft is re-synced with the batch branch
    (`Batch.reset`, OD15), so the next claim starts from what landed. A reset that fails never
    displaces a fault already propagating (it is logged); after a clean claim it raises."""
    if batch is None:
        yield
        return
    try:
        yield
    except BaseException:
        try:
            batch.reset()
        except Exception as unreset:  # noqa: BLE001 — never replaces the claim's own fault
            _logger.error(f"the draft could not be reset after a failed claim: {unreset!r}")
        raise
    batch.reset()




















def _invoke_pitfalls(  # noqa: PLR0913 — the pitfalls step's call shape, plus its bound label and the claim's items
    paths: LoopPaths, state: Any, *, label: DrainLabel, batch: Batch | None = None,  # noqa: ARG001 — `state`: the seam's call shape
    box: Any = None, on_curated: Callable[[PitfallsDisposition], None],
    lock_wait_seconds: int | None = None,
    git_timeout: float = GIT_TIMEOUT_SECONDS,
    items: list[Any] | None = None, feedback: str | None = None,
    outcomes: dict[tuple[str, str], Any] | None = None, make_model: Callable[..., Any] | None = None,
    systems: TenantSystems | Catalog,
) -> int:
    """The lead-author lane's default pitfalls work step: as `_invoke_lead_author` (its systems
    handed the same way), the held roots
    of the `label` lane's writable mounts in `batch`'s draft are opened here and closed when the
    curation returns or raises (#1134 A3), and a store claim's `items`, `feedback` and `outcomes` are
    handed through (#1278). With no `batch` (a checkout-shaped scene), the label's trees over `paths`
    are held, and the curation refuses any commit."""
    _logger.info("step=pitfalls-curation")
    with open_drain_trees(paths, label, batch=batch) as trees:
        rc = _run_curator_module(
            "pitfalls_curator",
            lambda mod: mod.run_pitfalls(
                paths=paths, trees=trees, batch=batch, box=box,
                on_curated=on_curated, lock_wait_seconds=lock_wait_seconds,
                git_timeout=git_timeout, systems=systems, **_store_kw(items, feedback, outcomes, make_model),
            ),
        )
    return rc if rc is not None else 0








def _validate_merge_mode() -> None:
    merge_mode()


#: The tick's refusal while it opens its tenant delivery or starts its batch (`store_tick.Refused`): the
#: stage's one-line `FatalConfigError`, or, when transient, a skipped tick.
_Refused = Refused
_classified_refusal = classified_refusal


@contextlib.contextmanager
def _open_delivery(
    paths: LoopPaths, *, directory: TenantDirectory, client: httpx.Client | None,
    identity: ForgeCredential | None, credential_config: Any,
    issuer_transport: httpx.BaseTransport | None, purpose: str = "drain",
    relay: Callable[..., dict[str, Any]] | None = None,
) -> Iterator[TenantDelivery]:
    """Flow 4's front: the selected tenant's delivery, opened by `vc.opened_delivery` (its forge
    wiring from the tenant records, then its credential — the given one, else the tenant's forge
    credential minted through its live generation — then `TenantDelivery.open` against the
    recorded origin), its own clients closed on exit. Missing wiring or issuer configuration is
    decided locally, before any request (O9); every refusal is `_Refused`, naming why."""
    from defender.learning.author import version_control as vc
    from defender.tenancy import RecordsUnreachable

    tenant = paths.tenant
    if tenant is None:
        raise _Refused("the drain delivers to a tenant's repository: no tenant is selected")
    with contextlib.ExitStack() as opened:
        try:
            # The batch box's code mount is this process's own code tree, never the checkout
            # the learning paths name (whose adapters the lanes read).
            delivery = opened.enter_context(vc.opened_delivery(
                tenant, defender_dir=process_defender_dir(), directory=directory, purpose=purpose,
                client=client, identity=identity, credential_config=credential_config,
                issuer_transport=issuer_transport, relay=relay))
        except RecordsUnreachable as down:
            raise _Refused(f"the tenant {tenant.id}'s records could not be read: {down}", transient=True) from None
        except TenantRefused as unbound:
            raise _Refused(
                f"the tenant {tenant.id} has no usable forge wiring: {unbound}") from None
        except (vc.DeliveryRefused, vc.ForgejoAuthError) as refused:
            raise _classified_refusal(
                f"the tenant {tenant.id}'s delivery refused: {refused}", refused) from None
        yield delivery


def revert_delivery(
    admitted: Admitted, *, client: httpx.Client | None = None, identity: ForgeCredential | None = None,
    credential_config: Any = None, issuer_transport: httpx.BaseTransport | None = None,
) -> contextlib.AbstractContextManager[TenantDelivery]:
    """The author lane's delivery for a by-hand lesson revert (`revert_lesson.py`, flow 5), which
    runs under the author drain's lock: `vc.opened_delivery` as `_open_delivery` opens it, for the
    tenant the revert's host acceptance admitted (`admitted`, r10.1 C1: its tenant and the records
    it was admitted through; the admission is a parameter, not a precondition). A refusal is
    `TenantRefused`, `DeliveryRefused` or `ForgejoAuthError`."""
    from defender.learning.author import version_control as vc

    return vc.opened_delivery(
        admitted.tenant, defender_dir=process_defender_dir(), directory=admitted.directory, purpose="revert",
        client=client, identity=identity, credential_config=credential_config, issuer_transport=issuer_transport)


def _drain_directory(directory: TenantDirectory | None) -> TenantDirectory:
    """The drain's tenant records: the one its entry hands it, else the one
    `DEFENDER_DATABASE_DSN` names (#1214 Flow 4); neither is the stage's configuration refusal."""
    from defender.systems.run_tenant import entry_directory

    try:
        return entry_directory(directory)
    except TenantRefused as refused:
        raise FatalConfigError(str(refused)) from refused



def _store_curators(
    paths: LoopPaths, trigger_author: Callable[..., None], *, box: Any, batch: Batch, held: Any,
    feedback: str | None, outcomes: dict[tuple[str, str], Any],
) -> None:
    """The author lane's work over a claim (A2 D1): each curator whose kind has items in the batch is
    handed its own kind's items (and, on a replacement, the framed feedback, H13); a kind with none is
    not run. Each curator's fault is contained to it, so the other still runs, unless it halts the tick
    (`_HALTING`: a stop, a lost lease, a box fault, a `RETIRE_SET` fault)."""
    for kind, threshold_env, module_name, pending_label in _AUTHOR_CURATORS:
        mine = [item for item in held.items if item[0] == kind]
        if not mine:
            continue
        try:
            trigger_author(paths, None, kind, threshold_env, module_name, pending_label, box=box, batch=batch,
                           items=mine, feedback=feedback, outcomes=outcomes)
        except _HALTING:
            raise
        except (Exception, SystemExit) as e:  # noqa: BLE001 — contained to this curator, never silently
            _logger.error(f"{module_name}: {type(e).__name__} took this curator out of the tick: {one_line(str(e))} "
                          "(its items take what the batch's commits show; the other curator still ran)")


#: The author lane's curators, in order: the kind each is handed, its wake count's variable, its module
#: and its log label.
_AUTHOR_CURATORS = (
    ("finding", "LEARNING_AUTHOR_THRESHOLD", "author", "pending"),
    ("questioner_finding", "LEARNING_QUESTIONER_THRESHOLD", "questioner_curator", "questioner_pending"),
    # One instruction wakes it, with no knob (#1414 D11): its threshold is the store's, fixed at 1.
    ("feedback_instruction", "", "feedback_curator", "feedback_pending"),
)


def _store_lead_work(  # noqa: PLR0913, C901 — the lane's two steps, its claim and what the curators decide, kept as one pass over the claim
    paths: LoopPaths, run_lead_author: Callable[..., None], run_pitfalls: Callable[..., int], *,
    box: Any, batch: Batch, held: Any, feedback: str | None, outcomes: dict[tuple[str, str], Any],
) -> None:
    """The lead-author lane's work over a claim: each curation request's run served through the drain's
    accepted tenant, then the pitfalls curation over the claim's pitfalls, each one claim of `batch`
    (the draft re-synced after it). Items kept until the batch ends (r8 Lead-author lane): an item stays in the
    batch only when its curator positively took it (`Outcome.kept()`: a request its serve finished, a pitfall the
    curation committed); an item that is not named waits again when the batch enters review (P3); a request whose
    run is gone is dead."""
    from defender.learning.author.version_control import DeliveryRefused
    from defender.learning.store import Outcome
    from defender.records import RunAbsent

    for kind, key, payload in [item for item in held.items if item[0] == "curation_request"]:  # lint-half-table: ok — this lane serves the curation request's own run rule, not a lane decision
        run = _run_of(payload, paths.tenant)
        if isinstance(run, RunAbsent):
            outcomes[(kind, key)] = Outcome.dead("artifact-missing")
            continue
        if not isinstance(run, Run):
            outcomes.setdefault((kind, key), Outcome.waiting())
            continue
        done: list[str | None] = []
        with _batch_claim(batch):
            try:
                run_lead_author(paths, None, run, box=box, on_done=done.append, batch=batch,
                                items=[(kind, key, payload)], feedback=feedback, outcomes=outcomes)
            except _LEAD_HALTING:
                raise
            except (_LeadAuthorRetry, DeliveryRefused, Exception) as e:  # noqa: BLE001 — contained to this request
                _logger.warning(f"lead_author_drain: request {key}: {type(e).__name__}: {one_line(str(e))}")  # lint-run-records: ok — the lead-author role/drain/module's own name, not the `lead_author/` record dir
        outcomes.setdefault((kind, key), Outcome.kept() if done else Outcome.waiting())
    pitfalls = [item for item in held.items if item[0] == "pitfall"]  # lint-half-table: ok — the pitfall curation is the kind's own rule, not a lane decision
    if not pitfalls:
        return
    curated: list[PitfallsDisposition] = []
    with _batch_claim(batch):
        try:
            run_pitfalls(paths, None, box=box, on_curated=curated.append, batch=batch, items=pitfalls,
                         feedback=feedback, outcomes=outcomes)
        except _LEAD_HALTING:
            raise
        except Exception as e:  # noqa: BLE001 — contained: the pitfalls take their fates below
            _logger.error(f"lead_author_drain: pitfalls curation error: {e!r}")  # lint-run-records: ok — the lead-author role/drain/module's own name, not the `lead_author/` record dir
    committed = set(curated[-1].committed_ids) if curated else set()
    declined = set(curated[-1].held_ids) if curated else set()
    for kind, key, _payload in pitfalls:
        if key in declined:
            outcomes.setdefault((kind, key), Outcome.declined())
        else:
            outcomes.setdefault((kind, key), Outcome.kept() if key in committed else Outcome.waiting())


def _run_of(payload: dict, tenant: Tenant | None) -> Run | Exception:
    """The run a curation request names (`{case_id, tenant_id, run_id}`), opened through the drain's own
    accepted tenant and its repository, else the refusal (`RunAbsent` when the run is gone)."""
    from defender.records import RunAddress, RunRefused

    try:
        address = RunAddress(payload["tenant_id"], payload["run_id"])
    except (KeyError, TypeError, ValueError, TenantRefused, RunRefused) as unreadable:
        # A missing, null or mistyped field is a request that names no run (the address checks each field).
        return TenantRefused(f"the request names no run: {unreadable}")
    if tenant is None or str(tenant.id) != str(address.tenant_id):
        return TenantRefused(f"tenant {address.tenant_id} is not the drain's accepted tenant")
    try:
        return tenant.runs_repository().resolve(address)
    except RunRefused as refused:
        _logger.warning(f"request for run {address.run_id}: its run cannot be opened ({refused})")
        return refused


#: The lanes the author drain's tick reconciles (in review, PRs to close): its own, the lead lane's and the feedback
#: lane's. Its wake test (`author_work_waiting`) asks of the same lanes.
AUTHOR_DRAIN_RECONCILES = (AUTHOR_LANE, LEAD_LANE, FEEDBACK_LANE)


def author_work_waiting(paths: LoopPaths) -> bool:
    """Whether `author_drain` could act now or later without a person (#1344 amendment 3, G-T1; `lane_waiting` over the
    lanes it reconciles). What a post-step reports as still waiting."""
    if paths.tenant is None:
        return False
    with opened_store() as store:
        return lane_waiting(store, str(paths.tenant.id), AUTHOR_LANE, reconcile_lanes=AUTHOR_DRAIN_RECONCILES)


def _refusing(entry: Callable[[], int]) -> int:
    """`entry()`, a `_Refused` turned into the stage's one-line `FatalConfigError` raised from
    outside the `except`, so it carries no context for the stage runner to report. A transient
    `_Refused` (an outage) is a warning and a skipped tick: the next tick tries again."""
    try:
        return entry()
    except _Refused as e:
        if e.transient:
            _logger.warning(f"{one_line(str(e))} — an outage; skipping this tick")
            return 0
        refused = str(e)
    raise FatalConfigError(one_line(refused))




def _tick_systems(paths: LoopPaths, records: TenantDirectory) -> TenantSystems:
    """The lead-author tick's systems (#1366 O1, R16): the selected tenant's, from its current
    records over the catalog of the product checkout `paths` names. Read once, after the tick
    delivers the batches earlier ticks retained and before any claim, so every claim and the
    pitfalls curation of the tick are handed one set, and an outage skips the tick (`_Refused`, transient) with no claim taken and
    no attempt counted. An unreadable adapters directory refuses the stage."""
    from defender.learning.leads.declared_systems import AdaptersUnreadable, tenant_systems_of
    from defender.records.formats import TenantRefused
    from defender.tenancy import RecordsUnreachable

    tenant = paths.tenant
    if tenant is None:
        raise _Refused("the drain delivers to a tenant's repository: no tenant is selected")
    try:
        return tenant_systems_of(paths.repo_root, records.current_records(tenant.id), tenant_id=tenant.id)
    except RecordsUnreachable as down:
        raise _Refused(f"the tenant {tenant.id}'s records could not be read: {down}", transient=True) from None
    except TenantRefused as refused:  # not imported (R8): the tick is refused before any claim, and nothing is charged
        raise _Refused(str(refused)) from None
    except AdaptersUnreadable as unreadable:
        raise _Refused(f"the product checkout's adapters could not be read: {unreadable}") from None


def _store_tick(paths: LoopPaths, *, lane: str, label: DrainLabel, open_delivery: Callable[..., Any],
          author_work: Callable[..., None], start_box: Callable[..., Any] | None, stop_box: Callable[..., None],
          **fields: Any) -> int:
    """One lane's `store_tick.Tick` over the opened store; `fields` its further fields (`reconcile_lanes`,
    `before_claim`)."""
    if paths.tenant is None:
        raise FatalConfigError("the drain delivers to a tenant's repository: no tenant is selected")
    with opened_store() as store:
        tick = Tick(paths=paths, lane=lane, label=label, store=store, open_delivery=open_delivery,
                    author_work=author_work, start_box=start_box, stop_box=stop_box,
                    **fields)
        return _refusing(tick.run)


def author_drain(  # noqa: PLR0913 — the stage's seams: the author step, the forge, the tenant records, the issuer, the box
    paths: LoopPaths,
    *,
    # `(paths, state, kind, threshold_env, module_name, pending_label, *, batch, box, items, feedback, outcomes)`.
    trigger_author: Callable[..., None] | None = None,
    client: httpx.Client | None = None,
    identity: ForgeCredential | None = None,
    directory: TenantDirectory | None = None,
    credential_config: Any = None,
    issuer_transport: httpx.BaseTransport | None = None,
    start_box: Callable[..., Any] | None = None,
    stop_box: Callable[..., None] = box_mod.stop_box,
    make_model: Callable[..., Any] | None = None,
    container: Any = None,
) -> int:
    """The lessons lane's tick into the selected tenant's repository over the learning store (#1278):
    reconcile every batch in review (every lane, D9; the feedback lane's registry batches too, A4), recover a
    lapsed batch of the lane, then claim and
    author (`store_tick.Tick`). `container`, the post-step's job container (#1170,
    `learning.branch.container.JobContainer`): the tenant records, the forge credential, the batch's publish, draft
    and box are then the per-job host helper's, asked over the job socket (no forge login here, O3, O4, C23).
    `directory` is the tenant records (else the ones `DEFENDER_DATABASE_DSN`
    names); `client` the forge's HTTP client; `identity` the tenant's delivery credential, else minted
    through its live generation (`credential_config`, `issuer_transport`); `start_box`/`stop_box` the
    batch's box (default `TenantDelivery.start_batch_box`); `make_model` the curators' model (default their own)."""
    _validate_merge_mode()
    records, credential, relay = _drain_sources(container, directory=directory, identity=identity)
    # The lane's label reaches its work step bound into the DEFAULT seam, so an injected seam
    # keeps its call shape (#1134).
    if trigger_author is None:
        trigger_author = functools.partial(_maybe_trigger_author, label=AUTHOR_DRAIN_LABEL, make_model=make_model)
    seam = trigger_author

    def open_delivery() -> contextlib.AbstractContextManager[TenantDelivery]:
        return _open_delivery(paths, directory=records, client=client, identity=credential,
                              credential_config=credential_config, issuer_transport=issuer_transport,
                              relay=relay)

    return _store_tick(paths, lane=AUTHOR_LANE, label=AUTHOR_DRAIN_LABEL, open_delivery=open_delivery,
                 author_work=lambda work_paths, **kw: _store_curators(work_paths, seam, **kw),
                 start_box=start_box, stop_box=stop_box, reconcile_lanes=AUTHOR_DRAIN_RECONCILES)


def _drain_sources(container: Any, *, directory: TenantDirectory | None,
                   identity: ForgeCredential | None) -> tuple[Any, ForgeCredential | None, Any]:
    """The drain's tenant records, forge credential and relay: a job container's (#1170: the helper answers them over
    the job socket; an `identity` given still wins; with no `container` and no `directory`, the one the environment's job
    socket names), else `directory` (or the DSN's) with `identity` and no relay."""
    found = container if container is not None or directory is not None else _job_container()
    if found is None:
        return _drain_directory(directory), identity, None
    return found.records(), identity if identity is not None else found.forge_credential(), found.ask


def _job_container() -> Any:
    """The job container this drain runs in (#1170: the post-step's), by the job socket in the environment; None on a
    host."""
    from defender.learning.branch.container import JobContainer

    return JobContainer.in_environ()


def lead_author_drain(  # noqa: PLR0913 — the stage's seams (OD4, OD16): two steps, the forge, the issuer, the box
    paths: LoopPaths,
    *,
    run_lead_author: Callable[..., None] | None = None,
    run_pitfalls: Callable[..., int] | None = None,
    client: httpx.Client | None = None,
    identity: ForgeCredential | None = None,
    directory: TenantDirectory | None = None,
    credential_config: Any = None,
    issuer_transport: httpx.BaseTransport | None = None,
    start_box: Callable[..., Any] | None = None,
    stop_box: Callable[..., None] = box_mod.stop_box,
    git_timeout: float = GIT_TIMEOUT_SECONDS,
    make_model: Callable[..., Any] | None = None,
) -> int:
    """The lead-author lane's tick over the learning store (operator-only, A2 D9): reconcile the lane's
    batches in review, recover a lapsed one, then claim its pitfalls and curation requests and author
    them; its delivery seams as `author_drain`'s. `git_timeout` is bound into the DEFAULT work steps only
    (the lanes' own bounded reads, #1175)."""
    _validate_merge_mode()
    records = _drain_directory(directory)
    # Read every configured value before a batch, box or agent exists, so a malformed setting
    # refuses the tick rather than a commit.
    lock_wait_seconds = repo_lock_wait_seconds()
    # The default steps are handed the tenant's systems, read once per claiming tick, after the reconcile and the
    # recovery (which need none) and right before the claim (#1366 O1, R16); an injected step brings its own.
    tick_systems: list[TenantSystems] = []
    reads_systems = run_lead_author is None or run_pitfalls is None

    def read_systems() -> None:
        tick_systems[:] = [_tick_systems(paths, records)]

    def lead_step(*args: Any, **kw: Any) -> None:
        step = run_lead_author or functools.partial(
            _invoke_lead_author, label=LEAD_AUTHOR_DRAIN_LABEL, git_timeout=git_timeout, make_model=make_model,
            systems=tick_systems[0])
        step(*args, **kw)

    def pitfalls_step(*args: Any, **kw: Any) -> int:
        step = run_pitfalls or functools.partial(
            _invoke_pitfalls, lock_wait_seconds=lock_wait_seconds, label=LEAD_AUTHOR_DRAIN_LABEL,
            git_timeout=git_timeout, make_model=make_model, systems=tick_systems[0])
        return step(*args, **kw)

    def open_delivery() -> contextlib.AbstractContextManager[TenantDelivery]:
        return _open_delivery(paths, directory=records, client=client, identity=identity,
                              credential_config=credential_config, issuer_transport=issuer_transport)

    return _store_tick(paths, lane=LEAD_LANE, label=LEAD_AUTHOR_DRAIN_LABEL, open_delivery=open_delivery,
                 author_work=lambda work_paths, **kw: _store_lead_work(work_paths, lead_step, pitfalls_step, **kw),
                 start_box=start_box, stop_box=stop_box, reconcile_lanes=(LEAD_LANE,),
                 before_claim=read_systems if reads_systems else None)


def feedback_drain(  # noqa: PLR0913 — the stage's seams: the model's decision, the forge, the records, the issuer
    paths: LoopPaths,
    *,
    decide: Callable[..., dict] | None = None,
    client: httpx.Client | None = None,
    identity: ForgeCredential | None = None,
    directory: TenantDirectory | None = None,
    credential_config: Any = None,
    issuer_transport: httpx.BaseTransport | None = None,
    eligibility_max_age: datetime.timedelta | None = None,
) -> int:
    """The feedback tick (#1414 F2) over the learning store (#1278 A4): open issues, read eligible comments,
    decide each once, draft approved entries onto a registry PR, and post the replies owed, under the
    tenant's feedback tick lease (one tick per tenant, O12; the store at `DEFENDER_DATABASE_DSN`)."""
    from defender.learning.core import feedback
    from defender.learning.core.feedback_model import model_decide

    _validate_merge_mode()
    records = _drain_directory(directory)

    def open_delivery() -> contextlib.AbstractContextManager[TenantDelivery]:
        return _open_delivery(paths, directory=records, client=client, identity=identity,
                              credential_config=credential_config, issuer_transport=issuer_transport)

    return _refusing(lambda: feedback.run(paths, open_delivery, records, decide=decide or model_decide,
                                          eligibility_max_age=eligibility_max_age))
