from __future__ import annotations

import contextlib
import functools
import importlib
import logging
import subprocess
from defender._model import model
from typing import TYPE_CHECKING, Any
from collections.abc import Callable, Iterator

from defender.learning.core.config import (
    AUTHOR_DRAIN_LABEL,
    DrainLabel,
    FatalConfigError,
    LEAD_AUTHOR_DRAIN_LABEL,
    LoopPaths,
    author_max_attempts,
    env_int,
    merge_mode,
    pitfalls_threshold,
    repo_lock_wait_seconds,
)
from defender import box as box_mod
from defender._paths import process_defender_dir
from defender._text import one_line
from defender.learning.author import drain
from defender.learning.core.faults import run_or_dead_letter
from defender.learning.core.lane_trees import open_drain_trees
from defender.learning.author._config import GIT_TIMEOUT_SECONDS
from defender.learning.core.persist import (
    merge_pitfalls,
    pitfalls_lane_is_open,
    read_pitfalls,
)
from defender.learning.core.pitfalls_disposition import PitfallsDisposition
# A runtime import, not a `TYPE_CHECKING` one: `ServedMarker` (a model) names it as a field.
from defender.records import Run
from defender.learning.core.state import (
    FINDINGS,
    PITFALLS,
    QUESTIONER_FINDINGS,
    Channel,
    Claimed,
    LearningState,
    PendingDelivery,  # noqa: F401 — re-export: the delivery record the drains and the pin name
)
from defender.records.formats import TenantRefused
from defender.learning.core.store_tick import (
    AUTHOR_LANE,
    LEAD_LANE,
    Refused,
    Tick,
    classified_refusal,
    lane_waiting,
    opened_store,
)
from defender.learning.store import Stop

if TYPE_CHECKING:
    import httpx

    from defender.learning.author.version_control import Batch, TenantDelivery
    from defender.learning.author.version_control.auth import ForgeCredential
    from defender.systems.run_tenant import Admitted
    from defender.tenancy import Tenant, TenantDirectory

_logger = logging.getLogger(__name__)


class _LeadAuthorRetry(Exception):
    pass


def _invoke_lead_author(  # noqa: PLR0913 — the lead step's call shape, plus its bound label and the claim's items
    paths: LoopPaths, state: LearningState | None, run: Run, *, label: DrainLabel,
    batch: Batch | None = None, box: Any = None, on_done: Callable[[str | None], None],
    git_timeout: float = GIT_TIMEOUT_SECONDS, items: list[Any] | None = None, feedback: str | None = None,
    outcomes: dict[tuple[str, str], Any] | None = None, make_model: Callable[..., Any] | None = None,
) -> None:
    """The lead-author lane's default work step for one claimed curation request. `label` is the lane's
    (bound in by `lead_author_drain`): the held roots of its writable mounts — the lanes of `batch`'s
    draft — are opened here, with the batch's box stopped, and closed when the request's serve returns
    or raises (#1134 A3, #1108 P4). A fault holding them propagates as itself, never as a swallowed
    transient. Over the store (#1278) the claim's `items`, the framed `feedback` of a replacement and
    the `outcomes` the curator decides are handed through to the curator's entry. With no `batch` (a
    checkout-shaped scene), the label's trees over `paths` are held, and the curator refuses at its
    commit (it commits only into a batch)."""
    from defender.learning.leads.lead_extraction import LeadAuthorError

    _logger.info("step=lead-author")
    with open_drain_trees(paths, label, batch=batch) as trees:
        rc = _run_curator_module(
            "lead_author",  # lint-run-records: ok — the lead-author role/drain/module's own name, not the `lead_author/` record dir
            lambda mod: mod.run_under_held_queue_lock(
                run, paths=paths, state=state, trees=trees, box=box, on_done=on_done,
                git_timeout=git_timeout, batch=batch, **_store_kw(items, feedback, outcomes, make_model),
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
    seam when one is given. Nothing outside a claim (a by-hand run passes none)."""
    kw: dict[str, Any] = {}
    if items is not None:
        kw.update(items=items, feedback=feedback, outcomes=outcomes)
    if make_model is not None:
        kw["make_model"] = make_model
    return kw


def _maybe_trigger_author(  # noqa: PLR0913 — the trigger seam's call shape, plus its bound label and the tick's claim
    paths: LoopPaths,
    state: LearningState | None,
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
                hold_committed=True, paths=paths, state=state, trees=trees, box=box,
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
}


def _run_curator_module(module_name: str, call: Callable[[Any], int]):
    mod = importlib.import_module(_CURATOR_MODULES[module_name])
    try:
        return call(mod)
    except (subprocess.SubprocessError, OSError) as e:
        _logger.error(f"{module_name} crashed: {e!r} (continuing)")
        return None


def _curator_queue_checks() -> list[tuple[Channel, str]]:
    """The queues whose depth can wake this drain: the findings and questioner-findings
    channels.

    Named rather than derived from another table, so adding or removing a channel is an
    explicit edit here."""
    return [
        (FINDINGS, "LEARNING_AUTHOR_THRESHOLD"),
        (QUESTIONER_FINDINGS, "LEARNING_QUESTIONER_THRESHOLD"),
    ]


def _pending_queue_counts(state: LearningState, channel: Channel) -> tuple[int, int]:
    """`(authorable, held)` — queued rows a tick could still author, and rows it has declined.
    Both come from one read, since the wake gate's number means little to an operator without
    the other."""
    rows, unreadable = state.rows_report(channel)
    held = sum(1 for row in rows if "held_reason" in row)
    return len(rows) - held + unreadable, held


def _has_curator_work(state: LearningState) -> bool:
    """Whether any wakeable queue holds a threshold's worth of authorable rows.

    Logs the counts for a non-empty queue that doesn't wake: this is the gate that stops the
    tick, so otherwise a queue of permanent holds would show only "nothing queued". Empty
    queues stay silent, to avoid a line every pass on every queue. Not `any(...)`, so every
    queue gets its line."""
    woken = False
    for channel, env in _curator_queue_checks():
        threshold = env_int(env, 5)
        authorable, held = _pending_queue_counts(state, channel)
        if authorable >= threshold:
            woken = True
        elif authorable or held:
            _logger.info(
                f"{channel.name}: pending={authorable} held={held} "
                f"threshold={threshold} — not woken"
            )
    return woken


def _has_lead_author_work(state: LearningState) -> bool:
    threshold = pitfalls_threshold()
    # Queued requests, and any stranded in `inflight/` by a drain that died mid-serve: the
    # drainer reclaims those, so this gate must wake for them.
    if state.has_requests():
        return True
    # The same condition `run_pitfalls` gates on, so the drain never wakes for a curation that
    # then declines, nor sleeps through one it would take.
    return pitfalls_lane_is_open(merge_pitfalls(read_pitfalls(state)), threshold)


#: The faults `_drain_one_curator` lets out of a curator rather than containing to its channel:
#: a `RETIRE_SET` fault; a `BoxFault`, since a box that won't start or stop halts the batch as it
#: halts the lead-author lane (#1195 O4, O5); and an interrupt, since swallowing it would record
#: Ctrl-C as a curator fault, run the sibling curator, and go on to commit, push and open a PR
#: for the batch the operator asked to stop.
_HALTING: tuple[type[BaseException], ...] = (
    *drain.RETIRE_SET, box_mod.BoxFault, KeyboardInterrupt, Stop,
)


def _drain_one_curator(  # noqa: PLR0913 — the trigger seam's arguments, threaded through
    paths: LoopPaths, state: LearningState, trigger_author: Callable[..., None],
    channel: Channel, threshold_env: str, module_name: str, pending_label: str, *, box: Any,
    batch: Batch | None = None,
) -> None:
    """Run one curator, containing its fault to its own channel.

    `trigger_author` is a caller-supplied seam whose exception discipline can't be assumed, so
    the isolation lives here. A `RETIRE_SET` fault or a `BoxFault` (#1195) propagates; so does a
    `StateRefused`, which no `Exception` arm catches (a planted entry below the state root stops
    the whole tick, and recording it stuck would write after the refusal); anything else is
    recorded on this channel's stuck report and swallowed, so the sibling curator still runs."""
    # `run_batch` already records non-`RETIRE_SET` faults before re-raising. A second record
    # here, with a different row set, would reset `consecutive_ticks` every tick, so the count
    # tells "already recorded" from "raised above `run_batch`, recorded nowhere".
    recorded_before = state.stuck_count(channel)
    fault: BaseException | None = None
    try:
        trigger_author(
            paths, state, channel, threshold_env, module_name, pending_label, box=box,
            **_batch_kw(batch))
    # `SystemExit` is contained, since it is not an interrupt: escaping would skip the sibling
    # curator and unwind past `finish_batch`, discarding the first curator's authored lessons
    # with nothing recorded on either channel.
    except _HALTING:
        raise
    except (Exception, SystemExit) as e:  # noqa: BLE001 — every other fault class is recorded, never silently swallowed
        fault = e
    if fault is None:
        return
    # Recorded after the arm has closed: the fault is contained, not displaced, so a refusal met
    # while recording it carries no `__context__` for the stage runner to report as displaced.
    # An ordinary failure to record is logged, never raised: this frame must not raise on a
    # non-retiring fault, the recording's own included.
    try:
        already = state.stuck_count(channel) > recorded_before
        if not already:
            drain.record_stuck(state, channel, fault, state.rows(channel))
    except Exception as unrecorded:  # noqa: BLE001 — never replaces the contained fault
        _logger.error(f"{module_name}: stuck record NOT written: {unrecorded!r} (the fault "
                      f"itself: {fault!r})")
        return
    _logger.error(f"{module_name}: {type(fault).__name__} took this curator out of the tick "
                  f"({'already recorded in' if already else 'recorded to'} "
                  f"{channel.name}'s stuck report); the other curator still ran")


def _drain_curators(
    paths: LoopPaths,
    state: LearningState,
    trigger_author: Callable[..., None],
    *,
    box: Any = None,
    batch: Batch | None = None,
) -> None:
    # The same two channels the wake gate (`_curator_queue_checks`) answers for. Both curators
    # share one tick — batch, box, branch, PR lease — each its own claim, and
    # `_drain_one_curator` contains each one's non-retiring fault, so it never stops the other
    # or its commit. A `RETIRE_SET` fault propagates, so one in the first curator can cost the
    # second its turn; so does a refusal. This frame must not raise on any other fault but a
    # `BoxFault`, or the batch is never delivered and neither curator's work reaches the forge.
    # The batch's box is stopped between agent runs and runs only inside each spawn's
    # `box_for_run` (#1195).
    _drain_one_curator(paths, state, trigger_author, FINDINGS, "LEARNING_AUTHOR_THRESHOLD",
                       "author", "pending", box=box, batch=batch)
    _drain_one_curator(paths, state, trigger_author, QUESTIONER_FINDINGS,
                       "LEARNING_QUESTIONER_THRESHOLD", "questioner_curator",
                       "questioner_pending", box=box, batch=batch)


def _batch_kw(batch: Batch | None) -> dict[str, Any]:
    """The tick's batch as a lane entry's `batch=` keyword (OD16), or nothing when the caller
    drives the lane's loop with none (a unit scene's own step)."""
    return {} if batch is None else {"batch": batch}


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


def _quarantine_lead_author_failure(
    state: LearningState, claim: Claimed, e: Exception
) -> None:
    state.quarantine(claim, f"lead-author-error: {e!r}")


def _requeue_or_drop(state: LearningState, claim: Claimed, *, note: str) -> None:
    """Hand one claimed request back to the queue, then release the claim.

    The re-queue lands at the top level (not the `inflight/` slot being released) and is
    create-if-absent: a fresher request for the same case that arrived meanwhile wins, and
    this older spec is dropped. The spec comes off the claim so the re-queue and the release
    can't refer to different claims."""
    if state.requeue(claim):
        _logger.info(f"lead_author_drain: {note} — left queued for retry")  # lint-run-records: ok — the lead-author role/drain/module's own name, not the `lead_author/` record dir
    else:
        _logger.info(
            f"lead_author_drain: {note} — a fresher request for the same case landed "  # lint-run-records: ok — the lead-author role/drain/module's own name, not the `lead_author/` record dir
            "while it was claimed and supersedes it; dropping this one"
        )
    state.done(claim)


@model(frozen=True)
class ServedMarker:
    """One lead-author request the tick served cleanly: the claim still in `inflight/`, the run
    it served (opened from the claim's address), whether the curator reached the exit that
    records the run done (the no-executed-leads, no-pending-drafts exit doesn't), and its
    commit (`None` for done without a commit)."""

    claim: Claimed
    run: Run
    done: bool
    sha: str | None


@model(frozen=True)
class BatchDisposition:
    """Everything a lead-author tick consumes from shared state, collected during `do_work`
    and applied only once the batch's tree has passed the scrub."""

    served: list[ServedMarker]
    pitfalls: PitfallsDisposition | None
    #: The pitfalls append-lock wait, resolved at the drain's entry rather than here, after the
    #: commit exists. `None` (no deadline) only when a test drives the internals directly.
    lock_wait_seconds: int | None

    def apply(self, state: LearningState) -> None:
        from defender.learning.leads.lead_author import write_done_sentinel

        for marker in self.served:
            if marker.done:
                write_done_sentinel(marker.run.run_dir, marker.sha)
        for marker in self.served:
            state.done(marker.claim)
        if self.pitfalls is not None:
            self.pitfalls.apply(state, timeout_seconds=self.lock_wait_seconds)

    def retained_summary(self) -> str:
        """What a tick that did not reach the apply left behind — for the log line that says
        what stays for the next tick's reclaim."""
        committed = len(self.pitfalls.committed_ids) if self.pitfalls is not None else 0
        held = len(self.pitfalls.held_ids) if self.pitfalls is not None else 0
        return (
            f"{len(self.served)} served marker(s) left in inflight/, "
            f"{committed} committed pitfall row(s) left queued, "
            f"{held} held row(s) not bumped"
        )


def _retry_or_exhaust(
    state: LearningState, claim: Claimed, attempts: int, max_retries: int, cause: object,
) -> None:
    """A transient failure of one counted attempt (`attempts`, this attempt's count): the row
    re-queued for a later tick carrying that count, or — at `max_retries` — quarantined
    `transient-exhausted`. The one transient lane: a lead-author run's `_LeadAuthorRetry` and a
    row whose run cannot be reached right now both end here."""
    if attempts >= max_retries:
        state.quarantine(claim, f"transient-exhausted after {attempts} attempt(s): {cause!r}")
        return
    claim.spec["attempts"] = attempts
    _requeue_or_drop(
        state, claim,
        note=f"transient on {claim.identity} (attempt {attempts}/{max_retries})",
    )


def _set_aside(paths: LoopPaths, state: LearningState, claim: Any, directory: TenantDirectory) -> bool:
    """Is `claim` not to be served this tick? A claim of a tenant other than the selected one is
    quarantined; one whose tenant is no longer `active` (read afresh now, #1214 Flow 4) is handed
    back to the queue unserved and uncounted. Records that cannot be read raise
    `RecordsUnreachable` (`_servable` hands the claim back and takes no more)."""
    from defender import tenancy

    owner = claim.spec.get("tenant_id")
    if paths.tenant is not None and owner != str(paths.tenant.id):
        state.quarantine(claim, f"tenant {owner!r} does not own selected tenant {paths.tenant.id}'s queue")
        return True
    inactive = tenancy.still_active(directory, claim.address.tenant_id)
    if inactive is not None:
        _requeue_or_drop(state, claim, note=f"{claim.identity} not served: {inactive}")
        return True
    return False


def _servable(
    paths: LoopPaths, state: LearningState, claims: Iterator[Claimed], directory: TenantDirectory,
) -> Iterator[Claimed]:
    """Each claim of `claims` to serve now, the others set aside (`_set_aside`). When the tenant
    records cannot be read (an outage, `RecordsUnreachable`), that claim is handed back to the
    queue unserved and uncounted, and no more are taken this tick: the claims not yet taken stay
    queued, so an outage never counts an attempt against a row."""
    from defender.tenancy import RecordsUnreachable

    for claim in claims:
        try:
            if _set_aside(paths, state, claim, directory):
                continue
        except RecordsUnreachable as down:
            _requeue_or_drop(state, claim, note=f"{claim.identity} not served: {one_line(str(down))}")
            _logger.warning(f"lead_author_drain: the tenant records could not be read ({one_line(str(down))}) "  # lint-run-records: ok — the lead-author role/drain/module's own name, not the `lead_author/` record dir
                            "— an outage; no more claims are served this tick")
            return
        yield claim


def _drain_lead_author_markers(
    paths: LoopPaths,
    state: LearningState,
    run_lead_author: Callable[..., None],
    *,
    box: Any = None,
    batch: Batch | None = None,
    directory: TenantDirectory,
    git_timeout: float = GIT_TIMEOUT_SECONDS,
) -> list[ServedMarker]:
    """Claim the queued curation requests and serve each one's run to `run_lead_author`, each
    one claim of `batch` (the draft re-synced after it, OD15). Before each claim is served its
    tenant's state is read afresh from `directory` (#1214 Flow 4, P3): a claim of a tenant no
    longer `active` (offboarded since the tick began) is handed back to the queue unserved and
    uncounted; when the records cannot be read (an outage), that claim is handed back the same way
    and the tick serves no more (the claims not yet taken stay queued). A claim the commit-maker refuses
    (P3's `DeliveryRefused`: a link, a FIFO, an out-of-lane path...) is U10's refused claim:
    its draft is reset, it counts its attempt and its row is re-queued until the ceiling
    quarantines it; the other claims go ahead."""
    from defender.learning.author.version_control import DeliveryRefused
    from defender.records import RunAbsent

    max_retries = env_int("LEAD_AUTHOR_MAX_RETRIES", 3)
    # `case_id`: this queue's live writer (`enqueue_curation`) mints the filename from the
    # case, so that is what an unreadable row's dead letter is keyed on.
    claims = state.claim(
        "case_id", label=LEAD_AUTHOR_DRAIN_LABEL, noun="lead-author",
    )
    served: list[ServedMarker] = []
    for claim in _servable(paths, state, claims, directory):
        spec = claim.spec
        run = _rehydrate(claim, paths.tenant)
        if isinstance(run, RunAbsent):
            state.quarantine(claim, "artifact-missing")
            continue
        # Every serve is an attempt, counted before the agent runs: a claim the apply never
        # reached is reclaimed next tick, and a run that taints every tree must hit the ceiling.
        attempts = int(spec.get("attempts", 0)) + 1
        if not isinstance(run, Run):
            # Not reached right now (see the docstring): a counted, transient attempt.
            _retry_or_exhaust(state, claim, attempts, max_retries, run)
            continue
        if attempts > max_retries:
            state.quarantine(
                claim, f"served {attempts - 1} time(s) without being recorded done")
            continue
        # On the claim alone: the spec in hand stays as read, so a terminal refusal's dead
        # letter carries no counter; the transient arm stamps the spec only when it re-queues.
        state.stamp(claim, {**spec, "attempts": attempts})
        # The curator's commit, handed back for `BatchDisposition.apply` to record once the
        # batch is delivered.
        done: list[str | None] = []
        with _batch_claim(batch):
            try:
                drained = run_or_dead_letter(
                    functools.partial(
                        run_lead_author, paths, state, run, box=box, on_done=done.append,
                        **_batch_kw(batch),
                    ),
                    functools.partial(_quarantine_lead_author_failure, state, claim),
                    propagate=(_LeadAuthorRetry, DeliveryRefused),
                )
            except _LeadAuthorRetry as e:
                drained = False
                _retry_or_exhaust(state, claim, attempts, max_retries, e)
            except DeliveryRefused as refused:
                drained = False
                # Named by the entry's repo-relative spelling, never the draft's host path.
                said = one_line(str(refused))
                if batch is not None:
                    said = said.replace(f"{batch.draft_root}/", "")
                _logger.warning(f"lead_author_drain: the claim of {claim.identity} was refused "  # lint-run-records: ok — the lead-author role/drain/module's own name, not the `lead_author/` record dir
                                f"by the commit-maker: {said}")
                _retry_or_exhaust(state, claim, attempts, max_retries, refused)
        if drained:
            # Not unlinked here: the claim stays in `inflight/` until the batch is delivered
            # (`BatchDisposition.apply`).
            served.append(ServedMarker(claim, run=run, done=bool(done),
                                       sha=done[-1] if done else None))
    return served


def _rehydrate(claim: Claimed, tenant: Tenant | None) -> Run | Exception:
    """The run `claim`'s address names, opened through the drain's own accepted tenant (r10.1 C1:
    the value of drain start's host acceptance, `paths.tenant`; nothing under that scope accepts
    again) and its repository, which never follows a link at its name. Else the refusal, logged:
    `TenantRefused` when the drain has no accepted tenant or the claim names another (fail closed;
    `_set_aside` already quarantines a claim of another tenant), or the open's `RunRefused`
    (`RunAbsent` when the run is gone)."""
    from defender.records import RunRefused

    address = claim.address
    if tenant is None or str(tenant.id) != str(address.tenant_id):
        refused = TenantRefused(f"tenant {address.tenant_id} is not the drain's accepted tenant")
        _logger.warning(f"{claim.identity}: its tenant cannot be accepted ({refused})")
        return refused
    try:
        return tenant.runs_repository().resolve(address)
    except RunRefused as refused:
        _logger.warning(f"{claim.identity}: its run cannot be opened ({refused})")
        return refused


def _invoke_pitfalls(  # noqa: PLR0913 — the pitfalls step's call shape, plus its bound label and the claim's items
    paths: LoopPaths, state: LearningState | None, *, label: DrainLabel, batch: Batch | None = None,
    box: Any = None, on_curated: Callable[[PitfallsDisposition], None],
    lock_wait_seconds: int | None = None,
    git_timeout: float = GIT_TIMEOUT_SECONDS,
    items: list[Any] | None = None, feedback: str | None = None,
    outcomes: dict[tuple[str, str], Any] | None = None, make_model: Callable[..., Any] | None = None,
) -> int:
    """The lead-author lane's default pitfalls work step: as `_invoke_lead_author`, the held roots
    of the `label` lane's writable mounts in `batch`'s draft are opened here and closed when the
    curation returns or raises (#1134 A3), and a store claim's `items`, `feedback` and `outcomes` are
    handed through (#1278). With no `batch` (a checkout-shaped scene), the label's trees over `paths`
    are held, and the curation refuses any commit."""
    _logger.info("step=pitfalls-curation")
    with open_drain_trees(paths, label, batch=batch) as trees:
        rc = _run_curator_module(
            "pitfalls_curator",
            lambda mod: mod.run_pitfalls(
                paths=paths, state=state, trees=trees, batch=batch, box=box,
                on_curated=on_curated, lock_wait_seconds=lock_wait_seconds,
                git_timeout=git_timeout, **_store_kw(items, feedback, outcomes, make_model),
            ),
        )
    return rc if rc is not None else 0


def _retire_pitfalls_batch(
    state: LearningState, batch_ids: list[str], lock_wait_seconds: int | None, e: Exception,
) -> None:
    _logger.error(f"lead_author_drain: pitfalls curation error: {e!r}; discarding edits")  # lint-run-records: ok — the lead-author role/drain/module's own name, not the `lead_author/` record dir
    if not batch_ids:
        return
    drain.retire(
        state,
        channel=PITFALLS,
        batch_ids=batch_ids,
        # `batch-error:<class>` is the groupable vocabulary, beside `_graveyard_dropped_rows`'
        # classes and the hold ceiling's reason. The truncated message follows because one
        # class covers very different failures (a timeout, an attempted deletion), and the
        # graveyard is the lane's only durable record.
        reason=f"batch-error:{type(e).__name__}: {str(e)[:200]}",
        max_attempts=author_max_attempts(),
        timeout_seconds=lock_wait_seconds,
    )


def _drain_pitfalls(
    paths: LoopPaths,
    state: LearningState,
    run_pitfalls: Callable[..., int],
    *,
    box: Any = None,
    batch: Batch | None = None,
    lock_wait_seconds: int | None = None,
) -> PitfallsDisposition | None:
    # The batch is fixed at this read: a pitfall appended while the curation runs must not be
    # bumped.
    batch_ids = [str(r["pitfall_id"]) for r in read_pitfalls(state) if r.get("pitfall_id")]
    # Only the success-path consumption is handed back; failure dispositions don't depend on
    # the delivery and are applied immediately.
    curated: list[PitfallsDisposition] = []
    with _batch_claim(batch):
        run_or_dead_letter(
            lambda: run_pitfalls(paths, state, box=box, on_curated=curated.append,
                                 **_batch_kw(batch)),
            functools.partial(_retire_pitfalls_batch, state, batch_ids, lock_wait_seconds),
        )
    return curated[-1] if curated else None


def _drain_lead_author(  # noqa: PLR0913 — the tick's two steps and its batch, threaded rather than global
    paths: LoopPaths,
    state: LearningState,
    run_lead_author: Callable[..., None],
    run_pitfalls: Callable[..., int],
    *,
    claims: bool,
    directory: TenantDirectory,
    box: Any = None,
    batch: Batch | None = None,
    lock_wait_seconds: int | None = None,
    git_timeout: float = GIT_TIMEOUT_SECONDS,
) -> BatchDisposition:
    """The tick's work: serve each curation request's run through the drain's accepted tenant,
    then run the pitfalls curation, every claim into `batch`. `claims` is False when no request
    was queued as the tick started (`lead_author_drain`): the tick then claims none — a row that
    lands mid-tick waits, queued, for the next tick — and only the pitfalls step runs."""
    # The batch's box is stopped between agent runs and runs only inside each spawn's
    # `box_for_run`, so no host step of the tick runs beside a process an agent left (#1195).
    served = [] if not claims else _drain_lead_author_markers(
        paths, state, run_lead_author, box=box, batch=batch, directory=directory, git_timeout=git_timeout)
    pitfalls = _drain_pitfalls(
        paths, state, run_pitfalls, box=box, batch=batch, lock_wait_seconds=lock_wait_seconds,
    )
    return BatchDisposition(
        served=served, pitfalls=pitfalls, lock_wait_seconds=lock_wait_seconds,
    )


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
    issuer_transport: httpx.BaseTransport | None,
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
                tenant, defender_dir=process_defender_dir(), directory=directory, purpose="drain",
                client=client, identity=identity, credential_config=credential_config,
                issuer_transport=issuer_transport))
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
)


def _store_lead_work(  # noqa: PLR0913, C901 — the lane's two steps, its claim and what the curators decide, kept as one pass over the claim
    paths: LoopPaths, run_lead_author: Callable[..., None], run_pitfalls: Callable[..., int], *,
    box: Any, batch: Batch, held: Any, feedback: str | None, outcomes: dict[tuple[str, str], Any],
) -> None:
    """The lead-author lane's work over a claim: each curation request's run served through the drain's
    accepted tenant, then the pitfalls curation over the claim's pitfalls, each one claim of `batch`
    (the draft re-synced after it). Items kept until the batch ends (r8 Lead-author lane): an item no
    commit took waits again when the batch enters review; a request whose run is gone is dead."""
    from defender.learning.author.version_control import DeliveryRefused
    from defender.learning.store import Outcome
    from defender.records import RunAbsent

    for kind, key, payload in [item for item in held.items if item[0] == "curation_request"]:
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
            except _HALTING:
                raise
            except (_LeadAuthorRetry, DeliveryRefused, Exception) as e:  # noqa: BLE001 — contained to this request
                _logger.warning(f"lead_author_drain: request {key}: {type(e).__name__}: {one_line(str(e))}")  # lint-run-records: ok — the lead-author role/drain/module's own name, not the `lead_author/` record dir
        if not done:
            outcomes.setdefault((kind, key), Outcome.waiting())
    pitfalls = [item for item in held.items if item[0] == "pitfall"]
    if not pitfalls:
        return
    curated: list[PitfallsDisposition] = []
    with _batch_claim(batch):
        try:
            run_pitfalls(paths, None, box=box, on_curated=curated.append, batch=batch, items=pitfalls,
                         feedback=feedback, outcomes=outcomes)
        except _HALTING:
            raise
        except Exception as e:  # noqa: BLE001 — contained: the pitfalls take their fates below
            _logger.error(f"lead_author_drain: pitfalls curation error: {e!r}")  # lint-run-records: ok — the lead-author role/drain/module's own name, not the `lead_author/` record dir
    committed = set(curated[-1].committed_ids) if curated else set()
    for kind, key, _payload in pitfalls:
        if key not in committed:
            outcomes.setdefault((kind, key), Outcome.waiting())


def _run_of(payload: dict, tenant: Tenant | None) -> Run | Exception:
    """The run a curation request names (`{case_id, tenant_id, run_id}`), opened through the drain's own
    accepted tenant and its repository, else the refusal (`RunAbsent` when the run is gone)."""
    from defender.records import RunAddress, RunRefused

    try:
        address = RunAddress(payload["tenant_id"], payload["run_id"])
    except (KeyError, TypeError, ValueError) as unreadable:
        return TenantRefused(f"the request names no run: {unreadable}")
    if tenant is None or str(tenant.id) != str(address.tenant_id):
        return TenantRefused(f"tenant {address.tenant_id} is not the drain's accepted tenant")
    try:
        return tenant.runs_repository().resolve(address)
    except RunRefused as refused:
        _logger.warning(f"request for run {address.run_id}: its run cannot be opened ({refused})")
        return refused


def author_work_waiting(paths: LoopPaths) -> bool:
    """Whether `author_drain` could find work now (#1344 amendment 3, G-T1): a batch not ended (in review
    to check, working to recover, or a person's), a replacement due or an author-lane kind at its
    threshold. What a post-step reports as still waiting."""
    if paths.tenant is None:
        return False
    with opened_store() as store:
        return lane_waiting(store, str(paths.tenant.id), AUTHOR_LANE)


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




def _store_tick(paths: LoopPaths, *, lane: str, label: DrainLabel, open_delivery: Callable[..., Any],
          author_work: Callable[..., None], start_box: Callable[..., Any] | None, stop_box: Callable[..., None],
          reconcile_lanes: tuple[str, ...]) -> int:
    if paths.tenant is None:
        raise FatalConfigError("the drain delivers to a tenant's repository: no tenant is selected")
    with opened_store() as store:
        tick = Tick(paths=paths, lane=lane, label=label, store=store, open_delivery=open_delivery,
                    author_work=author_work, start_box=start_box, stop_box=stop_box,
                    reconcile_lanes=reconcile_lanes)
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
) -> int:
    """The lessons lane's tick into the selected tenant's repository over the learning store (#1278):
    reconcile every batch in review (both lanes, D9), recover a lapsed batch of the lane, then claim and
    author (`store_tick.Tick`). `directory` is the tenant records (else the ones `DEFENDER_DATABASE_DSN`
    names); `client` the forge's HTTP client; `identity` the tenant's delivery credential, else minted
    through its live generation (`credential_config`, `issuer_transport`); `start_box`/`stop_box` the
    batch's box; `make_model` the curators' model (default their own)."""
    _validate_merge_mode()
    records = _drain_directory(directory)
    # The lane's label reaches its work step bound into the DEFAULT seam, so an injected seam
    # keeps its call shape (#1134).
    if trigger_author is None:
        trigger_author = functools.partial(_maybe_trigger_author, label=AUTHOR_DRAIN_LABEL, make_model=make_model)
    seam = trigger_author

    def open_delivery() -> contextlib.AbstractContextManager[TenantDelivery]:
        return _open_delivery(paths, directory=records, client=client, identity=identity,
                              credential_config=credential_config, issuer_transport=issuer_transport)

    return _store_tick(paths, lane=AUTHOR_LANE, label=AUTHOR_DRAIN_LABEL, open_delivery=open_delivery,
                 author_work=lambda work_paths, **kw: _store_curators(work_paths, seam, **kw),
                 start_box=start_box, stop_box=stop_box, reconcile_lanes=(AUTHOR_LANE, LEAD_LANE))


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
    if run_lead_author is None:
        run_lead_author = functools.partial(
            _invoke_lead_author, label=LEAD_AUTHOR_DRAIN_LABEL, git_timeout=git_timeout, make_model=make_model,
        )
    if run_pitfalls is None:
        run_pitfalls = functools.partial(
            _invoke_pitfalls, lock_wait_seconds=lock_wait_seconds, label=LEAD_AUTHOR_DRAIN_LABEL,
            git_timeout=git_timeout, make_model=make_model,
        )
    lead_step, pitfalls_step = run_lead_author, run_pitfalls

    def open_delivery() -> contextlib.AbstractContextManager[TenantDelivery]:
        return _open_delivery(paths, directory=records, client=client, identity=identity,
                              credential_config=credential_config, issuer_transport=issuer_transport)

    return _store_tick(paths, lane=LEAD_LANE, label=LEAD_AUTHOR_DRAIN_LABEL, open_delivery=open_delivery,
                 author_work=lambda work_paths, **kw: _store_lead_work(work_paths, lead_step, pitfalls_step, **kw),
                 start_box=start_box, stop_box=stop_box, reconcile_lanes=(LEAD_LANE,))
