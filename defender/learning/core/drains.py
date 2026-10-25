from __future__ import annotations

import contextlib
import dataclasses
import functools
import importlib
import logging
import subprocess
import uuid
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
    now_iso,
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
from defender.run_repository import Run
from defender.learning.core.state import (
    AUTHOR_DRAIN_LOCK,
    FINDINGS,
    PITFALLS,
    LEAD_AUTHOR_DRAIN_LOCK,
    LEAD_QUEUE_LOCK,
    QUESTIONER_FINDINGS,
    TRY_ONCE,
    Channel,
    Claimed,
    LearningState,
    PendingDelivery,  # noqa: F401 — re-export: the delivery record the drains and the pin name
    StateRefused,
)

if TYPE_CHECKING:
    from pathlib import Path

    import httpx

    from defender.learning.author.version_control import Batch, ForgejoIdentity, TenantDelivery
    from defender.tenancy._tenant import Tenant

_logger = logging.getLogger(__name__)


class _LeadAuthorRetry(Exception):
    pass


def _invoke_lead_author(
    paths: LoopPaths, state: LearningState, run: Run, *, label: DrainLabel,
    batch: Batch | None = None, box: Any = None, on_done: Callable[[str | None], None],
    git_timeout: float = GIT_TIMEOUT_SECONDS,
) -> None:
    """The lead-author lane's default work step for one claim. `label` is the lane's (bound in by
    `lead_author_drain`): the held roots of its writable mounts — the lanes of `batch`'s draft —
    are opened here, with the batch's box stopped, and closed when the claim's serve returns or
    raises (#1134 A3, #1108 P4). A fault holding them propagates as itself, never as a
    swallowed transient. With no `batch` (a checkout-shaped scene), the label's trees over
    `paths` are held, and the curator refuses at its commit (it commits only into a batch)."""
    from defender.learning.leads.lead_extraction import LeadAuthorError

    _logger.info("step=lead-author")
    # The drain holds the per-author queue lock for the whole tick (`lead_author_drain`), so
    # the curator is entered past its own acquisition and its done sentinel is deferred to
    # `on_done`.
    with open_drain_trees(paths, label, batch=batch) as trees:
        rc = _run_curator_module(
            "lead_author",  # lint-run-records: ok — the lead-author role/drain/module's own name, not the `lead_author/` record dir
            lambda mod: mod.run_under_held_queue_lock(
                run, paths=paths, state=state, trees=trees, box=box, on_done=on_done,
                git_timeout=git_timeout, batch=batch,
            ),
        )
    if rc not in (0, None):
        raise LeadAuthorError(f"lead-author for {run.id} returned rc={rc}")
    if rc is None:
        raise _LeadAuthorRetry("lead-author hit a swallowed transient (rc=None)")


def _maybe_trigger_author(  # noqa: PLR0913 — the trigger seam's call shape, plus its bound label and the tick's batch
    paths: LoopPaths,
    state: LearningState,
    channel: Channel,
    threshold_env: str,
    module_name: str,
    pending_label: str,
    *,
    label: DrainLabel,
    batch: Batch | None = None,
    box: Any = None,
) -> None:
    """The author lane's default work step for one curator. `label` is the lane's (bound in by
    `author_drain`): when the curator's queue is at threshold, the held roots of the lane's
    writable mounts — the lanes of `batch`'s draft — are opened here, with the batch's box
    stopped, and closed when the curator's batch returns or raises (#1134 A3, #1108 P4). Each
    curator opens its own and is one claim of the batch. A fault holding them propagates out of
    this step (to `_drain_one_curator`'s stuck record), never as a swallowed crash. With no
    `batch` (a checkout-shaped scene), the label's trees over `paths` are held instead, and the
    curator refuses any commit (it commits only into a batch's draft)."""
    threshold = env_int(threshold_env, 5)
    # Held is logged beside authorable: the count is authorable rows, not queue depth, so
    # without it a queue of permanent holds would log `pending=0` with no explanation.
    pending_count, held_count = _pending_queue_counts(state, channel)
    if pending_count < threshold:
        _logger.info(
            f"{pending_label}={pending_count} held={held_count} threshold={threshold} "
            f"— {module_name} not invoked"
        )
        return
    _logger.info(
        f"step={module_name} {pending_label}={pending_count} held={held_count} "
        f"threshold={threshold}"
    )
    with open_drain_trees(paths, label, batch=batch) as trees:
        rc = _run_curator_module(
            module_name,
            lambda mod: mod.run_batch(
                hold_committed=True, paths=paths, state=state, trees=trees, box=box,
                batch=batch),
        )
    if rc not in (0, None):
        _logger.warning(f"{module_name} returned rc={rc} (queue intact, retry next tick)")


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
    *drain.RETIRE_SET, box_mod.BoxFault, KeyboardInterrupt,
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


def _tenant_acceptor(tenant: Tenant | None) -> Callable[[object], Tenant]:
    """Fresh tenant acceptance for a tick with queued curation requests.

    A selected tenant supplies the root through its owner. Scratch paths use the configured
    root. A missing or bad setting is the stage's configuration refusal
    (`FatalConfigError`, raised from `resolve_data_root`'s
    `TenantRefused`): `_run_stage` logs it on one line and exits 2."""
    from defender.tenancy import _tenant

    if tenant is not None:
        return tenant.accept_requested_tenant
    try:
        return functools.partial(_tenant.requested_tenant, _tenant.resolve_data_root())
    except _tenant.TenantRefused as refused:
        raise FatalConfigError(str(refused)) from refused


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


def _drain_lead_author_markers(
    paths: LoopPaths,
    state: LearningState,
    run_lead_author: Callable[..., None],
    *,
    box: Any = None,
    batch: Batch | None = None,
    accept_tenant: Callable[[object], Tenant],
    git_timeout: float = GIT_TIMEOUT_SECONDS,
) -> list[ServedMarker]:
    """Claim the queued curation requests and serve each one's run to `run_lead_author`, each
    one claim of `batch` (the draft re-synced after it, OD15). A claim the commit-maker refuses
    (P3's `DeliveryRefused`: a link, a FIFO, an out-of-lane path...) is U10's refused claim:
    its draft is reset, it counts its attempt and its row is re-queued until the ceiling
    quarantines it; the other claims go ahead."""
    from defender.learning.author.version_control import DeliveryRefused
    from defender.run_repository import RunAbsent

    max_retries = env_int("LEAD_AUTHOR_MAX_RETRIES", 3)
    accepted: dict[str, Tenant | Exception] = {}
    # `case_id`: this queue's live writer (`enqueue_curation`) mints the filename from the
    # case, so that is what an unreadable row's dead letter is keyed on.
    claims = state.claim(
        "case_id", label=LEAD_AUTHOR_DRAIN_LABEL, noun="lead-author",
    )
    served: list[ServedMarker] = []
    for claim in claims:
        spec = claim.spec
        if paths.tenant is not None and spec.get("tenant_id") != str(paths.tenant.id):
            state.quarantine(claim, f"tenant {spec.get('tenant_id')!r} does not own selected tenant {paths.tenant.id}'s queue")
            continue
        run = _rehydrate(claim, accept_tenant, accepted)
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


def _rehydrate(
    claim: Claimed, accept_tenant: Callable[[object], Tenant],
    accepted: dict[str, Tenant | Exception],
) -> Run | Exception:
    """The run `claim`'s address names: its tenant freshly accepted — as a natural
    run's acceptance has it, with no box mount beside the runs base (`box_mounted=()`), once
    per tenant per tick, a refusal included — then the run opened through that tenant's
    repository, which never follows a link at its name. Else the refusal, logged: the
    tenant's `TenantRefused`, or the open's `RunRefused` (`RunAbsent` when the run is gone)."""
    from defender.tenancy import _tenant
    from defender.run_repository import RunRefused

    address = claim.address
    key = str(address.tenant_id)
    if key not in accepted:
        try:
            accepted[key] = accept_tenant(address.tenant_id)
        except _tenant.TenantRefused as refused:
            _logger.warning(f"{claim.identity}: its tenant cannot be accepted ({refused})")
            accepted[key] = refused
    tenant = accepted[key]
    if isinstance(tenant, Exception):
        return tenant
    try:
        return tenant.runs_repository().resolve(address)
    except RunRefused as refused:
        _logger.warning(f"{claim.identity}: its run cannot be opened ({refused})")
        return refused


def _invoke_pitfalls(
    paths: LoopPaths, state: LearningState, *, label: DrainLabel, batch: Batch | None = None,
    box: Any = None, on_curated: Callable[[PitfallsDisposition], None],
    lock_wait_seconds: int | None = None,
    git_timeout: float = GIT_TIMEOUT_SECONDS,
) -> int:
    """The lead-author lane's default pitfalls work step: as `_invoke_lead_author`, the held roots
    of the `label` lane's writable mounts in `batch`'s draft are opened here and closed when the
    curation returns or raises (#1134 A3). With no `batch` (a checkout-shaped scene), the
    label's trees over `paths` are held, and the curation refuses any commit."""
    _logger.info("step=pitfalls-curation")
    with open_drain_trees(paths, label, batch=batch) as trees:
        rc = _run_curator_module(
            "pitfalls_curator",
            lambda mod: mod.run_pitfalls(
                paths=paths, state=state, trees=trees, batch=batch, box=box,
                on_curated=on_curated, lock_wait_seconds=lock_wait_seconds,
                git_timeout=git_timeout,
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
    accept_tenant: Callable[[object], Tenant] | None,
    box: Any = None,
    batch: Batch | None = None,
    lock_wait_seconds: int | None = None,
    git_timeout: float = GIT_TIMEOUT_SECONDS,
) -> BatchDisposition:
    """The tick's work: accept each curation request's tenant, then run the pitfalls
    curation, every claim into `batch`. `accept_tenant` is `None` when no request was queued as
    the tick started (`lead_author_drain`): the tick then claims none — a row that lands
    mid-tick waits, queued, for the next tick — and only the pitfalls step runs."""
    # The batch's box is stopped between agent runs and runs only inside each spawn's
    # `box_for_run`, so no host step of the tick runs beside a process an agent left (#1195).
    served = [] if accept_tenant is None else _drain_lead_author_markers(
        paths, state, run_lead_author, box=box, batch=batch, accept_tenant=accept_tenant,
        git_timeout=git_timeout)
    pitfalls = _drain_pitfalls(
        paths, state, run_pitfalls, box=box, batch=batch, lock_wait_seconds=lock_wait_seconds,
    )
    return BatchDisposition(
        served=served, pitfalls=pitfalls, lock_wait_seconds=lock_wait_seconds,
    )


def _validate_merge_mode() -> None:
    merge_mode()


def _branch_prefix(label: DrainLabel) -> str:
    """Each lane's branch prefix on the tenant repository, by its label: its writer lease and
    its retained deliveries are its own (the other lane delivers under its own drain lock). The
    author lane's is delivery's own lessons prefix. Read once per tick, by `_run_tenant_batch`,
    for both the no-network pre-check and the delivery it opens."""
    from defender.learning.author.version_control.delivery import LESSONS_BRANCH_PREFIX

    return LESSONS_BRANCH_PREFIX if label is AUTHOR_DRAIN_LABEL else "lead-author/"


class _Refused(Exception):
    """A delivery refusal met while the drain opens its tenant delivery or starts its batch:
    re-raised by the entry as one `FatalConfigError` line, outside every `except`, so the stage
    runner logs the cause alone (no displaced exception, no traceback) — unless `transient`
    (an outage that may pass by itself, `status.classify`), which skips the tick instead."""

    def __init__(self, message: str, *, transient: bool = False) -> None:
        super().__init__(message)
        self.transient = transient


def _classified_refusal(message: str, fault: BaseException) -> _Refused:
    """`message` as a `_Refused`, transient when `fault` is an outage (`status.classify`)."""
    from defender.learning.author.version_control.status import TRANSIENT, classify

    return _Refused(message, transient=classify(fault)[0] == TRANSIENT)


@contextlib.contextmanager
def _open_delivery(
    paths: LoopPaths, *, client: httpx.Client | None,
    identity: ForgejoIdentity | None, issuer_config: Path | None,
    issuer_transport: httpx.BaseTransport | None,
) -> Iterator[TenantDelivery]:
    """Flow 4's front: the selected tenant's delivery, opened by `vc.opened_delivery` (its
    forge binding, then its identity — the given one, else an AppRole login with the issuer
    client config the binding names, A-ID, OD4 — then `TenantDelivery.open` against the
    binding's origin), its own clients closed on exit. A missing binding or config is decided
    locally, before any request (O9); every refusal is `_Refused`, naming why."""
    from defender.learning.author import version_control as vc
    from defender.tenancy import _tenant

    tenant = paths.tenant
    if tenant is None:
        raise _Refused("the drain delivers to a tenant's repository: no tenant is selected")
    with contextlib.ExitStack() as opened:
        try:
            # The batch box's code mount is this process's own code tree, never the checkout
            # the learning paths name (whose adapters the lanes read).
            delivery = opened.enter_context(vc.opened_delivery(
                tenant, defender_dir=process_defender_dir(), client=client, identity=identity,
                issuer_config=issuer_config, issuer_transport=issuer_transport))
        except _tenant.TenantRefused as unbound:
            raise _Refused(
                f"the tenant {tenant.id} has no usable forge binding: {unbound}") from None
        except (vc.DeliveryRefused, vc.ForgejoAuthError) as refused:
            raise _classified_refusal(
                f"the tenant {tenant.id}'s delivery refused: {refused}", refused) from None
        yield delivery


def _record_pending_delivery(
    state: LearningState, batch: Batch, *, prefix: str, label: DrainLabel, reason: str,
) -> None:
    slug = prefix.rstrip("/").replace("/", "-") or "author"
    state.record_delivery(f"{slug}-{batch.id}", {
        "branch": batch.branch, "batch_id": batch.id, "label": str(label),
        "reason": reason, "at": now_iso(),
    })


def _deliver_pending(state: LearningState, delivery: TenantDelivery, label: DrainLabel) -> bool:
    """Deliver every batch this lane committed but could not push or open a PR for, before
    anything new is served (`TenantDelivery.deliver`: the batch's PR status when the forge has
    one — D-closed — else its branch pushed and a PR opened). Answers whether the lane is clear
    to serve.

    An undelivered batch holds the writer lease like an open PR: the next batch must build on
    its commit, and a fresh branch beside it would open conflicting PRs. So a failed delivery
    parks the lane until the remote takes it. Nothing here re-runs an agent."""
    from defender.learning.author.version_control import DeliveryRefused, DeliveryStatus

    for pending in state.deliveries(delivery.branch_prefix):
        try:
            delivered = delivery.deliver(pending.batch_id)
        except DeliveryRefused as e:
            _logger.error(
                f"{label}: delivery of retained batch {pending.branch} failed again: "
                f"{one_line(str(e))} — it holds the writer lease; nothing served this tick"
            )
            return False
        state.delivered(pending)
        if delivered.status is DeliveryStatus.NOTHING:
            _logger.info(f"{label}: retained batch {pending.branch} has nothing left to deliver "
                         "— record dropped")
        else:
            _logger.info(f"{label}: retained batch {pending.branch} delivered: its PR is "
                         f"{delivered.status}" + (f" ({delivered.url})" if delivered.url else ""))
    return True


def _land_batch(
    state: LearningState, delivery: TenantDelivery, batch: Batch, label: DrainLabel,
) -> None:
    """`TenantDelivery.finish`: the batch's branch pushed and its PR opened, or the status the
    forge already gives its PR (D-closed). On a refusal the commits stay on the batch branch of
    the tenant clone, and the batch is recorded for the next tick to deliver
    (`_deliver_pending`) before serving anything."""
    from defender.learning.author.version_control import DeliveryRefused, DeliveryStatus

    try:
        delivered = delivery.finish(batch)
    except DeliveryRefused as e:
        _record_pending_delivery(state, batch, prefix=delivery.branch_prefix, label=label,
                                 reason=one_line(str(e)))
        _logger.error(
            f"{label}: delivery of batch {batch.branch} failed: {one_line(str(e))} — its "
            "commits stay on that branch of the tenant clone; delivery is retried next tick, "
            "before anything new is served"
        )
        return
    if delivered.status is DeliveryStatus.NOTHING:
        _logger.info(f"{label}: batch produced no commits — no PR opened")
        return
    _logger.info(f"{label}: batch {batch.branch}: PR {delivered.status}"
                 + (f" {delivered.url}" if delivered.url else ""))
    if merge_mode() == "auto_on_green":
        _logger.info(f"{label}: merge_mode=auto_on_green — green-bar auto-merge not yet "
                     "wired (PR C); leaving PR for review")


def _stop_after_work(stop_box: Callable[..., None], box: Any, *, work_ok: bool,
                     label: DrainLabel) -> None:
    """Remove the batch's box after the work (amendment 3 C3: a draft box is stopped, never
    scrubbed). A teardown fault outranks a clean batch (nothing is delivered beside a box that
    may still run) and never displaces the work's own fault."""
    try:
        stop_box(box)
    except Exception as e:  # noqa: BLE001 — re-raised below unless a work fault outranks it
        if work_ok:
            raise
        _logger.error(f"{label}: the batch's box could not be torn down after a failed batch: {e!r}")


def _run_tenant_batch(  # noqa: PLR0913 — one batch, kept whole
    paths: LoopPaths,
    state: LearningState,
    *,
    label: DrainLabel,
    has_work: Callable[[LearningState], bool],
    do_work: Callable[..., BatchDisposition | None],
    open_delivery: Callable[[], contextlib.AbstractContextManager[TenantDelivery]],
    start_box: Callable[..., Any] | None,
    stop_box: Callable[..., None],
) -> int:
    """One tick of a lane (flow 4): open the tenant's delivery (login, `open`); deliver what an
    earlier tick retained; the wake gate; the writer lease (our open PR on the lane's prefix);
    `start_batch` (publish, then the draft); the box over the draft (`Batch.box_request`); the
    work, each claim committed by P3's commit-maker; the disposition; `finish`; `discard()`.

    A tick with nothing retained and nothing queued opens nothing. A refusal while opening is
    the stage's refusal, before any claim, box or model call (O9); an outage there skips the
    tick."""
    prefix = _branch_prefix(label)
    if not state.deliveries(prefix) and not has_work(state):
        _logger.info(f"{label}: nothing queued and no curator at threshold — skipping")
        return 0
    with open_delivery() as opened:
        delivery = dataclasses.replace(opened, branch_prefix=prefix)
        return _run_opened_batch(paths, state, delivery, label=label, has_work=has_work,
                                 do_work=do_work, start_box=start_box, stop_box=stop_box)


def _run_opened_batch(  # noqa: PLR0913 — one batch, kept whole
    paths: LoopPaths,
    state: LearningState,
    delivery: TenantDelivery,
    *,
    label: DrainLabel,
    has_work: Callable[[LearningState], bool],
    do_work: Callable[..., BatchDisposition | None],
    start_box: Callable[..., Any] | None,
    stop_box: Callable[..., None],
) -> int:
    """`_run_tenant_batch`'s tick past the open: everything after the delivery is open."""
    from defender.learning.author.version_control import DeliveryRefused

    prefix = delivery.branch_prefix
    if not _deliver_pending(state, delivery, label):
        return 0
    if not has_work(state):
        _logger.info(f"{label}: nothing queued and no curator at threshold — skipping")
        return 0
    try:
        if delivery.open_pr_exists():
            _logger.info(f"{label}: an open {prefix} PR holds the writer lease — skipping")
            return 0
        batch = delivery.start_batch(uuid.uuid4().hex[:12], lanes=label.lanes)
    except DeliveryRefused as e:
        raise _classified_refusal(f"{label}: the batch could not start: {e}", e) from None

    disposition: BatchDisposition | None = None
    consumed = False
    try:
        box = (start_box or delivery.start_box)(batch.box_request())
        # The lanes' handle: the box is reachable only inside a run window (#1195).
        runs = box_mod.BoxRuns(box)
        work_ok = False
        try:
            # Stopped before the batch's first host step; inside this `try`, so a stop that
            # fails still gets the batch-end removal.
            runs.stop()
            disposition = do_work(paths, batch=batch, box=runs)
            work_ok = True
        finally:
            _stop_after_work(stop_box, box, work_ok=work_ok, label=label)
        if disposition is not None:
            disposition.apply(state)
        consumed = True
        _land_batch(state, delivery, batch, label)
    except StateRefused as halted:
        # The halt may strand a commit this batch already made: it stays on the batch branch
        # of the tenant clone, so the operator is told which.
        _logger.error(
            f"{label}: halted by a refused state entry; any commit of batch {batch.id} is on "
            f"branch {batch.branch} of the tenant clone: {halted}")
        raise
    finally:
        # A disposition not (fully) applied stays for the next tick's reclaim; its steps are
        # idempotent, so a partial apply is safe.
        if disposition is not None and not consumed:
            _logger.info(
                f"{label}: batch not consumed — left for the next tick's reclaim, up to: "
                f"{disposition.retained_summary()}"
            )
        batch.discard()
    return 0


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


def author_drain(
    paths: LoopPaths,
    *,
    # `(paths, state, channel, threshold_env, module_name, pending_label, *, batch, box)`.
    trigger_author: Callable[..., None] | None = None,
    client: httpx.Client | None = None,
    identity: ForgejoIdentity | None = None,
    issuer_config: Path | None = None,
    issuer_transport: httpx.BaseTransport | None = None,
    start_box: Callable[..., Any] | None = None,
    stop_box: Callable[..., None] = box_mod.stop_box,
) -> int:
    """The lessons lane's tick into the selected tenant's repository (flow 4). `client` is the
    forge's HTTP client (one is built when absent); `identity` the tenant's delivery identity,
    else the drain logs in with the issuer client config the forge binding names (A-ID;
    `issuer_config` stands in for it), its
    requests through `issuer_transport` when given; `start_box`/`stop_box` the batch's box
    (default `TenantDelivery.start_box`, sandbox required, and `box.stop_box`)."""
    _validate_merge_mode()
    # The lane's label reaches its work step bound into the DEFAULT seam, so an injected seam
    # keeps its call shape (#1134).
    if trigger_author is None:
        trigger_author = functools.partial(_maybe_trigger_author, label=AUTHOR_DRAIN_LABEL)
    seam = trigger_author

    def open_delivery() -> contextlib.AbstractContextManager[TenantDelivery]:
        return _open_delivery(paths, client=client,
                              identity=identity, issuer_config=issuer_config,
                              issuer_transport=issuer_transport)

    # The root is opened once, here, and handed inward; a missing root stops the stage.
    with LearningState.open(paths) as state, state.lock(
            AUTHOR_DRAIN_LOCK, wait=TRY_ONCE) as locked:
        if not locked:
            _logger.warning("author_drain: another drainer holds the lock — exiting")
            return 0
        return _refusing(lambda: _run_tenant_batch(
            paths, state, label=AUTHOR_DRAIN_LABEL,
            has_work=_has_curator_work,
            do_work=lambda work_paths, *, batch, box=None: _drain_curators(
                work_paths, state, seam, box=box, batch=batch
            ),
            open_delivery=open_delivery, start_box=start_box, stop_box=stop_box,
        ))


def lead_author_drain(  # noqa: PLR0913 — the stage's seams (OD4, OD16): two steps, the forge, the issuer, the box
    paths: LoopPaths,
    *,
    run_lead_author: Callable[..., None] | None = None,
    run_pitfalls: Callable[..., int] | None = None,
    client: httpx.Client | None = None,
    identity: ForgejoIdentity | None = None,
    issuer_config: Path | None = None,
    issuer_transport: httpx.BaseTransport | None = None,
    start_box: Callable[..., Any] | None = None,
    stop_box: Callable[..., None] = box_mod.stop_box,
    git_timeout: float = GIT_TIMEOUT_SECONDS,
) -> int:
    """The lead-author lane's tick into the selected tenant's repository (flow 4), its
    delivery seams as `author_drain`'s. `git_timeout` is bound into the DEFAULT work steps only
    (the lanes' own bounded reads, #1175)."""
    _validate_merge_mode()
    # Read every configured value before a batch, box or agent exists, so a malformed setting
    # refuses the tick rather than a commit.
    lock_wait_seconds = repo_lock_wait_seconds()
    # The lane's label and git bound reach its work steps bound into the DEFAULT seams, so an
    # injected seam keeps its call shape (#1134).
    if run_lead_author is None:
        run_lead_author = functools.partial(
            _invoke_lead_author, label=LEAD_AUTHOR_DRAIN_LABEL, git_timeout=git_timeout,
        )
    if run_pitfalls is None:
        run_pitfalls = functools.partial(
            _invoke_pitfalls, lock_wait_seconds=lock_wait_seconds, label=LEAD_AUTHOR_DRAIN_LABEL,
            git_timeout=git_timeout,
        )
    lead_step, pitfalls_step = run_lead_author, run_pitfalls

    def open_delivery() -> contextlib.AbstractContextManager[TenantDelivery]:
        return _open_delivery(paths, client=client,
                              identity=identity, issuer_config=issuer_config,
                              issuer_transport=issuer_transport)

    with LearningState.open(paths) as state, state.lock(
            LEAD_AUTHOR_DRAIN_LOCK, wait=TRY_ONCE) as locked:
        if not locked:
            _logger.warning("lead_author_drain: another drainer holds the lock — exiting")  # lint-run-records: ok — the lead-author role/drain/module's own name, not the `lead_author/` record dir
            return 0
        # The per-author queue lock (the one a by-hand `lead_author.py --tenant T <run_id>` takes) is
        # held for the whole tick: the `done` sentinel is only written once the batch is
        # delivered, and a by-hand run in that gap would see no sentinel and re-serve the run.
        # Contended, the tick skips before claiming anything.
        with state.lock(LEAD_QUEUE_LOCK, wait=TRY_ONCE) as queue_locked:
            if not queue_locked:
                _logger.warning("lead_author_drain: another lead-author run holds the queue lock — skipping")  # lint-run-records: ok — the lead-author role/drain/module's own name, not the `lead_author/` record dir
                return 0
            # Choose request acceptance before a batch or box exists. A selected tenant
            # supplies it; scratch paths resolve the configured root here, so a bad setting
            # refuses the tick with every row still queued. A tick with nothing queued reads
            # no root and claims no row: one that lands mid-tick waits for the next tick.
            accept_tenant = _tenant_acceptor(paths.tenant) if state.has_requests() else None
            return _refusing(lambda: _run_tenant_batch(
                paths, state, label=LEAD_AUTHOR_DRAIN_LABEL,
                has_work=_has_lead_author_work,
                do_work=lambda work_paths, *, batch, box=None: _drain_lead_author(
                    work_paths, state, lead_step, pitfalls_step, box=box, batch=batch,
                    lock_wait_seconds=lock_wait_seconds, git_timeout=git_timeout,
                    accept_tenant=accept_tenant,
                ),
                open_delivery=open_delivery, start_box=start_box, stop_box=stop_box,
            ))
