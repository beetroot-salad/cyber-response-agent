from __future__ import annotations

import contextlib
import functools
import importlib
import json
import logging
import subprocess
import uuid
from defender._model import model
from pathlib import Path
from typing import Any
from collections.abc import Callable

from defender.learning.core.config import (
    AUTHOR_DRAIN_LABEL,
    DEFAULT_PATHS,
    LEAD_AUTHOR_DRAIN_LABEL,
    LoopPaths,
    QueueChannel,
    author_max_attempts,
    env_int,
    merge_mode,
    now_iso,
    pitfalls_threshold,
    repo_lock_wait_seconds,
)
from defender import _git
from defender._io import guarded_mkdir, read_jsonl_rows_report
from defender.runtime import box as box_mod
from defender.learning.author import drain
from defender.learning.author import shared as _author_shared
from defender.learning.author.branch import AuthorBranch, BranchError
from defender.learning.core.faults import run_or_dead_letter
from defender.learning.core.lane_trees import open_drain_trees
from defender.learning.core.markers import (
    ClaimedMarker,
    claim_markers,
    marker_identity,
    quarantine_marker,
    requeue_marker,
    rewrite_marker,
)
from defender.learning.core.persist import (
    merge_pitfalls,
    pitfalls_lane_is_open,
    read_pitfalls,
)
from defender.learning.core.pitfalls_disposition import PitfallsDisposition
from defender.learning.core.quarantine import preserve_tainted_tree

_logger = logging.getLogger(__name__)


class _LeadAuthorRetry(Exception):
    pass


def _invoke_lead_author(
    paths: LoopPaths, run_dir: Path, *, label: str, box: Any = None,
    on_done: Callable[[str | None], None],
) -> None:
    """The lead-author lane's default work step for one claim. `label` is the lane's (bound in by
    `lead_author_drain`): the held roots of its writable mounts are opened here, with the box up,
    and closed when the claim's serve returns or raises (#1134 A3). A fault holding them
    propagates as itself, never as a swallowed transient."""
    from defender.learning.leads.lead_extraction import LeadAuthorError

    _logger.info("step=lead-author")
    # The drain holds the per-author queue lock for the whole tick (`lead_author_drain`), so
    # the curator is entered past its own acquisition and its done sentinel is deferred to
    # `on_done`.
    with open_drain_trees(paths, label) as trees:
        rc = _run_curator_module(
            "lead_author",  # lint-run-records: ok — the lead-author role/drain/module's own name, not the `lead_author/` record dir
            lambda mod: mod.run_under_held_queue_lock(
                run_dir, paths=paths, trees=trees, box=box, on_done=on_done,
            ),
        )
    if rc not in (0, None):
        raise LeadAuthorError(f"lead-author for {run_dir.name} returned rc={rc}")
    if rc is None:
        raise _LeadAuthorRetry("lead-author hit a swallowed transient (rc=None)")


def _maybe_trigger_author(
    paths: LoopPaths,
    pending_file: Path,
    threshold_env: str,
    module_name: str,
    pending_label: str,
    *,
    box: Any = None,
) -> None:
    threshold = env_int(threshold_env, 5)
    # Held is logged beside authorable: the count is authorable rows, not queue depth, so
    # without it a queue of permanent holds would log `pending=0` with no explanation.
    pending_count, held_count = _pending_queue_counts(pending_file)
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
    rc = _run_curator_module(
        module_name, lambda mod: mod.run_batch(hold_committed=True, paths=paths, box=box)
    )
    if rc not in (0, None):
        _logger.warning(f"{module_name} returned rc={rc} (queue intact, retry next tick)")


_CURATOR_MODULES = {
    "lead_author": "defender.learning.leads.lead_author",  # lint-run-records: ok — the lead-author role/drain/module's own name, not the `lead_author/` record dir
    "pitfalls_curator": "defender.learning.leads.pitfalls_curator",
    "author": "defender.learning.author.lessons.run",
    # Runs as one unit with `author` — same tick, worktree, box, branch and PR lease — with
    # its own channel, corpus and consumption.
    "questioner_curator": "defender.learning.author.questioner.run",
}


def _run_curator_module(module_name: str, call: Callable[[Any], int]):
    mod = importlib.import_module(_CURATOR_MODULES[module_name])
    try:
        return call(mod)
    except (subprocess.SubprocessError, OSError) as e:
        _logger.error(f"{module_name} crashed: {e!r} (continuing)")
        return None


def _curator_queue_checks(paths: LoopPaths) -> list[tuple[Path, str]]:
    """The queues whose depth can wake this drain: the findings and questioner-findings
    channels.

    Named rather than derived from another table, so adding or removing a channel is an
    explicit edit here."""
    return [
        (paths.pending_file, "LEARNING_AUTHOR_THRESHOLD"),
        (paths.questioner_findings_file, "LEARNING_QUESTIONER_THRESHOLD"),
    ]


def _pending_queue_counts(pending_file: Path) -> tuple[int, int]:
    """`(authorable, held)` — queued rows a tick could still author, and rows it has declined.
    Both come from one read, since the wake gate's number means little to an operator without
    the other.

    A row is held iff it carries `held_reason`, which only the pre-author gate's permanent
    holds stamp (the closing rotation writes them back). Counting held rows as work would pin
    the wake gate open forever re-holding the same rows. Presence, not truthiness: a row
    stamped `held_reason: ""` or `null` is still held.

    An unreadable line counts as authorable, so a queue of junk still wakes a tick;
    `drain._tick` then runs through to a rotation, which rewrites the file without it."""
    rows, unreadable = read_jsonl_rows_report(pending_file)
    held = sum(1 for row in rows if "held_reason" in row)
    return len(rows) - held + unreadable, held


def _has_curator_work(paths: LoopPaths) -> bool:
    """Whether any wakeable queue holds a threshold's worth of authorable rows.

    Logs the counts for a non-empty queue that doesn't wake: this is the gate that stops the
    tick, so otherwise a queue of permanent holds would show only "nothing queued". Empty
    queues stay silent, to avoid a line every pass on every queue. Not `any(...)`, so every
    queue gets its line."""
    woken = False
    for pending_file, env in _curator_queue_checks(paths):
        threshold = env_int(env, 5)
        authorable, held = _pending_queue_counts(pending_file)
        if authorable >= threshold:
            woken = True
        elif authorable or held:
            _logger.info(
                f"{pending_file.name}: pending={authorable} held={held} "
                f"threshold={threshold} — not woken"
            )
    return woken


def _has_lead_author_work(paths: LoopPaths) -> bool:
    threshold = pitfalls_threshold()
    qdir = paths.author_queue_dir
    if qdir.is_dir() and any(qdir.glob("*.json")):
        return True
    # A marker stranded in `inflight/` by a drain that died mid-serve is still work: the
    # drainer reclaims it, so this gate must wake for it.
    inflight = qdir / "inflight"
    if inflight.is_dir() and any(inflight.glob("*.json")):
        return True
    # The same condition `run_pitfalls` gates on, so the drain never wakes for a curation that
    # then declines, nor sleeps through one it would take.
    return pitfalls_lane_is_open(merge_pitfalls(read_pitfalls(paths)), threshold)


def _drain_one_curator(
    paths: LoopPaths, trigger_author: Callable[..., None], channel: QueueChannel,
    threshold_env: str, module_name: str, pending_label: str, *, box: Any,
) -> None:
    """Run one curator, containing its fault to its own channel.

    `trigger_author` is a caller-supplied seam whose exception discipline can't be assumed, so
    the isolation lives here. A `RETIRE_SET` fault propagates; anything else is recorded on
    this channel's stuck report and swallowed, so the sibling curator still runs."""
    from defender._io import read_jsonl_rows

    # `run_batch` already records non-`RETIRE_SET` faults before re-raising. A second record
    # here, with a different row set, would reset `consecutive_ticks` every tick, so the count
    # tells "already recorded" from "raised above `run_batch`, recorded nowhere".
    recorded_before = drain.stuck_record_count(channel)
    try:
        trigger_author(paths, channel.file, threshold_env, module_name, pending_label, box=box)
    except drain.RETIRE_SET:
        raise
    # An interrupt leaves at once; swallowing it would record Ctrl-C as a curator fault, run
    # the sibling curator, and go on to commit, push and open a PR for the batch the operator
    # asked to stop.
    #
    # `SystemExit` is contained, since it is not an interrupt: escaping would skip the sibling
    # curator and unwind past `finish_batch`, discarding the first curator's authored lessons
    # with nothing recorded on either channel.
    except KeyboardInterrupt:
        raise
    except (Exception, SystemExit) as e:  # noqa: BLE001 — every other fault class is recorded, never silently swallowed
        already = drain.stuck_record_count(channel) > recorded_before
        if not already:
            rows = read_jsonl_rows(channel.file) if channel.file.is_file() else []
            drain.record_stuck(channel, e, rows)
        _logger.error(f"{module_name}: {type(e).__name__} took this curator out of the tick "
                      f"({'already recorded in' if already else 'recorded to'} "
                      f"{drain.stuck_report_file(channel)}); the other curator still ran")


def _drain_curators(
    paths: LoopPaths,
    trigger_author: Callable[..., None],
    *,
    box: Any = None,
) -> None:
    # The same two channels the wake gate (`_curator_queue_checks`) answers for. Both curators
    # share one tick — worktree, box, branch, PR lease — and `_drain_one_curator` contains each
    # one's non-retiring fault, so it never stops the other or its commit. A `RETIRE_SET` fault
    # propagates, so one in the first curator can cost the second its turn. This frame must not
    # raise on a non-retiring fault, or `finish_batch` is never reached and neither curator's
    # work is committed.
    _drain_one_curator(paths, trigger_author, paths.findings, "LEARNING_AUTHOR_THRESHOLD",
                       "author", "pending", box=box)
    _drain_one_curator(paths, trigger_author, paths.questioner_findings,
                       "LEARNING_QUESTIONER_THRESHOLD", "questioner_curator",
                       "questioner_pending", box=box)


def _discard_worktree_changes(repo_root: Path) -> None:
    if not (repo_root / ".git").exists():
        return
    for args in (["reset", "--hard", "--quiet"], ["clean", "-fdq"]):
        _git.git(args, cwd=repo_root, check=False)


def _quarantine_lead_author_failure(
    spec: dict, marker: Path, queue_dir: Path, e: Exception
) -> None:
    quarantine_marker(spec, marker, queue_dir, f"lead-author-error: {e!r}")


def _requeue_or_drop(claim: ClaimedMarker, *, note: str) -> None:
    """Hand one claimed request back to the queue, then release the claim.

    The re-queue lands at the top level (not the `inflight/` slot being released) and is
    create-if-absent: a fresher request for the same case that arrived meanwhile wins, and
    this older spec is dropped. The spec comes off the claim so the re-queue and the unlink
    can't refer to different claims."""
    if requeue_marker(claim.queued_path, claim.spec):
        _logger.info(f"lead_author_drain: {note} — left queued for retry")  # lint-run-records: ok — the lead-author role/drain/module's own name, not the `lead_author/` record dir
    else:
        _logger.info(
            f"lead_author_drain: {note} — a fresher request for the same case landed "  # lint-run-records: ok — the lead-author role/drain/module's own name, not the `lead_author/` record dir
            "while it was claimed and supersedes it; dropping this one"
        )
    with contextlib.suppress(OSError):
        claim.path.unlink()


@model(frozen=True)
class ServedMarker:
    """One lead-author request the tick served cleanly: the claim still in `inflight/`,
    whether the curator reached the exit that records the run done (the no-executed-leads,
    no-pending-drafts exit doesn't), and its commit (`None` for done without a commit)."""

    claim: ClaimedMarker
    done: bool
    sha: str | None


@model(frozen=True)
class BatchDisposition:
    """Everything a lead-author tick consumes from shared state, collected during `do_work`
    and applied only once the batch's tree has passed the scrub.

    The consumption points (served marker unlink, per-run `done` sentinel, pitfalls rotation
    and decline bumps) write to the state root, which survives the worktree swap. Applied
    inside `do_work`, a tainted scrub would already have emptied the queue for a commit that
    must never be delivered.

    After the scrub, not the push: the commits then sit on a local branch as durable as the
    queues, and delivery is retried separately (`_deliver_pending`) without re-running agents.

    Never persisted: an exit before the apply drops it, and served claims stay in `inflight/`
    for `claim_markers` to reclaim (not re-queued, since a stale re-queue and a fresher
    same-case marker would collide on one inflight path). Each reclaim counts an attempt, so a
    batch that never passes the scrub is quarantined at the usual ceiling.

    `apply` is ordered sentinels → unlinks → pitfalls rotation → decline bumps, so a crash
    mid-apply costs a re-serve or re-curation, never a loss."""

    served: list[ServedMarker]
    pitfalls: PitfallsDisposition | None
    #: The pitfalls append-lock wait, resolved at the drain's entry rather than here, after the
    #: commit exists. `None` (no deadline) only when a test drives the internals directly.
    lock_wait_seconds: int | None

    def apply(self, paths: LoopPaths) -> None:
        from defender.learning.leads.lead_author import write_done_sentinel

        for marker in self.served:
            if marker.done:
                write_done_sentinel(marker.claim.run_dir, marker.sha)
        for marker in self.served:
            with contextlib.suppress(OSError):
                marker.claim.path.unlink()
        if self.pitfalls is not None:
            self.pitfalls.apply(paths, timeout_seconds=self.lock_wait_seconds)

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


def _drain_lead_author_markers(
    paths: LoopPaths,
    run_lead_author: Callable[..., None],
    *,
    box: Any = None,
) -> list[ServedMarker]:
    qdir = paths.author_queue_dir
    max_retries = env_int("LEAD_AUTHOR_MAX_RETRIES", 3)
    # `case_id`: this queue's live writer (`enqueue_case_for_curation`) mints the filename
    # from the case, so that is what an unreadable row's dead letter is keyed on.
    claims = claim_markers(
        qdir, identity_key="case_id", label=LEAD_AUTHOR_DRAIN_LABEL, noun="lead-author",
    )
    served: list[ServedMarker] = []
    for claim in claims:
        claimed, spec, run_dir = claim.path, claim.spec, claim.run_dir
        # Every serve is an attempt, counted before the agent runs: a claim the apply never
        # reached is reclaimed next tick, and a run that taints every tree must hit the ceiling.
        attempts = int(spec.get("attempts", 0)) + 1
        if attempts > max_retries:
            quarantine_marker(
                spec, claimed, qdir,
                f"served {attempts - 1} time(s) without being recorded done",
            )
            continue
        # On the claim alone: the spec in hand stays as read, so a terminal refusal's dead
        # letter carries no counter; the transient arm stamps the spec only when it re-queues.
        rewrite_marker(claimed, {**spec, "attempts": attempts})
        # The curator's commit, handed back for `BatchDisposition.apply` to record once the
        # tree passes the scrub.
        done: list[str | None] = []
        try:
            drained = run_or_dead_letter(
                functools.partial(
                    run_lead_author, paths, run_dir, box=box, on_done=done.append,
                ),
                functools.partial(
                    _quarantine_lead_author_failure, spec, claimed, paths.author_queue_dir
                ),
                propagate=(_LeadAuthorRetry,),
            )
        except _LeadAuthorRetry as e:
            if attempts >= max_retries:
                quarantine_marker(
                    spec, claimed, paths.author_queue_dir,
                    f"transient-exhausted after {attempts} attempt(s): {e!r}",
                )
            else:
                spec["attempts"] = attempts
                _requeue_or_drop(
                    claim,
                    note=f"transient on {marker_identity(spec, claimed)} "
                         f"(attempt {attempts}/{max_retries})",
                )
            continue
        finally:
            _discard_worktree_changes(paths.repo_root)
        if drained:
            # Not unlinked here: the claim stays in `inflight/` until the tree passes the
            # scrub (`BatchDisposition.apply`).
            served.append(ServedMarker(claim, done=bool(done), sha=done[-1] if done else None))
    return served


def _invoke_pitfalls(
    paths: LoopPaths, *, label: str, box: Any = None,
    on_curated: Callable[[PitfallsDisposition], None], lock_wait_seconds: int | None = None,
) -> int:
    """The lead-author lane's default pitfalls work step: as `_invoke_lead_author`, the held roots
    of the `label` lane's writable mounts are opened here and closed when the curation returns
    or raises (#1134 A3)."""
    _logger.info("step=pitfalls-curation")
    with open_drain_trees(paths, label) as trees:
        rc = _run_curator_module(
            "pitfalls_curator",
            lambda mod: mod.run_pitfalls(
                paths=paths, trees=trees, box=box, on_curated=on_curated,
                lock_wait_seconds=lock_wait_seconds,
            ),
        )
    return rc if rc is not None else 0


def _retire_pitfalls_batch(
    paths: LoopPaths, batch_ids: list[str], lock_wait_seconds: int | None, e: Exception,
) -> None:
    _logger.error(f"lead_author_drain: pitfalls curation error: {e!r}; discarding edits")  # lint-run-records: ok — the lead-author role/drain/module's own name, not the `lead_author/` record dir
    if not batch_ids:
        return
    drain.retire(
        channel=paths.pitfalls,
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
    run_pitfalls: Callable[..., int],
    *,
    box: Any = None,
    lock_wait_seconds: int | None = None,
) -> PitfallsDisposition | None:
    # The batch is fixed at this read: a pitfall appended while the curation runs must not be
    # bumped.
    batch_ids = [str(r["pitfall_id"]) for r in read_pitfalls(paths) if r.get("pitfall_id")]
    # Only the success-path consumption is handed back; failure dispositions don't depend on
    # the scrub and are applied immediately.
    curated: list[PitfallsDisposition] = []
    try:
        run_or_dead_letter(
            lambda: run_pitfalls(paths, box=box, on_curated=curated.append),
            functools.partial(_retire_pitfalls_batch, paths, batch_ids, lock_wait_seconds),
        )
    finally:
        _discard_worktree_changes(paths.repo_root)
    return curated[-1] if curated else None


def _drain_lead_author(
    paths: LoopPaths,
    run_lead_author: Callable[..., None],
    run_pitfalls: Callable[..., int],
    *,
    box: Any = None,
    lock_wait_seconds: int | None = None,
) -> BatchDisposition:
    served = _drain_lead_author_markers(paths, run_lead_author, box=box)
    pitfalls = _drain_pitfalls(
        paths, run_pitfalls, box=box, lock_wait_seconds=lock_wait_seconds,
    )
    return BatchDisposition(
        served=served, pitfalls=pitfalls, lock_wait_seconds=lock_wait_seconds,
    )


def _validate_merge_mode() -> None:
    merge_mode()


def _drain_box_request(
    wt: Path, batch_id: str, label: str, paths: LoopPaths,
) -> box_mod.BoxRequest:
    """The drain box's mounts: ro over the whole worktree leaf (it carries `<wt>/defender` and
    is both drain roles' cwd_anchor), rw over exactly the leaf's
    `LoopPaths.drain_writable_trees(label)`, in its order, each at its own path. Nothing
    outside the leaf.

    The rw list is taken whole from its owner, never derived here, so the box's writable
    mounts and the roots `lane_trees.open_drain_trees` holds are one list (#1134 O4). An
    unrecognized label therefore gets no writable tree."""
    wt_paths = paths.with_repo_root(wt)
    mounts = [box_mod.Mount(source=wt, target=wt, writable=False)]
    for d in wt_paths.drain_writable_trees(label):
        mounts.append(box_mod.Mount(source=d, target=d, writable=True))
    return box_mod.BoxRequest(
        name=f"defender-drain-{batch_id}", mounts=tuple(mounts), workdir=wt, env={},
    )


@model(frozen=True)
class PendingDelivery:
    """One batch whose commit is on a local branch and whose push or PR has not yet
    landed. Written by the tick that failed to deliver it; read, and removed once delivered,
    by a later tick of the same lane."""

    path: Path
    branch: str
    batch_id: str


def _pending_delivery_record(paths: LoopPaths, branch: AuthorBranch, batch_id: str) -> Path:
    slug = branch.branch_prefix.rstrip("/").replace("/", "-") or "author"
    return paths.pending_delivery_dir / f"{slug}-{batch_id}.json"


def _record_pending_delivery(
    paths: LoopPaths, branch: AuthorBranch, batch_id: str, *, label: str, reason: str,
) -> None:
    record = _pending_delivery_record(paths, branch, batch_id)
    guarded_mkdir(record.parent, base=paths.state_root)
    rewrite_marker(record, {
        "branch": branch.branch_name(batch_id), "batch_id": batch_id, "label": label,
        "reason": reason, "at": now_iso(),
    })


def _pending_deliveries(paths: LoopPaths, branch: AuthorBranch) -> list[PendingDelivery]:
    """This lane's undelivered batches — only those under `branch.branch_prefix`, since the
    other lane delivers under its own drain lock. An unreadable record names no branch or lane,
    so it is quarantined rather than logged every tick forever."""
    d = paths.pending_delivery_dir
    out: list[PendingDelivery] = []
    for path in sorted(d.glob("*.json")) if d.is_dir() else []:
        try:
            spec = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            spec = None
        if not isinstance(spec, dict) or not isinstance(spec.get("batch_id"), str):
            quarantine_marker({}, path, d, "unreadable pending-delivery record")
            continue
        name = str(spec.get("branch", ""))
        if name.startswith(branch.branch_prefix):
            out.append(PendingDelivery(path, name, spec["batch_id"]))
    return out


def _deliver_pending(paths: LoopPaths, branch: AuthorBranch, label: str) -> bool:
    """Deliver every batch this lane committed but could not push or open a PR for, before
    anything new is served. Answers whether the lane is clear to serve.

    An undelivered batch holds the writer lease like an open PR: the next batch must build on
    its commit, and a fresh branch beside it would open conflicting PRs. So a failed delivery
    parks the lane until the remote takes it. Nothing here re-runs an agent."""
    for pending in _pending_deliveries(paths, branch):
        try:
            pr = branch.deliver(pending.batch_id)
        except BranchError as e:
            _logger.error(
                f"{label}: delivery of retained branch {pending.branch} failed again: {e} — "
                "it holds the writer lease; nothing served this tick"
            )
            return False
        with contextlib.suppress(OSError):
            pending.path.unlink()
        if pr is None:
            _logger.info(
                f"{label}: retained branch {pending.branch} has nothing left to deliver "
                "— record dropped"
            )
        else:
            _logger.info(f"{label}: delivered retained branch {pending.branch}: opened PR {pr}")
    return True


def _land_batch(
    paths: LoopPaths, branch: AuthorBranch, batch_id: str, wt: Path, label: str,
) -> tuple[str | None, bool]:
    """Push and open the PR: `(pr, delivered)`. `pr` is `None` for a zero-commit batch. On a
    `BranchError` the commit stays on a local branch `cleanup` never deletes, and the failure
    is recorded for the next tick to deliver (`_deliver_pending`) before serving anything."""
    try:
        return branch.finish_batch(batch_id, wt), True
    except BranchError as e:
        _record_pending_delivery(paths, branch, batch_id, label=label, reason=str(e))
        _logger.error(
            f"{label}: finish_batch failed: {e} — commit retained on local branch "
            f"{branch.branch_name(batch_id)}; delivery is retried next tick, before "
            "anything new is served"
        )
        return None, False


def _open_batch(
    paths: LoopPaths, branch: AuthorBranch, *, label: str, has_work: Callable[[LoopPaths], bool],
) -> tuple[str, Path] | None:
    """Everything that decides whether a tick serves at all, in order: an earlier batch's
    delivery (which holds the lease while it fails), the wake gate, the open-PR lease, the
    worktree. `(batch_id, worktree)` to serve into, or `None` for a tick that stops here."""
    if not _deliver_pending(paths, branch, label):
        return None
    if not has_work(paths):
        _logger.info(f"{label}: nothing queued and no curator at threshold — skipping")
        return None
    try:
        if branch.open_pr_exists():
            _logger.info(f"{label}: an open {branch.branch_prefix} PR holds the writer lease — skipping")
            return None
        batch_id = uuid.uuid4().hex[:12]
        return batch_id, branch.start_batch(batch_id)
    except BranchError as e:
        _logger.warning(f"{label}: cannot start batch worktree: {e} — skipping")
        return None


def _unwind_worktree_start_fault(e: BaseException, wt: Path, branch: AuthorBranch) -> None:
    """Destroy the worktree after a box-start fault. A `BoxFault`'s remedy may name a build
    command relative to this about-to-be-deleted worktree, so it is re-raised with a durable
    pointer: the commit the worktree was cut from, plus "run the build from it" only when the
    fault carries a build remedy (a name collision or unreachable daemon isn't fixed by a
    build). Otherwise returns and the caller re-raises `e` unchanged; non-`BoxFault` unwinds
    spawn no git."""
    cut_sha: str | None = None
    if isinstance(e, box_mod.BoxFault):
        with contextlib.suppress(Exception):
            cut_sha = _git.git_head_sha(wt)
    with contextlib.suppress(Exception):
        branch.cleanup(wt)
    if isinstance(e, box_mod.BoxFault) and cut_sha:
        pointer = f"origin/main @ {cut_sha} — check out that commit"
        pointer += " and run the build from it." if box_mod.carries_build_remedy(e) else "."
        raise box_mod.BoxFault(f"{e}\n\n{pointer}") from e


def _run_worktree_batch(
    paths: LoopPaths,
    branch: AuthorBranch,
    *,
    label: str,
    has_work: Callable[[LoopPaths], bool],
    do_work: Callable[..., BatchDisposition | None],
    start_box: Callable[..., Any] = box_mod.start_box,
    stop_box: Callable[..., None] = box_mod.stop_box,
    scrub: Callable[[Path], None] = box_mod.scrub,
) -> int:
    """One batch: deliver what an earlier tick retained, then worktree, box, `do_work`,
    scrub, consume, `finish_batch`, cleanup.

    `do_work` may return a `BatchDisposition` (the lead-author lane does; the lessons lane
    returns `None`), applied once the tree has passed the scrub. A push or PR that then fails
    is recorded for next tick's delivery, not re-served. On exits before the apply (taint, box
    fault, interrupt) the disposition is dropped and the log says what stays for reclaim."""
    opened = _open_batch(paths, branch, label=label, has_work=has_work)
    if opened is None:
        return 0
    batch_id, wt = opened

    # Started after the worktree and wake checks, so it mounts exactly this batch's needs. A
    # startup fault must unwind the worktree and branch already minted.
    try:
        box = start_box(_drain_box_request(wt, batch_id, label, paths))
    except BaseException as e:
        _unwind_worktree_start_fault(e, wt, branch)
        raise

    wt_paths = paths.with_repo_root(wt)
    pr = None
    disposition: BatchDisposition | None = None
    consumed = False
    delivered = True
    try:
        # Tear down and scan on any exit from do_work (`stop_and_scrub` owns the ordering and
        # exception preference). The scan precedes consumption and finish_batch's push; a
        # failed teardown blocks all three.
        work_ok = False
        try:
            disposition = do_work(wt_paths, box=box)
            work_ok = True
        finally:
            box_mod.stop_and_scrub(
                box, wt, stop_box=stop_box, scrub_tree=scrub, in_flight=not work_ok,
            )
        if disposition is not None:
            disposition.apply(paths)
        consumed = True
        pr, delivered = _land_batch(paths, branch, batch_id, wt, label)
    except box_mod.RunTainted as taint:
        # The `finally` destroys this tree, which is the only copy of what the box planted
        # (nothing was consumed or pushed), so preserve it for a human. An except clause
        # because it must run before the `finally`; the re-raise keeps the taint signal.
        preserve_tainted_tree(
            wt, branch.quarantine_dir,
            batch_id=batch_id, branch=branch.branch_name(batch_id), label=label, taint=taint,
        )
        raise
    finally:
        # A disposition not (fully) applied stays for the next tick's reclaim; its steps are
        # idempotent, so a partial apply is safe.
        if disposition is not None and not consumed:
            _logger.info(
                f"{label}: batch not consumed — left for the next tick's reclaim, up to: "
                f"{disposition.retained_summary()}"
            )
        try:
            branch.cleanup(wt)
        except Exception as e:  # noqa: BLE001 — best-effort cleanup; the real fault outranks it
            _logger.error(f"{label}: worktree cleanup failed: {e} — {wt} leaked, scrub state unknown")

    if not delivered:
        return 0
    if pr is None:
        _logger.info(f"{label}: batch produced no commits — no PR opened")
        return 0
    _logger.info(f"{label}: opened PR {pr}")
    if merge_mode() == "auto_on_green":
        _logger.info(f"{label}: merge_mode=auto_on_green — green-bar auto-merge not yet "
                     "wired (PR C); leaving PR for review")
    return 0


def _lead_author_pr_title(batch_id: str) -> str:
    return f"learning: lead-author catalog/skill batch {batch_id}"


def _lead_author_pr_body(branch: str) -> str:
    return (
        "Automated gather-catalog / system-skill curation from the lead-author drain "
        f"(branch `{branch}`, off freshly-fetched `origin/main`). May also fold "
        "agent-fixable execution failures into per-system `execution.md` "
        "`## Common pitfalls`. Touches `defender/skills/` only — distinct from the "
        "lessons PR."
    )


def author_drain(
    paths: LoopPaths = DEFAULT_PATHS,
    *,
    # `(paths, pending_file, threshold_env, module_name, pending_label, *, box)`.
    trigger_author: Callable[..., None] | None = None,
    branch: AuthorBranch | None = None,
    start_box: Callable[..., Any] = box_mod.start_box,
    stop_box: Callable[..., None] = box_mod.stop_box,
    scrub: Callable[[Path], None] = box_mod.scrub,
) -> int:
    _validate_merge_mode()
    if trigger_author is None:
        trigger_author = _maybe_trigger_author
    if branch is None:
        branch = AuthorBranch(repo_root=paths.repo_root)

    with _author_shared.flock_or_skip(paths.author_drain_lock_file) as locked:
        if not locked:
            _logger.warning("author_drain: another drainer holds the lock — exiting")
            return 0
        return _run_worktree_batch(
            paths, branch, label=AUTHOR_DRAIN_LABEL,
            has_work=_has_curator_work,
            do_work=lambda wt_paths, *, box=None: _drain_curators(
                wt_paths, trigger_author, box=box
            ),
            start_box=start_box, stop_box=stop_box, scrub=scrub,
        )


def lead_author_drain(
    paths: LoopPaths = DEFAULT_PATHS,
    *,
    run_lead_author: Callable[..., None] | None = None,
    run_pitfalls: Callable[..., int] | None = None,
    branch: AuthorBranch | None = None,
    start_box: Callable[..., Any] = box_mod.start_box,
    stop_box: Callable[..., None] = box_mod.stop_box,
    scrub: Callable[[Path], None] = box_mod.scrub,
) -> int:
    _validate_merge_mode()
    # Read every configured value before a worktree, box or agent exists, so a malformed
    # setting refuses the tick rather than a commit.
    lock_wait_seconds = repo_lock_wait_seconds()
    # The lane's label reaches its work steps bound into the DEFAULT seams, so an injected seam
    # keeps its call shape (#1134).
    if run_lead_author is None:
        run_lead_author = functools.partial(_invoke_lead_author, label=LEAD_AUTHOR_DRAIN_LABEL)
    if run_pitfalls is None:
        run_pitfalls = functools.partial(
            _invoke_pitfalls, lock_wait_seconds=lock_wait_seconds, label=LEAD_AUTHOR_DRAIN_LABEL,
        )
    if branch is None:
        branch = AuthorBranch(
            repo_root=paths.repo_root,
            branch_prefix="lead-author/",
            pr_title=_lead_author_pr_title,
            pr_body=_lead_author_pr_body,
        )

    from defender.learning.leads.lead_author import acquire_queue_lock, release_queue_lock

    with _author_shared.flock_or_skip(paths.lead_author_drain_lock_file) as locked:
        if not locked:
            _logger.warning("lead_author_drain: another drainer holds the lock — exiting")  # lint-run-records: ok — the lead-author role/drain/module's own name, not the `lead_author/` record dir
            return 0
        # The per-author queue lock (the one a by-hand `lead_author.py <run_dir>` takes) is
        # held for the whole tick: the `done` sentinel is only written after the scrub, and a
        # by-hand run in that gap would see no sentinel and re-serve the run. Contended, the
        # tick skips before claiming anything.
        queue_lock = acquire_queue_lock(paths)
        if queue_lock is None:
            _logger.warning("lead_author_drain: another lead-author run holds the queue lock — skipping")  # lint-run-records: ok — the lead-author role/drain/module's own name, not the `lead_author/` record dir
            return 0
        try:
            return _run_worktree_batch(
                paths, branch, label=LEAD_AUTHOR_DRAIN_LABEL,
                has_work=_has_lead_author_work,
                do_work=lambda wt_paths, *, box=None: _drain_lead_author(
                    wt_paths, run_lead_author, run_pitfalls, box=box,
                    lock_wait_seconds=lock_wait_seconds,
                ),
                start_box=start_box, stop_box=stop_box, scrub=scrub,
            )
        finally:
            release_queue_lock(queue_lock)
