from __future__ import annotations

import contextlib
import functools
import importlib
import json
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any
from collections.abc import Callable

from defender.learning.core.config import (
    DEFAULT_PATHS,
    LoopPaths,
    QueueChannel,
    _log,
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
from defender.learning.core.quarantine import preserve_tainted_tree

if TYPE_CHECKING:
    # A type only: every curator module is loaded lazily through `_CURATOR_MODULES`, and
    # the lessons lane must not pay for the lead-author package's import tree.
    from defender.learning.leads.pitfalls_curator import PitfallsDisposition


class _LeadAuthorRetry(Exception):
    pass


def _invoke_lead_author(
    paths: LoopPaths, run_dir: Path, *, box: Any = None,
    on_done: Callable[[str | None], None],
) -> None:
    from defender.learning.leads.lead_extraction import LeadAuthorError

    _log("step=lead-author")
    # The per-author queue lock is the DRAIN's for the whole tick (`lead_author_drain`), so
    # the curator is entered past its own acquisition: the sentinel it would have written
    # under that lock is deferred to `on_done`, and a by-hand run that took the lock in the
    # gap between this serve and the scrub would otherwise re-serve the run (#952 M5).
    rc = _run_curator_module(
        "lead_author",
        lambda mod: mod.run_under_held_queue_lock(
            run_dir, paths=paths, box=box, on_done=on_done,
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
    # HELD IS LOGGED BESIDE AUTHORABLE ON BOTH ARMS, off the same single read. Since #881 this
    # count is authorable rows and not queue depth, so a queue of a hundred permanently-held
    # rows logs `pending=0`, and a batch of six authored beside two hundred held ones logs
    # `pending=6` — neither number is the file's length, and the held report, those rows' only
    # other trace, is written from inside a tick. `_has_curator_work` says the same pair
    # earlier and more often: it is the gate that actually declines to run a tick, and this
    # one is reached only after it has already answered yes.
    pending_count, held_count = _pending_queue_counts(pending_file)
    if pending_count < threshold:
        _log(
            f"{pending_label}={pending_count} held={held_count} threshold={threshold} "
            f"— {module_name} not invoked"
        )
        return
    _log(
        f"step={module_name} {pending_label}={pending_count} held={held_count} "
        f"threshold={threshold}"
    )
    rc = _run_curator_module(
        module_name, lambda mod: mod.run_batch(hold_committed=True, paths=paths, box=box)
    )
    if rc not in (0, None):
        _log(f"{module_name} returned rc={rc} (queue intact, retry next tick)")


_CURATOR_MODULES = {
    "lead_author": "defender.learning.leads.lead_author",
    "pitfalls_curator": "defender.learning.leads.pitfalls_curator",
    "author": "defender.learning.author.lessons.run",
    # #1007 M6/M7/R1: the second curator, one unit with `author` — same tick, same worktree,
    # same box, same branch and PR lease; its own channel, its own corpus, its own consumption.
    "questioner_curator": "defender.learning.author.questioner.run",
}


def _run_curator_module(module_name: str, call: Callable[[Any], int]):
    mod = importlib.import_module(_CURATOR_MODULES[module_name])
    try:
        return call(mod)
    except (subprocess.SubprocessError, OSError) as e:
        _log(f"{module_name} crashed: {e!r} (continuing)")
        return None


def _curator_queue_checks(paths: LoopPaths) -> list[tuple[Path, str]]:
    """The queues whose depth can wake this drain: the findings channel, and nothing else.

    NAMED, not derived. Until #922 this walked the direction table and added each direction's
    observation triggers, which made the OLD LOOP'S DISPATCH TABLE the registry for a stage
    that outlives it — so deleting the table would have narrowed this list to its one literal
    silently, with no error and no failing test. The three observation channels lost their
    producer in the same change (the family judge writes findings rows only), so the honest
    shape is one channel spelled once. A second channel returning is an edit here, in a diff,
    which is the property the loop did not have."""
    return [
        (paths.pending_file, "LEARNING_AUTHOR_THRESHOLD"),
        # #1007 M6/M7: the second channel, named the same deliberate way — an edit here, in a
        # diff, is #922's own stated property for what a second channel returning looks like.
        (paths.questioner_findings_file, "LEARNING_QUESTIONER_THRESHOLD"),
    ]


def _pending_queue_counts(pending_file: Path) -> tuple[int, int]:
    """`(authorable, held)` — how many queued rows a tick could still author, and how many it
    has already declined. NEITHER is how many lines the file has, which is why both are
    answered here: the number the wake gate compares is meaningless to an operator without
    the number that explains it, and re-reading the file to say the second would parse the
    whole queue twice on the commonest path there is.

    `held_reason` IS the answer, and it is the drain's own: both arms of the pre-author gate
    stamp it on the copy they hold, and the closing rotation writes those stamped copies back
    into this file. So the field this reads is the field the holder wrote, one source of
    truth, and no second rule about what "held" means (#881/O2).

    IT IS THE PERMANENT HOLD'S FIELD ALONE. The forward-check bucket used to write it too,
    and that made this count answer "not work" for a hold the very next tick would have
    RETRIED — `_gate_findings` re-admits a forward-check row, and the check gets another
    verdict once the corpus has moved. Those rows were then never retried and never consumed:
    queued, uncounted, invisible, which is this issue's own subject. That bucket writes
    `forward_bad_reason` now, so one field carries one meaning.

    PRESENCE, NOT TRUTHINESS. The field is the contract and its value is the holder's prose,
    so a row stamped `held_reason: ""` (or `null`, by a writer that had no wording to give) is
    held — a truthiness test reads it as authorable and the wake gate spins on it every tick,
    which is O2's own defect by the one route no gate in the tree spells today.

    Counting lines instead made a permanent hold look like pending work. A hold is permanent
    by construction — the fact it waits on has no writer any more — so five of them pinned the
    wake gate open forever: every tick fetched, added a worktree, started a box and scrubbed
    it, to re-hold the same five rows; and the first genuinely authorable row arrived at a
    count already over threshold, so the curator got a batch of one against a documented five.

    AN UNREADABLE LINE COUNTS AS ONE, and the tick it wakes is what clears it: a count that
    skipped what it could not parse would strand a queue full of junk below the threshold,
    invisible. It is NOT retired — there is no row to graveyard — so `drain._tick` runs
    through to a rotation on an all-unreadable queue rather than returning on the empty batch,
    and every rotation rewrites the file from the rows it can read. Returning early instead
    left the junk counted and uncleared, which is this function's own defect wearing the other
    mask: the gate fired on the same bytes every tick, forever."""
    rows, unreadable = read_jsonl_rows_report(pending_file)
    held = sum(1 for row in rows if "held_reason" in row)
    return len(rows) - held + unreadable, held


def _has_curator_work(paths: LoopPaths) -> bool:
    """Whether any wakeable queue holds a threshold's worth of AUTHORABLE rows.

    THE COUNTS ARE SAID HERE, because this is the gate that actually stops the tick.
    `_maybe_trigger_author` logs them too, but it is only reached once this has already
    answered True on the same file against the same threshold — so on the queue the count
    exists for (a hundred permanent holds, authorable zero) the only line an operator would
    otherwise see is `_run_worktree_batch`'s "nothing queued", against a file with a hundred
    lines in it. The held report, those rows' other trace, is written from inside a tick this
    gate is what stops from running, so silence here is silence everywhere.

    SAID ONLY WHEN THE FILE IS NOT EMPTY, and as a bare status line: a queue holding nothing
    is exactly what "nothing queued" already reports, and a line that fires every pass on
    every queue is the thing `write_held_report`'s own docstring refuses. `authorable` covers
    the junk-only case as well as the below-threshold one — an unreadable line counts toward
    it, so a file of four torn lines still says so rather than passing for empty.

    Not `any(...)`: every wakeable queue is read whether or not an earlier one already woke
    the drain, because the line above is per queue and a short-circuit would drop it."""
    woken = False
    for pending_file, env in _curator_queue_checks(paths):
        threshold = env_int(env, 5)
        authorable, held = _pending_queue_counts(pending_file)
        if authorable >= threshold:
            woken = True
        elif authorable or held:
            _log(
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
    # drainer reclaims it, so this gate has to wake for it or it never runs again.
    inflight = qdir / "inflight"
    if inflight.is_dir() and any(inflight.glob("*.json")):
        return True
    # The same arrival condition `run_pitfalls` gates on, asked through the same function: a
    # wake gate that counted rows, or answered a different question from the tick's, would
    # spin the drain up for a curation that then declines to run — or never wake for work the
    # tick would have taken.
    return pitfalls_lane_is_open(merge_pitfalls(read_pitfalls(paths)), threshold)


def _drain_one_curator(
    paths: LoopPaths, trigger_author: Callable[..., None], channel: QueueChannel,
    threshold_env: str, module_name: str, pending_label: str, *, box: Any,
) -> None:
    """One curator's own fault CONTAINED to its own channel (#1007 A2's third clause) —
    `trigger_author` here is a caller-supplied seam (`_maybe_trigger_author` in production,
    an arbitrary fake in tests) and this frame cannot assume ITS OWN exception discipline, so
    the isolation lives here rather than inside it. A fault whose class IS in `RETIRE_SET`
    (`AuthorError`/`GitError`/`ModelRetry`) is production's own "this row is bad, retire it"
    signal and propagates as it always has; anything else is durably recorded on THIS channel's
    own stuck report and swallowed — the other curator's own `_drain_one_curator` call is a
    sibling statement, never inside this one's `try`, so it still runs."""
    from defender._io import read_jsonl_rows

    # WHAT THE STUCK REPORT HELD BEFORE THIS CURATOR RAN. `run_batch` records every
    # non-`RETIRE_SET` fault before it re-raises, so on the ordinary path this frame's own
    # record would be the SECOND for one tick — and the two frames hold different row sets
    # (the rows in flight there, the whole queue here), so the next tick's record matched
    # neither and `consecutive_ticks` reset to 1 forever. Comparing the count is what tells
    # "already recorded" from "raised by the seam above `run_batch`, recorded nowhere".
    recorded_before = drain.stuck_record_count(channel)
    try:
        trigger_author(paths, channel.file, threshold_env, module_name, pending_label, box=box)
    except drain.RETIRE_SET:
        raise
    # AN INTERRUPT LEAVES AT ONCE, and nothing else does — drain.py's own recorder states the
    # first half of the rule ("so an interrupt arriving mid-record still leaves at once").
    # Caught as a bare `BaseException` this frame swallowed `KeyboardInterrupt`: an operator's
    # Ctrl-C was written to the channel's stuck report as if it were a curator fault, the SECOND
    # curator's model calls then started, and `_run_worktree_batch` went on to `finish_batch` —
    # committing, pushing and opening a PR for the batch the operator had just asked to stop.
    #
    # `SystemExit` IS STILL CONTAINED, though, because it is not an interrupt: it is this
    # repo's own fatal-configuration idiom (`verify_forward/checks._verify` raises it for a
    # check carrying no verifier prompt, `curator_engine._refuse_forward_check` for a direction
    # that registers none). Let out, it escapes `_drain_curators` — the one thing that frame's
    # own comment says this frame must never do — skipping the sibling curator entirely and
    # unwinding past `finish_batch`, so the FIRST curator's already-authored lessons are
    # discarded with the worktree and nothing is committed, pushed or recorded on either
    # channel. That is A2's third clause exactly: recorded on this channel, contained here.
    except KeyboardInterrupt:
        raise
    except (Exception, SystemExit) as e:  # noqa: BLE001 — A2's third clause: EVERY other fault class is recorded, never silently swallowed
        already = drain.stuck_record_count(channel) > recorded_before
        if not already:
            rows = read_jsonl_rows(channel.file) if channel.file.is_file() else []
            drain.record_stuck(channel, e, rows)
        _log(f"{module_name}: {type(e).__name__} took this curator out of the tick "
             f"({'already recorded in' if already else 'recorded to'} "
             f"{drain.stuck_report_file(channel)}); the other curator still ran")


def _drain_curators(
    paths: LoopPaths,
    trigger_author: Callable[..., None],
    *,
    box: Any = None,
) -> None:
    # TWO curators, each named — see `_curator_queue_checks` for why this is no longer a walk
    # of the direction table. Each channel this fires for is the same one the wake gate answers
    # for, spelled the same way in both places so they cannot disagree about what work exists.
    # A2/R1: both calls share this ONE tick — one worktree, one box, one branch, one PR lease —
    # and `_drain_one_curator` contains each curator's own NON-RETIRING fault independently, so
    # such a fault in one curator never stops the other from being triggered or from landing
    # its own commit. A `RETIRE_SET`-class fault (`_drain_one_curator`'s own `except: raise`)
    # is the one exception: it propagates past this frame, so a retiring fault in the FIRST
    # curator this pass calls can still cost the second curator its turn this tick (this frame
    # itself must not raise on a non-retiring fault, or `_run_worktree_batch`'s `do_work` never
    # reaches `finish_batch` and NEITHER curator's work is committed).
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

    The re-queue lands at the TOP level — never at `claim.path`, the `inflight/` slot the
    claim occupies and this hand-back releases — and it is CREATE-IF-ABSENT. A fresher
    request for the same case that arrived while this one was claimed already occupies that
    slot, and the queue's contract is that the later run wins, so the older spec is dropped
    rather than written over it.

    The spec comes off the CLAIM rather than as its own argument: what goes back on the
    queue and what is unlinked from `inflight/` are two halves of one hand-back, and a
    caller able to pass a spec belonging to some other claim could split them."""
    if requeue_marker(claim.queued_path, claim.spec):
        _log(f"lead_author_drain: {note} — left queued for retry")
    else:
        _log(
            f"lead_author_drain: {note} — a fresher request for the same case landed "
            "while it was claimed and supersedes it; dropping this one"
        )
    with contextlib.suppress(OSError):
        claim.path.unlink()


@dataclass(frozen=True)
class ServedMarker:
    """One lead-author request the tick served cleanly: the claim still sitting in
    `inflight/`, whether the curator reached the exit that records the run done (the one
    clean exit that does not — no executed leads, no pending drafts — writes no sentinel
    today), and the commit it made (`None` for a run recorded done with no commit)."""

    claim: ClaimedMarker
    done: bool
    sha: str | None


@dataclass(frozen=True)
class BatchDisposition:
    """Everything a lead-author tick consumes from SHARED state, collected during `do_work`
    and applied only once the batch's tree has passed the scrub (#952 M1).

    The lane's three consumption points — the served marker's unlink, the per-run `done`
    sentinel, the pitfalls rows' `consumed_committed` rotation with the held rows' decline
    bump behind it — all write to the state root, which `LoopPaths.with_repo_root` keeps when
    it swaps the repo root for the worktree. Consumed inside `do_work`, a scrub that then
    found the tree tainted had already emptied the queue the next tick would read, for a
    commit that must never be delivered. So the curators REPORT what they consumed and the
    drain, which is the party that sees the scrub's verdict, applies it afterwards.

    AFTER THE SCRUB, NOT AFTER THE PUSH. Once the tree is clean the curators' commits sit on
    a local branch on the same disk as the queues — exactly as durable as the state being
    consumed — and the remote adds nothing to that. Waiting for the push instead meant every
    rejected push re-ran the agents to regenerate a commit that already existed; delivery is
    the drain's own retry (`_deliver_pending`), and never re-serves anything.

    Derived per tick, never persisted: an exit before the apply — the scrub's taint, a box
    fault — drops it, and the served claims stay in `inflight/` for `claim_markers` to
    reclaim next tick (M2 — never re-queued, because a stale re-queue and a fresher
    same-case marker land on one inflight path, stale first). Each reclaim is one more
    `attempts` on the marker, so a batch that never passes the scrub is quarantined at the
    same ceiling as one that never spawns.

    `apply` is ordered sentinels → unlinks → pitfalls rotation → decline bumps, so a crash
    mid-apply leaves the lead-author half a no-op re-serve and the pitfalls half a
    re-curation — a re-spend, never a loss."""

    served: list[ServedMarker]
    pitfalls: PitfallsDisposition | None
    #: The tick's configured wait on the pitfalls append lock, resolved at the drain's entry
    #: (`lead_author_drain`) — never read here, after the commit exists. `None` is no deadline:
    #: what a test driving the tick's internals directly gets, never what the drain passes.
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
        qdir, identity_key="case_id", label="lead_author_drain", noun="lead-author",
    )
    served: list[ServedMarker] = []
    for claim in claims:
        claimed, spec, run_dir = claim.path, claim.spec, claim.run_dir
        # EVERY serve is an attempt, counted on the claim BEFORE the agent runs — not only
        # the transient-failure arm below. A claim the apply never reached (the tick died,
        # the scrub found the tree tainted) is reclaimed next tick, and without this count
        # a run that taints every tree would be re-served, and re-quarantined, forever.
        attempts = int(spec.get("attempts", 0)) + 1
        if attempts > max_retries:
            quarantine_marker(
                spec, claimed, qdir,
                f"served {attempts - 1} time(s) without being recorded done",
            )
            continue
        # On the CLAIM alone: the spec in hand stays as read, so a terminal refusal's dead
        # letter carries no counter (it is not a retry), and the transient arm below stamps
        # the spec itself only when it re-queues.
        rewrite_marker(claimed, {**spec, "attempts": attempts})
        # The commit the curator would have recorded under the shared run dir, handed back
        # here instead (#952 M4) — written by `BatchDisposition.apply` once the batch's tree
        # passed the scrub, or dropped with the batch when it did not.
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
            # NOT unlinked here: the claim stays in `inflight/` until the batch's tree has
            # passed the scrub (`BatchDisposition.apply`); a taint leaves it for the next
            # tick's reclaim.
            served.append(ServedMarker(claim, done=bool(done), sha=done[-1] if done else None))
    return served


def _invoke_pitfalls(
    paths: LoopPaths, *, box: Any = None,
    on_curated: Callable[[PitfallsDisposition], None], lock_wait_seconds: int | None = None,
) -> int:
    _log("step=pitfalls-curation")
    rc = _run_curator_module(
        "pitfalls_curator",
        lambda mod: mod.run_pitfalls(
            paths=paths, box=box, on_curated=on_curated, lock_wait_seconds=lock_wait_seconds,
        ),
    )
    return rc if rc is not None else 0


def _retire_pitfalls_batch(
    paths: LoopPaths, batch_ids: list[str], lock_wait_seconds: int | None, e: Exception,
) -> None:
    _log(f"lead_author_drain: pitfalls curation error: {e!r}; discarding edits")
    if not batch_ids:
        return
    drain.retire(
        channel=paths.pitfalls,
        batch_ids=batch_ids,
        # `batch-error:<class>: <message>` (#870 FK-11, widened by the round's review).
        #
        # FK-11's decision was that two writers append to one `pitfalls.deadletter.jsonl` and
        # a raw `str(e)` beside `_graveyard_dropped_rows`' three named classes leaves a human
        # triaging that file with three classes and a traceback string. That holds, and the
        # PREFIX is what carries it: `batch-error:<class>` is still the vocabulary — closed,
        # groupable, one member per fault class beside `_graveyard_dropped_rows`' three and the
        # hold ceiling's `reducer-offered-never-taught` — exactly as the undeclared class
        # carries its name after the same `:` separator.
        #
        # What the class ALONE cost was the diagnosis. A curator that exited rc=124, one that
        # tried to delete a section, and one that wrote outside `defender/skills` all raise
        # `LeadAuthorError` and all filed as the identical four words, so the graveyard — the
        # only durable record this lane leaves, unread until #903 — could not tell a timed-out
        # spawn from an attempted gutting. The message survived solely in the transient
        # operator log. Truncated, because a reason is a label and a row is not a place to
        # store a traceback.
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
    # "The batch" is the id set fixed at THIS read, before the leg runs — a pitfall
    # appended while the curation was in flight is outside it and must not be bumped.
    batch_ids = [str(r["pitfall_id"]) for r in read_pitfalls(paths) if r.get("pitfall_id")]
    # The curation's success-path consumption, handed back rather than applied (#952 M4);
    # the failure dispositions (`_retire_pitfalls_batch`, the unattributable rotation inside
    # the curator) are not deferred — they do not depend on the scrub.
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
    """The drain box's geography: ro over the whole worktree leaf (it carries `<wt>/defender`
    and is both drain roles' cwd_anchor), rw ONLY over what this batch actually needs — BOTH
    lessons corpora for `author_drain` (#1007 M7/A2: one shared batch, two curators, so the one
    box must hold write access for both), `<wt>/defender/skills` for `lead_author_drain` — never
    a static union, never anything outside the leaf.

    `author_drain`'s rw mounts are NAMED here rather than derived. Until #922 they came from a
    walk of the direction table, which added an actor or environment corpus whenever that
    direction's observation queue was over threshold; deleting the table would have shrunk the
    mount set to its literals with nothing saying so. Those corpora and their queues went with
    the table, so the box now gets exactly the corpora the wake gate answers for.

    THREE-WAY, deliberately — never a two-way `if/else` that lets an unrecognized label fall
    through to the defender corpus rw: a future drain role whose label does not match either
    literal here gets NO lesson corpus writable, which is the safe default for a mount grant
    (`test_an_unrecognized_drain_label_mounts_no_lesson_corpus_writable`)."""
    wt_paths = paths.with_repo_root(wt)
    mounts = [box_mod.Mount(source=wt, target=wt, writable=False)]
    rw_dirs: tuple[Path, ...]
    if label == "lead_author_drain":
        rw_dirs = (wt_paths.skills_dir,)
    elif label == "author_drain":
        rw_dirs = (wt_paths.lessons_dir, wt_paths.lessons_questioner_dir)
    else:
        rw_dirs = ()
    for d in rw_dirs:
        mounts.append(box_mod.Mount(source=d, target=d, writable=True))
    return box_mod.BoxRequest(
        name=f"defender-drain-{batch_id}", mounts=tuple(mounts), workdir=wt, env={},
    )


@dataclass(frozen=True)
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
    """This lane's undelivered batches — those under `branch.branch_prefix` alone, because
    each lane delivers under its own drain lock and the other lane's records are another
    process's to touch. A record that cannot be read names no branch to deliver and no
    lane to skip it, so it is quarantined beside the queues' own dead letters rather than
    left to be logged every tick forever."""
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

    An undelivered batch HOLDS THE WRITER LEASE exactly as an open PR does: its commit is
    the corpus change the next batch must build on, and a fresh branch off `origin/main`
    beside it would open two conflicting PRs. So a delivery that fails again leaves the lane
    parked — no worktree, no box, no agent — until the remote takes it. Nothing here re-runs
    an agent; the work was done when the tree passed the scrub."""
    for pending in _pending_deliveries(paths, branch):
        try:
            pr = branch.deliver(pending.batch_id)
        except BranchError as e:
            _log(
                f"{label}: delivery of retained branch {pending.branch} failed again: {e} — "
                "it holds the writer lease; nothing served this tick"
            )
            return False
        with contextlib.suppress(OSError):
            pending.path.unlink()
        if pr is None:
            _log(
                f"{label}: retained branch {pending.branch} has nothing left to deliver "
                "— record dropped"
            )
        else:
            _log(f"{label}: delivered retained branch {pending.branch}: opened PR {pr}")
    return True


def _land_batch(
    paths: LoopPaths, branch: AuthorBranch, batch_id: str, wt: Path, label: str,
) -> tuple[str | None, bool]:
    """Push and open the PR: `(pr, delivered)`. `pr` is `None` for a zero-commit batch. A
    `BranchError` — push rejected, PR refused — is not a loss and not a retry of the work:
    the commit is on a local branch `cleanup` never deletes, the failure is RECORDED, and
    the next tick delivers it (`_deliver_pending`) before it serves anything new."""
    try:
        return branch.finish_batch(batch_id, wt), True
    except BranchError as e:
        _record_pending_delivery(paths, branch, batch_id, label=label, reason=str(e))
        _log(
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
        _log(f"{label}: nothing queued and no curator at threshold — skipping")
        return None
    try:
        if branch.open_pr_exists():
            _log(f"{label}: an open {branch.branch_prefix} PR holds the writer lease — skipping")
            return None
        batch_id = uuid.uuid4().hex[:12]
        return batch_id, branch.start_batch(batch_id)
    except BranchError as e:
        _log(f"{label}: cannot start batch worktree: {e} — skipping")
        return None


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

    `do_work` may return a `BatchDisposition` — the shared-state consumption it collected
    instead of performing (the lead-author lane does; the lessons lane returns `None` and
    holds its committed rows its own way). It is applied once the tree has passed the scrub
    (#952 M1/O1): the curators' commits are then on a local branch, as durable as the queues
    themselves. A push or PR that then fails is RECORDED, not re-served — the next tick
    delivers the branch before it takes new work — and on the exits before the apply (a
    taint, a box fault, an interrupt) the disposition is dropped unapplied and the log says
    what stays for the next tick's reclaim."""
    opened = _open_batch(paths, branch, label=label, has_work=has_work)
    if opened is None:
        return 0
    batch_id, wt = opened

    # The box is created after the worktree exists AND after the threshold checks that decide
    # which curators wake, over exactly this batch's needs. A startup fault here must unwind
    # the worktree/branch resources already minted.
    try:
        box = start_box(_drain_box_request(wt, batch_id, label, paths))
    except BaseException:
        with contextlib.suppress(Exception):
            branch.cleanup(wt)
        raise

    wt_paths = paths.with_repo_root(wt)
    pr = None
    disposition: BatchDisposition | None = None
    consumed = False
    delivered = True
    try:
        # The box is torn down and the written tree scanned on ANY exit from do_work. Both
        # halves live in `stop_and_scrub`, which owns the ordering (teardown first — the rw
        # bind must be released before the walk, or the scan races a live writer), the
        # only-scrub-a-provably-dead-box rule, and the exception preference. The scan lands
        # BEFORE the consumption and before finish_batch's push+PR step ever reads the tree;
        # a failed teardown blocks all three.
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
        # The `finally` below destroys this tree, and on the taint path it is the ONLY copy
        # of what the box planted: the scrub raises before the consumption and before
        # finish_batch, so nothing was consumed or pushed, and the curators' commits sit on
        # a local branch nothing will deliver — so preserve the tree for the human who opens
        # it by hand. The served claims stay in `inflight/`, one attempt older.
        #
        # An except clause rather than a check inside the `finally`, because handlers run
        # BEFORE the finally, which is the ordering needed. The re-raise is load-bearing —
        # preserving the tree must not swallow the signal that it is tainted.
        preserve_tainted_tree(
            wt, branch.quarantine_dir,
            batch_id=batch_id, branch=branch.branch_name(batch_id), label=label, taint=taint,
        )
        raise
    finally:
        # A disposition collected but not applied — the scrub's taint, a box fault, an
        # interrupt, or an apply that raised partway (every step of it is idempotent, so a
        # re-serve is a re-spend, never a loss) — stays for the next tick's reclaim, and the
        # only thing left to do is say so once.
        if disposition is not None and not consumed:
            _log(
                f"{label}: batch not consumed — left for the next tick's reclaim, up to: "
                f"{disposition.retained_summary()}"
            )
        try:
            branch.cleanup(wt)
        except Exception as e:  # noqa: BLE001 — best-effort cleanup; the real fault outranks it
            _log(f"{label}: worktree cleanup failed: {e} — {wt} leaked, scrub state unknown")

    if not delivered:
        return 0
    if pr is None:
        _log(f"{label}: batch produced no commits — no PR opened")
        return 0
    _log(f"{label}: opened PR {pr}")
    if merge_mode() == "auto_on_green":
        _log(f"{label}: merge_mode=auto_on_green — green-bar auto-merge not yet "
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
            _log("author_drain: another drainer holds the lock — exiting")
            return 0
        return _run_worktree_batch(
            paths, branch, label="author_drain",
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
    # Every configured value the tick will need, read HERE — before a worktree, a box or an
    # agent exists — so a malformed setting refuses the tick rather than a commit.
    lock_wait_seconds = repo_lock_wait_seconds()
    if run_lead_author is None:
        run_lead_author = _invoke_lead_author
    if run_pitfalls is None:
        run_pitfalls = functools.partial(_invoke_pitfalls, lock_wait_seconds=lock_wait_seconds)
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
            _log("lead_author_drain: another drainer holds the lock — exiting")
            return 0
        # The per-author queue lock — the one a by-hand `lead_author.py <run_dir>` takes — is
        # held for the WHOLE tick, not per serve (#952 M5). The `done` sentinel used to be
        # written under it; deferred to after the scrub, the gap between a serve and the
        # sentinel (the remaining serves, the pitfalls curation, box teardown) is one in
        # which a by-hand run would take the lock, see no sentinel, and serve the run again.
        # Contended, the tick skips before claiming anything.
        queue_lock = acquire_queue_lock(paths)
        if queue_lock is None:
            _log("lead_author_drain: another lead-author run holds the queue lock — skipping")
            return 0
        try:
            return _run_worktree_batch(
                paths, branch, label="lead_author_drain",
                has_work=_has_lead_author_work,
                do_work=lambda wt_paths, *, box=None: _drain_lead_author(
                    wt_paths, run_lead_author, run_pitfalls, box=box,
                    lock_wait_seconds=lock_wait_seconds,
                ),
                start_box=start_box, stop_box=stop_box, scrub=scrub,
            )
        finally:
            release_queue_lock(queue_lock)
