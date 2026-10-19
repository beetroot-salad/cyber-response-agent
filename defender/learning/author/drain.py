"""The corpus-author drain body and its retire seam.

Every corpus-author channel reaches its batch through `run_batch`. What varies per channel
(pre-author gate, AUTHOR_RESULT buckets, row key, the queue's locks, commit trailers, the held
report) is a field on the config; the batch body (read, partition, author, commit, project,
rotate, log) is this module.

Retirement is reachable only from `RETIRE_SET`. A fault whose class is not in it leaves its row
queued — stuck, recoverable, and recorded in the channel's stuck-row file — so a novel exception
class retries unboundedly rather than being counted toward a ceiling and deleted. The authoring
region's cleanup is class-blind: it restores the worktree, then retires or re-raises.

A `GitError` is a member only where the commit failed. Git reads of repo state (worktree status,
HEAD) go through `_git_read`, which re-raises as the non-member `GitProbeError`: index-lock
contention on a busy repo records a stuck tick instead of burning one of the batch's attempts.
Each read over the worktree is bounded by `cfg.git_timeout` and runs with attributes from HEAD's
tree (`_git.committed_view_env`): one that does not answer in time is a `GitProbeError` too, so a
FIFO the agent left where git opens a file (`.gitignore`) stops the tick instead of hanging it,
and one at `.gitattributes` is never opened at all.

The pitfalls and lead-author legs use `core/faults.run_or_dead_letter`'s re-raise set, which
contains `GitError`, so a commit-time `GitError` retires here but kills the drain there.
"""
from __future__ import annotations

import hashlib
import logging
import uuid
from collections.abc import Callable
import contextlib
import errno
import functools
import os
from dataclasses import replace
from defender._model import model
from pathlib import Path
from typing import Any, TypeVar

from pydantic_ai.exceptions import ModelRetry

from defender import _git
from defender._clock import now_iso
from defender._git import GitError, GitTimeout
from defender._frontmatter import FrontmatterError, split_frontmatter
from defender._io import (
    ENTRY_DIR,
    Bound,
)
from defender.learning.author import shared as author_shared
from defender.learning.author._config import BucketSpec, CorpusAuthorConfig
from defender.learning.core.config import (
    provenance_field,
)
from defender.learning.core.state import (
    REPO_LOCK,
    TRY_ONCE,
    Channel,
    LearningState,
    StateRefused,
    canonical_row,
    retirement_stamp,
)
from defender._tree_listing import entry_kind
from defender import box as box_mod

AuthorError = author_shared.AuthorError

from defender.learning.author.version_control.restore import (
    _commit_landed as _commit_landed,
    _left_for_scrub as _left_for_scrub,
    _logger as _logger,
    _put_back as _put_back,
    _restore_corpus as _restore_corpus,
    _revert_strays as _revert_strays,
    _snapshot_corpus as _snapshot_corpus,
    _unanswered as _unanswered,
    _unchanged_names as _unchanged_names,
    _undo_agent_edits as _undo_agent_edits,
    _worktree_files_instead as _worktree_files_instead,
    _worktree_git as _worktree_git,
)


#: Graveyard reason for a deferral that hit the ceiling, distinguishable from a fault's.
DEFERRED_CEILING_REASON = "deferred_ceiling"
#: git status codes for an unmerged path, refused before vouching rather than committed as
#: ordinary text.
_UNMERGED_XY = frozenset({"DD", "AU", "UD", "UA", "DU", "AA", "UU"})

#: Not `faults.SYSTEMIC_FAULTS`, which keeps `GitError` out of retirement — the opposite of what
#: a commit-time git failure needs here. Nor just `AuthorError`: without `GitError` a commit-time
#: git failure would wedge the channel, and without `ModelRetry` an externally killed boxed
#: command would report success.
RETIRE_SET: tuple[type[BaseException], ...] = (AuthorError, GitError, ModelRetry)

_T = TypeVar("_T")


class GitProbeError(RuntimeError):
    """A git command that reads repo state failed.

    Not a `GitError` subclass and not in `RETIRE_SET`: a `git status` that lost a race for the
    index lock says nothing about the batch, so it must not spend an attempt. The tick is
    recorded as stuck instead."""


def _git_read(what: str, fn: Callable[..., _T], *args: Any) -> _T:
    """Run a step that reads repo state, re-raising its `GitError`, or a git call of it that did
    not answer within its bound (`GitTimeout`), as `GitProbeError`.

    Wraps whole steps, so an `AuthorError` the step raises on what it finds still retires."""
    try:
        return fn(*args)
    except GitError as e:
        raise GitProbeError(f"read-only git probe ({what}) failed: {e}") from e
    except GitTimeout as e:
        raise GitProbeError(
            f"read-only git probe ({what}) failed: git did not answer within {e.timeout}s") from e


def _revert_non_md_strays(cfg: CorpusAuthorConfig) -> None:
    """Revert non-`.md` files under the corpus before vouching. They cite nothing by
    construction, so leaving them to the vouching gate would turn a cleanup into a tick-wide
    fault."""
    for xy, rel in _git.git_status(cfg.repo_root, pathspec=cfg.corpus_dir, no_renames=True,
                                   **_worktree_git(cfg.git_timeout)):
        if not rel.endswith(".md") and "D" not in xy:
            _put_back(cfg.repo_root, rel, tree_for=cfg.tree_for, timeout=cfg.git_timeout)


def _assert_no_unmerged(cfg: CorpusAuthorConfig) -> None:
    """Refuse the tick on an unmerged path under the corpus, rather than handing conflict
    markers as ordinary text."""
    for xy, rel in _git.git_status(cfg.repo_root, pathspec=cfg.corpus_dir, no_renames=True,
                                   **_worktree_git(cfg.git_timeout)):
        if xy in _UNMERGED_XY:
            raise AuthorError(
                f"{cfg.corpus_dir_rel} has an unmerged file ({xy.strip()} {rel}) — "
                "refusing to author"
            )


#: Lock acquisition order. Drain lock first, so a contended tick skips before taking the
#: globally serialising repo lock; append lock last and briefly, so an appender never waits on
#: the agent call.
LOCK_ORDER: tuple[str, ...] = ("drain_lock", "repo_lock", "append_lock")


@model(frozen=True)
class RetireOutcome:
    #: id -> the attempt count the row now carries, for every row in the batch.
    bumped: dict[str, int]
    #: the ids that crossed the ceiling on this observation and left the queue.
    retired: tuple[str, ...]


@model(frozen=True)
class DrainOutcome:
    """What one completed tick did, handed to `cfg.post_rotate` after the rotation."""

    batch_id: str
    commit_sha: str | None
    committed: list[dict]
    #: @owns held["deferred"] — the one key beyond the AUTHOR_RESULT bucket names, assembled
    #: in `_author_and_rotate`.
    held: dict[str, list[dict]]
    consumed: dict[str, list[dict]]
    #: The pre-author gate's holds. Kept out of `held` (the AUTHOR_RESULT buckets, rows the
    #: agent judged) because these never reached the agent. They are also the permanent holds —
    #: they wait on a fact with no writer — so the operator report needs them most.
    gate_held: list[dict]


def retire(
    state: LearningState,
    *,
    channel: Channel,
    batch_ids: list[str],
    reason: str,
    max_attempts: int,
    counter_key: str = "attempts",
    timeout_seconds: int | None = None,
) -> RetireOutcome:
    """Bump every named row by one; retire the rows now at or over the ceiling.

    The count is a lifetime count on the row — never reset by a success or a requeue — and the
    ceiling is consulted only here, after an observed failure, so a row already over the
    ceiling rides through a clean tick untouched.

    `counter_key` names what is counted. `attempts` (the default) counts faulting ticks; the
    pitfalls lane also counts offers the curator declined, which are not faults. One shared
    counter would make each ceiling arrive early under the other's traffic: two infra faults
    would spend a fresh row's offer budget and its first decline would retire it untaught. The
    graveyard's `attempts` slot reports whichever count drove the retirement; the other rides
    inside `row`.

    The graveyard entry lands first, then the locked rotation writes the row into the consumed
    ledger, which makes retirement terminal (the append path dedups against it). A crash
    between the two costs one duplicate advisory record.

    `timeout_seconds` bounds both append-lock waits and is required of any caller holding the
    repo lock (the corpus drain; the pitfalls leg via `PitfallsDisposition.apply`): that lock
    serialises every channel, so an unbounded wait would let one wedged appender stall them
    all. Expiry raises `TimeoutError`; the batch is not bumped and the tick surfaces as stuck."""
    key = channel.id_key

    bumped = state.retire_rows(
        channel, batch_ids,
        lambda named: _bump_rows(
            state, channel, named, counter_key=counter_key, max_attempts=max_attempts,
            reason=reason,
        ),
        timeout=timeout_seconds,
    )
    survivors, retired = bumped.survivors, bumped.retired

    state.rotate(
        channel, survivors,
        [{**rec, "consumed_category": "consumed_retired"} for rec in retired],
        None, timeout=timeout_seconds,
    )
    return RetireOutcome(
        bumped={rec[key]: rec[counter_key] for rec in [*survivors, *retired]},
        retired=tuple(rec[key] for rec in retired),
    )


@model(frozen=True)
class _Bumped:
    #: the bumped rows still under the ceiling, each carrying its new count.
    survivors: list[dict]
    #: the bumped rows at or over the ceiling, already written to the graveyard.
    retired: list[dict]


def _bump_rows(
    state: LearningState, channel: Channel, rows: list[dict], *, counter_key: str, max_attempts: int, reason: str,
) -> _Bumped:
    """Bump `counter_key` on every row and partition at the ceiling, graveyarding the rows that
    crossed it. Shared by fault retirement (`attempts`) and the deferral fold (`deferrals`)."""
    key = channel.id_key
    survivors: list[dict] = []
    retired: list[dict] = []
    for row in rows:
        count = int(row.get(counter_key) or 0) + 1
        rec = {**row, counter_key: count}
        (retired if count >= max_attempts else survivors).append(rec)
    if retired:
        state.deadletter(
            channel,
            [
                {
                    key: rec[key],
                    # Whichever count reached its ceiling, under the slot every reader knows;
                    # the other counter stays inside `row` as provenance.
                    "attempts": rec[counter_key],
                    "deadletter_reason": reason,
                    **retirement_stamp(),
                    # Nested rather than spread, so a `_bump_rows` entry has one shape on every
                    # channel and is readable without knowing its queue (`_retire_unkeyable`
                    # spreads its row flat; the queue page reads both shapes).
                    "row": {k: v for k, v in rec.items() if k != counter_key},
                }
                for rec in retired
            ],
        )
    return _Bumped(survivors=survivors, retired=retired)



def channel_logger(cfg: CorpusAuthorConfig) -> logging.Logger:
    """This curator channel's logger — one child of this module's per channel, since both
    curators run this module's code."""
    return logging.getLogger(f"{__name__}.{cfg.log_prefix}")

def run_batch(
    *, cfg: CorpusAuthorConfig, hold_committed: bool = False, box: Any = None
) -> int:
    """One tick of one corpus-author channel.

    Returns 0 for nothing-to-do — an empty queue, a drain lock another process holds, an
    unavailable repo lock, an append lock an appender is holding past the deadline — and 2
    for a batch whose authoring faulted with a member of `RETIRE_SET`. Anything else
    propagates."""
    if box is not None:
        cfg = replace(cfg, box=box)
    log = channel_logger(cfg)
    channel = cfg.channel

    state = cfg.state
    with contextlib.ExitStack() as locks:
        if channel.drain_role is not None and not locks.enter_context(
                state.lock(channel.drain_role, wait=TRY_ONCE)):
            log.info("drain lock held by another process — skipping this tick")
            return 0
        try:
            locks.enter_context(state.lock(REPO_LOCK, wait=cfg.repo_lock_wait_seconds))
        except TimeoutError as e:
            log.warning(f"repo lock unavailable: {e}; queue intact")
            return 0
        try:
            author_shared.assert_clean_corpus_dir(
                cfg.repo_root, cfg.corpus_dir, cfg.corpus_dir_rel, corpus=cfg.corpus,
            )
        except AuthorError as e:
            log.critical(f"{e}")
            # An already-dirty corpus at tick start is recorded as stuck, not skipped
            # silently.
            try:
                _record_stuck(state, channel, e, [])
            except Exception as unrecorded:  # noqa: BLE001 — never replaces `e`
                log.error(f"stuck record NOT written: {unrecorded!r} (the fault itself follows)")
            return 2
        return _tick(cfg=cfg, hold_committed=hold_committed, log=log)


def _tick(*, cfg: CorpusAuthorConfig, hold_committed: bool, log) -> int:
    channel = cfg.channel
    key = channel.id_key

    state = cfg.state
    window = state.read_window(channel, timeout=cfg.repo_lock_wait_seconds)
    if window is None:
        log.info("append lock held by an appender past the deadline — skipping this tick")
        return 0
    batch, unreadable = window
    if not batch and not unreadable:
        log.info("queue empty — nothing to author")
        return 0
    if unreadable:
        # Fall through rather than return: the wake gate (`core/drains._pending_queue_counts`)
        # counts an unreadable line as work, so returning would re-fire on the same junk every
        # tick. Such a line can't be graveyarded (there is no row), but any rotation rewrites
        # the queue from the rows it can read, so whichever rotation runs next drops it. This
        # warning is the deletion's only trace; a fault before any rotation leaves the lines
        # for the next tick.
        log.warning(
            f"{unreadable} unreadable line(s) in the queue — the next rotation this tick "
            "reaches, if it reaches one, will drop them"
        )

    keyed: list[dict] = []
    unkeyable: list[dict] = []
    for row in batch:
        (keyed if _row_id(row, key) else unkeyable).append(row)
    # One stuck-recording guard around the whole tick body, with `stuck_rows` naming the rows
    # the phase in flight is stuck on, so no phase can lack one. E.g. `_retire_unkeyable`
    # retakes the append lock for its own rotation, and an appender in that window raises
    # `TimeoutError` (outside `RETIRE_SET`), which must still leave a stuck record.
    stuck_rows = unkeyable
    try:
        _retire_unkeyable(state, channel, unkeyable, log, cfg.repo_lock_wait_seconds)
        # The gate reads per-row fields the queue's own key check cannot vouch for
        # (`run_id`, `direction`), so it is a live source of non-retiring faults.
        stuck_rows = keyed
        held, consumed_pre, to_author = cfg.gate(keyed, cfg)
        batch_id = uuid.uuid4().hex[:12]
        log.info(
            f"batch={batch_id} total={len(batch)} to_author={len(to_author)} "
            f"held={len(held)} pre_consumed={len(consumed_pre)} unkeyable={len(unkeyable)}"
        )
        # This call also runs the closing rotation, which writes the gate's held rows back.
        # When the gate held or consumed everything, `to_author` is `[]` and a rotation fault
        # would record no rows, so name `keyed` — what the rotation was writing.
        stuck_rows = to_author or keyed
        return _author_and_rotate(
            cfg=cfg,
            log=log,
            batch_id=batch_id,
            hold_committed=hold_committed,
            all_rows=author_shared.by_id(keyed, key),
            held=held,
            consumed_pre=consumed_pre,
            to_author=to_author,
        )
    except BaseException as e:
        if not isinstance(e, (*RETIRE_SET, StateRefused)):
            # The recorder must never replace the fault it records (a full disk would surface
            # the writer's `OSError` instead). `Exception`, not `BaseException`, so an
            # interrupt mid-record still leaves at once. Logged rather than swallowed: the
            # record is a stuck row's only external trace. A refusal writes nothing at all: a
            # planted entry stops the tick, and nothing is recorded after it.
            try:
                _record_stuck(state, channel, e, stuck_rows)
            except Exception as unrecorded:  # noqa: BLE001 — see above; never replaces `e`
                log.error(f"stuck record NOT written: {unrecorded!r} (the fault itself follows)")
        raise


@model(frozen=True)
class _PreState:
    """The worktree just before the agent runs, so a fault after it can restore it. Leftover
    uncommitted edits would fail the next tick's cleanliness gate and wedge the channel."""

    snapshot: dict[str, bytes] | None
    baseline_stray: list[str]
    head_before: str


def _capture_pre_state(cfg: CorpusAuthorConfig) -> _PreState:
    bound = cfg.git_timeout
    head_before = _git_read(
        "HEAD", functools.partial(author_shared.git_head_sha, timeout=bound), cfg.repo_root)
    return _PreState(
        snapshot=_git_read(
            "corpus before-state", functools.partial(_snapshot_corpus, timeout=bound),
            cfg.repo_root, cfg.corpus_dir, head_before,
        ),
        baseline_stray=_git_read(
            "worktree status",
            functools.partial(author_shared.changes_outside, timeout=bound,
                              env=_git.committed_view_env()),
            cfg.repo_root, cfg.corpus_dir_rel,
        ),
        head_before=head_before,
    )


# ---------------------------------------------------------------------------
# The authoring region. One truth — the corpus tree after the spawn — from which every
# decision is computed once: changed files, citations, approvals, the commit, and
# each row's fate. A spawn's own report is read only for skip reasons and the commit message,
# plus one cross-check: an id it claims committed that no file cites is deferred.
# ---------------------------------------------------------------------------


@model(frozen=True)
class _Tree:
    """The corpus after `_settle_tree`: repo-relative paths whose bytes differ from HEAD, and
    paths deleted. Every later step reads the corpus through this."""

    changed: tuple[str, ...]
    deleted: tuple[str, ...]


def _settle_tree(cfg: CorpusAuthorConfig, state: _PreState) -> _Tree:
    """The post-spawn normaliser. In order:

    1. non-`.md` files under the corpus are reverted — they cite nothing, so this is cleanup,
       and it must precede the stray check that would otherwise refuse the tick;
    2. a change outside the corpus (beyond tick-start dirt) raises `AuthorError`;
    3. an unmerged path under the corpus raises;
    4. a mode-only change (bytes identical to HEAD) is put back — it isn't content to commit,
       and would stay dirty after the commit and wedge the next tick's cleanliness gate;
    5. the curator spawn's deletions are honoured and committed.

    Git reads go through `_git_read`: a git failure here is the host's, not the batch's."""

    def settle() -> _Tree:
        _revert_non_md_strays(cfg)
        author_shared.assert_no_new_stray(cfg.repo_root, cfg.corpus_dir_rel, state.baseline_stray,
                                          **_worktree_git(cfg.git_timeout))
        _assert_no_unmerged(cfg)
        changed: list[str] = []
        deleted: list[str] = []
        for xy, rel in _changed_corpus_records(cfg):
            if "D" in xy:
                deleted.append(rel)
            elif xy != "??" and _byte_identical_to_head(cfg.repo_root, rel,
                                                        timeout=cfg.git_timeout):
                _git.git(["checkout", "-q", "--", rel], cwd=cfg.repo_root,
                         **_worktree_git(cfg.git_timeout))
            else:
                changed.append(rel)
        return _Tree(changed=tuple(sorted(changed)), deleted=tuple(sorted(deleted)))

    return _git_read("settle tree", settle)


#: How many times `_read_citations` will re-read a tree that moved under it before giving up.
#: Two is the honest need (read, then confirm nothing moved); the rest is slack for a
#: concurrent editor that is still writing when the first confirmation runs.
_CITE_ROUNDS = 4


def _read_citations(
    cfg: CorpusAuthorConfig, files: tuple[str, ...], batch: set[str],
) -> dict[str, frozenset[str]]:
    """rel_path -> the this-batch ids each of `files` cites, on the bytes it holds now. Rounds
    repeat until nothing moved during one, so the citations approval reads are those of the
    bytes that land in HEAD."""
    field_name = provenance_field(cfg.channel.id_key)
    view = cfg.corpus.view()

    def read(rel: str) -> str:
        return _read_or_empty(view, _corpus_relative(cfg, rel))

    texts: dict[str, str] = {}
    for _ in range(_CITE_ROUNDS):
        texts = {rel: read(rel) for rel in files}
        if all(read(rel) == text for rel, text in texts.items()):
            break
    else:
        raise AuthorError(
            f"{cfg.corpus_dir_rel} kept changing under the citation read for {_CITE_ROUNDS} "
            "rounds — refusing to commit bytes no citation was read from"
        )
    return {rel: frozenset(_cited_ids_in(text, field_name) & batch) for rel, text in texts.items()}


@model(frozen=True)
class _Fates:
    """Every row the batch read, sorted into exactly one ending."""

    #: ids some approved file cites.
    committed: list[str]
    #: ids that could not land through no fault of their own.
    deferred: set[str]


def _decide_fates(
    batch_ids: set[str], cites: dict[str, frozenset[str]], claimed_committed: set[str],
) -> _Fates:
    """Each batch row's ending, read off the tree's citations. An id some file cites is
    committed: every citing file is approved. For an id no file cites, the curator's word is
    only cross-checked: claimed committed means deferred, never consumed; otherwise the row is
    left queued as it was."""
    cited = {fid for ids in cites.values() for fid in ids}
    return _Fates(committed=sorted(batch_ids & cited),
                  deferred=(batch_ids - cited) & claimed_committed)


@model(frozen=True)
class _BatchOutcome:
    commit_sha: str | None
    committed: list[dict]
    bucket_held: dict[str, list[dict]]
    bucket_consumed: dict[str, list[dict]]
    deferred_ids: set[str]


def _author_batch(
    cfg: CorpusAuthorConfig,
    to_author: list[dict],
    batch_id: str,
    state: _PreState,
    all_rows: dict[str, dict],
) -> _BatchOutcome:
    """Spawn, settle, read citations; then read every fate off them and commit what they
    approve."""
    key = cfg.channel.id_key
    batch_ids = {row[key] for row in to_author}

    # The box runs for the spawn only, and is stopped before any host step reads what it
    # wrote (#1195).
    with box_mod.box_for_run(cfg.box) as box:
        result = cfg.invoke_agent(to_author, batch_id, replace(cfg, box=box))
    tree = _settle_tree(cfg, state)
    _git_read(
        "agent report",
        functools.partial(author_shared.verify_agent_report, timeout=cfg.git_timeout,
                          env=_git.committed_view_env()),
        cfg.repo_root, result, cfg.corpus_dir, cfg.corpus_dir_rel, cfg.noun,
    )
    author_shared.validate_agent_result_partition(
        result, to_author, id_key=key,
        buckets=tuple(b.name for b in cfg.buckets), noun=cfg.noun,
    )
    _assert_corpus_attributable(cfg, tree.changed, batch_ids)

    cites = _read_citations(cfg, tree.changed, batch_ids)
    # Approved: cites something from this batch. A changed file citing nothing is not approved.
    approved = {rel for rel, ids in cites.items() if ids}
    fates = _decide_fates(
        batch_ids, cites, claimed_committed=set(author_shared.result_list(result, "committed")),
    )
    # Before the commit, so a restore failure can never coexist with a commit.
    _restore_unapproved_files(cfg, state.snapshot, set(tree.changed) - approved,
                              head_before=state.head_before)

    message = (
        author_shared.commit_message(result, cfg.noun) if approved or tree.deleted else ""
    )
    commit_sha = author_shared.commit_corpus_paths(
        message, cfg, sorted(approved), list(tree.deleted)
    )

    # The curator's buckets, minus every id the tree already gave a fate.
    fated = set(fates.committed) | fates.deferred
    bucket_held, bucket_consumed = _project(result, all_rows, cfg, exclude=fated)
    return _BatchOutcome(
        commit_sha=commit_sha,
        committed=[
            {**all_rows[fid], "consumed_category": "consumed_committed"}
            for fid in fates.committed
        ],
        bucket_held=bucket_held,
        bucket_consumed=bucket_consumed,
        deferred_ids=fates.deferred,
    )


def _handle_retire(
    cfg: CorpusAuthorConfig, e: BaseException, to_author: list[dict], key: str, log
) -> int:
    channel = cfg.channel
    log.critical(f"{e}")
    outcome = retire(
        cfg.state,
        channel=channel,
        batch_ids=[row[key] for row in to_author],
        reason=str(e),
        max_attempts=cfg.max_attempts,
        timeout_seconds=cfg.repo_lock_wait_seconds,
    )
    # Only rows that survive the bump are recorded as stuck: a retired row's graveyard entry
    # already names the reason, and recording it too would make the signal fire on every
    # retiring fault.
    survivors = [row for row in to_author if row[key] not in outcome.retired]
    if survivors:
        try:
            _record_stuck(cfg.state, channel, e, survivors)
        except Exception as unrecorded:  # noqa: BLE001 — never replaces `e`
            log.error(f"stuck record NOT written: {unrecorded!r} (the fault itself follows)")
    return 2


def _fold_deferrals(
    cfg: CorpusAuthorConfig, deferred_ids: set[str], all_rows: dict[str, dict]
) -> tuple[list[dict], list[dict]]:
    """Bump deferred rows for the closing rotation to write — one write, so the increment
    cannot be lost to a lock timeout between two rotations.

    @owns deferrals — the one function that increments a queued row's `deferrals` counter."""
    bumped = _bump_rows(
        cfg.state, cfg.channel, [all_rows[fid] for fid in sorted(deferred_ids)],
        counter_key="deferrals", max_attempts=cfg.max_attempts, reason=DEFERRED_CEILING_REASON,
    )
    return bumped.survivors, [
        {**rec, "consumed_category": "consumed_retired"} for rec in bumped.retired
    ]


def _author_and_rotate(  # noqa: PLR0913 — one tick's whole state, threaded rather than global
    *,
    cfg: CorpusAuthorConfig,
    log,
    batch_id: str,
    hold_committed: bool,
    all_rows: dict[str, dict],
    held: list[dict],
    consumed_pre: list[dict],
    to_author: list[dict],
) -> int:
    channel = cfg.channel
    key = channel.id_key
    outcome = _BatchOutcome(
        commit_sha=None, committed=[], bucket_held={}, bucket_consumed={}, deferred_ids=set(),
    )

    if to_author:
        state = _capture_pre_state(cfg)
        try:
            outcome = _author_batch(cfg, to_author, batch_id, state, all_rows)
        except BaseException as e:
            # Clean up on every fault, member or not: a stuck tick leaves the same edits a
            # retiring one does, and leaving them wedges the channel.
            box_fault = isinstance(e, box_mod.BoxFault)
            try:
                _undo_agent_edits(cfg, state.snapshot, state.baseline_stray, state.head_before)
            except Exception as undo_fault:
                # A box whose stop failed may still be writing while the undo runs, and the
                # undo's own fault (a folder swapped for a link: ELOOP) must not replace the box
                # fault: an `OSError` is contained above `run_batch`, and the box fault must
                # halt the batch (#1195 D3a, O4). Any other fault keeps today's precedence.
                if not box_fault:
                    raise
                log.error(f"undo after a box fault failed: {undo_fault!r} "
                          "(the box fault follows)", exc_info=undo_fault)
            if box_fault or not isinstance(e, RETIRE_SET):
                raise
            return _handle_retire(cfg, e, to_author, key, log)

    committed = outcome.committed
    bucket_held, bucket_consumed = outcome.bucket_held, outcome.bucket_consumed
    deferred_ids = outcome.deferred_ids
    commit_sha = outcome.commit_sha

    held_committed, rotated_committed = author_shared.partition_committed(
        committed, hold_committed=hold_committed
    )

    deferred_held, deferred_consumed = _fold_deferrals(cfg, deferred_ids, all_rows)

    cfg.state.rotate(
        channel,
        [*held, *_flatten(cfg.buckets, bucket_held), *held_committed, *deferred_held],
        [
            *consumed_pre,
            *rotated_committed,
            *_flatten(cfg.buckets, bucket_consumed),
            *deferred_consumed,
        ],
        commit_sha,
        timeout=cfg.repo_lock_wait_seconds,
    )
    if cfg.post_rotate is not None:
        cfg.post_rotate(
            DrainOutcome(
                batch_id=batch_id, commit_sha=commit_sha, committed=committed,
                held={**bucket_held, "deferred": deferred_held + deferred_consumed},
                consumed=bucket_consumed, gate_held=held,
            ),
            cfg,
        )
    log.info(
        f"done batch={batch_id} committed={len(committed)} held={len(held)} "
        f"pre_consumed={len(consumed_pre)} "
        f"deferred={len(deferred_ids)} commit_sha={commit_sha}"
    )
    return 0


def _corpus_relative(cfg: CorpusAuthorConfig, rel: str) -> str:
    """The repo-relative corpus path `rel` as a name under the corpus mount."""
    return (cfg.repo_root / rel).relative_to(cfg.corpus_dir).as_posix()


def _restore_unapproved_files(
    cfg: CorpusAuthorConfig, snapshot: dict[str, bytes] | None, rels: set[str], *,
    head_before: str,
) -> None:
    """Put every file this tick changed but did not approve back to its tick-start bytes, or
    remove it if the tick created it, through the corpus mount (#1134).

    Which tick-start files still hold their bytes is git's answer against `head_before`, the
    commit the before-state was read at (`_unchanged_names`, addendum 3 D1); the rest are written
    back. A git failure there is the tick's `GitProbeError`, raised before anything is written
    or removed. Not on the fault path, so a refusal propagates: anything left at a created name,
    even a non-file, must go, and the held root refuses (never follows, never unlinks) a link, a
    hard link or a FIFO there, leaving it for the scrub (O5.2); a folder raises
    `IsADirectoryError`, as the plain `unlink()` did. The folder test asks the name's folder
    listing (`entry_kind`, addendum 2 B3); a holding folder whose listing is refused is no folder
    here, so the `unlink` meets it and the core's `OSError` propagates."""
    if snapshot is None:
        return
    names = {rel: _corpus_relative(cfg, rel) for rel in rels}
    unchanged: frozenset[str] = frozenset()
    if any(name in snapshot for name in names.values()):
        unchanged = _git_read("unapproved restore",
                              functools.partial(_unchanged_names, timeout=cfg.git_timeout),
                              cfg.repo_root, cfg.corpus_dir, head_before)
    view = cfg.corpus.view()
    for rel, name in names.items():
        pre = snapshot.get(name)
        if pre is None:
            if entry_kind(view, name).kind == ENTRY_DIR:
                # A folder was never removable here; it keeps the error `unlink()` gave it.
                raise IsADirectoryError(errno.EISDIR, os.strerror(errno.EISDIR), rel)
            cfg.corpus.unlink(name)
            continue
        if name not in unchanged:
            cfg.corpus.write(name, pre, mode="replace")


def _flatten(buckets: tuple[BucketSpec, ...], rows: dict[str, list[dict]]) -> list[dict]:
    return [row for bucket in buckets for row in rows.get(bucket.name, [])]


def _project(
    result: dict, all_rows: dict[str, dict], cfg: CorpusAuthorConfig, *, exclude: set[str],
) -> tuple[dict[str, list[dict]], dict[str, list[dict]]]:
    """The curator's held/consumed buckets as queue rows, minus `exclude` — ids the tree
    already gave a fate, which outranks the curator's filing. The `committed` bucket is not
    projected: what committed is read off the tree."""
    key = cfg.channel.id_key
    bucket_held: dict[str, list[dict]] = {}
    bucket_consumed: dict[str, list[dict]] = {}
    for bucket in cfg.buckets:
        if bucket.disposition == "committed":
            continue
        rows: list[dict] = []
        for entry in author_shared.result_list(result, bucket.name):
            rid = entry.get(key)
            src = all_rows.get(rid)
            if src is None:
                raise AuthorError(f"author {bucket.name} unknown {key}={rid!r}")
            if rid in exclude:
                continue
            rec = dict(src)
            if bucket.disposition == "consumed":
                rec["consumed_category"] = bucket.name
            if bucket.reason_field is not None:
                rec[bucket.reason_field] = bucket.formatter(entry.get("reason", ""))
            rows.append(rec)
        target = bucket_consumed if bucket.disposition == "consumed" else bucket_held
        target[bucket.name] = rows
    return bucket_held, bucket_consumed


def _assert_corpus_attributable(
    cfg: CorpusAuthorConfig, changed: tuple[str, ...], ids: set[str],
) -> None:
    """Every corpus file the curator spawn changed must cite, under the channel's provenance
    key, an id this batch read — whatever bucket the curator reported it under.

    The `AuthorError` unwinds the tick via `_undo_agent_edits`; the batch is bumped and stays
    queued."""
    field = provenance_field(cfg.channel.id_key)
    unattributed = [
        rel for rel in changed
        if not (_cited_ids(cfg.corpus.view(), _corpus_relative(cfg, rel), field) & ids)
    ]
    if unattributed:
        raise AuthorError(
            f"author left {len(unattributed)} file(s) in {cfg.corpus_dir_rel} that no "
            f"finding of this batch vouches for: {unattributed}; each must cite a "
            f"{field} entry from this batch ({sorted(ids)}) — refusing to commit"
        )


def _changed_corpus_records(cfg: CorpusAuthorConfig) -> list[tuple[str, str]]:
    """`(status, repo-relative path)` for everything git reports under the corpus.

    The corpus is clean at tick start (`assert_clean_corpus_dir`), so this is exactly what the
    spawns wrote or removed. `no_renames=True` splits a rename into its `D`/`A` halves rather
    than one `R` record naming two paths."""
    return sorted(
        _git.git_status(cfg.repo_root, pathspec=cfg.corpus_dir, no_renames=True,
                        **_worktree_git(cfg.git_timeout)),
        key=lambda rec: rec[1],
    )


def _byte_identical_to_head(repo_root: Path, rel: str, *, timeout: float | None = None) -> bool:
    """Whether the working-copy `rel` still holds the exact bytes HEAD carries for it, asked of
    git (`_git.git_unchanged_since`, #1134 addendum 3 D1): raw bytes, so a CRLF-only rewrite is a
    change (text decoding's universal newlines would call it equal); the executable bit ignored,
    so a mode-only change is identical. A symlink, a FIFO or a folder at `rel` is never identical
    and is neither followed nor opened; a hard link is judged by its content, which git hashes
    (N-a, declared). A path HEAD does not carry is not identical. A git failure raises
    `GitError`; one not answering within `timeout`, `GitTimeout`."""
    return rel in _git.git_unchanged_since(repo_root, "HEAD", rel, timeout=timeout)


def _cited_ids(corpus: Bound, name: str, field: str) -> set[str]:
    """The queue-row ids the corpus file `name` claims as its source, read through the corpus
    mount's view. A file whose frontmatter cannot be read (a link or hard link at the name
    included) cites nothing, so it is unattributable."""
    return _cited_ids_in(_read_or_empty(corpus, name), field)


def _cited_ids_in(text: str, field: str) -> set[str]:
    try:
        fm, _raw, _body = split_frontmatter(text)
    except FrontmatterError:
        return set()
    cited = fm.get(field)
    if not isinstance(cited, list):
        return set()
    return {c for c in cited if isinstance(c, str)}


def _read_or_empty(corpus: Bound, name: str) -> str:
    """The text of the corpus file `name`, read through the corpus mount's view; `""` when it is
    absent, undecodable or refused (a link, hard link or FIFO at the name, O5.1)."""
    rec = corpus.read(name)
    return rec.text if rec.text is not None else ""


def _retire_unkeyable(
    state: LearningState, channel: Channel, rows: list[dict], log, timeout_seconds: int
) -> None:
    """Retire rows with no id under the channel's key at once, on their own rotation; their
    well-formed batch-mates are authored this tick.

    Not left to the closing rotation, which never runs on a retiring or stuck tick. A keyless
    row can't be matched by id, so this rotation names the rows as read (`drop`) and `rotate`
    removes exactly those, keeping any other keyless row appended meanwhile.

    The record is flat (row content at top level, not nested under `row` as `retire` writes
    it), since there is no id to reference; consumers must branch on the presence of `row`."""
    if not rows:
        return
    reason = f"row carries no value under {channel.id_key!r}"
    log.warning(f"{len(rows)} unkeyable row(s) retired: {reason}")
    state.deadletter(
        channel,
        [{**row, "attempts": int(row.get("attempts") or 0) + 1,
          "deadletter_reason": reason, **retirement_stamp()} for row in rows],
    )
    state.rotate(
        channel, [],
        [{**row, "consumed_category": "consumed_retired"} for row in rows],
        None, drop=rows, timeout=timeout_seconds,
    )


def _row_id(row: dict, key: str) -> str | None:
    """This row's id under its channel's key, or `None` where it has none.

    Shared by `_tick` (to split the batch) and `_stuck_row_ids` (to name rows): if they
    disagreed, a truthy non-string id filed as unkeyable would be named as a real id."""
    rid = row.get(key)
    return rid if isinstance(rid, str) and rid else None


def _stuck_row_ids(channel: Channel, rows: list[dict]) -> list[str]:
    """@owns row_ids — how a stuck record names the rows a tick is stuck on.

    A row's own id where it has one; otherwise a prefixed fingerprint of its canonical JSON,
    stable across ticks and processes. Naming nothing would make `_record_stuck` fold
    unrelated keyless ticks into one rising count and hide which rows are stuck."""
    named: list[str] = []
    for row in rows:
        rid = _row_id(row, channel.id_key)
        if rid is not None:
            named.append(rid)
            continue
        digest = hashlib.sha256(canonical_row(row).encode("utf-8")).hexdigest()
        named.append(f"unkeyed:{digest[:16]}")
    return sorted(named)


def record_stuck(
    state: LearningState, channel: Channel, exc: BaseException, rows: list[dict],
) -> None:
    """Record this fault on the channel's stuck report (the public entry point, used by
    `drains._drain_one_curator`)."""
    _record_stuck(state, channel, exc, rows)


def _record_stuck(
    state: LearningState, channel: Channel, exc: BaseException, rows: list[dict],
) -> None:
    """@owns recorded_at — the operator signal for a stuck tick, and when it was written.

    The stuck report is the visible trace of a fault outside `RETIRE_SET`, whose row stays
    queued: one record per non-retiring tick, naming the fault class, the stalled rows and how
    many consecutive ticks they have been stuck. A row can be both graveyarded and queued:
    `_retire_unkeyable` and `retire` append dead letters before the rotation that removes the
    rows, releasing the append lock in between, so a rotation that times out against an
    appender (or a crash) in that window leaves the row in both, plus a duplicate dead letter
    each later stuck tick. Keyless rows are named by a content fingerprint (`_stuck_row_ids`).

    The file is append-only and never cleared, so the stamp is what lets the queue page say
    "last faulted at". The count is per tick, not per row: a non-retiring row must stay
    byte-identical, so the last record is read back instead."""
    fault_class = type(exc).__name__
    ids = _stuck_row_ids(channel, rows)
    previous = state.stuck_rows(channel)
    consecutive = 1
    # An empty id list is a row set too: the faulting phase had no rows in flight (e.g. the
    # gate held the whole batch). Consecutive such ticks with one fault class are the same
    # problem recurring, so they fold.
    if previous:
        last = previous[-1]
        same_ids = sorted(str(i) for i in (last.get("row_ids") or [])) == ids
        if last.get("fault_class") == fault_class and same_ids:
            consecutive = int(last.get("consecutive_ticks") or 0) + 1
    state.stuck_append(channel, {
        "fault_class": fault_class,
        "row_ids": ids,
        "consecutive_ticks": consecutive,
        "reason": str(exc),
        "recorded_at": now_iso(),
    })
