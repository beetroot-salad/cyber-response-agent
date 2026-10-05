"""The corpus-author drain body and its retire seam.

Every corpus-author channel reaches its batch through `run_batch`. What varies per channel
(pre-author gate, AUTHOR_RESULT buckets, row key, the queue's locks, commit trailers, the held
report) is a field on the config; the batch body (read, partition, author, verify, commit,
project, rotate, log) is this module.

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
import itertools
import json
import logging
import uuid
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
import contextlib
import dataclasses
import errno
import functools
import os
from dataclasses import replace
from defender._model import model
from pathlib import Path
from typing import TYPE_CHECKING, Any, TypeVar

from pydantic_ai.exceptions import ModelRetry

from defender import _git
from defender._clock import now_iso
from defender._git import GitError, GitTimeout
from defender._frontmatter import FrontmatterError, split_frontmatter
from defender._io import (
    ENTRY_DIR,
    ENTRY_FILE,
    ENTRY_OTHER,
    Bound,
    Held,
    NotPlainEntry,
    append_jsonl,
    read_jsonl_rows,
    read_jsonl_rows_report,
)
from defender._untrusted import wrap
from defender.learning._prompt import stage_user_message
from defender.learning.author import shared as author_shared
from defender.learning.author._config import BucketSpec, CorpusAuthorConfig
from defender.learning.author.verify_forward.checks import CheckContext
from defender.learning.author.verify_forward.engine import _run_verify_pydantic
from defender.learning.author.verify_forward.shared import VerdictError
from defender.learning.core import config, persist
from defender.learning.core.config import (
    FatalConfigError,
    QueueChannel,
    provenance_field,
)
from defender._tree_listing import entry_kind
from defender.learning.core.lane_trees import TreeFor, kind_at
from defender.runtime import box as box_mod

AuthorError = author_shared.AuthorError

_logger = logging.getLogger(__name__)

#: The forward-check gap ledger, under the host-side pending dir.
GAP_LEDGER_NAME = "findings.forward_bad.jsonl"
#: Reasoning prefix on the BAD recorded for a pair whose check failed twice.
ERROR_PREFIX = "forward_check_error: "
#: Header of the commit-message block naming terminal findings. Advisory; the gap ledger is
#: the authoritative record.
TERMINAL_BLOCK_HEADER = "Forward-check terminal:"
#: Graveyard reason for a deferral that hit the ceiling, distinguishable from a fault's.
DEFERRED_CEILING_REASON = "deferred_ceiling"
#: git status codes for an unmerged path, refused before vouching rather than handed to the
#: verifier as ordinary text.
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


def _worktree_git(timeout: float | None) -> dict[str, Any]:
    """The keywords of a curator git call over the worktree: `timeout`, and an environment that
    reads attributes from HEAD's tree and ignores replace objects (`_git.committed_view_env`), so
    no `.gitattributes` the agent left is opened."""
    return {"timeout": timeout, "env": _git.committed_view_env()}


def _unanswered(e: GitError | GitTimeout) -> str:
    """How a git call failed, for a warning: its exit code, or the bound it did not answer within."""
    if isinstance(e, GitTimeout):
        return f"no answer within {e.timeout}s"
    return f"rc={e.returncode}"


@model(frozen=True)
class PairVerdict:
    """One (changed corpus file, cited finding from this batch) pair's forward-check outcome.

    `rel_path` is on every entry so a finding refused on differently-named files across the two
    passes is recoverable from its one gap-ledger record. `lesson_text` lets the repair prompt
    be rebuilt from the pair after the file itself has been restored."""

    rel_path: str
    finding_id: str
    source_id: str
    verdict: str  # GOOD | BAD | EXEMPT
    reasoning: str
    lesson_text: str
    pass_no: int


def _revert_non_md_strays(cfg: CorpusAuthorConfig) -> None:
    """Revert non-`.md` files under the corpus before vouching. They cite nothing by
    construction, so leaving them to the vouching gate would turn a cleanup into a tick-wide
    fault."""
    for xy, rel in _git.git_status(cfg.repo_root, pathspec=cfg.corpus_dir, no_renames=True,
                                   **_worktree_git(cfg.git_timeout)):
        if not rel.endswith(".md") and "D" not in xy:
            _put_back(cfg.repo_root, rel, tree_for=cfg.tree_for, timeout=cfg.git_timeout)


def _put_back(
    repo_root: Path, rel: str, *, tree_for: TreeFor, timeout: float | None = None,
) -> None:
    """Return one path to what HEAD has: checked out if tracked, removed if not.

    An untracked name is judged by `kind_at` (#1134, addendum 2 B3). Inside one of the lane's
    mounts (this corpus or its sibling) it is judged by its folder's listing and removed through
    that mount's held root: a plain file is unlinked; anything else that is not a folder (a link,
    a hard link, a FIFO, or a name below a holding folder whose listing is refused) goes to the
    same `unlink`, which refuses it — `NotPlainEntry` for an entry AT the name, left in place for
    the scrub (O5.2), the core's plain `OSError` for a refused holding folder. A name outside the
    lane's mounts lies in the box's read-only area and keeps its plain path (D3): `kind_at`
    answers it from that path, and only a file there is unlinked."""
    _git.git(["checkout", "-q", "--", rel], cwd=repo_root, check=False, **_worktree_git(timeout))
    tracked = _git.git_ok(["ls-files", "--error-unmatch", "--", rel], cwd=repo_root,
                          **_worktree_git(timeout))
    if tracked:
        return
    target = repo_root / rel
    kind = kind_at(repo_root, tree_for, rel)
    hit = tree_for(target)
    if hit is None:
        if kind == ENTRY_FILE:
            target.unlink()
        return
    held, name = hit
    if kind in (ENTRY_FILE, ENTRY_OTHER):
        held.unlink(name)


def _assert_no_unmerged(cfg: CorpusAuthorConfig) -> None:
    """Refuse the tick on an unmerged path under the corpus, rather than handing conflict
    markers to the verifier as ordinary text."""
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


def graveyard_file(channel: QueueChannel) -> Path:
    """The channel's retirement record. Advisory: the queue rewrite is authoritative. Read only
    by the queue page (`frontend/serialize_queues.py`); the drains never read it back."""
    return channel.file.with_suffix(".deadletter.jsonl")


def retirement_stamp() -> dict[str, str]:
    """@owns retired_at — when a graveyard record was written, on every writer's record.

    Shared by every dead-letter writer (`_bump_rows`, `_retire_unkeyable`, the pitfalls
    curator's `_graveyard_dropped_rows`); the queue page sorts and places records by it."""
    return {"retired_at": now_iso()}


def stuck_report_file(channel: QueueChannel) -> Path:
    """The channel's stuck-row record: the visible trace of a fault outside `RETIRE_SET`, whose
    row stays queued. One record per non-retiring tick, naming the fault class, the stalled
    rows and how many consecutive ticks they have been stuck.

    A row can be both graveyarded and queued: `_retire_unkeyable` and `retire` append dead
    letters before the rotation that removes the rows, releasing the append lock in between, so
    a rotation that times out against an appender (or a crash) in that window leaves the row in
    both, plus a duplicate dead letter each later stuck tick. Keyless rows are named by a
    content fingerprint (`_stuck_row_ids`)."""
    return channel.file.with_suffix(".stuck.jsonl")


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
    #: @owns held["forward_bad_terminal"], held["deferred"] — the two keys beyond the
    #: AUTHOR_RESULT bucket names, both assembled in `_author_and_rotate`.
    held: dict[str, list[dict]]
    consumed: dict[str, list[dict]]
    #: The pre-author gate's holds. Kept out of `held` (the AUTHOR_RESULT buckets, rows the
    #: agent judged) because these never reached the agent. They are also the permanent holds —
    #: they wait on a fact with no writer — so the operator report needs them most.
    gate_held: list[dict]


def retire(
    *,
    channel: QueueChannel,
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
    ids = {str(i) for i in batch_ids}
    key = channel.id_key

    with persist.queue_lock(channel.append_lock, timeout_seconds=timeout_seconds):
        named = [
            row for row in read_jsonl_rows(channel.file)
            if isinstance(row.get(key), str) and row[key] in ids
        ]
        bumped = _bump_rows(
            channel, named, counter_key=counter_key, max_attempts=max_attempts, reason=reason,
        )
    survivors, retired = bumped.survivors, bumped.retired

    persist.rotate_queue_locked(
        pending_file=channel.file,
        consumed_file=channel.consumed,
        lock_file=channel.append_lock,
        id_key=key,
        held=survivors,
        consumed=[{**rec, "consumed_category": "consumed_retired"} for rec in retired],
        commit_sha=None,
        timeout_seconds=timeout_seconds,
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
    channel: QueueChannel, rows: list[dict], *, counter_key: str, max_attempts: int, reason: str,
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
        append_jsonl(  # lint-unguarded-tree-write: ok — learning_queue sidecar, host-side, outside every box mount
            graveyard_file(channel),
            [
                {
                    key: rec[key],
                    # Whichever count reached its ceiling, under the slot every reader knows;
                    # the other counter stays inside `row` as provenance.
                    "attempts": rec[counter_key],
                    "deadletter_reason": reason,
                    **retirement_stamp(),
                    # Nested rather than spread, so a graveyard entry has one shape on every
                    # channel and is readable without knowing its queue.
                    "row": {k: v for k, v in rec.items() if k != counter_key},
                }
                for rec in retired
            ],
        )
    return _Bumped(survivors=survivors, retired=retired)



def channel_logger(cfg: CorpusAuthorConfig) -> logging.Logger:
    """This curator channel's logger — one child of this module's per channel, since both
    curators run this module's code; the repair pass logs under its `repair` child."""
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

    drain_fh = None
    if channel.drain_lock is not None:
        drain_fh = author_shared.acquire_flock(channel.drain_lock)
        if drain_fh is None:
            log.info("drain lock held by another process — skipping this tick")
            return 0
    try:
        try:
            repo_fh = author_shared.acquire_repo_lock(
                cfg.repo_lock_file, timeout_seconds=cfg.repo_lock_wait_seconds
            )
        except TimeoutError as e:
            log.warning(f"repo lock unavailable: {e}; queue intact")
            return 0
        try:
            try:
                author_shared.assert_clean_corpus_dir(
                    cfg.repo_root, cfg.corpus_dir, cfg.corpus_dir_rel, corpus=cfg.corpus,
                )
            except AuthorError as e:
                log.critical(f"{e}")
                # An already-dirty corpus at tick start is recorded as stuck, not skipped
                # silently.
                try:
                    _record_stuck(channel, e, [])
                except Exception as unrecorded:  # noqa: BLE001 — never replaces `e`
                    log.error(f"stuck record NOT written: {unrecorded!r} (the fault itself follows)")
                return 2
            return _tick(cfg=cfg, hold_committed=hold_committed, log=log)
        finally:
            author_shared.release_repo_lock(repo_fh)
    finally:
        author_shared.release_flock(drain_fh)


def _tick(*, cfg: CorpusAuthorConfig, hold_committed: bool, log) -> int:
    channel = cfg.channel
    key = channel.id_key

    append_fh = author_shared.acquire_flock_within(
        channel.append_lock, timeout_seconds=cfg.repo_lock_wait_seconds
    )
    if append_fh is None:
        log.info("append lock held by an appender past the deadline — skipping this tick")
        return 0
    try:
        batch, unreadable = read_jsonl_rows_report(channel.file)
    finally:
        author_shared.release_flock(append_fh)
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
        _retire_unkeyable(channel, unkeyable, log, cfg.repo_lock_wait_seconds)
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
        if not isinstance(e, RETIRE_SET):
            # The recorder must never replace the fault it records (a full disk would surface
            # the writer's `OSError` instead). `Exception`, not `BaseException`, so an
            # interrupt mid-record still leaves at once. Logged rather than swallowed: the
            # record is a stuck row's only external trace.
            try:
                _record_stuck(channel, e, stuck_rows)
            except Exception as unrecorded:  # noqa: BLE001 — see above; never replaces `e`
                log.error(f"stuck record NOT written: {unrecorded!r} (the fault itself follows)")
        raise


def _verifier_key_preflight(cfg: CorpusAuthorConfig) -> None:
    # Source the verifier key before the first spawn, so a keyless host doesn't pay for a
    # spawn it cannot check. Only channels with a forward check need it. Not gated on provider
    # match: the curator spawn is `cfg.invoke_agent`, an injection seam whose internals the
    # drain doesn't control, so this is the only place "checked before the first spawn" holds.
    if cfg.forward_check is not None and cfg.forward_check.prompt_path is not None:
        cfg.source_key(
            config.verifier_model(), label=f"verify:{cfg.forward_check.error_prefix}"
        )


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
# The authoring region. One truth — the corpus tree after the last spawn — from which every
# decision is computed once: changed files, citations, verdicts, approvals, the commit, and
# each row's fate. A spawn's own report is read only for skip reasons and the commit message,
# plus one cross-check: an id it claims committed that no file cites is deferred.
# ---------------------------------------------------------------------------


@model(frozen=True)
class _Tree:
    """The corpus after `_settle_tree`: repo-relative paths whose bytes differ from HEAD, and
    paths deleted. Every later step reads the corpus through this."""

    changed: tuple[str, ...]
    deleted: tuple[str, ...]


def _settle_tree(
    cfg: CorpusAuthorConfig, state: _PreState, *, honoured_deletions: tuple[str, ...] | None,
) -> _Tree:
    """The post-spawn normaliser, shared by the curator and repair spawns so the repair is held
    to the same rule. In order:

    1. non-`.md` files under the corpus are reverted — they cite nothing, so this is cleanup,
       and it must precede the stray check that would otherwise refuse the tick;
    2. a change outside the corpus (beyond tick-start dirt) raises `AuthorError`;
    3. an unmerged path under the corpus raises;
    4. a mode-only change (bytes identical to HEAD) is put back — it isn't content to judge,
       and would stay dirty after the commit and wedge the next tick's cleanliness gate;
    5. deletions: the curator spawn's are honoured (`honoured_deletions is None`) and
       committed; the repair spawn cannot delete, so any deletion beyond the honoured set is
       restored from the tick-start snapshot.

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
        if honoured_deletions is not None:
            unhonoured = sorted(set(deleted) - set(honoured_deletions))
            _restore_from_snapshot(cfg, state.snapshot, unhonoured)
            deleted = [rel for rel in deleted if rel in honoured_deletions]
        return _Tree(changed=tuple(sorted(changed)), deleted=tuple(sorted(deleted)))

    return _git_read("settle tree", settle)


@model(frozen=True)
class _Judged:
    """One judgement of the tree: every (finding, file) verdict on the files' current bytes,
    and what each file cites from this batch."""

    #: (finding_id, rel_path) -> its verdict on the file's current bytes; after a repair, also
    #: the BAD for a citation the repair dropped.
    pairs: dict[tuple[str, str], PairVerdict]
    #: rel_path -> the this-batch ids the file's current bytes cite.
    cites: dict[str, frozenset[str]]


#: How many times `_Judgement.judge` will re-read a tree that moved under it before giving
#: up. Two is the honest need (judge, then confirm nothing moved); the rest is slack for a
#: concurrent editor that is still writing when the first confirmation runs.
_JUDGE_ROUNDS = 4


if TYPE_CHECKING:
    #: `itertools.count[int]` raises `TypeError` at runtime, and a pydantic dataclass evaluates
    #: its field annotations at decoration time despite `from __future__ import annotations`.
    #: The alias gives mypy the `[int]` and pydantic the bare class (checked with `isinstance`).
    CheckCounter = itertools.count[int]
else:
    CheckCounter = itertools.count


@model
class _Judgement:
    """The verdict memo for one tick.

    @owns PairVerdict — the one constructor of `PairVerdict` instances (GOOD/BAD via
    `_verdict_for_pair`, EXEMPT via `cfg.exempt` or a channel with no check, and the
    dropped-citation BAD).

    Memoised by (file, content digest, finding): re-judging after the repair re-submits only
    pairs whose bytes moved, so an untouched file's verdict is never re-rolled, and a file
    rewritten back to its pre-repair bytes keeps its verdict. `history` holds every verdict
    minted this tick in order; a gap record carries the file's whole history, sibling findings
    included."""

    cfg: CorpusAuthorConfig
    rows: dict[str, dict]
    batch: set[str]
    memo: dict[tuple[str, str, str], PairVerdict] = dataclasses.field(default_factory=dict)
    history: list[PairVerdict] = dataclasses.field(default_factory=list)
    #: the check index every `CheckContext` this tick carries is drawn from — one counter,
    #: so two concurrently-minted checks never share one.
    counter: CheckCounter = dataclasses.field(default_factory=itertools.count)

    def judge(
        self, files: tuple[str, ...], pass_no: int, *, before: _Judged | None = None,
    ) -> _Judged:
        """Judge every this-batch id each of `files` cites, on the bytes the file holds now.
        Rounds repeat until nothing moved during one, so the bytes a verdict judged are the
        bytes that land in HEAD.

        `before` is the judgement the repair spawn answered. A finding it cited that no file
        cites any more had its lesson dropped by the rewrite: terminal for that finding, and
        recorded as a BAD on the file that dropped it. That pair goes in `pairs` (the
        finding's fate reads it) but not `cites` (the file's approval doesn't)."""
        field_name = provenance_field(self.cfg.channel.id_key)
        texts: dict[str, str] = {}
        for _ in range(_JUDGE_ROUNDS):
            texts = {rel: self.read(rel) for rel in files}
            jobs = [
                (rel, fid, text)
                for rel, text in texts.items()
                for fid in sorted(_cited_ids_in(text, field_name) & self.batch)
                if (rel, _digest(text), fid) not in self.memo
            ]
            self.mint(jobs, pass_no)
            if all(self.read(rel) == text for rel, text in texts.items()):
                break
        else:
            raise AuthorError(
                f"{self.cfg.corpus_dir_rel} kept changing under the forward check for "
                f"{_JUDGE_ROUNDS} rounds — refusing to commit bytes no verdict judged"
            )
        cites = {
            rel: frozenset(_cited_ids_in(text, field_name) & self.batch)
            for rel, text in texts.items()
        }
        pairs = {
            (fid, rel): self.memo[(rel, _digest(texts[rel]), fid)]
            for rel, ids in cites.items()
            for fid in ids
        }
        if before is not None:
            cited_now = {fid for ids in cites.values() for fid in ids}
            for fid, rel in sorted(before.pairs):
                if fid in cited_now:
                    continue
                row = self.rows[fid]
                dropped = PairVerdict(
                    rel_path=rel, finding_id=fid, source_id=str(row.get("run_id") or ""),
                    verdict="BAD",
                    reasoning="repair rewrite dropped this file's citation of this finding",
                    lesson_text=texts.get(rel, self.read(rel)),
                    pass_no=pass_no,
                )
                self.history.append(dropped)
                pairs[(fid, rel)] = dropped
        return _Judged(pairs=pairs, cites=cites)

    def read(self, rel: str) -> str:
        """The text the repo-relative corpus file `rel` holds now, read through the corpus
        mount's view; `""` when it cannot be read."""
        return _read_or_empty(self.cfg.corpus.view(), _corpus_relative(self.cfg, rel))

    def mint(self, jobs: list[tuple[str, str, str]], pass_no: int) -> None:
        """Judge the pairs concurrently, bounded by `verify_batch_workers()`."""
        if not jobs:
            return

        def one(job: tuple[str, str, str]) -> PairVerdict:
            rel, fid, text = job
            row = self.rows[fid]
            if self.cfg.exempt(row):
                verdict, reasoning = "EXEMPT", "exempt: this finding's kind is out of the check's scope"
            elif self.cfg.forward_check is None:
                verdict, reasoning = "EXEMPT", "exempt: this channel runs no forward check"
            else:
                verdict, reasoning = _verdict_for_pair(
                    self.cfg, self.counter, rel, row, self.cfg.repo_root / rel, text,
                )
            return PairVerdict(
                rel_path=rel, finding_id=fid, source_id=str(row.get("run_id") or ""),
                verdict=verdict, reasoning=reasoning, lesson_text=text, pass_no=pass_no,
            )

        workers = max(1, config.verify_batch_workers())
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for pv in pool.map(one, jobs):
                self.memo[(pv.rel_path, _digest(pv.lesson_text), pv.finding_id)] = pv
                self.history.append(pv)


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@model(frozen=True)
class _Fates:
    """Every row the batch read, sorted into exactly one ending."""

    #: ids an approved file cites, every citing file approved.
    committed: list[str]
    #: id -> the files it cites, for an id whose every pair is BAD.
    terminal: dict[str, list[str]]
    #: ids that could not land through no fault of their own.
    deferred: set[str]


def _decide_fates(
    batch_ids: set[str], judged: _Judged, approved: set[str], claimed_committed: set[str],
) -> _Fates:
    """Each batch row's ending, read off the judged tree. An id some file cites takes its fate
    from its pairs. For an id no file cites, the curator's word is only cross-checked: claimed
    committed means deferred, never consumed; otherwise the row is left queued as it was."""
    committed: list[str] = []
    terminal: dict[str, list[str]] = {}
    deferred: set[str] = set()
    for fid in sorted(batch_ids):
        own = [pv for (f, _rel), pv in judged.pairs.items() if f == fid]
        if not own:
            if fid in claimed_committed:
                deferred.add(fid)
            continue
        if all(pv.verdict == "BAD" for pv in own):
            terminal[fid] = sorted({pv.rel_path for pv in own})
        elif all(pv.rel_path in approved for pv in own):
            committed.append(fid)
        else:
            # Its citing files disagree on approval; the drain never guesses between the two.
            deferred.add(fid)
    return _Fates(committed=committed, terminal=terminal, deferred=deferred)


@model(frozen=True)
class _BatchOutcome:
    commit_sha: str | None
    committed: list[dict]
    bucket_held: dict[str, list[dict]]
    bucket_consumed: dict[str, list[dict]]
    terminal_rows: list[dict]
    deferred_ids: set[str]


def _author_batch(
    cfg: CorpusAuthorConfig,
    to_author: list[dict],
    batch_id: str,
    state: _PreState,
    all_rows: dict[str, dict],
) -> _BatchOutcome:
    """Spawn, settle, judge; if anything is BAD, spawn the repair, settle, judge again; then
    read every fate off the last judgement and commit what it approved."""
    key = cfg.channel.id_key
    batch_ids = {row[key] for row in to_author}

    # The box runs for the spawn only, and is stopped before any host step reads what it
    # wrote (#1195).
    with box_mod.box_for_run(cfg.box) as box:
        result = cfg.invoke_agent(to_author, batch_id, replace(cfg, box=box))
    tree = _settle_tree(cfg, state, honoured_deletions=None)
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

    judgement = _Judgement(cfg=cfg, rows=all_rows, batch=batch_ids)
    judged = judgement.judge(tree.changed, pass_no=1)
    #: every path either spawn left changed — the restore below covers a file the first
    #: spawn wrote and the repair spawn then removed or replaced with something else.
    touched = set(tree.changed)
    bad = [pv for pv in judged.pairs.values() if pv.verdict == "BAD"]
    if bad:
        _spawn_repair(cfg, bad, batch_id)
        tree = _settle_tree(cfg, state, honoured_deletions=tree.deleted)
        touched |= set(tree.changed)
        judged = judgement.judge(tree.changed, pass_no=2, before=judged)

    # Approved: cites something from this batch and every citing pair is GOOD or EXEMPT. A
    # changed file citing nothing is not approved.
    approved = {
        rel for rel, ids in judged.cites.items()
        if ids and all(judged.pairs[(fid, rel)].verdict in ("GOOD", "EXEMPT") for fid in ids)
    }
    fates = _decide_fates(
        batch_ids, judged, approved,
        claimed_committed=set(author_shared.result_list(result, "committed")),
    )
    # Before the commit, so a restore failure can never coexist with a commit.
    _restore_unapproved_files(cfg, state.snapshot, touched - approved,
                              head_before=state.head_before)

    message = (
        author_shared.commit_message(result, cfg.noun) if approved or tree.deleted else ""
    )
    message = _append_terminal_block(message, sorted(fates.terminal))
    commit_sha = author_shared.commit_corpus_paths(
        message, cfg, sorted(approved), list(tree.deleted)
    )

    terminal_rows: list[dict] = []
    for fid, files in fates.terminal.items():
        row = all_rows[fid]
        _append_gap_record(
            cfg, batch_id, row, key,
            [pv for pv in judgement.history if pv.rel_path in files],
        )
        terminal_rows.append({**row, "consumed_category": "consumed_forward_bad"})

    # The curator's buckets, minus every id the tree already gave a fate.
    fated = set(fates.committed) | set(fates.terminal) | fates.deferred
    bucket_held, bucket_consumed = _project(result, all_rows, cfg, exclude=fated)
    return _BatchOutcome(
        commit_sha=commit_sha,
        committed=[
            {**all_rows[fid], "consumed_category": "consumed_committed"}
            for fid in fates.committed
        ],
        bucket_held=bucket_held,
        bucket_consumed=bucket_consumed,
        terminal_rows=terminal_rows,
        deferred_ids=fates.deferred,
    )


def _spawn_repair(cfg: CorpusAuthorConfig, bad: list[PairVerdict], batch_id: str) -> None:
    """The one bounded, write-only repair spawn, handed every BAD pair of this tick. A
    configured but missing repair prompt is fatal config; `None` means the shipped default,
    resolved inside `invoke_repair`."""
    if cfg.repair_prompt is not None and not cfg.repair_prompt.is_file():
        raise FatalConfigError(f"repair prompt {cfg.repair_prompt} is not a readable file")
    with box_mod.box_for_run(cfg.box) as box:
        cfg.invoke_repair(bad, batch_id, replace(cfg, box=box))


def _handle_retire(
    cfg: CorpusAuthorConfig, e: BaseException, to_author: list[dict], key: str, log
) -> int:
    channel = cfg.channel
    log.critical(f"{e}")
    outcome = retire(
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
            _record_stuck(channel, e, survivors)
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
        cfg.channel, [all_rows[fid] for fid in sorted(deferred_ids)],
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
        commit_sha=None, committed=[], bucket_held={}, bucket_consumed={},
        terminal_rows=[], deferred_ids=set(),
    )

    if to_author:
        _verifier_key_preflight(cfg)
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
    terminal_rows, deferred_ids = outcome.terminal_rows, outcome.deferred_ids
    commit_sha = outcome.commit_sha

    held_committed, rotated_committed = author_shared.partition_committed(
        committed, hold_committed=hold_committed
    )

    deferred_held, deferred_consumed = _fold_deferrals(cfg, deferred_ids, all_rows)

    persist.rotate_queue_locked(
        pending_file=channel.file,
        consumed_file=channel.consumed,
        lock_file=channel.append_lock,
        id_key=key,
        held=[*held, *_flatten(cfg.buckets, bucket_held), *held_committed, *deferred_held],
        consumed=[
            *consumed_pre,
            *rotated_committed,
            *_flatten(cfg.buckets, bucket_consumed),
            *terminal_rows,
            *deferred_consumed,
        ],
        commit_sha=commit_sha,
        timeout_seconds=cfg.repo_lock_wait_seconds,
    )
    if cfg.post_rotate is not None:
        cfg.post_rotate(
            DrainOutcome(
                batch_id=batch_id, commit_sha=commit_sha, committed=committed,
                held={**bucket_held, "forward_bad_terminal": terminal_rows,
                      "deferred": deferred_held + deferred_consumed},
                consumed=bucket_consumed, gate_held=held,
            ),
            cfg,
        )
    log.info(
        f"done batch={batch_id} committed={len(committed)} held={len(held)} "
        f"pre_consumed={len(consumed_pre)} terminal={len(terminal_rows)} "
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


def _restore_from_snapshot(
    cfg: CorpusAuthorConfig, snapshot: dict[str, bytes] | None, rels: list[str],
) -> None:
    """Put each of `rels` back to its tick-start bytes, through the corpus mount (#1134). A
    name the snapshot does not hold is skipped."""
    if snapshot is None:
        return
    for rel in rels:
        name = _corpus_relative(cfg, rel)
        pre = snapshot.get(name)
        if pre is None:
            continue
        cfg.corpus.write(name, pre, mode="replace")


def _append_terminal_block(message: str, terminal_ids: list[str]) -> str:
    """Append the block naming this tick's terminal findings to the commit message. Appended
    last, so `message.split(TERMINAL_BLOCK_HEADER)[-1]` is always this block even if the
    curator wrote a line shaped like the header."""
    if not terminal_ids:
        return message
    block = TERMINAL_BLOCK_HEADER + " " + ", ".join(terminal_ids)
    return message.rstrip("\n") + "\n\n" + block + "\n"


def _append_gap_record(
    cfg: CorpusAuthorConfig, batch_id: str, row: dict, key: str, pvs: list[PairVerdict],
) -> None:
    """Append one durable record per terminal finding, before the queue rotation — a crash in
    between costs a duplicate record on replay, never a silent consumption.

    @owns findings.forward_bad.jsonl row shape — the one producer of a gap-ledger record.
    `verdicts` is the file's full `PairVerdict` history, not just the terminal finding's."""
    last = pvs[-1]
    record = {
        "finding_id": row[key],
        "run_id": row.get("run_id"),
        "direction": row.get("direction"),
        "batch_id": batch_id,
        "lesson_path": last.rel_path,
        "lesson_text": last.lesson_text,
        "verdicts": [
            {
                "rel_path": pv.rel_path, "source_id": pv.source_id,
                "verdict": pv.verdict, "reasoning": pv.reasoning, "pass": pv.pass_no,
            }
            for pv in pvs
        ],
        "recorded_at": now_iso(),
    }
    append_jsonl(  # lint-unguarded-tree-write: ok — learning_queue sidecar, host-side, outside every box mount
        cfg.pending_dir / GAP_LEDGER_NAME, [record],
    )


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

    First spawn only: after the repair the drain knows which findings each file owned, so an
    unvouched file is refused per file (no approval) rather than per tick. The `AuthorError`
    unwinds the tick via `_undo_agent_edits`; the batch is bumped and stays queued."""
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


def _resolves_inside_runs_dir(runs_dir: Path, source_id: str) -> bool:
    """Whether `source_id` resolves inside `runs_dir`. The id comes from a queue row, not the
    model, but rows are machine-written and unvalidated, so a traversal-shaped `run_id` is
    possible."""
    runs_root = runs_dir.resolve()
    resolved = (runs_dir / source_id).resolve()
    return resolved == runs_root or runs_root in resolved.parents


def _attempt_pair(
    cfg: CorpusAuthorConfig, counter: Any, rel: str, row: dict, path: Path, lesson_text: str,
) -> tuple[str, str]:
    """One attempt at one pair: build the `CheckContext` and call the check.

    A missing, malformed or escaping `run_id` raises `VerdictError` — the class an unparseable
    verifier reply raises — so a malformed row gets the same retry-once-then-BAD disposition.
    Any other exception (a call that never completed) propagates unretried."""
    try:
        source_id = row["run_id"]
    except KeyError as e:
        raise VerdictError("forward_check: row carries no run_id") from e
    if not isinstance(source_id, str) or not source_id:
        raise VerdictError(f"forward_check: row's run_id is not a usable string: {source_id!r}")
    if not _resolves_inside_runs_dir(cfg.runs_dir, source_id):
        raise VerdictError(f"forward_check: run_id resolves outside runs_dir: {source_id!r}")
    # `_Judgement.mint` only routes here when a check is configured; narrowed for mypy.
    assert cfg.forward_check is not None
    idx = next(counter)
    ctx = CheckContext(
        check=cfg.forward_check,
        lesson_path=path,
        lesson_text=lesson_text,
        source_id=source_id,
        direction=str(row.get("direction") or "adversarial"),
        runs_dir=cfg.runs_dir,
        pending=cfg.channel.file,
        corpus_dir=cfg.corpus_dir,
        repo_root=cfg.repo_root,
        check_index=idx,
        run_verify=_run_verify_pydantic,
    )
    return cfg.forward_check.run(ctx)


def _verdict_for_pair(
    cfg: CorpusAuthorConfig, counter: Any, rel: str, row: dict, path: Path, lesson_text: str,
) -> tuple[str, str]:
    """Retry a `VerdictError` once; a second one records BAD with `ERROR_PREFIX` reasoning
    carrying both attempts' text. Any other exception propagates on the first attempt and
    mints no verdict."""
    try:
        return _attempt_pair(cfg, counter, rel, row, path, lesson_text)
    except VerdictError as e1:
        try:
            return _attempt_pair(cfg, counter, rel, row, path, lesson_text)
        except VerdictError as e2:
            return "BAD", f"{ERROR_PREFIX}{e1}; {e2}"


def build_repair_user_prompt(
    pairs: list[PairVerdict], cfg: CorpusAuthorConfig, *, salt: str | None = None,
) -> str:
    """The repair spawn's user turn: per BAD pair, the finding's identity, the file's
    pre-repair text and the verifier's reasoning, each in its own `wrap()` envelope since all
    three are model-authored."""
    from uuid import uuid4

    stage_salt = salt if salt is not None else uuid4().hex
    sections: list[str] = []
    for pv in pairs:
        header = (
            f"finding_id: {pv.finding_id}\n"
            f"source_id: {pv.source_id}\n"
            f"lesson_path: {pv.rel_path}\n"
        )
        sections.append(wrap(header, "bad_pair", stage_salt))
        sections.append(wrap(pv.lesson_text, "candidate_lesson", stage_salt))
        sections.append(wrap(pv.reasoning, "verifier_reasoning", stage_salt))
    return stage_user_message(stage_salt, *sections)


def _retire_unkeyable(
    channel: QueueChannel, rows: list[dict], log, timeout_seconds: int
) -> None:
    """Retire rows with no id under the channel's key at once, on their own rotation; their
    well-formed batch-mates are authored this tick.

    Not left to the closing rotation: a keyless row can't be matched by id, so that rotation
    would remove it via `None` in the processed set — swallowing any keyless row appended
    meanwhile, with no graveyard entry — and it never runs on a retiring or stuck tick.

    The record is flat (row content at top level, not nested under `row` as `retire` writes
    it), since there is no id to reference; consumers must branch on the presence of `row`."""
    if not rows:
        return
    reason = f"row carries no value under {channel.id_key!r}"
    log.warning(f"{len(rows)} unkeyable row(s) retired: {reason}")
    append_jsonl(  # lint-unguarded-tree-write: ok — learning_queue sidecar, host-side, outside every box mount
        graveyard_file(channel),
        [{**row, "attempts": int(row.get("attempts") or 0) + 1,
          "deadletter_reason": reason, **retirement_stamp()} for row in rows],
    )
    persist.rotate_queue_locked(
        pending_file=channel.file,
        consumed_file=channel.consumed,
        lock_file=channel.append_lock,
        id_key=channel.id_key,
        held=[],
        consumed=[{**row, "consumed_category": "consumed_retired"} for row in rows],
        commit_sha=None,
        timeout_seconds=timeout_seconds,
    )


def _row_id(row: dict, key: str) -> str | None:
    """This row's id under its channel's key, or `None` where it has none.

    Shared by `_tick` (to split the batch) and `_stuck_row_ids` (to name rows): if they
    disagreed, a truthy non-string id filed as unkeyable would be named as a real id."""
    rid = row.get(key)
    return rid if isinstance(rid, str) and rid else None


def _stuck_row_ids(channel: QueueChannel, rows: list[dict]) -> list[str]:
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
        digest = hashlib.sha256(
            json.dumps(row, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()
        named.append(f"unkeyed:{digest[:16]}")
    return sorted(named)


def record_stuck(channel: QueueChannel, exc: BaseException, rows: list[dict]) -> None:
    """Record this fault on the channel's stuck report (the public entry point, used by
    `drains._drain_one_curator`)."""
    _record_stuck(channel, exc, rows)


def stuck_record_count(channel: QueueChannel) -> int:
    """How many records the channel's stuck report holds right now.

    Lets a second frame ask whether this tick's fault is already recorded: `_record_stuck`
    folds `consecutive_ticks` only when fault class and row ids both match, so two records per
    tick with different row sets would reset the count to 1 forever. Asked of the file rather
    than marked on the exception, because a raiser may reuse one exception instance across
    ticks.
    """
    path = stuck_report_file(channel)
    return len(read_jsonl_rows(path)) if path.is_file() else 0


def _record_stuck(channel: QueueChannel, exc: BaseException, rows: list[dict]) -> None:
    """@owns recorded_at — the operator signal for a stuck tick, and when it was written.

    The file is append-only and never cleared, so the stamp is what lets the queue page say
    "last faulted at". The count is per tick, not per row: a non-retiring row must stay
    byte-identical, so the last record is read back instead."""
    fault_class = type(exc).__name__
    ids = _stuck_row_ids(channel, rows)
    path = stuck_report_file(channel)
    previous = read_jsonl_rows(path)
    consecutive = 1
    # An empty id list is a row set too: the faulting phase had no rows in flight (e.g. the
    # gate held the whole batch). Consecutive such ticks with one fault class are the same
    # problem recurring, so they fold.
    if previous:
        last = previous[-1]
        same_ids = sorted(str(i) for i in (last.get("row_ids") or [])) == ids
        if last.get("fault_class") == fault_class and same_ids:
            consecutive = int(last.get("consecutive_ticks") or 0) + 1
    append_jsonl(  # lint-unguarded-tree-write: ok — learning_queue sidecar, host-side, outside every box mount
        path,
        [{
            "fault_class": fault_class,
            "row_ids": ids,
            "consecutive_ticks": consecutive,
            "reason": str(exc),
            "recorded_at": now_iso(),
        }],
    )


def _snapshot_corpus(
    repo_root: Path, corpus_dir: Path, head: str, *, timeout: float | None = None,
) -> dict[str, bytes]:
    """The corpus's before-state: every regular file the commit `head` carries under
    `corpus_dir`, nested folders included, with its exact stored bytes, keyed by its name under
    the corpus mount.

    Read from git, not from the worktree (#1134 addendum 2 correction, C1): the clean gate
    (`assert_clean_corpus_dir`) refused the tick unless the corpus equals the tick-start commit,
    so `head` names exactly what stood there, and git's own read (`_git.git_tree_blobs`, N-a)
    lists no folder and follows no worktree entry (O3, O5.1). A tracked symlink (mode 120000) is
    left out, so no restore writes it back as a file. A git failure raises `GitError` before the
    agent runs."""
    rel = corpus_dir.relative_to(repo_root).as_posix()
    prefix = "" if rel == "." else f"{rel}/"
    return {path[len(prefix):]: blob
            for path, blob in _git.git_tree_blobs(repo_root, head, rel, timeout=timeout).items()}


def _undo_agent_edits(
    cfg: CorpusAuthorConfig,
    snapshot: dict[str, bytes] | None,
    baseline_stray: list[str],
    head_before: str,
) -> None:
    """Put the worktree back the way the agent found it after a faulted tick.

    The corpus is restored only if the commit did not land: `git_commit` reads HEAD after
    committing, so a git failure there arrives with the lessons already in history, and
    restoring would delete them and wedge the channel. When git can't say whether HEAD moved,
    nothing is deleted.

    Strays outside the corpus are always reverted (the commit is pathspec-limited, so it
    can't have captured them); otherwise they fold into the next tick's baseline and disarm
    the out-of-scope-write guard.

    Both run while a fault is propagating, and every host touch of the lane's trees goes through
    its held mounts (#1134). An entry the core will not remove or write over because it is not a
    plain file (`NotPlainEntry`: a link, hard link, FIFO or folder at the name) is logged and
    passed over (`_left_for_scrub`), so the fault being unwound propagates unchanged and keeps
    its routing; the entry stays for the scrub (O5.3). Any other `OSError` propagates."""
    if not _commit_landed(cfg.repo_root, head_before, timeout=cfg.git_timeout):
        _restore_corpus(cfg.repo_root, cfg.corpus_dir, snapshot, corpus=cfg.corpus,
                        head_before=head_before, timeout=cfg.git_timeout)
    _revert_strays(cfg.repo_root, cfg.corpus_dir_rel, baseline_stray, tree_for=cfg.tree_for,
                   timeout=cfg.git_timeout)


def _left_for_scrub(what: str, fn: Callable[..., Any], *args: Any) -> None:
    """Run one fault-path restore step; the core's leaf refusal (`NotPlainEntry`: an entry at the
    name that is not a plain file) is logged and passed over, the entry left in place. Any other
    `OSError` (a linked or non-directory folder on the way, EACCES, EIO, ENOSPC) propagates
    (#1134 O5.3)."""
    try:
        fn(*args)
    except NotPlainEntry as e:
        _logger.warning(f"warn: {what} left for the scrub: {e.strerror}")


def _commit_landed(repo_root: Path, head_before: str, *, timeout: float | None = None) -> bool:
    """Whether HEAD moved; True when git cannot say (or does not within `timeout`), so nothing
    gets deleted."""
    try:
        return author_shared.git_head_sha(repo_root, timeout=timeout) != head_before
    except (GitError, GitTimeout):
        return True


def _revert_strays(
    repo_root: Path, corpus_dir_rel: str, baseline_stray: list[str], *, tree_for: TreeFor,
    timeout: float | None = None,
) -> None:
    """Undo what the agent wrote outside the corpus this tick, leaving pre-existing dirt alone.

    Best-effort: it runs while a fault is propagating, and a second failure would replace that
    diagnosis — a git failure (or a git call not answering within `timeout`) listing the strays
    or putting one back, or a non-plain entry at one."""
    try:
        strays = sorted(
            set(author_shared.changes_outside(repo_root, corpus_dir_rel, **_worktree_git(timeout)))
            - set(baseline_stray)
        )
    except (GitError, GitTimeout):
        return
    for rel in strays:
        try:
            _left_for_scrub(rel, functools.partial(_put_back, tree_for=tree_for, timeout=timeout),
                            repo_root, rel)
        except GitTimeout as e:
            _logger.warning(f"warn: {rel} left for the scrub: git did not answer within "
                            f"{e.timeout}s")


def _unchanged_names(
    repo_root: Path, corpus_dir: Path, rev: str, *, timeout: float | None = None,
) -> frozenset[str]:
    """The names under the corpus mount of the regular files `rev` carries there that git still
    finds unchanged in the worktree (`_git.git_unchanged_since`, #1134 addendum 3 D1): the
    before-state files a restore need not write back. A git failure raises `GitError`; one not
    answering within `timeout`, `GitTimeout`."""
    rel = corpus_dir.relative_to(repo_root).as_posix()
    prefix = "" if rel == "." else f"{rel}/"
    return frozenset(path[len(prefix):]
                     for path in _git.git_unchanged_since(repo_root, rev, rel, timeout=timeout))


def _worktree_files_instead(
    repo_root: Path, corpus_dir: Path, status_fault: GitError | GitTimeout, *,
    timeout: float | None,
) -> list[str]:
    """`_restore_corpus`'s answer when its `git status` failed or did not answer within
    `timeout`: every non-ignored worktree file under the corpus that `git_worktree_files` names,
    or none when that fails too (a warning names both failures)."""
    try:
        made = _git.git_worktree_files(repo_root, str(corpus_dir), timeout=timeout)
    except (GitError, GitTimeout) as files_fault:
        _logger.warning(
            "warn: the corpus restore cannot ask git what changed (git status "
            f"{_unanswered(status_fault)}, git ls-files {_unanswered(files_fault)}); "
            "nothing swept")
        return []
    _logger.warning(
        f"warn: the corpus restore's git status failed ({_unanswered(status_fault)}); "
        "it swept the worktree files git ls-files names instead")
    return made


def _restore_corpus(
    repo_root: Path, corpus_dir: Path, snapshot: dict[str, bytes] | None, *, corpus: Held,
    head_before: str, timeout: float | None = None,
) -> None:
    """Put the corpus back to its pre-agent contents, through `corpus`, its held mount
    (`corpus_dir` is that folder's spelling, the git pathspec only), as the before-state read at
    `head_before` holds them.

    The content restore is filesystem-only: the failure it handles is usually git's, and a git
    restore would need the index lock that failed (`git status`, a read, needs none). The
    unstage is best-effort, for a rejected commit where the add did land.

    No folder is listed (#1134 addendum 2 correction, C1): which names the agent made comes from
    git (`git status --untracked-files=all` over the corpus), and each one the snapshot (the
    before-state) does not hold is removed through `corpus`: a plain file is unlinked; a link,
    hard link or anything else at the name is the core's refusal, never followed (O5.2). A name
    git does not report — a gitignored file, a FIFO or socket — is left (C2).

    When `git status` fails (a broken index: the fault being unwound is often git's), git is
    asked instead for every non-ignored worktree file under the corpus against an empty index
    (`_git.git_worktree_files`, which never opens the real index), and each the snapshot lacks
    is swept the same way; a tracked symlink is then among them, and its unlink is refused and
    logged. If git cannot answer that either, nothing is swept (a warning).

    Then each snapshot file git does not find unchanged since `head_before` — rewritten, gone,
    replaced by a link or anything else — is written back through `corpus` (`_unchanged_names`,
    addendum 3 D1: git compares, nothing here reads the worktree). A hard link holding the exact
    before-state bytes is unchanged to git and left (declared, N-a). If git cannot compare, every
    snapshot file is written back (a warning): an identical rewrite is harmless. Each git call is
    bounded by `timeout` and reads attributes from HEAD's tree (`_worktree_git`); one that does not
    answer in time is handled as one that failed, so the fault being unwound keeps propagating.
    Fault path only: see `_undo_agent_edits`."""
    if snapshot is None:
        return
    # Best-effort, like its unchecked exit: a reset that does not answer in time is passed over.
    with contextlib.suppress(GitTimeout):
        _git.git(["reset", "-q", "--", str(corpus_dir)], cwd=repo_root, check=False,
                 **_worktree_git(timeout))
    try:
        made = [rel for xy, rel in _git.git_status(repo_root, pathspec=corpus_dir,
                                                   no_renames=True, **_worktree_git(timeout))
                if "D" not in xy]
    except (GitError, GitTimeout) as status_fault:
        made = _worktree_files_instead(repo_root, corpus_dir, status_fault, timeout=timeout)
    for rel in made:
        name = (repo_root / rel).relative_to(corpus_dir).as_posix()
        if name not in snapshot:
            _left_for_scrub(name, corpus.unlink, name)
    unchanged: frozenset[str] = frozenset()
    try:
        unchanged = _unchanged_names(repo_root, corpus_dir, head_before, timeout=timeout)
    except (GitError, GitTimeout) as compare_fault:
        _logger.warning(
            "warn: the corpus restore cannot ask git which files still hold their before-state "
            f"bytes (git diff {_unanswered(compare_fault)}); it writes every one back")
    for name, blob in snapshot.items():
        if name not in unchanged:
            _left_for_scrub(name, functools.partial(corpus.write, mode="replace"), name, blob)
