"""The one corpus-author drain body, and the one retire seam.

Every corpus-author channel reaches its batch through `run_batch` here. Since #922 that
is ONE channel — findings; the three observation channels lost their producer with the
old pipeline. The parameterisation stays because it is the batch driver's contract with
its config, not because a second channel is pending: what varies per direction
(pre-author gate, AUTHOR_RESULT buckets, row key, the queue's two locks, commit trailers,
the lessons-only held report) is a field on the config, and the batch body (read,
partition, author, verify, commit, project, rotate, log) is this module.

**Retirement is reachable only from `RETIRE_SET`.** A fault whose class is not in that
tuple never reaches the retire seam: it leaves its row queued — stuck, recoverable, and
recorded in the channel's stuck-row file. The accepted trade is that a novel exception
class returns to unbounded retry rather than being counted toward a ceiling and
permanently deleted.

The one class-blind clause is the authoring region's CLEANUP, which puts the worktree back
and then either retires (member) or re-raises unchanged. Disposition is still decided by
one `isinstance`.

`GitError` and `ModelRetry` are the two members the obvious `except AuthorError` spelling
would silently drop, reverting a commit-time git failure and an externally killed boxed
command back to "wedges the channel" and "reports success".

**A `GitError` is a member only where it means the COMMIT failed.** The drain also reads
repo state — the worktree status either side of the agent call, and HEAD — and a git
failure there is contention on a busy repo, not a defect in the batch. Those reads go
through `_git_read`, which re-raises as `GitProbeError`: not a member, so the batch keeps
its attempt count and the tick is recorded as stuck instead. Otherwise an index-lock
collision during a read-only probe burns an attempt against work that was fine, and three
collisions over a queue's life delete it.

SCOPE: the set governs the AUTHOR channel. The pitfalls and lead-author legs keep
`core/faults.run_or_dead_letter`'s own re-raise set, which CONTAINS `GitError` — so a
commit-time `GitError` retires here and kills the drain there. One class, two
classifications, by channel: deliberate, and left for a follow-up.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, TypeVar

from pydantic_ai.exceptions import ModelRetry

from defender import _git
from defender._git import GitError
from defender._frontmatter import FrontmatterError, split_frontmatter
from defender._io import (
    TEXT_READ_ERRORS,
    append_jsonl,
    guarded_mkdir,
    read_jsonl_rows,
    read_jsonl_rows_report,
    read_text_utf8,
    write_guarded,
)
from defender.learning.author import shared as author_shared
from defender.learning.author._config import BucketSpec, CorpusAuthorConfig
from defender.learning.core import persist
from defender.learning.core.config import QueueChannel, make_logger, provenance_field

AuthorError = author_shared.AuthorError

#: Spelled as a literal enumeration on purpose: it is NOT `faults.SYSTEMIC_FAULTS` (which
#: exists to keep `GitError` OUT of retirement, the opposite of what a commit-time git
#: failure must do here), and it is not narrowable to `AuthorError` alone (which drops the
#: other two members).
RETIRE_SET: tuple[type[BaseException], ...] = (AuthorError, GitError, ModelRetry)

_T = TypeVar("_T")


class GitProbeError(RuntimeError):
    """A git command the drain used to READ repo state failed.

    Deliberately not a `GitError` subclass and deliberately absent from `RETIRE_SET`: the
    ceiling bounds work that keeps failing, and a `git status` that lost a race for the
    index lock says nothing about the work, so it must not spend one of its three lives.
    The tick is stuck and loud instead."""


def _git_read(what: str, fn: Callable[..., _T], *args: Any) -> _T:
    """Run a call that READS repo state, converting its git failure to a non-member.

    Wraps whole steps rather than bare git calls, so a step that both probes git and
    raises `AuthorError` on what it finds keeps the second half intact: only the
    `GitError` is reclassified, and the batch's own faults still retire."""
    try:
        return fn(*args)
    except GitError as e:
        raise GitProbeError(f"read-only git probe ({what}) failed: {e}") from e


#: The acquisition order, declared in exactly one place so no call site can invent its own.
#: Drain lock first, because a contended tick must skip BEFORE it takes the globally
#: serialising repo lock; the append lock last and briefly, so an appender never waits on
#: the agent call.
LOCK_ORDER: tuple[str, ...] = ("drain_lock", "repo_lock", "append_lock")


def graveyard_file(channel: QueueChannel) -> Path:
    """The channel's retirement record. Advisory: the queue rewrite is authoritative, and
    nothing in production reads this back."""
    return channel.file.with_suffix(".deadletter.jsonl")


def stuck_report_file(channel: QueueChannel) -> Path:
    """The channel's stuck-row record — the externally visible trace of a fault whose class
    is NOT in `RETIRE_SET`, since such a row stays queued. One record per non-retiring tick,
    naming the fault class, the stalled rows and how many consecutive ticks they have been
    stuck.

    "Never reaches the graveyard" holds for every leg but the two that retire. BOTH
    `_retire_unkeyable` and `retire` append their dead letters BEFORE the rotation that
    removes the rows from the queue, and both release the append lock between the two — so a
    rotation that expires against an appender arriving in that window leaves a row both
    graveyarded AND queued, plus a further duplicate dead letter on every stuck tick after
    it. (`retire`'s own docstring names the same window from the crash side.) The stuck
    record is what says the two files disagree on purpose.

    A stalled row with no id under its channel's key is named by a content fingerprint —
    `_stuck_row_ids` owns that spelling — so the keyless leg's records are still tellable
    apart from one another."""
    return channel.file.with_suffix(".stuck.jsonl")


@dataclass(frozen=True)
class RetireOutcome:
    #: id -> the attempt count the row now carries, for every row in the batch.
    bumped: dict[str, int]
    #: the ids that crossed the ceiling on this observation and left the queue.
    retired: tuple[str, ...]


@dataclass(frozen=True)
class DrainOutcome:
    """What one completed tick did, handed to `cfg.post_rotate` after the rotation."""

    batch_id: str
    commit_sha: str | None
    committed: list[dict]
    held: dict[str, list[dict]]
    consumed: dict[str, list[dict]]
    #: The PRE-AUTHOR gate's holds, as its own field rather than a key in `held` (#881/O3).
    #: `held` is the AUTHOR_RESULT buckets, keyed by bucket name — rows the agent returned a
    #: verdict on. A gate hold never reached the agent, so folding it in there would report a
    #: row the forward check never saw as a forward-check verdict. These are also the holds
    #: that are PERMANENT: the bucket holds are one agent's opinion of one batch, while a gate
    #: hold waits on a fact with no writer, so the operator's report needs them most and had
    #: them not at all.
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

    The count is a LIFETIME count on the row — no reset on an intervening success, none on
    a requeue — and the ceiling is consulted only here, i.e. only after an observed
    failure. A row that arrives already over the ceiling rides through a clean tick
    untouched.

    `counter_key` NAMES WHAT IS BEING COUNTED, because one channel has two independent
    reasons to bump a row. `attempts` — the default, and every caller's answer but one —
    counts FAULTS: ticks that raised. The pitfalls lane also bounds a row the curator was
    OFFERED and declined, which is no fault at all, and folding both into `attempts` makes
    each ceiling arrive early in the other's traffic: two infra-faulting ticks spend a
    freshly-queued row's whole offer budget, so its FIRST decline retires it terminally with
    its lesson never taught. Two counters, two ceilings, one primitive; the graveyard's own
    `attempts` slot reports whichever count drove the retirement, so the record keeps its ONE
    shape and the other counter rides along inside `row`.

    The graveyard entry lands FIRST, then the row is written into the consumed ledger by
    the same locked rotation that rewrites the queue. The ledger write is what makes
    retirement terminal — the observation append path reads it to dedup — so a crash
    between the two costs one duplicate advisory record and nothing else.

    `timeout_seconds` bounds BOTH append-lock windows below and is required of any caller
    that holds the repo lock — i.e. the corpus drain, which passes its configured wait.
    That lock serialises every channel, so an unbounded wait here would let one channel's
    wedged appender stall all four indefinitely. Expiry raises `TimeoutError`: the batch
    is not bumped, and the tick surfaces as stuck. Left unset by the pitfalls leg, which
    retires outside the repo lock and so has nothing to starve."""
    ids = {str(i) for i in batch_ids}
    key = channel.id_key
    bumped: dict[str, int] = {}
    survivors: list[dict] = []
    retired: list[dict] = []

    with persist.queue_lock(channel.append_lock, timeout_seconds=timeout_seconds):
        for row in read_jsonl_rows(channel.file):
            rid = row.get(key)
            if not isinstance(rid, str) or rid not in ids:
                continue
            attempts = int(row.get(counter_key) or 0) + 1
            bumped[rid] = attempts
            rec = dict(row)
            rec[counter_key] = attempts
            (retired if attempts >= max_attempts else survivors).append(rec)
        if retired:
            append_jsonl(  # lint-unguarded-tree-write: ok — learning_queue sidecar, host-side, outside every box mount
                graveyard_file(channel),
                [
                    {
                        key: rec[key],
                        # Whichever count reached ITS ceiling, under the slot every channel's
                        # reader already knows. A row bumped on the other counter too keeps
                        # that one inside `row`, where it is provenance rather than the verdict.
                        "attempts": rec[counter_key],
                        "deadletter_reason": reason,
                        # Nested rather than spread, so a graveyard entry has ONE shape on
                        # every channel and is readable without knowing its queue.
                        "row": {k: v for k, v in rec.items() if k != counter_key},
                    }
                    for rec in retired
                ],
            )

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
    return RetireOutcome(bumped=bumped, retired=tuple(rec[key] for rec in retired))


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
    log = make_logger(cfg.log_prefix)
    channel = cfg.channel

    drain_fh = None
    if channel.drain_lock is not None:
        drain_fh = author_shared.acquire_flock(channel.drain_lock)
        if drain_fh is None:
            log("drain lock held by another process — skipping this tick")
            return 0
    try:
        try:
            repo_fh = author_shared.acquire_repo_lock(
                cfg.repo_lock_file, timeout_seconds=cfg.repo_lock_wait_seconds
            )
        except TimeoutError as e:
            log(f"repo lock unavailable: {e}; queue intact")
            return 0
        try:
            try:
                author_shared.assert_clean_corpus_dir(
                    cfg.repo_root, cfg.corpus_dir, cfg.corpus_dir_rel
                )
            except AuthorError as e:
                log(f"FATAL: {e}")
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
        log("append lock held by an appender past the deadline — skipping this tick")
        return 0
    try:
        batch, unreadable = read_jsonl_rows_report(channel.file)
    finally:
        author_shared.release_flock(append_fh)
    if not batch and not unreadable:
        log("queue empty — nothing to author")
        return 0
    if unreadable:
        # NOT an early return, and that is the whole point. The wake gate counts an
        # unreadable line as work (`core/drains._pending_queue_counts`), so returning here
        # left it counted and uncleared: the gate re-fired on the same junk every tick,
        # fetching, minting a worktree and starting a box to read the same unparseable
        # bytes, forever. A line the tolerant reader could not turn into a row cannot be
        # graveyarded — there is no row to write — but every rotation rewrites this file from
        # the rows it CAN read, so falling through is what clears it. Said out loud, because
        # that rewrite is otherwise a silent deletion.
        # THE NEXT ROTATION, not the closing one: `persist._rewrite_queue` re-reads through
        # the same tolerant reader whoever calls it, so `_retire_unkeyable`'s own rotation —
        # which runs before the gate — drops these lines too, as does `retire`'s on the
        # retiring leg. Naming one of the three would send an operator looking for bytes a
        # different one had already taken.
        # "WILL drop", not "drops": several exits sit between here and every rotation — a
        # fault in the retirement, in the gate, or in the authoring region — and on each of
        # them the lines are still there next tick, printing this same line again. This is
        # the only trace the deletion leaves, so it must not claim to be one.
        log(
            f"{unreadable} unreadable line(s) in the queue — the next rotation this tick "
            "reaches, if it reaches one, will drop them"
        )

    keyed: list[dict] = []
    unkeyable: list[dict] = []
    for row in batch:
        (keyed if _row_id(row, key) else unkeyable).append(row)
    # ONE stuck-recording guard around the whole tick body, with `stuck_rows` naming the rows
    # the phase in flight is stuck on. It was three copies of one handler, and the copy the
    # unkeyable retirement never got is #881/O4: that retirement takes the append lock again
    # for its own rotation — after `_tick` released it ten lines up — so an ordinary appender
    # arriving in that window makes the rotation raise `TimeoutError`, a class deliberately
    # outside `RETIRE_SET` (a busy lock is not the batch's fault). Nothing retired, the row
    # stayed queued, and the fault escaped `run_batch` leaving no stuck record: the channel
    # wedged in silence, against this module's own contract that a non-`RETIRE_SET` fault is
    # always visible somewhere. A guard the next phase added here has to REMEMBER is the
    # shape that produced that hole, so there is no longer a per-phase guard to forget — and
    # the two lines between the gate and the authoring region, which no copy covered, are
    # inside it now too.
    stuck_rows = unkeyable
    try:
        _retire_unkeyable(channel, unkeyable, log, cfg.repo_lock_wait_seconds)
        # The gate reads per-row fields the queue's own key check cannot vouch for
        # (`run_id`, `direction`), so it is a live source of non-retiring faults.
        stuck_rows = keyed
        held, consumed_pre, to_author = cfg.gate(keyed, cfg)
        batch_id = uuid.uuid4().hex[:12]
        log(
            f"batch={batch_id} total={len(batch)} to_author={len(to_author)} "
            f"held={len(held)} pre_consumed={len(consumed_pre)} unkeyable={len(unkeyable)}"
        )
        # `to_author` NAMES THE AUTHORING REGION, but this same call also runs the closing
        # rotation, which writes the gate's held rows back — and on a tick the gate held or
        # consumed whole, `to_author` is `[]`. An empty list is a foldable dedup key in
        # `_record_stuck`, so a rotation that expires against a busy appender there would
        # record `row_ids: []`: none of the rows actually stuck named, and every such tick
        # folding into one rising count whatever queue it was about. `keyed` is what is still
        # in flight when nothing was admitted — the rows the rotation was writing — so the
        # record names them instead of nothing.
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
            # The recorder must never REPLACE the fault it records. It appends to a file, so
            # a full disk or an unwritable queue dir would otherwise hand the caller the
            # WRITER's `OSError` — the real fault surviving only as `__context__`, and the
            # `raise` below never reached. `Exception`, not `BaseException`, so an interrupt
            # arriving mid-record still leaves at once.
            #
            # LOGGED, NOT SWALLOWED. A silent suppression voids this module's own contract
            # that a non-`RETIRE_SET` fault is "always visible somewhere": the record is the
            # only external trace of a stuck row, so a channel that cannot write one — an
            # unwritable queue dir, or a defect inside the recorder itself — must still say
            # so, or it wedges in exactly the silence O4 was filed against.
            try:
                _record_stuck(channel, e, stuck_rows)
            except Exception as unrecorded:  # noqa: BLE001 — see above; never replaces `e`
                log(f"stuck record NOT written: {unrecorded!r} (the fault itself follows)")
        raise


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
    commit_sha: str | None = None
    committed: list[dict] = []
    bucket_held: dict[str, list[dict]] = {}
    bucket_consumed: dict[str, list[dict]] = {}

    if to_author:
        # All three taken BEFORE the agent runs, so a fault after it can put the worktree
        # back the way the agent found it. Otherwise the agent's edits stay uncommitted,
        # the next tick's cleanliness gate aborts before reaching any queue, and the
        # channel wedges instead of retrying.
        snapshot = _snapshot_corpus(cfg.corpus_dir)
        baseline_stray = _git_read(
            "worktree status", author_shared.changes_outside, cfg.repo_root, cfg.corpus_dir_rel
        )
        head_before = _git_read("HEAD", author_shared.git_head_sha, cfg.repo_root)
        try:
            result = cfg.invoke_agent(to_author, batch_id, cfg)
            _git_read(
                "agent state", author_shared.verify_agent_state,
                cfg.repo_root, result, cfg.corpus_dir, cfg.corpus_dir_rel,
                cfg.noun, baseline_stray,
            )
            author_shared.validate_agent_result_partition(
                result, to_author, id_key=key,
                buckets=tuple(b.name for b in cfg.buckets), noun=cfg.noun,
            )
            committed, bucket_held, bucket_consumed = _project(result, all_rows, cfg)
            if committed:
                _git_read("corpus attribution", _assert_corpus_attributable, cfg, committed)
                commit_sha = cfg.commit_fn(
                    author_shared.commit_message(result, cfg.noun), cfg
                )
        except BaseException as e:
            # Cleanup runs for EVERY fault, member or not: a stuck tick leaves the same
            # edits behind a retiring one does, and leaving them wedges the channel. The
            # membership test below still decides disposition.
            _undo_agent_edits(cfg, snapshot, baseline_stray, head_before)
            if not isinstance(e, RETIRE_SET):
                raise
            log(f"FATAL: {e}")
            retire(
                channel=channel,
                batch_ids=[row[key] for row in to_author],
                reason=str(e),
                max_attempts=cfg.max_attempts,
                timeout_seconds=cfg.repo_lock_wait_seconds,
            )
            return 2

    held_committed, rotated_committed = author_shared.partition_committed(
        committed, hold_committed=hold_committed
    )
    persist.rotate_queue_locked(
        pending_file=channel.file,
        consumed_file=channel.consumed,
        lock_file=channel.append_lock,
        id_key=key,
        held=[*held, *_flatten(cfg.buckets, bucket_held), *held_committed],
        consumed=[
            *consumed_pre,
            *rotated_committed,
            *_flatten(cfg.buckets, bucket_consumed),
        ],
        commit_sha=commit_sha,
        timeout_seconds=cfg.repo_lock_wait_seconds,
    )
    if cfg.post_rotate is not None:
        cfg.post_rotate(
            DrainOutcome(
                batch_id=batch_id, commit_sha=commit_sha, committed=committed,
                held=bucket_held, consumed=bucket_consumed, gate_held=held,
            ),
            cfg,
        )
    log(
        f"done batch={batch_id} committed={len(committed)} held={len(held)} "
        f"pre_consumed={len(consumed_pre)} commit_sha={commit_sha}"
    )
    return 0


def _flatten(buckets: tuple[BucketSpec, ...], rows: dict[str, list[dict]]) -> list[dict]:
    return [row for bucket in buckets for row in rows.get(bucket.name, [])]


def _project(
    result: dict, all_rows: dict[str, dict], cfg: CorpusAuthorConfig
) -> tuple[list[dict], dict[str, list[dict]], dict[str, list[dict]]]:
    key = cfg.channel.id_key
    committed: list[dict] = []
    bucket_held: dict[str, list[dict]] = {}
    bucket_consumed: dict[str, list[dict]] = {}
    for bucket in cfg.buckets:
        if bucket.disposition == "committed":
            for rid in author_shared.result_list(result, bucket.name):
                # The partition validator vouches for entry SHAPE by bucket NAME, this
                # projection by DISPOSITION. Name a committed-disposition bucket anything
                # but "committed" and the two stop agreeing — an unhashable dict would
                # reach `all_rows.get` as a TypeError instead of an AuthorError.
                if not isinstance(rid, str):
                    raise AuthorError(
                        f"AUTHOR_RESULT {bucket.name} entries must be {key} strings"
                    )
                src = all_rows.get(rid)
                if src is None:
                    raise AuthorError(f"author committed unknown {key}={rid!r}")
                committed.append({**src, "consumed_category": "consumed_committed"})
            continue
        rows: list[dict] = []
        for entry in author_shared.result_list(result, bucket.name):
            rid = entry.get(key)
            src = all_rows.get(rid)
            if src is None:
                raise AuthorError(f"author {bucket.name} unknown {key}={rid!r}")
            rec = dict(src)
            if bucket.disposition == "consumed":
                rec["consumed_category"] = bucket.name
            if bucket.reason_field is not None:
                rec[bucket.reason_field] = bucket.formatter(entry.get("reason", ""))
            rows.append(rec)
        target = bucket_consumed if bucket.disposition == "consumed" else bucket_held
        target[bucket.name] = rows
    return committed, bucket_held, bucket_consumed


def _assert_corpus_attributable(cfg: CorpusAuthorConfig, committed: list[dict]) -> None:
    """Every file this tick CHANGED in the corpus must be vouched for by a COMMITTED row.

    Vouched for means one of two things, and `_vouched_for` owns which: the file cites a
    committed id, or it was already in history and claims exactly the provenance it claimed
    there — the second being what keeps an ordinary supersede flip out of this gate's way.

    The other post-flight cross-check, `verify_agent_state`, is AGGREGATE (committed
    non-empty ⇔ corpus dirty), one bit for a whole batch, so it misses the MIXED case: with
    at least one lesson legitimately committed — the normal shape — a lesson the curator
    wrote and then itself reported as `held_forward_bad` rode into the pathspec-wide commit
    on its passing batch-mates, even though the forward check said it would flip a
    correctly-resolved case.

    Attribution is per FILE and by the channel's OWN provenance key — `source_finding_ids`
    on the lessons corpus, `source_observation_ids` on the observation corpora, the same
    field the pre-author idempotency gate reads back off the corpus. Keying on
    `channel.id_key` rather than accepting either spelling is what keeps a committed file
    visible to that gate: a lessons file citing observation ids would be attributable here
    and invisible there, i.e. authored again on every following tick.

    Raising `AuthorError` routes through `_undo_agent_edits` -> `_restore_corpus`: the
    unvouched-for file is deleted, the batch is bumped and stays queued, the tick returns 2."""
    key = cfg.channel.id_key
    field = provenance_field(key)
    ids = {row[key] for row in committed if isinstance(row.get(key), str)}
    unattributed = [
        rel for xy, rel in _changed_corpus_records(cfg)
        if not _vouched_for(cfg.repo_root, rel, xy, field, ids)
    ]
    if unattributed:
        raise AuthorError(
            f"author left {len(unattributed)} file(s) in {cfg.corpus_dir_rel} that no "
            f"committed row vouches for: {unattributed}; each must either cite a "
            f"{field} entry from this batch's committed set ({sorted(ids)}) or leave its "
            f"{field} exactly as HEAD has it — refusing to commit (a pathspec-wide commit "
            "would sweep them in)"
        )


def _changed_corpus_records(cfg: CorpusAuthorConfig) -> list[tuple[str, str]]:
    """`(status, repo-relative path)` for the corpus files this tick added or modified.

    The corpus is CLEAN at the top of every tick (`assert_clean_corpus_dir` refuses to
    author otherwise), so what git reports dirty under it is exactly what this agent call
    wrote. Deletions are excluded: there is no file left to attribute, and a lesson the
    curator retired is vouched for by the same commit that removes it. The STATUS rides
    along because `_vouched_for` needs to know whether the agent created the file or edited
    one that was already in history."""
    return sorted(
        (
            (xy, path)
            for xy, path in _git.git_status(cfg.repo_root, pathspec=cfg.corpus_dir)
            if "D" not in xy
        ),
        key=lambda rec: rec[1],
    )


def _vouched_for(
    repo_root: Path, rel: str, xy: str, field: str, ids: set[str]
) -> bool:
    """Does this changed corpus file need a voucher from this batch, and does it have one?

    Citing a committed id is the voucher, and for a file the agent CREATED (`??`) it is the
    only one.

    An already-committed file gets a second way to pass, and without it this gate faults on
    ordinary curation. The retired observation curators retired a contradicted lesson by
    flipping the OLD file to `status: stale, superseded_by: {new}` while the replacement was
    the file that cited the new observation (their prompts' "Supersede" rule), and the lessons
    curator reverts a forward-BAD fold by
    re-editing the target back to its pre-batch body. Neither edit claims new provenance —
    the file cites exactly what it cited at HEAD — so it vouches for nothing and needs no
    voucher. Requiring one reverts the whole tick, deletes the legitimately-authored
    replacement with it, and bumps the batch toward the graveyard ceiling."""
    cited = _cited_ids(repo_root / rel, field)
    if cited & ids:
        return True
    return xy != "??" and cited == _cited_ids_at_head(repo_root, rel, field)


def _cited_ids_at_head(repo_root: Path, rel: str, field: str) -> set[str]:
    """What the same corpus file cited BEFORE this tick — empty for a path HEAD has no blob
    for, which is why only a file git already tracks may lean on this comparison."""
    return _cited_ids_in(
        _git.git(["show", f"HEAD:{rel}"], cwd=repo_root, check=False), field
    )


def _cited_ids(path: Path, field: str) -> set[str]:
    """The queue-row ids one corpus file claims as its source. A file whose frontmatter
    cannot be read cites nothing — malformed is unattributable, which is the disposition it
    should have had anyway."""
    try:
        text = read_text_utf8(path)
    except TEXT_READ_ERRORS:
        return set()
    return _cited_ids_in(text, field)


def _cited_ids_in(text: str, field: str) -> set[str]:
    try:
        fm, _raw, _body = split_frontmatter(text)
    except FrontmatterError:
        return set()
    cited = fm.get(field)
    if not isinstance(cited, list):
        return set()
    return {c for c in cited if isinstance(c, str)}


def _retire_unkeyable(
    channel: QueueChannel, rows: list[dict], log, timeout_seconds: int
) -> None:
    """A row carrying no value under its channel's id field is bad data, not a broken
    system: it retires immediately as a per-item failure and its well-formed batch-mates
    are authored on the same tick.

    IMMEDIATELY means on its own rotation, not on the tick's closing one. A keyless row
    cannot be matched by id, so the closing rotation would remove it by putting `None` in
    the processed set — swallowing any keyless row appended while the agent ran, with no
    graveyard entry — and that rotation never runs on a retiring or stuck tick, leaving the
    row queued to be graveyarded again every following tick.

    The record is FLAT — the row's whole content spread at the top level, not nested under
    `row` the way `retire` writes it. There is no id to reference such a row by, so the
    content IS the record; a consumer of this file must branch on the presence of `row`
    rather than assume one shape."""
    if not rows:
        return
    reason = f"row carries no value under {channel.id_key!r}"
    log(f"{len(rows)} unkeyable row(s) retired: {reason}")
    append_jsonl(  # lint-unguarded-tree-write: ok — learning_queue sidecar, host-side, outside every box mount
        graveyard_file(channel),
        [{**row, "attempts": int(row.get("attempts") or 0) + 1,
          "deadletter_reason": reason} for row in rows],
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

    THE ONE PREDICATE. `_tick` splits the batch on it and `_stuck_row_ids` names rows by it,
    and the two disagreeing is not cosmetic: a bare `if rid:` says yes to a truthy non-string
    id, so a row filed as unkeyable on one side is named as though it had a real id on the
    other — the fold collision `_stuck_row_ids`' fingerprint exists to prevent, by a route
    no test takes."""
    rid = row.get(key)
    return rid if isinstance(rid, str) and rid else None


def _stuck_row_ids(channel: QueueChannel, rows: list[dict]) -> list[str]:
    """@owns row_ids — how a stuck record names the rows a tick is stuck on.

    A row's own id where it has one. A row that has NONE is named by a fingerprint of its
    content instead, because the alternative is naming nothing: the unkeyable leg (#881/O4)
    hands this function rows whose whole defect is a missing id, and dropping them left the
    record with an empty list — which reads to `_record_stuck`'s dedup as "the same rows as
    last time" for every keyless tick, folding two unrelated poison rows into one count that
    looks like one problem getting worse, and leaving the operator no way to tell WHICH rows
    the channel is stuck on.

    Canonical JSON so the same row fingerprints the same across ticks and processes, and
    prefixed so a fingerprint can never be mistaken for a real id."""
    named: list[str] = []
    for row in rows:
        # `_row_id`, the SAME function `_tick` split on, not a second spelling of it. A
        # second spelling said yes to a truthy non-string id — a row `_tick` had already
        # filed as unkeyable — and named it `str(rid)`: unprefixed, indistinguishable from a
        # real id, and identical for two different rows that happen to share it, which is the
        # fold collision the fingerprint below exists to prevent.
        rid = _row_id(row, channel.id_key)
        if rid is not None:
            named.append(rid)
            continue
        digest = hashlib.sha256(
            json.dumps(row, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()
        named.append(f"unkeyed:{digest[:16]}")
    return sorted(named)


def _record_stuck(channel: QueueChannel, exc: BaseException, rows: list[dict]) -> None:
    """The operator signal for a stuck tick. The count is per TICK, not per row — a
    non-retiring row must stay byte-identical, so the counter cannot live on it the way
    `attempts` does, which is why the last record is read back before appending."""
    fault_class = type(exc).__name__
    ids = _stuck_row_ids(channel, rows)
    path = stuck_report_file(channel)
    previous = read_jsonl_rows(path)
    consecutive = 1
    # AN EMPTY LIST IS A ROW SET, not a missing one. `_stuck_row_ids` names every row it is
    # handed — a keyless one by its fingerprint — so `ids == []` now means one thing only:
    # the phase that faulted had NO rows in flight. That is the authoring leg on a tick whose
    # gate held or consumed the whole batch, and two such ticks failing with one fault class
    # ARE the same problem recurring, which is what `consecutive_ticks` exists to say.
    # Refusing to fold there pinned the count at 1 forever for exactly the queue this issue
    # is about — a permanently gate-held one — so an operator paging on "stuck for N ticks"
    # saw N one-off faults and never fired. The collapse that guard was reaching for is the
    # one the fingerprint above already closed: two DIFFERENT poison rows reading as the same
    # rows, which cannot happen once every row is named.
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
        }],
    )


def _snapshot_corpus(corpus_dir: Path) -> dict[str, bytes] | None:
    if not corpus_dir.is_dir():
        return None
    return {
        str(p.relative_to(corpus_dir)): p.read_bytes()
        for p in sorted(corpus_dir.rglob("*"))
        if p.is_file()
    }


def _undo_agent_edits(
    cfg: CorpusAuthorConfig,
    snapshot: dict[str, bytes] | None,
    baseline_stray: list[str],
    head_before: str,
) -> None:
    """Put the worktree back the way the agent found it after a faulted tick.

    THE CORPUS HALF IS SKIPPED ONCE THE COMMIT HAS LANDED. `git_commit` reads HEAD after
    committing, so a git failure at that last step arrives with the lessons already in
    history — and an unconditional restore would delete exactly those files, leave the
    next tick staring at a corpus full of deletions, and wedge the channel. When git cannot
    say whether HEAD moved, nothing is deleted: the only thing this test gates is a
    deletion, so it fails toward keeping files.

    THE STRAY HALF IS UNCONDITIONAL, because the commit is pathspec-limited to the corpus
    and can never have captured a file outside it. Without it a file the agent wrote
    outside the corpus survives the fault and is folded into the NEXT tick's baseline, so
    the out-of-scope-write guard treats it as pre-existing dirt — fires once, then stays
    disarmed for the life of the worktree."""
    if not _commit_landed(cfg.repo_root, head_before):
        _restore_corpus(cfg.repo_root, cfg.corpus_dir, snapshot)
    _revert_strays(cfg.repo_root, cfg.corpus_dir_rel, baseline_stray)


def _commit_landed(repo_root: Path, head_before: str) -> bool:
    """Did HEAD move? Answers TRUE when git cannot say — see `_undo_agent_edits`."""
    try:
        return author_shared.git_head_sha(repo_root) != head_before
    except GitError:
        return True


def _revert_strays(repo_root: Path, corpus_dir_rel: str, baseline_stray: list[str]) -> None:
    """Undo what the agent wrote OUTSIDE the corpus during this tick.

    Scoped to the difference against the pre-agent status, so pre-existing dirt the drain
    did not cause is left exactly where it was. Best-effort by design: this runs while a
    fault is already propagating, and a second failure here would replace the diagnosis
    the caller is carrying with a worse one."""
    try:
        strays = sorted(
            set(author_shared.changes_outside(repo_root, corpus_dir_rel)) - set(baseline_stray)
        )
    except GitError:
        return
    for rel in strays:
        _git.git(["checkout", "-q", "--", rel], cwd=repo_root, check=False)
        target = repo_root / rel
        tracked = _git.git_ok(["ls-files", "--error-unmatch", "--", rel], cwd=repo_root)
        if not tracked and target.is_file():
            target.unlink()


def _restore_corpus(
    repo_root: Path, corpus_dir: Path, snapshot: dict[str, bytes] | None
) -> None:
    """Put the corpus back to its pre-agent contents.

    The content restore is filesystem-only on purpose: the failure this exists for is a
    git one, and a git-based restore would need the very index lock that failed. The
    unstage is best-effort for the other shape of commit failure — a rejected commit,
    where the add DID land — and is allowed to fail silently, since the case it cannot
    reach is the case where nothing was staged."""
    if snapshot is None:
        return
    _git.git(["reset", "-q", "--", str(corpus_dir)], cwd=repo_root, check=False)
    for p in sorted(corpus_dir.rglob("*")):
        if p.is_file() and str(p.relative_to(corpus_dir)) not in snapshot:
            p.unlink()
    for rel, blob in snapshot.items():
        target = corpus_dir / rel
        if not target.is_file() or target.read_bytes() != blob:
            guarded_mkdir(target.parent, base=corpus_dir)
            write_guarded(target, blob)
