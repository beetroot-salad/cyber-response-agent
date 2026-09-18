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
import itertools
import json
import uuid
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, TypeVar

from pydantic_ai.exceptions import ModelRetry

from defender import _git
from defender._clock import now_iso
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
    make_logger,
    provenance_field,
)

AuthorError = author_shared.AuthorError

#: #773 M6's ledger file name, under the host-side pending dir (S5/G6).
GAP_LEDGER_NAME = "findings.forward_bad.jsonl"
#: The reasoning prefix a doubly-failed pair's recorded BAD carries (M3.3, §7 FK-10).
ERROR_PREFIX = "forward_check_error: "
#: M6's commit-message block header — advisory prose beside the ledger, the authoritative
#: record (§7 FK-15).
TERMINAL_BLOCK_HEADER = "Forward-check terminal:"
#: §7 FK-17: a deferral that reaches the ceiling is greppable apart from a fault's.
DEFERRED_CEILING_REASON = "deferred_ceiling"
#: git status codes for an UNMERGED path (§7 FK-33) — refused loudly before vouching, since
#: the drain now reads the whole corpus tree and must have an opinion about one not in a
#: normal state.
_UNMERGED_XY = frozenset({"DD", "AU", "UD", "UA", "DU", "AA", "UU"})

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


@dataclass(frozen=True)
class PairVerdict:
    """#773's Data model: one (changed corpus file, this-batch cited finding) pair's
    outcome, minted by the drain and by nothing else (O5).

    `rel_path` per §7 FK-14 — carried on every entry, not just the record's own top-level
    field, so a finding refused on two differently-named files across the two passes is
    still fully recoverable from its one gap-ledger record. `lesson_text` rides along so
    M4's repair prompt can be rebuilt from the pair alone, after the file itself has been
    restored away."""

    rel_path: str
    finding_id: str
    source_id: str
    verdict: str  # GOOD | BAD | EXEMPT
    reasoning: str
    lesson_text: str
    pass_no: int


def _revert_non_md_strays(cfg: CorpusAuthorConfig) -> None:
    """§7 FK-5: a non-`.md` file left under the corpus is reverted as a stray BEFORE
    vouching, in both passes — vouching only ever sees `*.md` under the corpus. A non-lesson
    file has no citations by construction, so leaving it to the vouching gate converts an
    ordinary cleanup case into a tick-wide fault."""
    for xy, rel in _git.git_status(cfg.repo_root, pathspec=cfg.corpus_dir, no_renames=True):
        if rel.endswith(".md") or "D" in xy:
            continue
        _git.git(["checkout", "-q", "--", rel], cwd=cfg.repo_root, check=False)
        target = cfg.repo_root / rel
        tracked = _git.git_ok(["ls-files", "--error-unmatch", "--", rel], cwd=cfg.repo_root)
        if not tracked and target.is_file():
            target.unlink()


def _assert_no_unmerged(cfg: CorpusAuthorConfig) -> None:
    """§7 FK-33: an UNMERGED status code under the corpus refuses the tick loudly, before
    vouching — the same instinct as FK-4: the drain now reads the whole corpus tree and must
    have an opinion about a tree not in a normal state, rather than handing conflict markers
    to the verifier as ordinary text."""
    for xy, rel in _git.git_status(cfg.repo_root, pathspec=cfg.corpus_dir, no_renames=True):
        if xy in _UNMERGED_XY:
            raise AuthorError(
                f"{cfg.corpus_dir_rel} has an unmerged file ({xy.strip()} {rel}) — "
                "refusing to author"
            )


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
    #: @owns held["forward_bad_terminal"], held["deferred"] — the two #773 keys this dict
    #: carries beyond the AUTHOR_RESULT bucket names; `_author_and_rotate` is the ONE site
    #: that assembles this dict and is where both are produced (terminal_rows/deferred_held
    #: + deferred_consumed respectively).
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
    is not bumped, and the tick surfaces as stuck. The pitfalls leg passes the same
    configured wait through `PitfallsDisposition.apply` (#952): it retires from the
    lead-author drain tick, which holds that tick's locks while it waits, and a wedged
    appender must not hold it open indefinitely either; by hand it passes none."""
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
                # §7 FK-4: a NAMED, REPORTED disposition — an already-dirty corpus at tick
                # start is loud, not a silent skip an operator has no way to see.
                try:
                    _record_stuck(channel, e, [])
                except Exception as unrecorded:  # noqa: BLE001 — never replaces `e`
                    log(f"stuck record NOT written: {unrecorded!r} (the fault itself follows)")
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


def _verifier_key_preflight(cfg: CorpusAuthorConfig) -> None:
    # O10: the verifier-key preflight, moved OUT of the curator stage and ahead of the
    # first spawn — a keyless host must not pay for a spawn it cannot check. Gated on
    # `forward_check is not None` (§7 FK-27): a channel that never wanted a check (the
    # questioner's) must never meet this requirement. Runs unconditionally (not gated on
    # provider match) because the curator spawn this key would otherwise ride behind is
    # `cfg.invoke_agent`, an injection seam the drain does not control the internals of —
    # sourcing it here is the only place the property "checked before the first spawn"
    # is actually observable.
    if cfg.forward_check is not None and cfg.forward_check.prompt_path is not None:
        cfg.source_key(
            config.verifier_model(), label=f"verify:{cfg.forward_check.error_prefix}"
        )


@dataclass(frozen=True)
class _PreState:
    """The worktree's shape just before the agent runs, so a fault after it can put the
    worktree back the way the agent found it. Otherwise the agent's edits stay
    uncommitted, the next tick's cleanliness gate aborts before reaching any queue, and
    the channel wedges instead of retrying."""

    snapshot: dict[str, bytes] | None
    baseline_stray: list[str]
    head_before: str


def _capture_pre_state(cfg: CorpusAuthorConfig) -> _PreState:
    return _PreState(
        snapshot=_snapshot_corpus(cfg.corpus_dir),
        baseline_stray=_git_read(
            "worktree status", author_shared.changes_outside, cfg.repo_root, cfg.corpus_dir_rel
        ),
        head_before=_git_read("HEAD", author_shared.git_head_sha, cfg.repo_root),
    )


def _run_author_agent(
    cfg: CorpusAuthorConfig,
    to_author: list[dict],
    batch_id: str,
    baseline_stray: list[str],
    all_rows: dict[str, dict],
) -> tuple[dict, dict[str, list[dict]], dict[str, list[dict]], set[str], set[str], itertools.count[int]]:
    key = cfg.channel.id_key
    result = cfg.invoke_agent(to_author, batch_id, cfg)
    # §7 FK-5: the stray revert is AUTHORITATIVE and runs FIRST, ahead of even
    # `verify_agent_state`'s own stray check — a non-`.md` file under the corpus has
    # no citations by construction, so leaving it for that older, coarser check
    # turns an ordinary cleanup into a tick-wide fault (the O6 problem by a second
    # door). Once it is gone, `verify_agent_state` sees a tree with nothing left to
    # object to on that account.
    _git_read("stray revert", _revert_non_md_strays, cfg)
    _git_read(
        "agent state", author_shared.verify_agent_state,
        cfg.repo_root, result, cfg.corpus_dir, cfg.corpus_dir_rel,
        cfg.noun, baseline_stray,
    )
    author_shared.validate_agent_result_partition(
        result, to_author, id_key=key,
        buckets=tuple(b.name for b in cfg.buckets), noun=cfg.noun,
    )
    _, bucket_held, bucket_consumed = _project(result, all_rows, cfg)
    reported_committed_ids = set(author_shared.result_list(result, "committed"))

    # M3.2 — unconditional vouching over EVERY id this tick read, whatever bucket
    # the curator reported it under (O5).
    all_batch_ids = {row[key] for row in to_author}
    counter = itertools.count()
    _git_read("unmerged check", _assert_no_unmerged, cfg)
    _git_read("corpus attribution", _assert_corpus_attributable, cfg, all_batch_ids)

    return result, bucket_held, bucket_consumed, reported_committed_ids, all_batch_ids, counter


def _merge_pass(
    pass_result: dict[str, list[PairVerdict]],
    final: dict[tuple[str, str], PairVerdict],
    history: dict[str, list[PairVerdict]],
    by_file_history: dict[str, list[PairVerdict]],
) -> None:
    for rel, pvs in pass_result.items():
        for pv in pvs:
            history.setdefault(pv.finding_id, []).append(pv)
            by_file_history.setdefault(rel, []).append(pv)
            final[(pv.finding_id, rel)] = pv


def _run_repair_pass(  # noqa: PLR0913 — one repair round's whole state
    cfg: CorpusAuthorConfig,
    bad_pairs: list[PairVerdict],
    pass1: dict[str, list[PairVerdict]],
    batch_id: str,
    snapshot: dict[str, bytes] | None,
    baseline_stray: list[str],
    deletion_paths: list[str],
    all_rows: dict[str, dict],
    all_batch_ids: set[str],
    counter: itertools.count[int],
) -> dict[str, list[PairVerdict]] | None:
    if cfg.repair_prompt is not None and not cfg.repair_prompt.is_file():
        raise FatalConfigError(
            f"repair prompt {cfg.repair_prompt} is not a readable file"
        )
    repair_snapshot = _snapshot_corpus(cfg.corpus_dir)
    cfg.invoke_repair(bad_pairs, batch_id, cfg)
    _git_read("agent state after repair", _assert_no_new_stray, cfg, baseline_stray)
    _git_read("stray revert (pass 2)", _revert_non_md_strays, cfg)
    _git_read("unmerged check (pass 2)", _assert_no_unmerged, cfg)
    new_deletions = sorted(set(_deleted_corpus_records(cfg)) - set(deletion_paths))
    if new_deletions:
        _revert_repair_deletions(cfg, snapshot, new_deletions)
    changed2 = [rel for _xy, rel in _changed_corpus_records(cfg)]
    touched2 = sorted(
        rel for rel in changed2
        if _current_bytes(cfg, rel) != (repair_snapshot or {}).get(
            _corpus_relative(cfg, rel)
        )
    )
    if not touched2:
        return None
    fallback = {rel: {pv.finding_id for pv in pass1.get(rel, [])} for rel in touched2}
    return _run_verdict_pass(
        cfg, touched2, all_rows, all_batch_ids, counter, 2, fallback_citers=fallback,
    )


def _run_verdict_pipeline(  # noqa: PLR0913 — one tick's verdict-pipeline state
    cfg: CorpusAuthorConfig,
    changed1: list[str],
    deletion_paths: list[str],
    all_rows: dict[str, dict],
    all_batch_ids: set[str],
    counter: itertools.count[int],
    snapshot: dict[str, bytes] | None,
    baseline_stray: list[str],
    batch_id: str,
) -> tuple[
    dict[tuple[str, str], PairVerdict],
    dict[str, list[PairVerdict]],
    dict[str, list[PairVerdict]],
]:
    final: dict[tuple[str, str], PairVerdict] = {}
    history: dict[str, list[PairVerdict]] = {}
    #: EVERY `PairVerdict` ever minted for a file, across both passes and every
    #: finding that cites it — a terminal finding's gap record carries this, not
    #: just its own pairs, so a refusal caused by a SIBLING finding sharing the
    #: same file (a family-exempt pair beside a BAD one, say) is not lost (§7 FK-13).
    by_file_history: dict[str, list[PairVerdict]] = {}
    if cfg.forward_check is None:
        return final, history, by_file_history

    pass1_texts: dict[str, str] = {}
    pass1 = _run_verdict_pass(
        cfg, changed1, all_rows, all_batch_ids, counter, 1, texts_out=pass1_texts,
    )
    # O1: "the bytes a verdict judged are the bytes that land in HEAD." A file
    # that moved AGAIN between being read for this pass and the pass completing
    # (a concurrent editor, not M4's repair spawn) is re-judged on its current
    # bytes before anything downstream trusts the first verdict.
    drifted = sorted(
        rel for rel in pass1_texts
        if _read_or_empty(cfg.repo_root / rel) != pass1_texts[rel]
    )
    if drifted:
        redo = _run_verdict_pass(cfg, drifted, all_rows, all_batch_ids, counter, 1)
        pass1.update(redo)

    _merge_pass(pass1, final, history, by_file_history)

    bad_pairs = [pv for pvs in pass1.values() for pv in pvs if pv.verdict == "BAD"]
    if bad_pairs:
        pass2 = _run_repair_pass(
            cfg, bad_pairs, pass1, batch_id, snapshot, baseline_stray, deletion_paths,
            all_rows, all_batch_ids, counter,
        )
        if pass2 is not None:
            _merge_pass(pass2, final, history, by_file_history)

    return final, history, by_file_history


def _compute_approval(
    cfg: CorpusAuthorConfig,
    changed1: list[str],
    final: dict[tuple[str, str], PairVerdict],
    all_batch_ids: set[str],
) -> tuple[set[str], set[str], dict[str, list[str]]]:
    by_file: dict[str, list[PairVerdict]] = {}
    for pv in final.values():
        by_file.setdefault(pv.rel_path, []).append(pv)

    field = provenance_field(cfg.channel.id_key)
    citing_map: dict[str, list[str]] = {}
    if cfg.forward_check is None:
        approved_files = set(changed1)
        changed_final = set(changed1)
        for rel in changed_final:
            cited = _cited_ids(cfg.repo_root / rel, field) & all_batch_ids
            for fid in cited:
                citing_map.setdefault(fid, []).append(rel)
    else:
        approved_files = {
            rel for rel, pvs in by_file.items()
            if all(pv.verdict in ("GOOD", "EXEMPT") for pv in pvs)
        }
        changed_final = set(by_file)
        # Built from the PAIRS the drain actually minted (`final`), not by
        # re-reading citations off disk: a repair rewrite that dropped a file's
        # citations (§7 FK-6) still owes its terminal finding a record, and a fresh
        # disk read would find nothing to attribute it to any more.
        for fid, rel in final:
            citing_map.setdefault(fid, []).append(rel)
    return approved_files, changed_final, citing_map


def _classify_reported(  # noqa: PLR0913 — one classification pass's whole state
    cfg: CorpusAuthorConfig,
    reported_committed_ids: set[str],
    citing_map: dict[str, list[str]],
    approved_files: set[str],
    final: dict[tuple[str, str], PairVerdict],
    by_file_history: dict[str, list[PairVerdict]],
    all_rows: dict[str, dict],
) -> tuple[list[dict], dict[str, list[PairVerdict]], set[str]]:
    committed: list[dict] = []
    terminal_ids: dict[str, list[PairVerdict]] = {}
    deferred_ids: set[str] = set()
    for fid in sorted(reported_committed_ids):
        files = citing_map.get(fid, [])
        if not files:
            deferred_ids.add(fid)
            continue
        if cfg.forward_check is not None:
            own_pvs = [final[(fid, rel)] for rel in files if (fid, rel) in final]
            if own_pvs and all(pv.verdict == "BAD" for pv in own_pvs):
                # §7 FK-13: the record carries every verdict for the file(s) this
                # finding cites, not only its own pairs — a sibling finding's
                # EXEMPT/GOOD pair on the same file is part of why it was refused.
                terminal_ids[fid] = [
                    pv for rel in sorted(files) for pv in by_file_history.get(rel, [])
                ]
                continue
        if all(rel in approved_files for rel in files):
            committed.append({**all_rows[fid], "consumed_category": "consumed_committed"})
        else:
            deferred_ids.add(fid)
    return committed, terminal_ids, deferred_ids


def _commit_and_record(  # noqa: PLR0913 — one commit round's whole state
    cfg: CorpusAuthorConfig,
    batch_id: str,
    result: dict,
    approved_paths: list[str],
    deletion_paths: list[str],
    terminal_ids: dict[str, list[PairVerdict]],
    all_rows: dict[str, dict],
    key: str,
) -> tuple[str | None, list[dict]]:
    # A commit message is required only when something will actually be committed —
    # `commit_corpus_paths` itself short-circuits on an empty path list without ever
    # reading it, so a curator that only skipped/deferred this tick (self-reported
    # `committed=[]`, corpus genuinely clean) needs no message to be well-formed.
    message = (
        author_shared.commit_message(result, cfg.noun)
        if approved_paths or deletion_paths else ""
    )
    message = _append_terminal_block(message, sorted(terminal_ids))
    commit_sha = author_shared.commit_corpus_paths(
        message, cfg, approved_paths, deletion_paths
    )

    terminal_rows: list[dict] = []
    for fid, pvs in terminal_ids.items():
        row = all_rows[fid]
        _append_gap_record(cfg, batch_id, row, key, pvs)
        terminal_rows.append({**row, "consumed_category": "consumed_forward_bad"})
    return commit_sha, terminal_rows


def _handle_retire(
    cfg: CorpusAuthorConfig, e: BaseException, to_author: list[dict], key: str, log
) -> int:
    channel = cfg.channel
    log(f"FATAL: {e}")
    outcome = retire(
        channel=channel,
        batch_ids=[row[key] for row in to_author],
        reason=str(e),
        max_attempts=cfg.max_attempts,
        timeout_seconds=cfg.repo_lock_wait_seconds,
    )
    # A NAMED, REPORTED disposition for a row that SURVIVES the bump (§7 FK-4's own
    # instinct, applied to every gate this delta reads the whole corpus tree
    # through) — `retire`'s own graveyard entry already names the reason for a row
    # that crossed the ceiling, so recording it again there would fire the signal on
    # every retiring fault and make it noise rather than a stuck-tick marker.
    survivors = [row for row in to_author if row[key] not in outcome.retired]
    if survivors:
        try:
            _record_stuck(channel, e, survivors)
        except Exception as unrecorded:  # noqa: BLE001 — never replaces `e`
            log(f"stuck record NOT written: {unrecorded!r} (the fault itself follows)")
    return 2


def _fold_deferrals(
    cfg: CorpusAuthorConfig, deferred_ids: set[str], all_rows: dict[str, dict], key: str
) -> tuple[list[dict], list[dict]]:
    # M7 — fold the deferral bump into THIS SAME closing rotation (§7 FK-23): one write, so
    # a deferred row's incremented counter cannot be lost to a lock-wait timeout between two
    # separate rotations.
    # @owns deferrals — the ONE function that increments a queued row's `deferrals` counter.
    deferred_held: list[dict] = []
    deferred_graveyard: list[dict] = []
    deferred_consumed: list[dict] = []
    for fid in sorted(deferred_ids):
        row = all_rows[fid]
        attempts = int(row.get("deferrals") or 0) + 1
        rec = dict(row)
        rec["deferrals"] = attempts
        if attempts >= cfg.max_attempts:
            deferred_graveyard.append(
                {
                    key: rec[key], "attempts": attempts,
                    "deadletter_reason": DEFERRED_CEILING_REASON,
                    "row": {k: v for k, v in rec.items() if k != "deferrals"},
                }
            )
            deferred_consumed.append({**rec, "consumed_category": "consumed_retired"})
        else:
            deferred_held.append(rec)
    if deferred_graveyard:
        append_jsonl(  # lint-unguarded-tree-write: ok — learning_queue sidecar, host-side, outside every box mount
            graveyard_file(cfg.channel), deferred_graveyard,
        )
    return deferred_held, deferred_consumed


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
    terminal_rows: list[dict] = []
    deferred_ids: set[str] = set()

    if to_author:
        _verifier_key_preflight(cfg)
        state = _capture_pre_state(cfg)
        try:
            (
                result, bucket_held, bucket_consumed, reported_committed_ids,
                all_batch_ids, counter,
            ) = _run_author_agent(cfg, to_author, batch_id, state.baseline_stray, all_rows)

            changed1 = [rel for _xy, rel in _changed_corpus_records(cfg)]
            # N6/M4: a deletion rides the commit list only when the FIRST spawn made it —
            # captured here, before the repair spawn (which has no delete capability at
            # all) ever runs, so a repair-caused deletion is reverted rather than adopted.
            deletion_paths = _deleted_corpus_records(cfg)

            final, _history, by_file_history = _run_verdict_pipeline(
                cfg, changed1, deletion_paths, all_rows, all_batch_ids, counter,
                state.snapshot, state.baseline_stray, batch_id,
            )

            approved_files, changed_final, citing_map = _compute_approval(
                cfg, changed1, final, all_batch_ids
            )

            # FK-21: terminal/unapproved files are restored BEFORE the approved list is
            # computed for the commit, so a restore failure can never coexist with a commit.
            _restore_unapproved_files(cfg, state.snapshot, changed_final - approved_files)

            approved_paths = sorted(approved_files)
            committed, terminal_ids, deferred_ids = _classify_reported(
                cfg, reported_committed_ids, citing_map, approved_files, final,
                by_file_history, all_rows,
            )

            commit_sha, terminal_rows = _commit_and_record(
                cfg, batch_id, result, approved_paths, deletion_paths, terminal_ids,
                all_rows, key,
            )
        except BaseException as e:
            # Cleanup runs for EVERY fault, member or not: a stuck tick leaves the same
            # edits behind a retiring one does, and leaving them wedges the channel. The
            # membership test below still decides disposition.
            _undo_agent_edits(cfg, state.snapshot, state.baseline_stray, state.head_before)
            if not isinstance(e, RETIRE_SET):
                raise
            return _handle_retire(cfg, e, to_author, key, log)

    held_committed, rotated_committed = author_shared.partition_committed(
        committed, hold_committed=hold_committed
    )

    deferred_held, deferred_consumed = _fold_deferrals(cfg, deferred_ids, all_rows, key)

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
    log(
        f"done batch={batch_id} committed={len(committed)} held={len(held)} "
        f"pre_consumed={len(consumed_pre)} terminal={len(terminal_rows)} "
        f"deferred={len(deferred_ids)} commit_sha={commit_sha}"
    )
    return 0


def _current_bytes(cfg: CorpusAuthorConfig, rel: str) -> bytes | None:
    target = cfg.repo_root / rel
    return target.read_bytes() if target.is_file() else None


def _corpus_relative(cfg: CorpusAuthorConfig, rel: str) -> str:
    return str((cfg.repo_root / rel).relative_to(cfg.corpus_dir))


def _restore_unapproved_files(
    cfg: CorpusAuthorConfig, snapshot: dict[str, bytes] | None, rels: set[str],
) -> None:
    """§7 FK-21: put every file this tick changed but did NOT approve back the way the
    TICK-START snapshot had it — unlinked if the tick created it, restored to its pre-tick
    bytes if it already existed. Runs BEFORE the approved list is computed, so a restore
    failure can never coexist with a commit."""
    if snapshot is None:
        return
    for rel in rels:
        corpus_rel = _corpus_relative(cfg, rel)
        target = cfg.corpus_dir / corpus_rel
        pre = snapshot.get(corpus_rel)
        if pre is None:
            # Anything left at this path — including something that is not a plain file
            # any more — is a failed restore, not a no-op: `unlink()` raises its own
            # `IsADirectoryError` rather than this silently leaving a corrupted entry.
            if target.exists() or target.is_symlink():
                target.unlink()
            continue
        if not target.is_file() or target.read_bytes() != pre:
            guarded_mkdir(target.parent, base=cfg.corpus_dir)
            write_guarded(target, pre)


def _revert_repair_deletions(
    cfg: CorpusAuthorConfig, snapshot: dict[str, bytes] | None, rels: list[str],
) -> None:
    """N6/M4: the repair spawn has no delete capability at all — a deletion that appears
    only after it ran is put back from the TICK-START snapshot (a pre-existing file it had
    no business removing). A path the snapshot never held (created and then removed inside
    this same tick, before repair) is left as it is: there is nothing to restore it to."""
    if snapshot is None:
        return
    for rel in rels:
        corpus_rel = _corpus_relative(cfg, rel)
        pre = snapshot.get(corpus_rel)
        if pre is None:
            continue
        target = cfg.corpus_dir / corpus_rel
        guarded_mkdir(target.parent, base=cfg.corpus_dir)
        write_guarded(target, pre)


def _assert_no_new_stray(cfg: CorpusAuthorConfig, baseline_stray: list[str]) -> None:
    """The repair spawn's own out-of-scope guard (M4): re-runs the SAME stray check the
    first spawn gets, without `verify_agent_state`'s committed/corpus-dirty half — the
    repair spawn self-reports no AUTHOR_RESULT at all, so that half has nothing to read."""
    new_stray = sorted(
        set(author_shared.changes_outside(cfg.repo_root, cfg.corpus_dir_rel)) - set(baseline_stray)
    )
    if new_stray:
        raise AuthorError(
            f"repair spawn changed files outside {cfg.corpus_dir_rel}*.md: {new_stray}; "
            "refusing to commit/rotate"
        )


def _append_terminal_block(message: str, terminal_ids: list[str]) -> str:
    """M6: the drain's own commit-message block, naming exactly this tick's terminal
    findings — advisory prose beside the gap ledger, the authoritative record (§7 FK-15).
    Appended LAST, so a curator-authored line shaped like this header can never be mistaken
    for the drain's own: `message.split(TERMINAL_BLOCK_HEADER)[-1]` is always this block."""
    if not terminal_ids:
        return message
    block = TERMINAL_BLOCK_HEADER + " " + ", ".join(terminal_ids)
    return message.rstrip("\n") + "\n\n" + block + "\n"


def _append_gap_record(
    cfg: CorpusAuthorConfig, batch_id: str, row: dict, key: str, pvs: list[PairVerdict],
) -> None:
    """M6: one durable record per terminal finding, written BEFORE the queue rotation (O3)
    — a crash in that window costs one duplicate record on replay, never a silent
    consumption.

    @owns findings.forward_bad.jsonl row shape — the ONE function that produces a gap-ledger
    record. Every field, including `verdicts` (the file's full `PairVerdict` history, not just
    the terminal finding's own pairs — §7 FK-13), is built here."""
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


def _assert_corpus_attributable(cfg: CorpusAuthorConfig, ids: set[str]) -> None:
    """M3.2: every file this tick CHANGED in the corpus must be vouched for by THIS BATCH —
    a citation of an id this tick actually read, WHATEVER bucket the curator reported that
    finding under (O5). UNCONDITIONAL (§7's own correction, `drain.py:436-437`/G13): this
    used to run only `if committed:`; the drain now reads the whole corpus tree on every
    tick and must have an opinion about every file it changed, not only the self-reported
    ones.

    The HEAD-provenance exemption that used to let an unchanged-citation edit ride for free
    is GONE (M3.2/C13) — its only lessons-channel use was the BAD-fold revert, which D2
    replaces outright with a per-file restore.

    The other post-flight cross-check, `verify_agent_state`, is AGGREGATE (committed
    non-empty ⇔ corpus dirty), one bit for a whole batch, so it misses the MIXED case.

    Attribution is per FILE and by the channel's OWN provenance key. Raising `AuthorError`
    routes through `_undo_agent_edits` -> `_restore_corpus`: the tick unwinds, the batch is
    bumped and stays queued, the tick returns 2."""
    key = cfg.channel.id_key
    field = provenance_field(key)
    unattributed = [
        rel for _xy, rel in _changed_corpus_records(cfg)
        if not (_cited_ids(cfg.repo_root / rel, field) & ids)
    ]
    if unattributed:
        raise AuthorError(
            f"author left {len(unattributed)} file(s) in {cfg.corpus_dir_rel} that no "
            f"finding of this batch vouches for: {unattributed}; each must cite a "
            f"{field} entry from this batch ({sorted(ids)}) — refusing to commit"
        )


def _changed_corpus_records(cfg: CorpusAuthorConfig) -> list[tuple[str, str]]:
    """`(status, repo-relative path)` for the corpus files this tick added or modified.

    The corpus is CLEAN at the top of every tick (`assert_clean_corpus_dir` refuses to
    author otherwise), so what git reports dirty under it is exactly what this agent call
    wrote. Deletions are excluded: there is no file left to attribute, and a lesson the
    curator retired rides M5's own deletion list instead (`_deleted_corpus_records`).

    `no_renames=True` (§7 FK-32): a rename decomposes into its `D`/`A` halves before
    anything downstream sees it, rather than one `R` record naming two paths.

    A record whose WORKING-TREE bytes are byte-identical to HEAD's is dropped (FK-32's
    second half): "changed" means content the check must judge, and a mode-only change
    (a permission bit git tracks but nothing here reads) is not that."""
    out: list[tuple[str, str]] = []
    for xy, rel in _git.git_status(cfg.repo_root, pathspec=cfg.corpus_dir, no_renames=True):
        if "D" in xy:
            continue
        if xy != "??" and _byte_identical_to_head(cfg.repo_root, rel):
            continue
        out.append((xy, rel))
    return sorted(out, key=lambda rec: rec[1])


def _byte_identical_to_head(repo_root: Path, rel: str) -> bool:
    """RAW byte comparison, not text: `git_show_file`/`read_text` both decode with
    universal-newline translation, which makes CRLF and LF compare equal even though the
    bytes genuinely differ — a real content change (and, per `_changed_corpus_records`'s own
    contract, one that IS "content the check must judge") that a text-mode comparison would
    silently drop (#773 claims-adversary finding)."""
    head_bytes = _git.git_show_file_bytes(repo_root, "HEAD", rel)
    if head_bytes is None:
        return False
    try:
        wt_bytes = (repo_root / rel).read_bytes()
    except OSError:
        return False
    return wt_bytes == head_bytes


def _deleted_corpus_records(cfg: CorpusAuthorConfig) -> list[str]:
    """M5/RF-2: the repo-relative paths this tick DELETED under the corpus — the collector
    `_changed_corpus_records`'s own `D`-drop (C17) needs, since a curator deletion still
    rides M5's explicit commit list even though it never needs a voucher (N6)."""
    return sorted(
        {
            rel for xy, rel in _git.git_status(
                cfg.repo_root, pathspec=cfg.corpus_dir, no_renames=True
            )
            if "D" in xy
        }
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


def _read_or_empty(path: Path) -> str:
    try:
        return read_text_utf8(path)
    except TEXT_READ_ERRORS:
        return ""


def _resolves_inside_runs_dir(runs_dir: Path, source_id: str) -> bool:
    """§7 FK-30: the queue-side twin of O5 — a traversal-shaped `run_id` must resolve to a
    path INSIDE `runs_dir` when the check opens it. A provenance argument alone ("the id
    comes from the row, never the model") holds only as far as the row itself is validated,
    and the queue is written by a producer, not by a human."""
    runs_root = runs_dir.resolve()
    resolved = (runs_dir / source_id).resolve()
    return resolved == runs_root or runs_root in resolved.parents


def _attempt_pair(
    cfg: CorpusAuthorConfig, counter: Any, rel: str, row: dict, path: Path, lesson_text: str,
) -> tuple[str, str]:
    """One attempt at one pair: build the `CheckContext` and call the check.

    Raises `VerdictError` for a content-shaped local failure — no/malformed `run_id`, a
    `run_id` that resolves outside `runs_dir` — the SAME class M3.3's retry-once handler
    catches for an unparseable verifier reply, so a malformed queue row takes the identical
    disposition (retry once, then BAD). `StageAbort`/`FatalConfigError`/any other exception
    propagate unchanged — a call that never COMPLETED is a different failure kind entirely
    (§7 FK-9) and is never retried here."""
    try:
        source_id = row["run_id"]
    except KeyError as e:
        raise VerdictError("forward_check: row carries no run_id") from e
    if not isinstance(source_id, str) or not source_id:
        raise VerdictError(f"forward_check: row's run_id is not a usable string: {source_id!r}")
    if not _resolves_inside_runs_dir(cfg.runs_dir, source_id):
        raise VerdictError(f"forward_check: run_id resolves outside runs_dir: {source_id!r}")
    # Only ever called from `_run_verdict_pass`, itself only reachable once the caller has
    # already checked `cfg.forward_check is not None` — narrowed here for mypy, not a new
    # runtime check.
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
    """M3.3: a `VerdictError` (or a local content-shaped failure treated identically) is
    re-run exactly once; the second failure records BAD with `forward_check_error:`-prefixed
    reasoning that concatenates both attempts' text (§7 FK-10). Any other exception —
    `StageAbort`/`FatalConfigError` included — propagates on the FIRST attempt, never
    retried, and mints no `PairVerdict` at all (§7 FK-9)."""
    try:
        return _attempt_pair(cfg, counter, rel, row, path, lesson_text)
    except VerdictError as e1:
        try:
            return _attempt_pair(cfg, counter, rel, row, path, lesson_text)
        except VerdictError as e2:
            return "BAD", f"{ERROR_PREFIX}{e1}; {e2}"


def _run_verdict_pass(
    cfg: CorpusAuthorConfig,
    files: list[str],
    all_rows: dict[str, dict],
    all_batch_ids: set[str],
    counter: Any,
    pass_no: int,
    *,
    fallback_citers: dict[str, set[str]] | None = None,
    texts_out: dict[str, str] | None = None,
) -> dict[str, list[PairVerdict]]:
    """One M3.3 verdict pass, fanned out under `verify_batch_workers()` (the Scale
    section's own bound). Mints one `PairVerdict` per (file, this-batch cited id) pair.

    @owns PairVerdict — the ONE function that constructs `PairVerdict` instances (GOOD/BAD via
    `_verdict_for_pair`, EXEMPT via `cfg.exempt`, and the FK-6 fallback-BAD synthetic pair).

    `fallback_citers` is M4/§7 FK-6's own escape hatch: on pass 2, a file the repair spawn
    left with no this-batch citation is NOT a tick-wide `AuthorError` — it is terminal for
    the finding(s) that cited it in pass 1, and nothing else. `None` (pass 1) means every
    file here is ALREADY known-vouched (M3.2 raised otherwise), so the branch never fires.

    `texts_out`, when given, records the bytes each file was actually judged on — O1's own
    "the bytes a verdict judged are the bytes that land in HEAD" needs this to detect a file
    that moved AGAIN between being read for this pass and this pass completing."""
    field = provenance_field(cfg.channel.id_key)
    jobs: list[tuple[str, str, dict, Path, str]] = []
    results: dict[str, list[PairVerdict]] = {}
    for rel in files:
        path = cfg.repo_root / rel
        lesson_text = _read_or_empty(path)
        if texts_out is not None:
            texts_out[rel] = lesson_text
        cited = _cited_ids(path, field) & all_batch_ids
        if not cited and fallback_citers is not None:
            for fid in sorted(fallback_citers.get(rel, ())):
                row = all_rows.get(fid, {})
                results.setdefault(rel, []).append(
                    PairVerdict(
                        rel_path=rel, finding_id=fid, source_id=str(row.get("run_id") or ""),
                        verdict="BAD",
                        reasoning="repair rewrite dropped this file's citations to this batch",
                        lesson_text=lesson_text, pass_no=pass_no,
                    )
                )
            continue
        for fid in sorted(cited):
            jobs.append((rel, fid, all_rows[fid], path, lesson_text))

    if not jobs:
        return results

    def _one(job: tuple[str, str, dict, Path, str]) -> tuple[str, PairVerdict]:
        rel, fid, row, path, lesson_text = job
        if cfg.exempt(row):
            return rel, PairVerdict(
                rel_path=rel, finding_id=fid, source_id=str(row.get("run_id") or ""),
                verdict="EXEMPT",
                reasoning="exempt: this finding's kind is out of the check's scope",
                lesson_text=lesson_text, pass_no=pass_no,
            )
        verdict, reasoning = _verdict_for_pair(cfg, counter, rel, row, path, lesson_text)
        return rel, PairVerdict(
            rel_path=rel, finding_id=fid, source_id=str(row.get("run_id") or ""),
            verdict=verdict, reasoning=reasoning, lesson_text=lesson_text, pass_no=pass_no,
        )

    workers = max(1, config.verify_batch_workers())
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for rel, pv in pool.map(_one, jobs):
            results.setdefault(rel, []).append(pv)
    return results


def build_repair_user_prompt(
    pairs: list[PairVerdict], cfg: CorpusAuthorConfig, *, salt: str | None = None,
) -> str:
    """M4/S4: the repair spawn's user turn, one section-triple per BAD pair — the finding's
    own identity, the file's CURRENT (pre-repair) text and the verifier's reasoning — each
    inside its OWN `wrap()` envelope, since all three are model-authored (S4)."""
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


def record_stuck(channel: QueueChannel, exc: BaseException, rows: list[dict]) -> None:
    """THE public spelling of "record this fault on the channel's stuck report".

    `drains._drain_one_curator` is a second frame that catches faults this module raises, and
    it was reaching into `_record_stuck` directly — a private name whose signature could change
    under it with no lint and no test coupling. Same body, one supported entry point.
    """
    _record_stuck(channel, exc, rows)


def stuck_record_count(channel: QueueChannel) -> int:
    """How many records the channel's stuck report holds right now.

    The instrument a second frame uses to ask whether THIS tick's fault has already been
    recorded, without guessing from the exception. `_record_stuck` folds `consecutive_ticks`
    only when the previous record's fault class AND row ids both match — so two records per
    tick, written by two frames holding two different row sets, meant the next tick's record
    matched neither and the count reset to 1 forever. A permanently wedged channel emitted an
    endless run of `consecutive_ticks: 1` and an operator paging on "stuck for N ticks" never
    fired, which is the exact silence the counter exists against.

    ASKED OF THE FILE, never of the exception. Marking the exception itself would look simpler
    and is wrong: nothing stops a raiser reusing one exception instance across ticks (this
    suite's own `raising()` fake does), and a mark that outlives its tick suppresses every
    record after the first.
    """
    path = stuck_report_file(channel)
    return len(read_jsonl_rows(path)) if path.is_file() else 0


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
