"""The corpus-author drain body and its retire seam."""
from __future__ import annotations

import hashlib
import logging
import uuid
import contextlib
from dataclasses import replace
from defender._model import model
from typing import Any

from pydantic_ai.exceptions import ModelRetry

from defender._clock import now_iso
from defender._git import GitError
from defender._frontmatter import FrontmatterError, split_frontmatter
from defender._io import Bound
from defender._text import one_line
from defender.learning.author import shared as author_shared
from defender.learning.author._config import BucketSpec, CorpusAuthorConfig
from defender.learning.core.config import (
    FatalConfigError,
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
from defender import box as box_mod
from defender.learning.author.version_control import AgentChange, ChangeSet, DeliveryRefused

AuthorError = author_shared.AuthorError

_logger = logging.getLogger(__name__)


#: Graveyard reason for a deferral that hit the ceiling, distinguishable from a fault's.
DEFERRED_CEILING_REASON = "deferred_ceiling"
#: Not `faults.SYSTEMIC_FAULTS`, which keeps `GitError` out of retirement — the opposite of what
#: a commit-time git failure needs here. Nor just `AuthorError`: without `GitError` a commit-time
#: git failure would wedge the channel, and without `ModelRetry` an externally killed boxed
#: command would report success.
RETIRE_SET: tuple[type[BaseException], ...] = (AuthorError, GitError, ModelRetry)

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
    """Bump every named row by one; retire the rows now at or over the ceiling."""
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


# ---------------------------------------------------------------------------
# The authoring region. One truth — the claim's change set, the draft against the batch's base,
# taken after the spawn — from which every decision is computed once: changed files,
# citations, the commit, and each row's fate. A spawn's own report is read only for skip
# reasons and the commit message, plus one cross-check: an id it claims committed that no file
# cites is deferred.
# ---------------------------------------------------------------------------


def _claim_batch(cfg: CorpusAuthorConfig) -> Any:
    """The batch this channel's claim belongs to. A config with none (a scene's) never claims:
    the corpus is committed only by P3's commit-maker into a tenant batch (#1108 P4, O7)."""
    if cfg.batch is None:
        raise FatalConfigError(
            f"{cfg.log_prefix}: a curator commits only into a tenant batch's draft, and this "
            "config names none — nothing is committed"
        )
    return cfg.batch


def _reset_claim(cfg: CorpusAuthorConfig) -> None:
    """Re-sync the claim's draft with the batch branch (`Batch.reset`): the box's additions
    removed, its edits and deletions restored, links and FIFOs removed without being followed
    or opened. A config with no batch has nothing to reset."""
    if cfg.batch is not None:
        cfg.batch.reset()


@model(frozen=True)
class _Tree:
    """The claim's corpus changes: lessons whose bytes differ from the batch's base, and paths
    deleted. Every later step reads the corpus through this."""

    changed: tuple[AgentChange, ...]
    deleted: tuple[AgentChange, ...]


def _settle_tree(cfg: CorpusAuthorConfig, change_set: ChangeSet) -> _Tree:
    """The post-spawn normaliser over the claim's change set: a change outside the corpus is a
    stray the spawn was not asked to make, refusing the claim (no pre-run stray is tolerated,
    OD15); a non-`.md` file under the corpus cites nothing by construction and never lands
    (the claim's reset removes it), so it is dropped rather than turned into a tick-wide fault."""
    strays = sorted(c.path for c in change_set if not c.path.startswith(cfg.corpus_rel))
    if strays:
        raise AuthorError(
            f"agent changed files outside {cfg.corpus_rel}*.md: {strays}; "
            "refusing to commit/rotate"
        )
    return _Tree(
        changed=tuple(c for c in change_set if c.content is not None and c.path.endswith(".md")),
        deleted=tuple(c for c in change_set if c.content is None),
    )


def _corpus_name(cfg: CorpusAuthorConfig, path: str) -> str:
    """The repo-relative change path `path` as a name under the corpus mount."""
    return path[len(cfg.corpus_rel):]


def _read_citations(
    cfg: CorpusAuthorConfig, changed: tuple[AgentChange, ...], batch: set[str],
) -> dict[str, frozenset[str]]:
    """change path -> the this-batch ids each changed lesson cites. Each lesson is read through
    the corpus mount (`cfg.corpus`, #1134), and must still hold the bytes the claim's change set
    took from it: those are the bytes that land."""
    field_name = provenance_field(cfg.channel.id_key)
    view = cfg.corpus.view()
    cites: dict[str, frozenset[str]] = {}
    for change in changed:
        text = _read_or_empty(view, _corpus_name(cfg, change.path))
        assert change.content is not None  # `changed` holds no deletion
        if text.encode("utf-8", "surrogateescape") != change.content:
            raise AuthorError(
                f"{change.path} changed after the claim's change set was taken — refusing to "
                "commit bytes no citation was read from"
            )
        cites[change.path] = frozenset(_cited_ids_in(text, field_name) & batch)
    return cites


def _assert_corpus_attributable(
    cfg: CorpusAuthorConfig, changed: tuple[AgentChange, ...], ids: set[str],
) -> None:
    """Every corpus file the curator spawn added must cite, under the channel's provenance
    key, an id this batch read — whatever bucket the curator reported it under. Read through
    the corpus mount: a refused read cites nothing. (`changed` holds additions only: an edit
    of a base file citing nothing is repaired, never committed — `_author_batch`.)

    The `AuthorError` unwinds the claim (its reset); the batch is bumped and stays queued."""
    field = provenance_field(cfg.channel.id_key)
    unattributed = [
        c.path for c in changed
        if not (_cited_ids(cfg.corpus.view(), _corpus_name(cfg, c.path), field) & ids)
    ]
    if unattributed:
        raise AuthorError(
            f"author left {len(unattributed)} file(s) in {cfg.corpus_rel} that no "
            f"finding of this batch vouches for: {unattributed}; each must cite a "
            f"{field} entry from this batch ({sorted(ids)}) — refusing to commit"
        )


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
    all_rows: dict[str, dict],
) -> _BatchOutcome:
    """Spawn, take the claim's change set, read citations; then read every fate off them and
    commit what they approve through the batch's commit-maker. The change set is derived
    before anything is attributed (OD23), so a link, FIFO or out-of-lane entry the box left is
    a refused claim (`DeliveryRefused`), never read."""
    key = cfg.channel.id_key
    batch_ids = {row[key] for row in to_author}

    # The box runs for the spawn only, and is stopped before any host step reads what it
    # wrote (#1195).
    with box_mod.box_for_run(cfg.box) as box:
        result = cfg.invoke_agent(to_author, batch_id, replace(cfg, box=box))
    batch = _claim_batch(cfg)
    tree = _settle_tree(cfg, batch.change_set())
    author_shared.verify_agent_report(
        result, corpus_changed=bool(tree.changed or tree.deleted), corpus_rel=cfg.corpus_rel,
        noun=cfg.noun)
    author_shared.validate_agent_result_partition(
        result, to_author, id_key=key,
        buckets=tuple(b.name for b in cfg.buckets), noun=cfg.noun,
    )
    base = batch.base()
    _assert_corpus_attributable(
        cfg, tuple(c for c in tree.changed if c.path not in base), batch_ids)

    cites = _read_citations(cfg, tree.changed, batch_ids)
    fates = _decide_fates(
        batch_ids, cites, claimed_committed=set(author_shared.result_list(result, "committed")),
    )
    # Approved: a changed lesson citing this batch. Every added lesson is (attributable above);
    # an edit of a base lesson citing nothing from it is corpus repair — left out of the commit,
    # and put back from the batch's base by the claim's reset. The curator's deletions under the
    # corpus land with the approved lessons.
    landing = (*(c for c in tree.changed if cites[c.path]), *tree.deleted)
    commit_sha = (
        batch.commit(ChangeSet(landing), author_shared.commit_message(result, cfg.noun))
        if landing else None
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


def _handle_refused(
    cfg: CorpusAuthorConfig, refused: DeliveryRefused, to_author: list[dict], key: str, log,
) -> int:
    """U10: a claim the commit-maker refused counts one attempt on each of its rows, which stay
    queued until the ceiling retires them (#952); the tick itself completes (rc 0, OD19)."""
    # Named by the entry's repo-relative spelling (`agent/lessons/x.md`), never the draft's host
    # path.
    reason = one_line(str(refused)).replace(f"{cfg.repo_root}/", "")
    log.warning(f"the claim was refused by the commit-maker: {reason} — its draft is reset, "
                "its rows count one attempt and stay queued")
    outcome = retire(
        cfg.state,
        channel=cfg.channel,
        batch_ids=[row[key] for row in to_author],
        reason=f"refused-claim: {reason}",
        max_attempts=cfg.max_attempts,
        timeout_seconds=cfg.repo_lock_wait_seconds,
    )
    survivors = [row for row in to_author if row[key] not in outcome.retired]
    if survivors:
        try:
            _record_stuck(cfg.state, cfg.channel, refused, survivors)
        except Exception as unrecorded:  # noqa: BLE001 — never replaces the routed refusal
            log.error(f"stuck record NOT written: {unrecorded!r} (the refusal itself: {reason})")
    return 0


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
        try:
            outcome = _author_batch(cfg, to_author, batch_id, all_rows)
        except DeliveryRefused as refused:
            # U10 (OD18, OD23): the commit-maker refused the claim. Its draft is reset, its
            # rows count one attempt and stay queued until the ceiling; the tick goes on.
            _reset_claim(cfg)
            return _handle_refused(cfg, refused, to_author, key, log)
        except BaseException as e:
            # Reset on every fault, member or not: a stuck tick leaves the same edits a
            # retiring one does, and leaving them would hand them to the next claim.
            box_fault = isinstance(e, box_mod.BoxFault)
            try:
                _reset_claim(cfg)
            except Exception as undo_fault:
                # A box whose stop failed may still be writing while the reset runs, and the
                # reset's own fault must not replace the box fault: the box fault must halt
                # the batch (#1195 D3a, O4). Any other fault keeps today's precedence.
                if not box_fault:
                    raise
                log.error(f"reset after a box fault failed: {undo_fault!r} "
                          "(the box fault follows)", exc_info=undo_fault)
            if box_fault or not isinstance(e, RETIRE_SET):
                raise
            return _handle_retire(cfg, e, to_author, key, log)
        # The claim landed (or made no change): the draft is re-synced with what the branch
        # holds, so nothing unapproved reaches the next claim (OD15).
        _reset_claim(cfg)

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
    """@owns recorded_at — the operator signal for a stuck tick, and when it was written."""
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
