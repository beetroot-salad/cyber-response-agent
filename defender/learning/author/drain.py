"""The corpus-author drain body and its retire seam."""
from __future__ import annotations

import hashlib
import logging
import uuid
from dataclasses import replace
from defender._model import model
from collections.abc import Sequence
from typing import Any

from pydantic_ai.exceptions import ModelRetry

from defender._clock import now_iso
from defender._git import GitError
from defender._frontmatter import FrontmatterError, split_frontmatter
from defender._text import one_line
from defender.learning.author import shared as author_shared
from defender.learning.author._config import CorpusAuthorConfig
from defender.learning.core.config import (
    FatalConfigError,
    provenance_field,
)
from defender.learning.core.state import (
    Channel,
    LearningState,
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


#: One item of a store claim: `(kind, key, payload)` (`learning.store.Held.items`).
Item = tuple[str, str, dict[str, Any]]


def run_batch(
    *, cfg: CorpusAuthorConfig, items: Sequence[Item], outcomes: dict[tuple[str, str], Any],
    box: Any = None,
) -> int:
    """One claim of one corpus-author channel over a learning store claim (#1278 D1): `items` are the
    claim's items of this channel's kind, and `outcomes` the map this claim fills with each item's fate,
    keyed by the item's `(kind, key)`. The store's claim is the lane's lock, so no lock is taken here.
    The fates (applied by the tick when the batch enters review, or ends with no commits):

    - a row with no id under the channel's key is dead;
    - the gate's holds are held with the gate's reason; a row the corpus already cites is published;
      a world row naming no systems is skipped with that reason;
    - the curator's `consumed_skip` is skipped with its reason; an id it reports committed that no
      lesson cites is deferred;
    - a committed (cited) item is not named: it stays in the batch; nor is an item in no bucket: the
      tick's citation rule returns it to waiting.

    Returns 0 for a claim that ran (or had nothing to author) or that the commit-maker refused, and 2
    for one whose authoring faulted with a member of `RETIRE_SET` (its items then take what the batch's
    commits show). Anything else propagates."""
    if box is not None:
        cfg = replace(cfg, box=box)
    log = channel_logger(cfg)
    try:
        _require_clean_draft(cfg)
    except (AuthorError, DeliveryRefused) as e:
        # An already-dirty draft is never handed to the spawn (OD15: no pre-run stray is tolerated).
        log.critical(f"{e}")
        return 2
    return _claim(cfg=cfg, items=items, outcomes=outcomes, log=log)


def _require_clean_draft(cfg: CorpusAuthorConfig) -> None:
    """Refuse a claim over a draft that already differs from the batch's base before the spawn
    runs: whatever stands there would otherwise be read as the spawn's own work. A config with
    no batch has no draft to judge (it refuses at the commit, `_claim_batch`)."""
    if cfg.batch is None:
        return
    strays = sorted(c.path for c in cfg.batch.change_set())
    if strays:
        raise AuthorError(
            f"the draft is already dirty before the spawn: {strays}; refusing to start the tick"
        )


def _gate_outcome(rec: dict) -> Any:
    """The fate of a row the gate decided before the spawn: held with its reason, published when
    the corpus already cites it, else skipped naming the gate's category."""
    from defender.learning.store import Outcome

    if "held_reason" in rec:
        return Outcome.held(str(rec["held_reason"]))
    category = str(rec.get("consumed_category") or "")
    if category == "consumed_idempotent":
        return Outcome.published()
    if category == "consumed_no_systems":
        return Outcome.skipped("consumed_no_systems: the world finding names no systems")
    return Outcome.skipped(category or "declined at the gate")


def _keyed(
    items: Sequence[Item], key: str, outcomes: dict[tuple[str, str], Any],
) -> tuple[list[dict], dict[str, tuple[str, str]]]:
    """The claim's rows that carry an id under `key`, and each id's item; a row with none (or a
    second row under one id) is dead at once, named by its own item."""
    from defender.learning.store import Outcome

    keyed: list[dict] = []
    item_of: dict[str, tuple[str, str]] = {}
    for kind, item_key, payload in items:
        row = dict(payload)
        rid = _row_id(row, key)
        if rid is None or rid in item_of:
            outcomes[(kind, item_key)] = Outcome.dead(f"row carries no value under {key!r}")
            continue
        keyed.append(row)
        item_of[rid] = (kind, item_key)
    return keyed, item_of


def _claim(
    *, cfg: CorpusAuthorConfig, items: Sequence[Item], outcomes: dict[tuple[str, str], Any], log,
) -> int:
    key = cfg.channel.id_key
    keyed, item_of = _keyed(items, key, outcomes)
    if not item_of:
        log.info("no keyed item in the claim — nothing to author")
        return 0
    # The gate reads per-row fields the claim cannot vouch for (`run_id`, `direction`), so it can
    # raise; its fates are written before the spawn, so a later fault cannot lose them.
    held, consumed_pre, to_author = cfg.gate(keyed, cfg)
    for rec in (*held, *consumed_pre):
        outcomes[item_of[rec[key]]] = _gate_outcome(rec)
    batch_id = uuid.uuid4().hex[:12]
    log.info(
        f"batch={batch_id} total={len(items)} to_author={len(to_author)} "
        f"held={len(held)} pre_consumed={len(consumed_pre)} unkeyable={len(items) - len(item_of)}"
    )
    if not to_author:
        return 0
    outcome = _author_or_reset(cfg, to_author, batch_id, author_shared.by_id(keyed, key), log)
    if isinstance(outcome, int):
        return outcome
    _record_fates(outcome, item_of, key, outcomes)
    log.info(
        f"done batch={batch_id} committed={len(outcome.committed)} held={len(held)} "
        f"pre_consumed={len(consumed_pre)} deferred={len(outcome.deferred_ids)} "
        f"commit_sha={outcome.commit_sha}"
    )
    return 0


def _author_or_reset(
    cfg: CorpusAuthorConfig, to_author: list[dict], batch_id: str, all_rows: dict[str, dict], log,
) -> _BatchOutcome | int:
    """The claim authored (`_author_batch`), its draft re-synced with the branch after, whatever
    happened: the outcome, or the claim's rc (0 for a claim the commit-maker refused, 2 for an
    authoring fault in `RETIRE_SET`; anything else propagates)."""
    try:
        outcome = _author_batch(cfg, to_author, batch_id, all_rows)
    except DeliveryRefused as refused:
        # U10 (OD18, OD23): the commit-maker refused the claim. Its draft is reset; its items take
        # what the batch's commits show (the claim counted their attempt).
        _reset_claim(cfg)
        reason = one_line(str(refused)).replace(f"{cfg.repo_root}/", "")
        log.warning(f"the claim was refused by the commit-maker: {reason} — its draft is reset")
        return 0
    except BaseException as e:
        # Reset on every fault, member or not: leaving the edits would hand them to the next claim.
        box_fault = isinstance(e, box_mod.BoxFault)
        try:
            _reset_claim(cfg)
        except Exception as undo_fault:
            # A box whose stop failed may still be writing while the reset runs, and the reset's
            # own fault must not replace the box fault: the box fault must halt the batch (#1195
            # D3a, O4). Any other fault keeps today's precedence.
            if not box_fault:
                raise
            log.error(f"reset after a box fault failed: {undo_fault!r} "
                      "(the box fault follows)", exc_info=undo_fault)
        if box_fault or not isinstance(e, RETIRE_SET):
            raise
        log.critical(f"{e}")
        return 2
    # The claim landed (or made no change): the draft is re-synced with what the branch holds, so
    # nothing unapproved reaches the next claim (OD15).
    _reset_claim(cfg)
    return outcome


def _record_fates(
    outcome: _BatchOutcome, item_of: dict[str, tuple[str, str]], key: str,
    outcomes: dict[tuple[str, str], Any],
) -> None:
    """The authored claim's fates (D1): an id reported committed that no lesson cites is deferred,
    the curator's skips are skipped with its reason; a cited id is not named (it stays in the batch)."""
    from defender.learning.store import Outcome

    for fid in sorted(outcome.deferred_ids):
        outcomes[item_of[fid]] = Outcome.deferred()
    for rows in outcome.bucket_consumed.values():
        for rec in rows:
            outcomes[item_of[rec[key]]] = Outcome.skipped(
                str(rec.get("skip_reason") or rec.get("consumed_category")))
    for rows in outcome.bucket_held.values():
        for rec in rows:
            outcomes[item_of[rec[key]]] = Outcome.held(str(rec.get("held_reason") or "held by the curator"))


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


def _change_text(change: AgentChange) -> str:
    """The text `change` would land, decoded as the canonical text read decodes a file (UTF-8,
    universal newlines); `""` when it is not UTF-8, so it cites nothing."""
    assert change.content is not None  # a changed lesson, never a deletion
    try:
        text = change.content.decode("utf-8")
    except UnicodeDecodeError:
        return ""
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _change_cites(change: AgentChange, field: str) -> set[str]:
    """The queue-row ids the changed lesson claims as its source, read from the bytes it would
    land. A lesson whose frontmatter cannot be read cites nothing, so it is unattributable."""
    return _cited_ids_in(_change_text(change), field)


def _read_citations(
    cfg: CorpusAuthorConfig, changed: tuple[AgentChange, ...], batch: set[str],
) -> dict[str, frozenset[str]]:
    """change path -> the this-batch ids each changed lesson cites, read from the bytes the
    claim's change set took — the bytes that land (#773 one truth). Nothing is read back from
    the corpus, so a citation is always read from exactly what it approves."""
    field = provenance_field(cfg.channel.id_key)
    return {change.path: frozenset(_change_cites(change, field) & batch) for change in changed}


def _assert_corpus_attributable(
    cfg: CorpusAuthorConfig, changed: tuple[AgentChange, ...], ids: set[str],
) -> None:
    """Every corpus file in `changed` must cite, under the channel's provenance key, an id
    this batch read — whatever bucket the curator reported it under, read from the bytes it
    would land. (`changed` is every addition, and every edit of a base
    file that still claims a provenance — no other batch's citations vouch for this batch's
    edit, #773 C13. An edit of a base file citing nothing at all is repaired, never committed
    — `_author_batch`.)

    The `AuthorError` unwinds the claim (its reset); the batch is bumped and stays queued."""
    field = provenance_field(cfg.channel.id_key)
    unattributed = [
        c.path for c in changed
        if not (_change_cites(c, field) & ids)
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
    field = provenance_field(key)
    _assert_corpus_attributable(
        cfg,
        tuple(c for c in tree.changed if c.path not in base
              or _change_cites(c, field)),
        batch_ids)

    cites = _read_citations(cfg, tree.changed, batch_ids)
    fates = _decide_fates(
        batch_ids, cites, claimed_committed=set(author_shared.result_list(result, "committed")),
    )
    # Approved: a changed lesson citing this batch. Every added lesson, and every edited one
    # still claiming a provenance, is (attributable above); an edit of a base lesson citing
    # nothing at all is corpus repair — left out of the commit, and put back from the batch's
    # base by the claim's reset. The curator's deletions under the
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


def _cited_ids_in(text: str, field: str) -> set[str]:
    try:
        fm, _raw, _body = split_frontmatter(text)
    except FrontmatterError:
        return set()
    cited = fm.get(field)
    if not isinstance(cited, list):
        return set()
    return {c for c in cited if isinstance(c, str)}


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
