"""The one corpus-author drain body, and the one retire seam (#719).

Every corpus-author channel — findings and the three observation channels — reaches its
batch through `run_batch` here. What used to vary per direction (the pre-author gate, the
AUTHOR_RESULT buckets, the row key, the queue's two locks, the commit's provenance
trailers, the lessons-only held report) is a field on the config; what used to be copied
per direction (read, partition, author, verify, commit, project, rotate, log) is this
module.

**Retirement is reachable only from `RETIRE_SET`.** There is no bare `except Exception`
and no re-raise carve-out: a fault whose class is not in that tuple is not caught at all,
so it escapes and leaves its row queued — stuck, recoverable, and recorded in the channel's
stuck-row file. The accepted trade is that a novel exception class returns to unbounded
retry rather than being counted toward a ceiling and permanently deleted.

`GitError` and `ModelRetry` are the two members the obvious `except AuthorError` spelling
would silently drop, reverting a commit-time git failure and an externally killed boxed
command back to "wedges the channel" and "reports success".

SCOPE: the set governs the four AUTHOR channels. The pitfalls and lead-author legs keep
`core/faults.run_or_dead_letter`'s own re-raise set, which this change does not touch and
which CONTAINS `GitError` — so a commit-time `GitError` retires here and kills the drain
there. One class, two classifications, by channel: deliberate, and left for a follow-up.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from pydantic_ai.exceptions import ModelRetry

from defender import _git
from defender._git import GitError
from defender._io import append_jsonl, read_jsonl_rows
from defender.learning.author import shared as author_shared
from defender.learning.author._config import BucketSpec, CorpusAuthorConfig
from defender.learning.core import persist
from defender.learning.core.config import QueueChannel, make_logger

AuthorError = author_shared.AuthorError

#: Decision 8's ENUMERATED retire set. Spelled as a literal enumeration on purpose: it is
#: NOT `faults.SYSTEMIC_FAULTS` (which exists to keep `GitError` OUT of retirement, the
#: opposite of what a commit-time git failure must now do here), and it is not narrowable
#: to `AuthorError` alone (which drops the two members below it).
RETIRE_SET: tuple[type[BaseException], ...] = (AuthorError, GitError, ModelRetry)

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
    """The channel's stuck-row record — the only externally visible trace of a fault whose
    class is NOT in `RETIRE_SET`, since such a row stays queued and never reaches the
    graveyard. One record per non-retiring tick, naming the fault class, the stalled rows
    and how many consecutive ticks they have been stuck. A retiring fault writes nothing
    here; it is already visible in the graveyard."""
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


def retire(
    *,
    channel: QueueChannel,
    batch_ids: list[str],
    reason: str,
    max_attempts: int,
) -> RetireOutcome:
    """Bump every named row by one; retire the rows now at or over the ceiling.

    The count is a LIFETIME count on the row — no reset on an intervening success, none on
    a requeue — and the ceiling is consulted only here, i.e. only after an observed
    failure. A row that arrives already over the ceiling rides through a clean tick
    untouched.

    Ordering is decision 3's: the graveyard entry lands FIRST, then the row is written into
    the consumed ledger by the same locked rotation that rewrites the queue. The ledger
    write is what makes retirement terminal — the observation append path reads it to dedup
    — so a crash between the two costs one duplicate advisory record and nothing else."""
    ids = {str(i) for i in batch_ids}
    key = channel.id_key
    bumped: dict[str, int] = {}
    survivors: list[dict] = []
    retired: list[dict] = []

    with persist.queue_lock(channel.append_lock):
        for row in read_jsonl_rows(channel.file):
            rid = row.get(key)
            if not isinstance(rid, str) or rid not in ids:
                continue
            attempts = int(row.get("attempts") or 0) + 1
            bumped[rid] = attempts
            rec = dict(row)
            rec["attempts"] = attempts
            (retired if attempts >= max_attempts else survivors).append(rec)
        if retired:
            append_jsonl(
                graveyard_file(channel),
                [
                    {
                        key: rec[key],
                        "attempts": rec["attempts"],
                        "deadletter_reason": reason,
                        # The retired work itself, nested rather than spread: a graveyard
                        # entry has ONE shape on every channel, so the record is readable
                        # without knowing which queue produced it.
                        "row": {k: v for k, v in rec.items() if k != "attempts"},
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
        batch = read_jsonl_rows(channel.file)
    finally:
        author_shared.release_flock(append_fh)
    if not batch:
        log("queue empty — nothing to author")
        return 0

    keyed: list[dict] = []
    unkeyable: list[dict] = []
    for row in batch:
        rid = row.get(key)
        (keyed if isinstance(rid, str) and rid else unkeyable).append(row)
    retired_unkeyable = _retire_unkeyable(channel, unkeyable, log)

    held, consumed_pre, to_author = cfg.gate(keyed, cfg)
    batch_id = uuid.uuid4().hex[:12]
    log(
        f"batch={batch_id} total={len(batch)} to_author={len(to_author)} "
        f"held={len(held)} pre_consumed={len(consumed_pre)} unkeyable={len(unkeyable)}"
    )
    try:
        return _author_and_rotate(
            cfg=cfg,
            log=log,
            batch_id=batch_id,
            hold_committed=hold_committed,
            all_rows=author_shared.by_id(keyed, key),
            held=held,
            consumed_pre=consumed_pre,
            to_author=to_author,
            retired_unkeyable=retired_unkeyable,
        )
    except BaseException as e:
        if not isinstance(e, RETIRE_SET):
            _record_stuck(channel, e, to_author)
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
    retired_unkeyable: list[dict],
) -> int:
    channel = cfg.channel
    key = channel.id_key
    commit_sha: str | None = None
    committed: list[dict] = []
    bucket_held: dict[str, list[dict]] = {}
    bucket_consumed: dict[str, list[dict]] = {}

    if to_author:
        # Taken BEFORE the agent runs so a commit-time GitError can put the corpus back
        # the way it found it. Without this the agent's edits stay uncommitted, the next
        # tick's cleanliness gate aborts before it reaches any queue at all, and the
        # channel wedges instead of retrying.
        snapshot = _snapshot_corpus(cfg.corpus_dir)
        baseline_stray = author_shared.changes_outside(cfg.repo_root, cfg.corpus_dir_rel)
        try:
            result = cfg.invoke_agent(to_author, batch_id, cfg)
            author_shared.verify_agent_state(
                cfg.repo_root, result, cfg.corpus_dir, cfg.corpus_dir_rel,
                cfg.noun, baseline_stray,
            )
            author_shared.validate_agent_result_partition(
                result, to_author, id_key=key,
                buckets=tuple(b.name for b in cfg.buckets), noun=cfg.noun,
            )
            committed, bucket_held, bucket_consumed = _project(result, all_rows, cfg)
            if committed:
                commit_sha = cfg.commit_fn(
                    author_shared.commit_message(result, cfg.noun), cfg
                )
        except RETIRE_SET as e:
            log(f"FATAL: {e}")
            # Every retiring fault, not just the commit-time git one. A retiring tick
            # ends with the agent's edits still in the corpus and no commit to clear
            # them, and the NEXT tick's cleanliness gate aborts before it reaches any
            # queue — so without this the retry the bump exists to allow never happens.
            _restore_corpus(cfg.repo_root, cfg.corpus_dir, snapshot)
            retire(
                channel=channel,
                batch_ids=[row[key] for row in to_author],
                reason=str(e),
                max_attempts=cfg.max_attempts,
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
            *retired_unkeyable,
        ],
        commit_sha=commit_sha,
    )
    if cfg.post_rotate is not None:
        cfg.post_rotate(
            DrainOutcome(
                batch_id=batch_id, commit_sha=commit_sha, committed=committed,
                held=bucket_held, consumed=bucket_consumed,
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


def _retire_unkeyable(channel: QueueChannel, rows: list[dict], log) -> list[dict]:
    """A row carrying no value under its channel's id field is bad data, not a broken
    system: it retires immediately as a per-item failure and its well-formed batch-mates
    are authored on the same tick. Its whole content is the graveyard record, because
    there is no id to reference it by."""
    if not rows:
        return []
    reason = f"row carries no value under {channel.id_key!r}"
    log(f"{len(rows)} unkeyable row(s) retired: {reason}")
    append_jsonl(
        graveyard_file(channel),
        [{**row, "attempts": int(row.get("attempts") or 0) + 1,
          "deadletter_reason": reason} for row in rows],
    )
    return [{**row, "consumed_category": "consumed_retired"} for row in rows]


def _record_stuck(channel: QueueChannel, exc: BaseException, rows: list[dict]) -> None:
    """Decision 10's operator signal. The count is per TICK, not per row — a non-retiring
    row must stay byte-identical, so the counter cannot live on it the way `attempts`
    does — which is why the drain reads its own last record back before appending."""
    fault_class = type(exc).__name__
    ids = sorted(str(r[channel.id_key]) for r in rows if r.get(channel.id_key))
    path = stuck_report_file(channel)
    previous = read_jsonl_rows(path)
    consecutive = 1
    if previous:
        last = previous[-1]
        same_ids = sorted(str(i) for i in (last.get("row_ids") or [])) == ids
        if last.get("fault_class") == fault_class and same_ids:
            consecutive = int(last.get("consecutive_ticks") or 0) + 1
    append_jsonl(
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
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(blob)
