#!/usr/bin/env python3
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from collections.abc import Callable


from defender.learning.author import shared as _shared
from defender.learning.author.verify_forward.checks import ForwardCheck
from defender._corpus import iter_lesson_paths, iter_lessons
from defender._io import append_jsonl, read_jsonl_rows, write_atomic
from defender._run_paths import resolve_run_bundle
from defender.learning.core import config
from defender.learning.core.config import QueueChannel, make_logger
from defender.learning.core.persist import rotate_queue_locked




AuthorError = _shared.AuthorError




@dataclass(frozen=True)
class CuratorConfig:
    repo_root: Path
    pending_dir: Path
    runs_dir: Path
    corpus_dir: Path
    corpus_dir_rel: str
    channel: QueueChannel
    repo_lock_file: Path
    repo_lock_wait_seconds: int
    outcome_author: frozenset[str]
    outcome_skip: frozenset[str]
    trailer_label: str
    generation_fn: Callable[[], int]
    actor_model: str
    log_prefix: str
    author_prompt: Path
    author_model: str
    author_timeout: int
    author_effort: str
    invoke_agent: Callable[[list[dict], str, CuratorConfig], dict]

    @property
    def run_log(self) -> Path:
        return self.pending_dir / f"{self.log_prefix}_run.jsonl"




def read_batch(cfg: CuratorConfig) -> list[dict]:
    return read_jsonl_rows(cfg.channel.file)


_EXISTING_IDS_CACHE: dict[tuple[str, tuple[tuple[str, int], ...]], set[str]] = {}


def _mtime_ns(path: Path) -> int:
    try:
        return path.stat().st_mtime_ns
    except OSError:
        return -1


def existing_observation_ids(corpus_dir: Path) -> set[str]:
    if not corpus_dir.is_dir():
        return set()
    paths = iter_lesson_paths(corpus_dir)
    sig = (str(corpus_dir), tuple((p.name, _mtime_ns(p)) for p in paths))
    cached = _EXISTING_IDS_CACHE.get(sig)
    if cached is not None:
        return set(cached)
    ids: set[str] = set()
    for lesson in iter_lessons(
        corpus_dir, warn_label=lambda p: f"observation-id pre-flight: {p.name}"
    ):
        sids = lesson.fm.get("source_observation_ids") or []
        if isinstance(sids, list):
            ids.update(sid for sid in sids if isinstance(sid, str))
    _EXISTING_IDS_CACHE.clear()
    _EXISTING_IDS_CACHE[sig] = set(ids)
    return ids




def invoke_curator_agent(
    cfg: CuratorConfig,
    observations: list[dict],
    batch_id: str,
    *,
    check: ForwardCheck,
    request_limit: int,
) -> dict:
    from defender.learning.author import curator_engine

    cfg.pending_dir.mkdir(parents=True, exist_ok=True)
    stage_salt = uuid.uuid4().hex
    return curator_engine.run_curator_stage(
        system_prompt_file=cfg.author_prompt,
        batch_id=batch_id,
        user_prompt=_shared.build_curator_user_prompt(
            observations, batch_id, corpus_dir=cfg.corpus_dir,
            corpus_dir_rel=cfg.corpus_dir_rel, label="observations",
            salt=stage_salt,
        ),
        corpus_dir=cfg.corpus_dir,
        check=check,
        runs_dir=cfg.runs_dir,
        pending=cfg.channel.file,
        queued_ids=frozenset(
            str(o["observation_id"]) for o in observations if o.get("observation_id")
        ),
        repo_root=cfg.repo_root,
        learning_run_dir=cfg.pending_dir,
        log=make_logger(cfg.log_prefix),
        model=cfg.author_model,
        effort=cfg.author_effort,
        request_limit=request_limit,
        timeout=cfg.author_timeout,
        salt=stage_salt,
    )




def git_head_sha(repo_root: Path) -> str:
    return _shared.git_head_sha(repo_root)


def changes_outside_corpus(repo_root: Path, corpus_dir_rel: str) -> list[str]:
    return _shared.changes_outside(repo_root, corpus_dir_rel)


def commit_corpus(
    generation: int, model: str, message: str, cfg: CuratorConfig,
) -> str | None:
    return _shared.commit_corpus(
        cfg.repo_root,
        cfg.corpus_dir,
        message,
        trailers=[("Generation", str(generation)), (cfg.trailer_label, model)],
    )


def corpus_dir_clean(repo_root: Path, corpus_dir: Path) -> bool:
    return _shared.corpus_dir_clean(repo_root, corpus_dir)


def _result_list(result: dict, key: str) -> list[Any]:
    return _shared._result_list(result, key)


def _commit_message(result: dict) -> str:
    return _shared._commit_message(result, "observations")




def rotate_queue(
    *,
    held: list[dict],
    consumed: list[dict],
    commit_sha: str | None,
    cfg: CuratorConfig,
) -> None:
    rotate_queue_locked(
        pending_file=cfg.channel.file,
        consumed_file=cfg.channel.consumed,
        lock_file=cfg.channel.lock,
        id_key="observation_id",
        held=held,
        consumed=consumed,
        commit_sha=commit_sha,
        merge_concurrent=False,
    )




def _deadletter_file(queue_file: Path) -> Path:
    return queue_file.with_suffix(".deadletter.jsonl")


def _dead_letter_or_bump(
    batch: list[dict], *, queue_file: Path, pending_dir: Path, id_key: str, reason: str,
) -> None:
    batch_ids = {o[id_key] for o in batch}
    max_attempts = config.LEARNING_AUTHOR_MAX_ATTEMPTS
    survivors: list[dict] = []
    quarantined: list[dict] = []
    for row in read_jsonl_rows(queue_file):
        if row.get(id_key) not in batch_ids:
            survivors.append(row)
            continue
        rec = dict(row)
        rec["attempts"] = int(row.get("attempts") or 0) + 1
        if rec["attempts"] >= max_attempts:
            rec["deadletter_reason"] = reason
            quarantined.append(rec)
        else:
            survivors.append(rec)
    if quarantined:
        pending_dir.mkdir(parents=True, exist_ok=True)
        append_jsonl(_deadletter_file(queue_file), quarantined)
    write_atomic(queue_file, "".join(json.dumps(r) + "\n" for r in survivors))




def run_batch(*, hold_committed: bool, cfg: CuratorConfig) -> int:
    return _shared.run_batch_envelope(
        queue_lock_file=cfg.channel.lock,
        repo_lock_file=cfg.repo_lock_file,
        repo_lock_wait_seconds=cfg.repo_lock_wait_seconds,
        repo_root=cfg.repo_root,
        corpus_dir=cfg.corpus_dir,
        corpus_dir_rel=cfg.corpus_dir_rel,
        log=make_logger(cfg.log_prefix),
        inner=lambda: _run_batch_inner(hold_committed=hold_committed, cfg=cfg),
    )


def _run_batch_inner(*, hold_committed: bool, cfg: CuratorConfig) -> int:
    log = make_logger(cfg.log_prefix)
    batch = read_batch(cfg)
    if not batch:
        log("queue empty — nothing to author")
        return 0
    all_obs = _shared.by_id(batch, "observation_id")
    held, consumed_pre, to_author = _partition_pre_author(batch, cfg)

    batch_id = uuid.uuid4().hex[:12]
    generation = cfg.generation_fn()
    log(
        f"batch={batch_id} generation={generation} actor_model={cfg.actor_model} "
        f"total={len(batch)} to_author={len(to_author)} "
        f"held={len(held)} pre_consumed={len(consumed_pre)}"
    )

    commit_sha: str | None = None
    committed: list[dict] = []
    consumed_skip: list[dict] = []
    if to_author:
        rc, commit_sha, committed, consumed_skip = _author_to_author(
            to_author, all_obs, batch_id, generation, cfg,
        )
        if rc != 0:
            return rc

    held_committed, rotated_committed = _shared.partition_committed(
        committed, hold_committed=hold_committed
    )
    try:
        rotate_queue(
            held=held + held_committed,
            consumed=consumed_pre + rotated_committed + consumed_skip,
            commit_sha=commit_sha,
            cfg=cfg,
        )
    except AuthorError as e:
        log(f"FATAL during rotate: {e}")
        return 2
    log(
        f"done batch={batch_id} committed={len(committed)} "
        f"consumed_skip={len(consumed_skip)} pre_consumed={len(consumed_pre)} "
        f"held={len(held)} commit_sha={commit_sha}"
    )
    return 0


def _partition_pre_author(
    batch: list[dict], cfg: CuratorConfig,
) -> tuple[list[dict], list[dict], list[dict]]:
    existing = existing_observation_ids(cfg.corpus_dir)
    log = make_logger(cfg.log_prefix)
    held: list[dict] = []
    consumed_pre: list[dict] = []
    to_author: list[dict] = []
    for entry in batch:
        oid = entry["observation_id"]
        if oid in existing:
            rec = dict(entry)
            rec["consumed_category"] = "consumed_idempotent"
            consumed_pre.append(rec)
            continue
        outcome = entry.get("judge_outcome")
        if outcome in cfg.outcome_skip:
            rec = dict(entry)
            rec["consumed_category"] = "consumed_skip"
            rec["skip_reason"] = f"outcome_policy:{outcome}"
            consumed_pre.append(rec)
            continue
        src = entry.get("source_run_dir", "")
        if src and not resolve_run_bundle(cfg.runs_dir, src).is_dir():
            log(f"source bundle missing for observation {oid} "
                f"(source_run_dir={src!r} → {resolve_run_bundle(cfg.runs_dir, src)}) — holding")
            rec = dict(entry)
            rec["held_reason"] = "source_bundle_missing"
            held.append(rec)
            continue
        if outcome not in cfg.outcome_author:
            rec = dict(entry)
            rec["held_reason"] = f"unexpected_outcome:{outcome}"
            held.append(rec)
            continue
        to_author.append(entry)
    return held, consumed_pre, to_author


def _author_to_author(
    to_author: list[dict], all_obs: dict[str, dict],
    batch_id: str, generation: int, cfg: CuratorConfig,
) -> tuple[int, str | None, list[dict], list[dict]]:
    log = make_logger(cfg.log_prefix)
    baseline_stray = changes_outside_corpus(cfg.repo_root, cfg.corpus_dir_rel)
    try:
        result = cfg.invoke_agent(to_author, batch_id, cfg)
    except AuthorError as e:
        log(f"FATAL: {e}")
        _dead_letter_or_bump(
            to_author, queue_file=cfg.channel.file, pending_dir=cfg.pending_dir,
            id_key="observation_id", reason=str(e),
        )
        return 2, None, [], []
    try:
        _shared.verify_agent_state(
            cfg.repo_root, result, cfg.corpus_dir, cfg.corpus_dir_rel,
            "observations", baseline_stray,
        )
        _shared.validate_agent_result_partition(
            result, to_author, id_key="observation_id",
            buckets=("committed", "consumed_skip"), noun="observations",
        )
        commit_sha: str | None = None
        if _result_list(result, "committed"):
            commit_sha = commit_corpus(
                generation, cfg.actor_model, _commit_message(result), cfg,
            )
    except AuthorError as e:
        log(f"FATAL: {e}")
        return 2, None, [], []
    committed: list[dict] = []
    consumed_skip: list[dict] = []
    for oid in _result_list(result, "committed"):
        src = all_obs.get(oid)
        if src is None:
            raise AuthorError(f"author committed unknown observation_id={oid!r}")
        rec = dict(src)
        rec["consumed_category"] = "consumed_committed"
        committed.append(rec)
    for entry in _result_list(result, "consumed_skip"):
        oid = entry.get("observation_id")
        src = all_obs.get(oid)
        if src is None:
            raise AuthorError(f"author skipped unknown observation_id={oid!r}")
        rec = dict(src)
        rec["consumed_category"] = "consumed_skip"
        rec["skip_reason"] = entry.get("reason", "")
        consumed_skip.append(rec)
    return 0, commit_sha, committed, consumed_skip
