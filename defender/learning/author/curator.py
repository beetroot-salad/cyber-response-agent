#!/usr/bin/env python3
from __future__ import annotations

import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from collections.abc import Callable


from defender.learning.author import shared as _shared
from defender.learning.author import drain
from defender.learning.author._config import BucketSpec, CorpusAuthorConfig
from defender.learning.author.verify_forward.checks import ForwardCheck
from defender._corpus import iter_lesson_paths, iter_lessons
from defender._run_paths import resolve_run_bundle
from defender.learning.core.config import StageContext, StageWiring, make_logger




AuthorError = _shared.AuthorError




@dataclass(frozen=True, kw_only=True)
class CuratorConfig(CorpusAuthorConfig):
    """The actor/environment curators' drain config: the shared corpus-author core (#713)
    plus the five fields only an observation-queue curator has."""

    outcome_author: frozenset[str]
    outcome_skip: frozenset[str]
    trailer_label: str
    generation_fn: Callable[[], int]
    actor_model: str




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
        wiring=StageWiring.for_batch(
            cfg.author_prompt, cfg.author_model, cfg.author_effort,
            batch_id=batch_id, label="curator",
        ),
        ctx=StageContext(
            learning_run_dir=cfg.pending_dir,
            user=_shared.build_curator_user_prompt(
                observations, batch_id, corpus_dir=cfg.corpus_dir,
                corpus_dir_rel=cfg.corpus_dir_rel, label="observations",
                salt=stage_salt,
            ),
            request_limit=request_limit,
            wall_clock_timeout=cfg.author_timeout,
            repo_root=cfg.repo_root,
            box=cfg.box,
            salt=stage_salt,
        ),
        corpus_dir=cfg.corpus_dir,
        cfg=curator_engine.ForwardCheckConfig(
            check=check,
            runs_dir=cfg.runs_dir,
            pending=cfg.channel.file,
            queued_ids=frozenset(
                str(o["observation_id"]) for o in observations if o.get("observation_id")
            ),
        ),
        log=make_logger(cfg.log_prefix),
    )




OBSERVATION_BUCKETS: tuple[BucketSpec, ...] = (
    BucketSpec(name="committed", disposition="committed", reason_field=None, formatter=str),
    BucketSpec(
        name="consumed_skip", disposition="consumed", reason_field="skip_reason",
        formatter=str,
    ),
)


def commit_observations(message: str, cfg: CuratorConfig) -> str | None:
    """The observation directions' corpus commit: the loop owns provenance, so the
    generation counter and the direction's own model trailer are appended here rather than
    trusted from the agent's message."""
    return _shared.commit_corpus(
        cfg.repo_root,
        cfg.corpus_dir,
        message,
        trailers=[
            ("Generation", str(cfg.generation_fn())),
            (cfg.trailer_label, cfg.actor_model),
        ],
    )


def run_batch(*, hold_committed: bool = False, cfg: CuratorConfig, box: Any = None) -> int:
    """The observation directions' entry point — a config builder's counterpart, not a
    driver: the batch body lives in `drain.run_batch` (#719)."""
    return drain.run_batch(cfg=cfg, hold_committed=hold_committed, box=box)


def _gate_observations(
    batch: list[dict], cfg: CuratorConfig,
) -> tuple[list[dict], list[dict], list[dict]]:
    """The observation directions' pre-author policy: idempotency against the corpus,
    then the direction's outcome policy, then source-bundle existence.

    Direction-specific by NAME as well as by body (#719): the findings direction runs a
    different policy of the same shape, and the two sharing one name was a collision that
    read as duplication."""
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
        bundle = resolve_run_bundle(cfg.runs_dir, src) if src else None
        if bundle is not None and not bundle.is_dir():
            log(f"source bundle missing for observation {oid} "
                f"(source_run_dir={src!r} → {bundle}) — holding")
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
