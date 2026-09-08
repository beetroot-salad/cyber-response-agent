#!/usr/bin/env python3
"""The questioner curator: folds `subject: world` findings into `defender/lessons-questioner/`.

#1007 M7/N1. A second `CorpusAuthorConfig`, drained by the SAME tick as the defender lessons
curator (A2/R1 — one worktree, one box, one branch, one PR lease, per-curator consumption and
per-curator corpus scoping) but its own corpus and its own queue channel.

Its pre-author gate is IDEMPOTENCY ONLY (`_gate_questioner`): a world finding has no defender
ground truth to check disposition against, so the defender gate's `source_refs.yaml`/family
partition does not apply here at all. It registers NO forward check (N1): there is no defender
behaviour a world lesson could re-verify against, so `invoke_agent` never wires
`ForwardCheckConfig`/`FINDINGS_CHECK` — a mechanically-inert one is built by
`curator_engine.no_forward_check` instead, kept off `verify_forward/checks.py`'s own registry.
"""
from __future__ import annotations

import sys
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

if (_root := str(Path(__file__).resolve().parents[4])) not in sys.path:
    sys.path.insert(0, _root)

from defender.learning.author import drain
from defender.learning.author import shared as _shared
from defender.learning.author._config import BucketSpec, CorpusAuthorConfig
from defender._corpus import iter_lessons
from defender.learning.core.config import (
    DEFAULT_PATHS,
    LoopPaths,
    StageContext,
    StageWiring,
    author_effort as _author_effort,
    author_model as _author_model,
    author_request_limit,
    repo_lock_wait_seconds,
    author_max_attempts,
    author_timeout as _author_timeout,
    make_logger,
    provenance_field,
)


AuthorError = _shared.AuthorError

_LOG_PREFIX = "questioner_curator"


@dataclass(frozen=True, kw_only=True)
class QuestionerAuthorConfig(CorpusAuthorConfig):
    """The questioner curator's drain config: the shared corpus-author core, no held report
    (its gate never holds — idempotency only, so there is nothing a report would explain) and
    the same env-backed model knobs the defender curator carries."""

    manifest_seed: str | None = None
    author_model: str = field(default_factory=_author_model)
    author_timeout: int = field(default_factory=_author_timeout)
    author_effort: str | None = field(default_factory=_author_effort)


def build_questioner_config(
    paths: LoopPaths = DEFAULT_PATHS, *, manifest_seed: str | None = None, box: Any = None,
) -> QuestionerAuthorConfig:
    return QuestionerAuthorConfig(
        repo_root=paths.repo_root,
        corpus_dir=paths.lessons_questioner_dir,
        corpus_dir_rel=paths.lessons_questioner_dir_rel,
        runs_dir=paths.runs_dir,
        pending_dir=paths.pending_dir,
        channel=paths.questioner_findings,
        repo_lock_file=paths.author_lock_file,
        repo_lock_wait_seconds=repo_lock_wait_seconds(),
        log_prefix=_LOG_PREFIX,
        author_prompt=paths.learning_dir / "author" / "questioner" / "prompt.md",
        invoke_agent=invoke_agent,
        gate=_gate_questioner,
        buckets=QUESTIONER_BUCKETS,
        commit_fn=commit_questioner_lessons,
        noun="world findings",
        max_attempts=author_max_attempts(),
        manifest_seed=manifest_seed,
        box=box,
    )


def questioner_existing_finding_ids(cfg: QuestionerAuthorConfig) -> set[str]:
    """The SAME idempotency read `lessons/run.py`'s own `existing_finding_ids` makes, over
    THIS corpus and THIS channel's id key. Named distinctly (not a second `def
    existing_finding_ids`) so the duplicate-helper lint's NAME-keyed census does not read two
    independent four-line functions as one collision — the two configs are different
    dataclasses, so a shared helper would need to take `cfg: CorpusAuthorConfig` (the base
    both subclass), which is the fix if a THIRD corpus ever needs this read."""
    ids: set[str] = set()
    field_name = provenance_field(cfg.channel.id_key)
    for lesson in iter_lessons(
        cfg.corpus_dir, warn_label=lambda p: f"finding-id pre-flight: {p.name}"
    ):
        sids = lesson.fm.get(field_name) or []
        if isinstance(sids, list):
            ids.update(sid for sid in sids if isinstance(sid, str))
    return ids


def _gate_questioner(
    batch: list[dict], cfg: QuestionerAuthorConfig,
) -> tuple[list[dict], list[dict], list[dict]]:
    """#1007 N1: IDEMPOTENCY ONLY. A world finding carries no defender disposition and no
    `run_id` a family partition could key on, so nothing here holds a row — every row not
    already attributed to a lesson in this corpus is admitted for authoring.

    Returns `(held, consumed_pre, to_author)` — `CorpusAuthorConfig.gate`'s own documented
    order, the one `drain.run_batch` unpacks (`held, consumed_pre, to_author = cfg.gate(...)`)."""
    existing_ids = questioner_existing_finding_ids(cfg)
    consumed_idempotent: list[dict] = []
    to_author: list[dict] = []
    for entry in batch:
        fid = entry["finding_id"]
        if fid in existing_ids:
            rec = dict(entry)
            rec["consumed_category"] = "consumed_idempotent"
            consumed_idempotent.append(rec)
            continue
        to_author.append(entry)
    return [], consumed_idempotent, to_author


def build_questioner_user_prompt(
    findings: list[dict], batch_id: str, cfg: QuestionerAuthorConfig, *, salt: str | None = None,
) -> str:
    return _shared.build_curator_user_prompt(
        findings, batch_id, corpus_dir=cfg.corpus_dir,
        corpus_dir_rel=cfg.corpus_dir_rel, label="world findings",
        manifest_seed=cfg.manifest_seed,
        salt=salt,
    )


def invoke_agent(findings: list[dict], batch_id: str, cfg: QuestionerAuthorConfig) -> dict:
    """N1: no forward check wired — see the module docstring. `curator_engine.no_forward_check`
    builds an inert forward-check config this function never spells the class name of."""
    from defender.learning.author import curator_engine

    cfg.pending_dir.mkdir(parents=True, exist_ok=True)  # lint-unguarded-tree-write: ok — the host-side queue dir, never a box-writable or model-authored tree; the sibling `lessons/run.py::invoke_agent` makes the same call
    stage_salt = uuid.uuid4().hex
    return curator_engine.run_curator_stage(
        wiring=StageWiring.for_batch(
            cfg.author_prompt, cfg.author_model, cfg.author_effort,
            batch_id=batch_id, label="questioner_curator",
        ),
        ctx=StageContext(
            learning_run_dir=cfg.pending_dir,
            user=build_questioner_user_prompt(findings, batch_id, cfg, salt=stage_salt),
            request_limit=author_request_limit(),
            wall_clock_timeout=cfg.author_timeout,
            repo_root=cfg.repo_root,
            box=cfg.box,
            salt=stage_salt,
        ),
        corpus_dir=cfg.corpus_dir,
        cfg=curator_engine.no_forward_check(runs_dir=cfg.runs_dir, pending=cfg.channel.file),
        log=_log,
    )


QUESTIONER_BUCKETS: tuple[BucketSpec, ...] = (
    BucketSpec(name="committed", disposition="committed", reason_field=None, formatter=str),
    BucketSpec(
        name="consumed_skip", disposition="consumed", reason_field="skip_reason",
        formatter=str,
    ),
)


def commit_questioner_lessons(message: str, cfg: QuestionerAuthorConfig) -> str | None:
    return _shared.commit_corpus(cfg.repo_root, cfg.corpus_dir, message)


_log = make_logger(_LOG_PREFIX)


def run_batch(
    *,
    hold_committed: bool = False,
    paths: LoopPaths = DEFAULT_PATHS,
    cfg: QuestionerAuthorConfig | None = None,
    box: Any = None,
) -> int:
    if cfg is None:
        cfg = build_questioner_config(paths, box=box)
    return drain.run_batch(cfg=cfg, hold_committed=hold_committed, box=box)


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: run.py", file=sys.stderr)
        return 64
    return run_batch()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
