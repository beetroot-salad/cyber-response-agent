#!/usr/bin/env python3
"""The feedback curator: folds people's feedback instructions into the tenant's `agent/lessons/`.

#1414 D11. A person's comment on a feedback issue that asks the defender to work differently is
queued by the feedback tick on `FEEDBACK_LESSONS`, one row per comment id. This channel authors
those rows into lessons, in the same tick as the defender lessons curator (one batch, box, branch
and PR lease) and the same corpus, but with its own queue, prompt, claim and consumption. A single
row wakes it (`drains._wake_threshold`); the judge-findings path is untouched, and nothing here
writes the registry.

Its pre-author gate is idempotency alone: a comment already cited by a lesson of the corpus is
consumed, never authored twice. A lesson cites the comment id under `source_finding_ids`, like any
lesson cites its source row (`config.provenance_field`). The file-vs-batch attribution check and
the verdict-free lifecycle are the shared drain's, as for the questioner channel.
"""
from __future__ import annotations

import logging
import sys
import uuid
from dataclasses import field
from defender._model import model
from pathlib import Path
from typing import Any

if (_root := str(Path(__file__).resolve().parents[4])) not in sys.path:
    sys.path.insert(0, _root)

from defender.learning.author import drain
from defender.learning.author import shared as _shared
from defender.learning.author._config import BucketSpec, CorpusAuthorConfig
from defender.learning.core.config import (
    AUTHOR_DRAIN_LABEL,
    LoopPaths,
    StageContext,
    StageWiring,
    author_effort as _author_effort,
    author_model as _author_model,
    author_request_limit,
    repo_lock_wait_seconds,
    author_max_attempts,
    author_timeout as _author_timeout,
)
from defender.learning.core.lane_trees import DrainTrees
from defender.learning.core.state import FEEDBACK_LESSONS, LearningState
from defender.knowledge import LESSONS


AuthorError = _shared.AuthorError

_LOG_PREFIX = "feedback_curator"
#: The channel's own system prompt, beside this module (not under `paths`: the prompt ships with the code).
_PROMPT = Path(__file__).with_name("prompt.md")


@model(frozen=True, kw_only=True)
class FeedbackAuthorConfig(CorpusAuthorConfig):
    """The feedback curator's drain config: the shared corpus-author core, its own skip report, and
    the env-backed model knobs the other curators carry."""

    manifest_seed: str | None = None
    author_model: str = field(default_factory=_author_model)
    author_timeout: int = field(default_factory=_author_timeout)
    author_effort: str | None = field(default_factory=_author_effort)


def build_feedback_config(
    paths: LoopPaths, *, state: LearningState, trees: DrainTrees,
    manifest_seed: str | None = None, box: Any = None, batch: Any = None,
) -> FeedbackAuthorConfig:
    """This channel's config, reading and writing the lessons corpus through `trees`, the lane's
    open trees (`open_drain_trees`), which must hold the corpus itself (`shared.lane_corpus`, else
    `FatalConfigError`): `batch`'s draft `agent/lessons`, or — with no batch — the scene's
    `paths.lessons_dir`. The config must not outlive `trees`."""
    root, corpus_dir, corpus_rel = _shared.lane_corpus_dir(paths, batch, LESSONS)
    return FeedbackAuthorConfig(
        repo_root=root,
        corpus_dir=corpus_dir,
        corpus=_shared.lane_corpus(trees, corpus_dir),
        tree_for=trees.tree_for,
        corpus_rel=corpus_rel,
        batch=batch,
        state=state,
        channel=FEEDBACK_LESSONS,
        repo_lock_wait_seconds=repo_lock_wait_seconds(),
        log_prefix=_LOG_PREFIX,
        author_prompt=_PROMPT,
        invoke_agent=invoke_agent,
        gate=_gate_feedback,
        buckets=FEEDBACK_BUCKETS,
        post_rotate=_write_feedback_skip_report,
        noun="feedback instructions",
        max_attempts=author_max_attempts(),
        manifest_seed=manifest_seed,
        box=box,
    )


def _gate_feedback(
    batch: list[dict], cfg: FeedbackAuthorConfig,
) -> tuple[list[dict], list[dict], list[dict]]:
    """Idempotency only: a comment the corpus already cites is consumed, and every other row is
    authored (a person's instruction has no ground truth to gate on). One queue line per comment
    id reaches the model, however many times the tick wrote it."""
    if not batch:
        return [], [], []
    existing_ids = _shared.existing_finding_ids(cfg)
    consumed: list[dict] = []
    to_author: list[dict] = []
    seen: set[str] = set()
    for entry in batch:
        cid = entry["comment_id"]
        if cid in existing_ids:
            consumed.append({**entry, "consumed_category": "consumed_idempotent"})
        elif cid not in seen:
            seen.add(cid)
            to_author.append(entry)
    return [], consumed, to_author


def build_feedback_user_prompt(
    rows: list[dict], batch_id: str, cfg: FeedbackAuthorConfig, *, salt: str | None = None,
) -> str:
    """The spawn's user turn: each row whole, inside the run-salted `lesson_rows` frame only."""
    return _shared.build_curator_user_prompt(
        rows, batch_id, corpus=cfg.corpus.view(), corpus_dir=cfg.corpus_dir,
        corpus_dir_rel=cfg.corpus_rel, label="feedback instructions",
        manifest_seed=cfg.manifest_seed,
        salt=salt,
    )


def invoke_agent(rows: list[dict], batch_id: str, cfg: FeedbackAuthorConfig) -> dict:
    """Spawn the curator to author the batch and self-report."""
    from defender.learning.author import curator_engine

    stage_salt = uuid.uuid4().hex
    return curator_engine.run_curator_stage(
        wiring=StageWiring.for_batch(
            cfg.author_prompt, cfg.author_model, cfg.author_effort,
            batch_id=batch_id, label="feedback_curator",
        ),
        ctx=StageContext(
            learning_run_dir=cfg.state.stage_dir(AUTHOR_DRAIN_LABEL),
            user=build_feedback_user_prompt(rows, batch_id, cfg, salt=stage_salt),
            request_limit=author_request_limit(),
            wall_clock_timeout=cfg.author_timeout,
            repo_root=cfg.repo_root,
            box=cfg.box,
            salt=stage_salt,
        ),
        corpus_dir=cfg.corpus_dir,
        log=_logger,
    )


def _write_feedback_skip_report(outcome, cfg: FeedbackAuthorConfig) -> None:
    """The tick's closing edge: a `consumed_skip` is terminal, so this line is the only trace the
    instruction was seen and declined."""
    _shared.write_disposition_report(
        cfg.state, cfg.channel, batch_id=outcome.batch_id,
        groups={"skipped": outcome.consumed.get("consumed_skip", [])},
    )


FEEDBACK_BUCKETS: tuple[BucketSpec, ...] = (
    BucketSpec(name="committed", disposition="committed", reason_field=None, formatter=str),
    BucketSpec(
        name="consumed_skip", disposition="consumed", reason_field="skip_reason",
        formatter=str,
    ),
)


_logger = logging.getLogger(__name__)


def run_batch(
    *,
    hold_committed: bool = False,
    paths: LoopPaths | None = None,
    state: LearningState | None = None,
    trees: DrainTrees | None = None,
    cfg: FeedbackAuthorConfig | None = None,
    box: Any = None,
    batch: Any = None,
) -> int:
    """This channel's entry point; the batch body is `drain.run_batch`, one claim of `batch`.
    Exactly one of `trees` (the lane's open trees: the drain's work step opens them over the
    batch's draft) and `cfg` (a config already built over such trees) is given."""
    if (trees is None) == (cfg is None):
        raise TypeError("run_batch takes exactly one of trees= and cfg=")
    if trees is not None:
        if paths is None or state is None:
            raise TypeError("run_batch with trees= takes paths= and state=")
        cfg = build_feedback_config(paths, state=state, trees=trees, box=box, batch=batch)
    assert cfg is not None  # narrowed for mypy: exactly one of the two was given
    return drain.run_batch(cfg=cfg, hold_committed=hold_committed, box=box)


def main(argv: list[str]) -> int:
    import argparse

    from defender.learning.core import cli

    parser = argparse.ArgumentParser(description="Curate this tenant's queued feedback")
    parser.add_argument("--tenant", required=True)
    args = parser.parse_args(argv[1:])
    # Like the other curators: a claim of the author lane's one tick, never a run of its own.
    return cli.main(["loop.py", "--author-drain", "--tenant", args.tenant])


if __name__ == "__main__":
    from defender._log import configure_from_env
    configure_from_env()
    sys.exit(main(sys.argv))
