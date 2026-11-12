#!/usr/bin/env python3
"""The feedback curator: folds people's feedback instructions into the tenant's `agent/lessons/`.

#1414 D11 on the learning store (#1278 A4). A person's comment on a feedback issue that asks the defender
to work differently is recorded by the feedback tick as a `feedback_instruction` work item, one per comment
id, for good (the store's key). This channel authors those items into lessons, as a claim of the author
lane's batch (one batch, box, branch and PR lease with the lessons curator) and the same corpus, but with its
own kind, prompt and claim. One item wakes it (its threshold is fixed at 1, `store_tick.thresholds`); the
judge-findings path is untouched, and nothing here writes the registry.

Its pre-author gate is idempotency alone: a comment already cited by a lesson of the corpus is published,
never authored twice. A lesson cites the comment id under `source_finding_ids`, like any lesson cites its
source row (`config.provenance_field`). The curator's skip is the item's `skipped` fate; the skip report the
file channel wrote is retired (write-only, r8).
"""
from __future__ import annotations

import logging
import sys
import uuid
from collections.abc import Callable, Sequence
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
    LoopPaths,
    StageContext,
    StageWiring,
    author_effort as _author_effort,
    author_model as _author_model,
    author_request_limit,
    author_timeout as _author_timeout,
)
from defender.learning.core.lane_trees import DrainTrees
from defender.learning.core.state import FEEDBACK_LESSONS
from defender.knowledge import LESSONS


AuthorError = _shared.AuthorError

_LOG_PREFIX = "feedback_curator"
#: The channel's own system prompt, beside this module (not under `paths`: the prompt ships with the code).
_PROMPT = Path(__file__).with_name("prompt.md")


@model(frozen=True, kw_only=True)
class FeedbackAuthorConfig(CorpusAuthorConfig):
    """The feedback curator's drain config: the shared corpus-author core and the env-backed model knobs
    the other curators carry."""

    manifest_seed: str | None = None
    author_model: str = field(default_factory=_author_model)
    author_timeout: int = field(default_factory=_author_timeout)
    author_effort: str | None = field(default_factory=_author_effort)


def build_feedback_config(  # noqa: PLR0913 — the claim's seams: its trees, batch, box, feedback and model
    paths: LoopPaths, *, trees: DrainTrees,
    manifest_seed: str | None = None, box: Any = None, batch: Any = None,
    feedback: str | None = None, make_model: Callable[..., Any] | None = None,
) -> FeedbackAuthorConfig:
    """This channel's config, reading and writing the lessons corpus through `trees`, the lane's
    open trees (`open_drain_trees`), which must hold the corpus itself (`shared.lane_corpus`, else
    `FatalConfigError`): `batch`'s draft `agent/lessons`, or — with no batch — the scene's
    `paths.lessons_dir`. `feedback` is a replacement's framed review text (#1278 H13), `make_model`
    the spawn's model seam. The config must not outlive `trees`."""
    root, corpus_dir, corpus_rel = _shared.lane_corpus_dir(paths, batch, LESSONS)
    return FeedbackAuthorConfig(
        repo_root=root,
        corpus_dir=corpus_dir,
        corpus=_shared.lane_corpus(trees, corpus_dir),
        tree_for=trees.tree_for,
        corpus_rel=corpus_rel,
        batch=batch,
        channel=FEEDBACK_LESSONS,
        log_prefix=_LOG_PREFIX,
        author_prompt=_PROMPT,
        invoke_agent=invoke_agent,
        gate=_gate_feedback,
        buckets=FEEDBACK_BUCKETS,
        noun="feedback instructions",
        manifest_seed=manifest_seed,
        box=box,
        feedback=feedback,
        make_model=make_model,
    )


def _gate_feedback(
    batch: list[dict], cfg: FeedbackAuthorConfig,
) -> tuple[list[dict], list[dict], list[dict]]:
    """Idempotency only: a comment the corpus already cites is consumed (published), and every other
    row is authored (a person's instruction has no ground truth to gate on)."""
    if not batch:
        return [], [], []
    existing_ids = _shared.existing_finding_ids(cfg)
    consumed: list[dict] = []
    to_author: list[dict] = []
    for entry in batch:
        if entry["comment_id"] in existing_ids:
            consumed.append({**entry, "consumed_category": "consumed_idempotent"})
        else:
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
        salt=salt, feedback=cfg.feedback,
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
            learning_run_dir=curator_engine.call_folder_of(cfg, "feedback"),
            user=build_feedback_user_prompt(rows, batch_id, cfg, salt=stage_salt),
            request_limit=author_request_limit(),
            wall_clock_timeout=cfg.author_timeout,
            repo_root=cfg.repo_root,
            box=cfg.box,
            salt=stage_salt,
        ),
        corpus_dir=cfg.corpus_dir,
        log=_logger,
        run_author=curator_engine.curator_runner(cfg.make_model),
    )


FEEDBACK_BUCKETS: tuple[BucketSpec, ...] = (
    BucketSpec(name="committed", disposition="committed", reason_field=None, formatter=str),
    BucketSpec(
        name="consumed_skip", disposition="consumed", reason_field="skip_reason",
        formatter=str,
    ),
)


_logger = logging.getLogger(__name__)


def run_batch(  # noqa: PLR0913 — the drain's work step's call shape: the claim, its trees and its seams
    *,
    paths: LoopPaths | None = None,
    trees: DrainTrees | None = None,
    cfg: FeedbackAuthorConfig | None = None,
    box: Any = None,
    batch: Any = None,
    items: Sequence[drain.Item] = (),
    outcomes: dict[tuple[str, str], Any] | None = None,
    feedback: str | None = None,
    make_model: Callable[..., Any] | None = None,
) -> int:
    """This channel's entry point over a learning store claim (#1278 D1, A4); the claim body is
    `drain.run_batch`, one claim of `batch`. `items` are the claim's `feedback_instruction` items,
    `outcomes` the map their fates are written to (a comment the corpus already cites: published; the
    curator's skip: skipped), `feedback` a replacement's framed review text. Exactly one of `trees`
    (the lane's open trees: the drain's work step opens them over the batch's draft) and `cfg` (a
    config already built over such trees) is given."""
    if (trees is None) == (cfg is None):
        raise TypeError("run_batch takes exactly one of trees= and cfg=")
    if trees is not None:
        if paths is None:
            raise TypeError("run_batch with trees= takes paths=")
        cfg = build_feedback_config(paths, trees=trees, box=box, batch=batch, feedback=feedback,
                                    make_model=make_model)
    assert cfg is not None  # narrowed for mypy: exactly one of the two was given
    return drain.run_batch(cfg=cfg, items=items, outcomes=outcomes if outcomes is not None else {}, box=box)


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
