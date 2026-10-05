#!/usr/bin/env python3
"""The questioner curator: folds `subject: world` findings into `defender/lessons-questioner/`.

Drained in the same tick as the defender lessons curator (one worktree, box, branch and PR
lease) but with its own corpus and queue channel.

Its pre-author gate is idempotency only: a world finding has no defender ground truth to
gate on. Its config sets no drain-run check, since there is no defender behaviour a world
lesson could regress, so the verdict step and repair pass are skipped; the file-vs-batch
attribution check still runs.
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
    loop_paths,
    StageContext,
    StageWiring,
    author_effort as _author_effort,
    author_model as _author_model,
    author_request_limit,
    repo_lock_wait_seconds,
    author_max_attempts,
    author_timeout as _author_timeout,
)
from defender.learning.core.lane_trees import DrainTrees, open_drain_trees
from defender.learning.core.state import QUESTIONER_FINDINGS, LearningState


AuthorError = _shared.AuthorError

_LOG_PREFIX = "questioner_curator"


@model(frozen=True, kw_only=True)
class QuestionerAuthorConfig(CorpusAuthorConfig):
    """The questioner curator's drain config: the shared corpus-author core, its own skip
    report, and the same env-backed model knobs the defender curator carries.

    No hold report, since the idempotency-only gate never holds; but a skip report, because a
    `consumed_skip` is terminal and this line is the only trace the finding was seen."""

    manifest_seed: str | None = None
    author_model: str = field(default_factory=_author_model)
    author_timeout: int = field(default_factory=_author_timeout)
    author_effort: str | None = field(default_factory=_author_effort)


def build_questioner_config(
    paths: LoopPaths, *, state: LearningState, trees: DrainTrees,
    manifest_seed: str | None = None, box: Any = None,
) -> QuestionerAuthorConfig:
    """This channel's config over `paths`, reading and writing its corpus through `trees`, the
    lane's open trees (`open_drain_trees`): they must hold `paths.lessons_questioner_dir` itself
    (`shared.lane_corpus`, else `FatalConfigError`). The config must not outlive `trees`."""
    return QuestionerAuthorConfig(
        repo_root=paths.repo_root,
        corpus_dir=paths.lessons_questioner_dir,
        corpus=_shared.lane_corpus(trees, paths.lessons_questioner_dir),
        tree_for=trees.tree_for,
        corpus_dir_rel=paths.lessons_questioner_dir_rel,
        runs_dir=paths.runs_dir,
        state=state,
        channel=QUESTIONER_FINDINGS,
        repo_lock_wait_seconds=repo_lock_wait_seconds(),
        log_prefix=_LOG_PREFIX,
        author_prompt=paths.learning_dir / "author" / "questioner" / "prompt.md",
        invoke_agent=invoke_agent,
        gate=_gate_questioner,
        buckets=QUESTIONER_BUCKETS,
        post_rotate=_write_skip_report_after_rotate,
        commit_fn=commit_questioner_lessons,
        noun="world findings",
        max_attempts=author_max_attempts(),
        manifest_seed=manifest_seed,
        box=box,
        # No drain-run check (the base default): a world lesson has no defender behaviour to
        # re-verify. `exempt` is unreachable while that holds, but every row is out of scope.
        exempt=lambda row: True,
    )


def questioner_existing_finding_ids(cfg: QuestionerAuthorConfig) -> set[str]:
    """This channel's name for `shared.existing_finding_ids`, over this corpus and id key."""
    return _shared.existing_finding_ids(cfg)


def _gate_questioner(
    batch: list[dict], cfg: QuestionerAuthorConfig,
) -> tuple[list[dict], list[dict], list[dict]]:
    """Idempotency only: a world finding carries no defender disposition to gate on, so every
    row not already attributed to a lesson in this corpus is authored. Returns
    `(held, consumed_pre, to_author)`."""
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
        findings, batch_id, corpus=cfg.corpus.view(), corpus_dir=cfg.corpus_dir,
        corpus_dir_rel=cfg.corpus_dir_rel, label="world findings",
        manifest_seed=cfg.manifest_seed,
        salt=salt,
    )


def invoke_agent(findings: list[dict], batch_id: str, cfg: QuestionerAuthorConfig) -> dict:
    """Spawn the curator to author the batch and self-report."""
    from defender.learning.author import curator_engine

    stage_salt = uuid.uuid4().hex
    return curator_engine.run_curator_stage(
        wiring=StageWiring.for_batch(
            cfg.author_prompt, cfg.author_model, cfg.author_effort,
            batch_id=batch_id, label="questioner_curator",
        ),
        ctx=StageContext(
            learning_run_dir=cfg.state.stage_dir(AUTHOR_DRAIN_LABEL),
            user=build_questioner_user_prompt(findings, batch_id, cfg, salt=stage_salt),
            request_limit=author_request_limit(),
            wall_clock_timeout=cfg.author_timeout,
            repo_root=cfg.repo_root,
            box=cfg.box,
            salt=stage_salt,
        ),
        corpus_dir=cfg.corpus_dir,
        log=_logger,
    )


def _write_skip_report_after_rotate(outcome, cfg: QuestionerAuthorConfig) -> None:
    """The tick's closing edge — after both the corpus commit and the queue rotation.

    `gate_held` is reported too, though this gate never holds: a row there would reveal a gate
    this config doesn't know it has."""
    _shared.write_disposition_report(
        cfg.state, cfg.channel, batch_id=outcome.batch_id,
        groups={"skipped": outcome.consumed.get("consumed_skip", []),
                "gate_held": outcome.gate_held},
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


_logger = logging.getLogger(__name__)


def run_batch(
    *,
    hold_committed: bool = False,
    paths: LoopPaths | None = None,
    state: LearningState | None = None,
    trees: DrainTrees | None = None,
    cfg: QuestionerAuthorConfig | None = None,
    box: Any = None,
) -> int:
    """This channel's entry point; the batch body is `drain.run_batch`. Exactly one of `trees`
    (the lane's open trees: the drain's work step and `main` open them for their label, #1134)
    and `cfg` (a config already built over such trees) is given."""
    if (trees is None) == (cfg is None):
        raise TypeError("run_batch takes exactly one of trees= and cfg=")
    if trees is not None:
        if paths is None or state is None:
            raise TypeError("run_batch with trees= takes paths= and state=")
        cfg = build_questioner_config(paths, state=state, trees=trees, box=box)
    assert cfg is not None  # narrowed for mypy: exactly one of the two was given
    return drain.run_batch(cfg=cfg, hold_committed=hold_committed, box=box)


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: run.py", file=sys.stderr)
        return 64
    paths = loop_paths()
    with LearningState.open(paths) as state, open_drain_trees(
            paths, AUTHOR_DRAIN_LABEL) as trees:
        return run_batch(paths=paths, state=state, trees=trees)


if __name__ == "__main__":
    from defender._log import configure_from_env
    configure_from_env()
    sys.exit(main(sys.argv))
