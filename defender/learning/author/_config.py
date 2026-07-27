from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from defender.learning.core.config import QueueChannel


@dataclass(frozen=True, kw_only=True)
class CorpusAuthorConfig:
    """What every corpus-authoring drain needs, in one shape (#713).

    The two drains — `author/curator.py` (the actor/environment curators) and
    `author/lessons/run.py` (the lessons curator) — used to carry the same fields under
    divergent names: `corpus_dir` vs `lessons_dir`, `channel.file` vs `pending_file`. Both
    fed the SAME `shared.run_batch_envelope`, so the divergence bought nothing and cost a
    20-parameter adapter at `curator_engine.run_curator_stage` to normalize between them.

    Subclassed rather than composed, for the reason `LoopPaths(DefenderPaths)` gives: an
    attribute read (`cfg.repo_root`) keeps answering for the whole set, so the shared fields
    did not have to be re-spelled at ~80 call sites to gain the base.

    `kw_only` because the subclasses add their own required fields, and the base ends in one
    that has a default — without it every extension field would have to carry a default too,
    purely to satisfy dataclass field ordering.

    NOT unified here: the drains themselves. `_partition_pre_author` and `rotate_queue`
    differ between the two in argument order, return arity AND predicate (skip-outcomes vs
    idempotency); only the envelope is genuinely common, and both already call it.
    """

    repo_root: Path
    runs_dir: Path
    pending_dir: Path
    corpus_dir: Path
    corpus_dir_rel: str
    channel: QueueChannel
    repo_lock_file: Path
    repo_lock_wait_seconds: int
    log_prefix: str
    author_prompt: Path
    author_model: str
    author_timeout: int
    # `str | None` is the wider of the two the drains carried, and matches what
    # `run_curator_stage` already accepted for `effort`.
    author_effort: str | None
    invoke_agent: Callable[..., dict]
    box: Any = None
