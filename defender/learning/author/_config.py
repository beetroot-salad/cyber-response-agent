from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from defender.learning.core.config import QueueChannel


@dataclass(frozen=True)
class BucketSpec:
    """One bucket of an AUTHOR_RESULT, as data.

    The agent partitions the batch it was handed into named buckets; one list drives both
    `validate_agent_result_partition` and the projection.

    `formatter` is why a bare field name was not enough: the reason a bucket writes onto a
    row is not uniform (`forward_bad: <reason>` on the lessons hold, a bare `<reason>` on a
    skip), so the shaping travels with the bucket rather than being re-derived per site."""

    name: str
    #: `committed` (goes through the corpus commit), `consumed` (rotates out of the queue)
    #: or `held` (stays queued carrying a reason).
    disposition: str
    reason_field: str | None
    formatter: Callable[[str], str]


@dataclass(frozen=True, kw_only=True)
class CorpusAuthorConfig:
    """What every corpus-authoring drain needs, in one shape.

    Both drains — `author/curator.py` (the actor/environment curators) and
    `author/lessons/run.py` (the lessons curator) — feed the same batch envelope. Where
    they differ (pre-author gate, buckets, id field, append lock, commit trailers, the
    lessons-only held report) is a FIELD here rather than a second copy of the batch driver.

    Subclassed rather than composed, for the reason `LoopPaths(DefenderPaths)` gives: an
    attribute read (`cfg.repo_root`) keeps answering for the whole set, so the shared fields
    did not have to be re-spelled at ~80 call sites to gain the base.

    `kw_only` because the subclasses add their own required fields and the base ends in one
    that has a default — otherwise every extension field would need a default too, purely
    for dataclass field ordering.

    A prohibition against unifying the two drains once stood here; #719 reversed it. Their
    gates, rotations, locks and id fields really do differ — each difference became a field
    rather than a reason to keep two copies of the batch driver."""

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
    author_effort: str | None
    invoke_agent: Callable[..., dict]
    #: The direction's pre-author policy: `(batch, cfg) -> (held, consumed_pre, to_author)`.
    gate: Callable[..., tuple[list[dict], list[dict], list[dict]]]
    #: The AUTHOR_RESULT buckets this direction declares, in one list.
    buckets: tuple[BucketSpec, ...]
    #: `(message, cfg) -> commit sha | None`. Per-direction because the provenance trailers
    #: are.
    commit_fn: Callable[..., str | None]
    #: What the drain's diagnostics call a row: "observations" / "findings".
    noun: str
    #: The attempt ceiling, BOUND ONCE HERE rather than re-read from the environment inside
    #: the failure handler — so a malformed value fails the tick before any row is read, and
    #: an environment change mid-batch cannot move the ceiling a row is judged against.
    max_attempts: int
    #: Optional hook run after BOTH the corpus commit and the queue rotation, outside the
    #: clauses that name the retire set. The lessons direction populates it with its
    #: held-report writer; the observation directions leave it unset.
    post_rotate: Callable[..., None] | None = None
    box: Any = None
