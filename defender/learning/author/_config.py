from __future__ import annotations

from collections.abc import Callable
from defender._model import model
from pathlib import Path
from typing import Any

from defender._io import Held
from defender.learning.author import shared as _shared
from defender.learning.author.verify_forward.checks import ForwardCheck
from defender.learning.core.config import QueueChannel, source_first_party_key
from defender.learning.core.lane_trees import TreeFor


@model(frozen=True)
class BucketSpec:
    """One bucket of an AUTHOR_RESULT, as data.

    The agent partitions its batch into named buckets; one list drives both
    `validate_agent_result_partition` and the projection. `formatter` shapes the reason a
    bucket writes onto a row, which differs per bucket."""

    name: str
    #: `committed` (goes through the corpus commit), `consumed` (rotates out of the queue)
    #: or `held` (stays queued carrying a reason).
    disposition: str
    reason_field: str | None
    formatter: Callable[[str], str]


@model(frozen=True, kw_only=True)
class CorpusAuthorConfig:
    """What every corpus-authoring drain needs, in one shape.

    Where channels differ (pre-author gate, buckets, id field, locks, commit trailers, held
    report) is a field here rather than a second copy of the batch driver (#719); these fields
    are the driver's contract with whatever authors a corpus.

    Subclassed rather than composed, like `LoopPaths(DefenderPaths)`, so attribute reads
    (`cfg.repo_root`) answer for the whole set. `kw_only` so subclasses can add required
    fields after the base's defaulted ones."""

    repo_root: Path
    runs_dir: Path
    pending_dir: Path
    #: The corpus folder's spelling: git pathspecs, the readers' `where=`, the forward check's
    #: and the curator engine's path checks. Never opened: every host read, write, delete and
    #: listing of the corpus goes through `corpus` (#1134).
    corpus_dir: Path
    #: The corpus mount, held by the lane's open trees (`shared.lane_corpus`): writes through it,
    #: reads through its `view()`. Lives only as long as the `DrainTrees` it came from.
    corpus: Held
    #: The lane's `DrainTrees.tree_for`: a working-copy path (a git-status name joined to
    #: `repo_root`) to its held mount and name, the sibling corpus included, or `None` outside
    #: the lane's mounts.
    tree_for: TreeFor
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
    #: The channel's pre-author policy: `(batch, cfg) -> (held, consumed_pre, to_author)`.
    gate: Callable[..., tuple[list[dict], list[dict], list[dict]]]
    #: The AUTHOR_RESULT buckets this channel declares.
    buckets: tuple[BucketSpec, ...]
    #: `(message, cfg) -> commit sha | None`. Per-channel because the provenance trailers are.
    commit_fn: Callable[..., str | None]
    #: What the drain's diagnostics call a row, e.g. "findings".
    noun: str
    #: The attempt ceiling, bound once here so a malformed value fails the tick before any
    #: row is read and a mid-batch environment change can't move it.
    max_attempts: int
    #: Optional hook run after both the corpus commit and the queue rotation (the lessons
    #: channel's held report).
    post_rotate: Callable[..., None] | None = None
    box: Any = None
    #: The drain-run forward check. `None` makes every pair EXEMPT without a verifier call, so
    #: nothing is BAD and the repair spawn never fires; vouching, the explicit-list commit and
    #: tree-derived fates still run.
    forward_check: ForwardCheck | None = None
    #: A row this channel's check doesn't cover — EXEMPT by row kind, never by absence from an
    #: id set. Consulted before any verifier call.
    exempt: Callable[[dict], bool] = lambda row: False
    #: The repair spawn's prompt. `None` means the shipped default; a configured but
    #: unreadable path is fatal config.
    repair_prompt: Path | None = None
    #: The repair spawn's injection seam, like `invoke_agent`: `(pairs, batch_id, cfg) ->
    #: dict`. The drain ignores its return value and re-reads the tree.
    invoke_repair: Callable[..., dict] = _shared.invoke_repair
    #: Resolves the verifier key in the drain's preflight, only when `forward_check` is set.
    source_key: Callable[..., object] = source_first_party_key
