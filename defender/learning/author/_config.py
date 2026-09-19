from __future__ import annotations

from collections.abc import Callable
from defender._model import model
from pathlib import Path
from typing import Any

from defender.learning.author import shared as _shared
from defender.learning.author.verify_forward.checks import ForwardCheck
from defender.learning.core.config import QueueChannel, source_first_party_key


@model(frozen=True)
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


@model(frozen=True, kw_only=True)
class CorpusAuthorConfig:
    """What every corpus-authoring drain needs, in one shape.

    It had two subclasses — the observation curators' config and `author/lessons/run.py`'s —
    feeding the same batch envelope, and where they differed (pre-author gate, buckets, id
    field, append lock, commit trailers, the lessons-only held report) is a FIELD here rather
    than a second copy of the batch driver. #922 retired the observation directions, so one
    subclass is left; the base stays because the fields are the batch driver's contract with
    whatever authors a corpus, not a generalisation over two callers.

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
    #: #773 M2. The drain-run check, per channel — `None` means every (file, finding) pair
    #: is EXEMPT without a verifier call, so nothing is ever BAD and the repair spawn never
    #: fires; vouching (M3.2), the explicit-list commit (M5) and the tree-derived fates
    #: (O4/O5) run on EVERY channel regardless.
    forward_check: ForwardCheck | None = None
    #: A row this channel's check does not cover — EXEMPT by row kind, never by absence
    #: from any id set (which is ERROR territory, J12's already-shipped bug). Consulted
    #: BEFORE any verifier call, never by the check itself.
    exempt: Callable[[dict], bool] = lambda row: False
    #: The repair prompt M4's one bounded spawn reads. `None` is a legitimate, distinguished
    #: member (the shipped default), never a reason to skip the repair pass; a path that is
    #: CONFIGURED but unreadable is O10's fatal-config path.
    repair_prompt: Path | None = None
    #: M4's repair spawn — the injection seam its fake enters through, mirroring
    #: `invoke_agent`. `(pairs, batch_id, cfg) -> dict`; the drain never trusts its return
    #: value, only the tree it re-reads afterward.
    invoke_repair: Callable[..., dict] = _shared.invoke_repair
    #: The verifier-key preflight's resolver (M3.3), the seam `run_curator_stage` already
    #: carries under this exact name (C16), moved to the drain by M3.3 and gated per §7
    #: FK-27 on `forward_check is not None`.
    source_key: Callable[..., object] = source_first_party_key
