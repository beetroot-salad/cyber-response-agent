from __future__ import annotations

import logging
import os
from dataclasses import field
from defender._model import model
from pathlib import Path
from typing import Any

from defender._clock import now_iso  # noqa: F401 — re-export: core.config stays the loop's import surface
from defender._env import env_int, env_str
from defender._env import FatalConfigError  # noqa: F401 — re-export; enrolled as stage-fatal in core/faults.py
from defender._run_paths import WIRE_LOG_NAMES, RunPaths  # noqa: F401 — RunPaths re-exported
from defender._paths import DefenderPaths  # noqa: F401 — LoopPaths' base class + re-export


REPO_ROOT = Path(__file__).resolve().parents[3]


@model(frozen=True)
class QueueChannel:
    """One file-backed queue, with its lock topology and row key as data.

    `append_lock` excludes concurrent appenders (and the drain's read/rotate/retire window)
    from each other; `drain_lock` is the non-blocking one-drainer-per-channel gate. A channel
    no drain holds exclusively (`pitfalls`, drained inside the lead-author tick) has `None`."""

    file: Path
    consumed: Path
    append_lock: Path
    drain_lock: Path | None
    id_key: str


def provenance_field(id_key: str) -> str:
    """The corpus frontmatter list a lesson cites its source queue rows under.

    Derived in one place because two gates must agree on it: the pre-author idempotency gate
    and the drain's attribution gate. If they disagreed, a file would be re-authored every
    tick."""
    return f"source_{id_key}s"


#: The quarantine directory's name under `worktree_base`, spelled once for both sides
#: (`LoopPaths.quarantine_dir` reads it, `AuthorBranch.quarantine_dir` writes under it).
QUARANTINE_DIRNAME = "quarantine"


@model(frozen=True)
class LoopPaths(DefenderPaths):
    """The loop's paths: every checked-in tree `DefenderPaths` locates, plus the mutable
    learning state (queues, locks, run artifacts) rooted at `state_root`.

    Inherits the repo-tree paths rather than forwarding them, so `getattr(paths, name)` answers
    for the whole set and directory names stay owned by `_paths.py`."""

    state_dir: Path | None = None

    @property
    def state_root(self) -> Path:
        return self.state_dir if self.state_dir is not None else self.learning_dir

    def with_repo_root(self, repo_root: Path) -> LoopPaths:
        return LoopPaths(repo_root=repo_root, state_dir=self.state_root)

    @property
    def runs_dir(self) -> Path:
        return self.state_root / "runs"

    @property
    def pending_dir(self) -> Path:
        return self.state_root / "_pending"

    @property
    def lead_pending_dir(self) -> Path:
        return self.state_root / "_pending_leads"

    @property
    def pitfalls_pending_dir(self) -> Path:
        return self.state_root / "_pending_pitfalls"

    @property
    def pitfalls(self) -> QueueChannel:
        return QueueChannel(
            file=self.pitfalls_pending_dir / "pitfalls.jsonl",
            consumed=self.pitfalls_pending_dir / "pitfalls.consumed.jsonl",
            append_lock=self.pitfalls_pending_dir / ".pitfalls.lock",
            # No drain-role lock: the pitfalls queue is drained inside the lead-author tick,
            # which nothing else contends for, so one file serves the append role alone.
            drain_lock=None,
            id_key="pitfall_id",
        )

    @property
    def author_lock_file(self) -> Path:
        return self.state_root / "_author.lock"

    @property
    def author_queue_dir(self) -> Path:
        return self.state_root / "author-queue"

    @property
    def author_drain_lock_file(self) -> Path:
        return self.state_root / ".author-drain.lock"

    @property
    def lead_author_drain_lock_file(self) -> Path:
        return self.state_root / ".lead-author-drain.lock"

    @property
    def pending_delivery_dir(self) -> Path:
        """One record per drain batch that committed but whose push or PR failed: the
        commit is on a local branch, and the next tick of that lane delivers it before
        serving anything new."""
        return self.state_root / "_pending_delivery"

    @property
    def quarantine_dir(self) -> Path:
        """Where `quarantine.preserve_tainted_tree` archives a tainted worktree. Follows
        `worktree_base`, not `state_root`: a copied state dir carries none of this host's
        tainted trees. `AuthorBranch.quarantine_dir` is the same path on the writer's side."""
        return self.worktree_base / QUARANTINE_DIRNAME

    @property
    def pending_file(self) -> Path:
        return self.pending_dir / "findings.jsonl"

    @property
    def findings_lock_file(self) -> Path:
        """The findings queue's append-role lock (`findings.append_lock`), exposed because the
        live-run appender (`persist.append_findings`) reaches it off `paths` rather than a
        channel. The drain-role lock is a separate `QueueChannel` field (#719)."""
        return self.pending_dir / ".findings.lock"

    @property
    def findings(self) -> QueueChannel:
        return QueueChannel(
            file=self.pending_file,
            consumed=self.pending_dir / "consumed.jsonl",
            append_lock=self.findings_lock_file,
            drain_lock=self.pending_dir / ".lock",
            id_key="finding_id",
        )

    @property
    def questioner_findings_file(self) -> Path:
        return self.pending_dir / "questioner_findings.jsonl"

    @property
    def questioner_findings(self) -> QueueChannel:
        """The second queue channel: `subject: world` rows, questioner-authored.

        Shares `drain_lock` (`_pending/.lock`) with `findings`, so two curators never hold one
        worktree at once. Its own `append_lock` and `consumed` file, so an appender on one
        channel never blocks the other."""
        return QueueChannel(
            file=self.questioner_findings_file,
            consumed=self.pending_dir / "questioner_consumed.jsonl",
            append_lock=self.pending_dir / ".questioner_findings.lock",
            drain_lock=self.pending_dir / ".lock",
            id_key="finding_id",
        )


def _env_state_dir() -> Path | None:
    raw = os.environ.get("DEFENDER_LEARNING_STATE_DIR")
    if not raw:
        return None
    return Path(raw).resolve()


def learning_state_root() -> Path:
    return _env_state_dir() or (REPO_ROOT / "defender" / "learning")




DEFAULT_PATHS = LoopPaths(repo_root=REPO_ROOT, state_dir=_env_state_dir())


def loop_paths() -> LoopPaths:
    """`DEFAULT_PATHS`, resolved at call time rather than at import.

    The constant freezes `DEFENDER_LEARNING_STATE_DIR` at import; callers that must honour a
    state root set later (a test isolating the queue, a re-pointed worker) use this."""
    return LoopPaths(repo_root=REPO_ROOT, state_dir=_env_state_dir())

LEARNING_DIR = DEFAULT_PATHS.learning_dir


#: The four buckets a lesson can be authored from. Separate from `QUEUEABLE_FINDING_TYPES`,
#: which also includes the family bucket below.
PIPELINE_FINDING_TYPES = {
    "lead-set",
    "lead-quality",
    "analyze-discipline",
    "observability",
}
#: A resolution moved past the branch's fence and the verdict still disagreed with the
#: declared disposition. Produced only by the family judge's appender
#: (`learning/judge/enqueue.py`), so the queue accepts it but it is kept apart from the four
#: above.
FAMILY_ONLY_FINDING_TYPES = {"decision-discipline"}
QUEUEABLE_FINDING_TYPES = PIPELINE_FINDING_TYPES | FAMILY_ONLY_FINDING_TYPES

# Every env-backed knob is read at call time, never at import: an import-time read freezes
# and `monkeypatch.setenv` can't reach it. A module-level constant built from one of these
# (an `AgentDefinition`'s `effort=`, a signature default) still freezes at its own import.


# The judge is on k3 for stability, not per-verdict quality: GLM at this effort relabelled
# identical frozen inputs across reps on the caught<->survived / refuted<->survived axis,
# which decides which findings become lessons. The forward check re-runs the same judge, so
# it can't catch that noise.
def judge_model() -> str:
    return env_str("JUDGE_MODEL", "kimi-k3")




def judge_effort() -> str:
    return env_str("JUDGE_EFFORT", "medium")




@model(frozen=True)
class StageWiring:
    """How one in-process stage is wired, handed down to `run_stage` unchanged.

    Carries no limits: a wiring may be a module constant (the `JudgeWiring`s in
    `directions.py`), which would freeze env-backed values like `subagent_timeout()` at
    import. Those belong on `StageContext`."""

    prompt_path: Path
    model: str
    effort: str | None
    trace_name: str
    label: str
    # The batch this spawn is for, kept explicitly so a stage that names the batch
    # (`run_curator_stage`) needn't take it separately from `trace_name`/`label`. `None` on
    # wirings that aren't per-batch.
    #
    # `kw_only` so it stays off the positional tail: `JudgeWiring` extends this class and
    # `directions.py` passes the base five positionally.
    batch_id: str | None = field(default=None, kw_only=True)

    @classmethod
    def for_batch(
        cls, prompt_path: Path, model: str, effort: str | None,
        *, batch_id: str, label: str,
    ) -> StageWiring:
        """The per-spawn wiring both drain entry points build.

        The trace name is unique on (batch_id, pid): `batch_id` separates concurrent spawns
        for different runs, `pid` separates concurrent drain processes sharing one run dir."""
        return cls(
            prompt_path=prompt_path, model=model, effort=effort,
            trace_name=WIRE_LOG_NAMES.curator_batch(batch_id, os.getpid()),
            label=f"{label}:{batch_id}",
            batch_id=batch_id,
        )




@model(frozen=True)
class StageContext:
    """What one spawn of a stage is about: the per-call transport `run_stage` consumes.

    Built per call, never a module constant, so the env-backed `wall_clock_timeout` and
    `request_limit` aren't frozen at import (`tests/test_loop_config_env.py` enforces this).

    `repo_root` is only needed by stages that bind a corpus or skills tree. `run_stage` reads
    the first four fields; `repo_root`/`box` are bind inputs, and every engine binds off this
    object (`bind(..., box=ctx.box)`) rather than a parallel local, so the two can't diverge.

    `salt` is not a bind input (tool returns are framed by `_untrusted.wrap_fresh`); its reader
    is `curator_engine.run_curator_stage`, to tell whether `ctx.user` is already its own
    salted message."""

    learning_run_dir: Path
    user: str
    request_limit: int
    wall_clock_timeout: int
    repo_root: Path | None = None
    box: Any = None
    salt: str | None = None


def subagent_timeout() -> int:
    return env_int("LEARNING_SUBAGENT_TIMEOUT_SECONDS", 450)


def verifier_model() -> str:
    return env_str("LEARNING_VERIFIER_MODEL", "glm-5.3")


def verifier_effort() -> str:
    return env_str("LEARNING_VERIFIER_EFFORT", "medium")


def verifier_timeout() -> int:
    return env_int("LEARNING_VERIFIER_TIMEOUT_SECONDS", 180)


def verify_batch_workers() -> int:
    n = env_int("LEARNING_VERIFY_BATCH_WORKERS", 8)
    if n < 1:
        raise FatalConfigError(f"LEARNING_VERIFY_BATCH_WORKERS must be >= 1; got {n}")
    return n


def author_model() -> str:
    return env_str("LEARNING_AUTHOR_MODEL", "glm-5.3")


def author_timeout() -> int:
    return env_int("LEARNING_AUTHOR_TIMEOUT_SECONDS", 1800)


def author_effort() -> str:
    return env_str("LEARNING_AUTHOR_EFFORT", "medium")


def author_request_limit() -> int:
    return env_int("LEARNING_AUTHOR_REQUEST_LIMIT", 250)


def author_max_attempts() -> int:
    return env_int("LEARNING_AUTHOR_MAX_ATTEMPTS", 3)


def lead_author_model() -> str:
    return env_str("LEAD_AUTHOR_MODEL", "glm-5.3")


def lead_author_effort() -> str:
    return env_str("LEAD_AUTHOR_EFFORT", "medium")


def lead_author_timeout() -> int:
    return env_int("LEAD_AUTHOR_TIMEOUT_SECONDS", 1800)


def lead_author_request_limit() -> int:
    return env_int("LEAD_AUTHOR_REQUEST_LIMIT", 250)


def repo_lock_wait_seconds() -> int:
    return env_int("LEARNING_REPO_LOCK_WAIT_SECONDS", 1800)


VALID_MERGE_MODES = ("auto_on_green", "human_review")


def merge_mode() -> str:
    return env_str("LEARNING_MERGE_MODE", "human_review", choices=VALID_MERGE_MODES)


class StageAbort(Exception):
    pass


class RunUnprocessable(Exception):
    pass


class RunAlreadyLive(Exception):
    """Another pass already holds this run's per-run lock, so this one did no work.

    A type rather than a return code because callers must act on it: a drain keeps the queue
    marker (the run isn't learned), and the CLI exits 0 without a traceback. Transient, unlike
    `RunUnprocessable`: the marker is re-queued, never quarantined."""


def pitfalls_threshold() -> int:
    # 3, not 5: at 5 the queue never filled (three archived runs put only 2 records in front
    # of the curator). A reasoned floor, not a measured one.
    return env_int("LEARNING_PITFALLS_THRESHOLD", 3)


_logger = logging.getLogger(__name__)


def source_first_party_key(model: str, *, label: str = "judge") -> None:
    from defender.runtime import providers
    from defender._first_party_key import resolve_first_party_key

    try:
        var = providers.provider_for(model).api_key_var
    except ValueError as e:
        raise FatalConfigError(str(e)) from e
    key, src = resolve_first_party_key(var=var, root=REPO_ROOT)
    if key:
        os.environ[var] = key
        _logger.info(f"{label}_key: {var} sourced from {src} (overrides ambient)")
        return
    if os.environ.get(var):
        _logger.info(f"{label}_key: no .env key; using the ambient {var}")
        return
    raise FatalConfigError(
        f"the in-process PydanticAI {label} (model {model!r}) needs {var} — set it in "
        "<repo>/.env or $DEFENDER_ENV_FILE (the in-process stage bills the first-party API)."
    )
