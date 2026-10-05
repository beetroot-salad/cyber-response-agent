from __future__ import annotations

import enum
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


def provenance_field(id_key: str) -> str:
    """The corpus frontmatter list a lesson cites its source queue rows under.

    Derived in one place because two gates must agree on it: the pre-author idempotency gate
    and the drain's attribution gate. If they disagreed, a file would be re-authored every
    tick."""
    return f"source_{id_key}s"


class DrainLabel(enum.Enum):
    """The drain lanes (#1134, owner decision 2026-09-29; members since #1179). Each lane passes
    its own to `_run_worktree_batch`, and the member answers its own writable trees.

    Only a member names a lane (#1179 amendment, O1'): the lane's behaviour lives on the member,
    so anything else (a string, a member's name, a look-alike enum, an object carrying a value)
    has no `writable_trees` and raises at its first use, rather than every user of a label
    coping with a non-member on its own. A plain `Enum`, never a `str` mixin, so no string
    stands in for one. `str()` is both the display form (a log line's `{label}`) and the written
    form (the pending-delivery record, the quarantine manifest)."""

    AUTHOR = "author_drain"
    LEAD_AUTHOR = "lead_author_drain"  # lint-run-records: ok — the lead-author role/drain/module's own name, not the `lead_author/` record dir

    def __str__(self) -> str:
        """@owns DrainLabel display and written form — the value, never `DrainLabel.AUTHOR`."""
        return self.value

    def writable_trees(self, paths: DefenderPaths) -> tuple[Path, ...]:
        """@owns drain_writable_trees

        The trees under `paths.repo_root` that this lane's drain box mounts read-write, each a
        mount point in its own right: both lessons corpora for the author lane (its two
        curators share one box), the whole skills tree for the lead-author lane (the catalog,
        `skills/gather/queries/`, lies inside it). No two members' trees nest.

        Lexical: read off `paths` as given, nothing resolved or looked up on disk.
        `_drain_box_request` mounts exactly this list and `lane_trees.open_drain_trees` holds
        exactly it, so a tree cannot be mounted writable without a held root, nor a root held
        anywhere but a mount point (#1134 O4). Neither re-derives it."""
        return tuple(getattr(paths, attr) for attr in _WRITABLE_TREE_ATTRS[self])


#: Each lane's writable trees, by the `DefenderPaths` attribute that spells each, in order.
_WRITABLE_TREE_ATTRS: dict[DrainLabel, tuple[str, ...]] = {
    DrainLabel.AUTHOR: ("lessons_dir", "lessons_questioner_dir"),
    DrainLabel.LEAD_AUTHOR: ("skills_dir",),
}


#: Each lane's label, by the name its call sites and the census anchors spell.
AUTHOR_DRAIN_LABEL = DrainLabel.AUTHOR
LEAD_AUTHOR_DRAIN_LABEL = DrainLabel.LEAD_AUTHOR


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
    def quarantine_dir(self) -> Path:
        """Where `quarantine.preserve_tainted_tree` archives a tainted worktree. Follows
        `worktree_base`, not `state_root`: a copied state dir carries none of this host's
        tainted trees. `AuthorBranch.quarantine_dir` is the same path on the writer's side."""
        return self.worktree_base / QUARANTINE_DIRNAME


def _env_state_dir() -> Path | None:
    raw = os.environ.get("DEFENDER_LEARNING_STATE_DIR")
    if not raw:
        return None
    return Path(raw).resolve()




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
