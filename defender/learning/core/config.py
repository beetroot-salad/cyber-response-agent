from __future__ import annotations

from defender.records._locations import (LearningRoot)

import dataclasses
import enum
import logging
import math
import os
from dataclasses import field
from defender._model import model
from pathlib import Path
from collections.abc import Mapping
from typing import Any

from defender._clock import now_iso  # noqa: F401 — re-export: core.config stays the loop's import surface
from defender.configuration._env import env_int, env_str
from defender.configuration._env import FatalConfigError  # noqa: F401 — re-export; enrolled as stage-fatal in core/faults.py
from defender.run_repository import WIRE_LOG_NAMES
from defender._paths import DefenderPaths  # noqa: F401 — LoopPaths' base class + re-export


from defender.tenancy._tenant import Tenant

REPO_ROOT = Path(__file__).resolve().parents[3]


def provenance_field(id_key: str) -> str:
    """The corpus frontmatter list a lesson cites its source queue rows under.

    Derived in one place because two gates must agree on it: the pre-author idempotency gate
    and the drain's attribution gate. If they disagreed, a file would be re-authored every
    tick."""
    return f"source_{id_key}s"


class DrainLabel(enum.Enum):
    """The drain lanes (#1134, owner decision 2026-09-29; members since #1179). Each lane passes
    its own to `_run_worktree_batch`, and the member answers its own writable trees."""

    AUTHOR = "author_drain"
    LEAD_AUTHOR = "lead_author_drain"  # lint-run-records: ok — the lead-author role/drain/module's own name, not the `lead_author/` record dir

    def __str__(self) -> str:
        """@owns DrainLabel display and written form — the value, never `DrainLabel.AUTHOR`."""
        return self.value

    def writable_trees(self, paths: DefenderPaths) -> tuple[Path, ...]:
        """@owns drain_writable_trees"""
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

    state_dir: Path | LearningRoot | None = None
    tenant: Tenant | None = field(default=None, kw_only=True)

    def __post_init__(self) -> None:
        if self.tenant is not None and not isinstance(self.state_dir, LearningRoot):
            raise FatalConfigError("tenant learning state requires LearningRoot")
        if self.tenant is None and isinstance(self.state_dir, LearningRoot):
            raise FatalConfigError("scratch learning state requires an explicit Path")

    @classmethod
    def for_tenant(cls, tenant: Tenant) -> LoopPaths:
        """@owns tenant learning root — accepted identity selects mutable state, never env."""
        from defender.run_repository._held import require_accepted_tenant

        accepted = require_accepted_tenant(tenant)
        return accepted.learning_paths(cls, repo_root=REPO_ROOT)

    @property
    def state_root(self) -> Path | LearningRoot:
        if self.state_dir is None:
            raise FatalConfigError("learning state requires an explicit tenant or scratch state_dir")
        return self.state_dir

    def with_repo_root(self, repo_root: Path) -> LoopPaths:
        return LoopPaths(repo_root=repo_root, state_dir=self.state_root, tenant=self.tenant)

    @property
    def quarantine_dir(self) -> Path:
        """Where `quarantine.preserve_tainted_tree` archives a tainted worktree. Follows
        `worktree_base`, not `state_root`: a copied state dir carries none of this host's
        tainted trees. `AuthorBranch.quarantine_dir` is the same path on the writer's side."""
        return self.worktree_base / QUARANTINE_DIRNAME


#: The three buckets a lesson can be authored from. Separate from `QUEUEABLE_FINDING_TYPES`,
#: which also includes the family bucket below. A deployment gap is never a defender type
#: (#1234 P-a): it is reported to the user, never taught.
PIPELINE_FINDING_TYPES = {
    "lead-set",
    "lead-quality",
    "analyze-discipline",
}
#: A resolution moved past the branch's fence and the verdict still disagreed with the
#: declared disposition. Produced only by the family judge's appender
#: (`learning/judge/enqueue.py`), so the queue accepts it but it is kept apart from the three
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



#: The oracle roles' defaults (#1224, M11): each routes on its own, so a launch with no knob set
#: still preflights clean. Read through the accessors below, at call time.
ORACLE_MODEL_DEFAULT = "kimi-k3"
ORACLE_CHECK_MODEL_DEFAULT = "glm-5.3"
ORACLE_EFFORT_DEFAULT = "medium"
ORACLE_CHECK_EFFORT_DEFAULT = "medium"


def oracle_model() -> str:
    return env_str("ORACLE_MODEL", ORACLE_MODEL_DEFAULT)


def oracle_check_model() -> str:
    return env_str("ORACLE_CHECK_MODEL", ORACLE_CHECK_MODEL_DEFAULT)


def oracle_effort() -> str:
    return env_str("ORACLE_EFFORT", ORACLE_EFFORT_DEFAULT)


def oracle_check_effort() -> str:
    return env_str("ORACLE_CHECK_EFFORT", ORACLE_CHECK_EFFORT_DEFAULT)


#: The oracle's knobs (#1224): platform settings, read from the process environment at the
#: process boundary, never tenant settings.
KNOB_MODEL = "ORACLE_MODEL"
KNOB_CHECK_MODEL = "ORACLE_CHECK_MODEL"
KNOB_EFFORT = "ORACLE_EFFORT"
KNOB_CHECK_EFFORT = "ORACLE_CHECK_EFFORT"
KNOB_RETRY_CAP = "ORACLE_RETRY_CAP"
KNOB_RATE = "ORACLE_RATE"
KNOB_BUDGET = "ORACLE_BUDGET"
KNOB_TURN_DEADLINE = "ORACLE_TURN_DEADLINE"

DEFAULT_RETRY_CAP = 3
#: Oracle-side queries per second, per episode (a sibling gets its slice R/k from the launcher).
DEFAULT_RATE = 5.0
#: The oracle's own spend bound per world, in USD (`defender.configuration._pricing` on each response's
#: usage, oracle and verifier together). Not the investigator's budget.
DEFAULT_BUDGET = 20.0
#: Seconds one attempt may take, rate-limiter waits excluded (M03=A, M11=A).
DEFAULT_TURN_DEADLINE = 300.0


@dataclasses.dataclass(frozen=True)
class OracleSettings:
    retry_cap: int
    rate: float
    budget: float
    turn_deadline: float
    model: str
    check_model: str
    effort: str
    check_effort: str


def _positive_float(knobs: Mapping[str, str], name: str, default: float, *,
                    allow_zero: bool = False) -> float:
    raw = knobs.get(name)
    if raw is None or raw == "":
        return default
    try:
        value = float(raw)
    except ValueError:
        raise FatalConfigError(f"{name} must be a number; got {raw!r}") from None
    if not math.isfinite(value) or value < 0 or (value == 0 and not allow_zero):
        bound = "zero or more" if allow_zero else "greater than zero"
        raise FatalConfigError(f"{name} must be a finite number {bound}; got {raw!r}")
    return value


def oracle_settings(env: Mapping[str, str]) -> OracleSettings:
    """The oracle's knobs read from `env`. A bad knob raises `FatalConfigError` naming it."""
    raw_cap = env.get(KNOB_RETRY_CAP)
    retry_cap = DEFAULT_RETRY_CAP
    if raw_cap is not None and raw_cap != "":
        try:
            retry_cap = int(raw_cap)
        except ValueError:
            raise FatalConfigError(
                f"{KNOB_RETRY_CAP} must be a whole number of at least 1; got {raw_cap!r}") from None
        if retry_cap < 1:
            raise FatalConfigError(
                f"{KNOB_RETRY_CAP} must be a whole number of at least 1; got {raw_cap!r}")
    return OracleSettings(
        retry_cap=retry_cap,
        rate=_positive_float(env, KNOB_RATE, DEFAULT_RATE),
        budget=_positive_float(env, KNOB_BUDGET, DEFAULT_BUDGET, allow_zero=True),
        turn_deadline=_positive_float(env, KNOB_TURN_DEADLINE, DEFAULT_TURN_DEADLINE),
        model=env.get(KNOB_MODEL, ORACLE_MODEL_DEFAULT),
        check_model=env.get(KNOB_CHECK_MODEL, ORACLE_CHECK_MODEL_DEFAULT),
        effort=env.get(KNOB_EFFORT, ORACLE_EFFORT_DEFAULT),
        check_effort=env.get(KNOB_CHECK_EFFORT, ORACLE_CHECK_EFFORT_DEFAULT),
    )


def process_oracle_settings() -> OracleSettings:
    """`oracle_settings` over this process's environment."""
    return oracle_settings(os.environ)


def oracle_settings_with(**given: Any) -> OracleSettings:
    """This process's oracle knobs with each `given` value that is not `None` in its place: the
    one place a caller's explicit knob and the environment's default are reconciled."""
    return dataclasses.replace(process_oracle_settings(),
                               **{name: value for name, value in given.items() if value is not None})




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
    """What one spawn of a stage is about: the per-call transport `run_stage` consumes."""

    learning_run_dir: Path
    user: str
    request_limit: int
    wall_clock_timeout: int
    repo_root: Path | None = None
    box: Any = None
    salt: str | None = None


def subagent_timeout() -> int:
    return env_int("LEARNING_SUBAGENT_TIMEOUT_SECONDS", 450)


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
