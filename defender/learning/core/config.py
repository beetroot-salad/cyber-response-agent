from __future__ import annotations

import os
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from defender._clock import now_iso  # noqa: F401 — re-export: core.config stays the loop's import surface
from defender._env import env_int, env_str
from defender._env import FatalConfigError  # noqa: F401 — re-export; enrolled as stage-fatal in core/faults.py
from defender._run_paths import RunPaths  # noqa: F401 — re-export
from defender._paths import DefenderPaths  # noqa: F401 — LoopPaths' base class + re-export


REPO_ROOT = Path(__file__).resolve().parents[3]


@dataclass(frozen=True)
class QueueChannel:

    file: Path
    consumed: Path
    lock: Path


@dataclass(frozen=True)
class LoopPaths(DefenderPaths):
    """The loop's paths: every checked-in tree `DefenderPaths` locates, PLUS the mutable
    learning state (queues, locks, run artifacts) rooted at `state_root`.

    It INHERITS the repo-tree paths rather than forwarding them — eleven one-line
    pass-throughs used to shadow `DefenderPaths`, so every path added to `_paths.py` had
    to be declared twice or it was invisible here. Inheriting keeps `getattr(paths, name)`
    (drains.py resolves each curator's corpus dir that way) answering for the whole set,
    and keeps the directory NAMES owned by `_paths.py` alone."""

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
            lock=self.pitfalls_pending_dir / ".pitfalls.lock",
        )

    @property
    def author_lock_file(self) -> Path:
        return self.state_root / "_author.lock"

    @property
    def learn_queue_dir(self) -> Path:
        return self.state_root / "learn-queue"

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
    def pending_file(self) -> Path:
        return self.pending_dir / "findings.jsonl"

    @property
    def findings_lock_file(self) -> Path:
        """The lessons drain's READ-side lock, held while `read_batch` slurps the queue.

        Distinct from `findings.lock` below, which is the drain-wide queue lock the batch
        envelope takes. Two locks, two jobs — do not fold this into the channel."""
        return self.pending_dir / ".findings.lock"

    @property
    def findings(self) -> QueueChannel:
        return QueueChannel(
            file=self.pending_file,
            consumed=self.pending_dir / "consumed.jsonl",
            lock=self.pending_dir / ".lock",
        )

    @property
    def actor_observations(self) -> QueueChannel:
        return QueueChannel(
            file=self.pending_dir / "actor_observations.jsonl",
            consumed=self.pending_dir / "actor_observations.consumed.jsonl",
            lock=self.pending_dir / ".actor.lock",
        )

    @property
    def environment_observations(self) -> QueueChannel:
        return QueueChannel(
            file=self.pending_dir / "environment_observations.jsonl",
            consumed=self.pending_dir / "environment_observations.consumed.jsonl",
            lock=self.pending_dir / ".environment.lock",
        )

    @property
    def actor_environment_observations(self) -> QueueChannel:
        return QueueChannel(
            file=self.pending_dir / "actor_environment_observations.jsonl",
            consumed=self.pending_dir / "actor_environment_observations.consumed.jsonl",
            lock=self.pending_dir / ".actor_environment.lock",
        )


def _env_state_dir() -> Path | None:
    raw = os.environ.get("DEFENDER_LEARNING_STATE_DIR")
    if not raw:
        return None
    return Path(raw).resolve()


def learning_state_root() -> Path:
    return _env_state_dir() or (REPO_ROOT / "defender" / "learning")


def learning_run_paths(run_id: str) -> RunPaths:
    learning_run_dir = learning_state_root() / "runs" / run_id
    return RunPaths(run_dir=learning_run_dir, learning_run_dir=learning_run_dir)


DEFAULT_PATHS = LoopPaths(repo_root=REPO_ROOT, state_dir=_env_state_dir())

LEARNING_DIR = DEFAULT_PATHS.learning_dir

_PIPELINE_DIR = LEARNING_DIR / "pipeline"
ACTOR_PROMPT = _PIPELINE_DIR / "malicious_actor" / "prompt.md"
ACTOR_BENIGN_PROMPT = _PIPELINE_DIR / "benign_actor" / "prompt.md"
ORACLE_PROMPT = _PIPELINE_DIR / "oracle" / "prompt.md"
JUDGE_PROMPT = _PIPELINE_DIR / "judge" / "malicious.md"
JUDGE_BENIGN_PROMPT = _PIPELINE_DIR / "judge" / "benign.md"

LESSONS_ACTOR_DIR = DEFAULT_PATHS.lessons_actor_dir
LESSONS_ENVIRONMENT_DIR = DEFAULT_PATHS.lessons_environment_dir

_LESSONS_SCRIPTS_DIR = REPO_ROOT / "defender" / "scripts" / "lessons"
LESSONS_ENV_RETRIEVE_SCRIPT = _LESSONS_SCRIPTS_DIR / "lessons_env_retrieve.py"
LESSONS_ACTOR_INDEX_SCRIPT = _LESSONS_SCRIPTS_DIR / "lessons_actor_index.py"


DISPOSITION_ENUM = {"benign", "inconclusive", "malicious"}
ADVERSARIAL_DISPOSITIONS = {"benign", "inconclusive"}
BENIGN_DISPOSITIONS = {"malicious", "inconclusive"}

OUTCOME_ENUM = {"caught", "survived", "undecidable", "incoherent", "skip-passthrough"}
BENIGN_OUTCOME_ENUM = {
    "survived",
    "refuted",
    "undecidable",
    "incoherent",
    "skip-passthrough",
}

QUEUEABLE_FINDING_TYPES = {
    "lead-set",
    "lead-quality",
    "analyze-discipline",
    "observability",
}
ADVERSARIAL_AUDIT_ONLY_FINDING_TYPES = {"detection-confirmed"}
ALL_FINDING_TYPES = QUEUEABLE_FINDING_TYPES | ADVERSARIAL_AUDIT_ONLY_FINDING_TYPES
BENIGN_AUDIT_ONLY_FINDING_TYPES = {"disposition-confirmed"}
BENIGN_ALL_FINDING_TYPES = QUEUEABLE_FINDING_TYPES | BENIGN_AUDIT_ONLY_FINDING_TYPES
ACTOR_OBSERVATION_TYPES = {"misprediction", "framing-choice", "discarded-class"}

# Every env-backed knob is read HERE, at call time — one idiom for the whole file (#717).
# The import-time `X = os.environ.get(...)` half froze its value at first import, so a test
# could only move it by reloading the module; these read the live environment, so
# `monkeypatch.setenv` reaches the code under test.
#
# A module-level constant BUILT from one of these still freezes at ITS import (the six
# `AgentDefinition`s' `effort=`, directions.py's `JudgeWiring`s, a signature default) — the
# freeze is now visible at that construction site instead of hidden here.


def actor_model() -> str:
    return env_str("ACTOR_MODEL", "glm-5.2")


def benign_actor_model() -> str:
    return env_str("BENIGN_ACTOR_MODEL", "glm-5.2")


def actor_effort() -> str:
    return env_str("ACTOR_EFFORT", "low")


def benign_actor_effort() -> str:
    return env_str("BENIGN_ACTOR_EFFORT", "low")


def oracle_model() -> str:
    return env_str("ORACLE_MODEL", "glm-5.2")


def oracle_effort() -> str:
    return env_str("ORACLE_EFFORT", "none")


def oracle_max_concurrency() -> int:
    return env_int("ORACLE_MAX_CONCURRENCY", 8)


def judge_model() -> str:
    return env_str("JUDGE_MODEL", "glm-5.2")


def benign_judge_model() -> str:
    return env_str("BENIGN_JUDGE_MODEL", "glm-5.2")


def judge_effort() -> str:
    return env_str("JUDGE_EFFORT", "medium")


def benign_judge_effort() -> str:
    return env_str("BENIGN_JUDGE_EFFORT", "medium")


@dataclass(frozen=True)
class StageWiring:
    """How one in-process stage is wired: the five fields every stage engine used to
    re-declare and hand down to `run_stage` unchanged (#713).

    Deliberately carries NO limits. `request_limit` and `wall_clock_timeout` live on
    `StageContext` instead, because a wiring is allowed to be a module constant (the two
    `JudgeWiring`s in `directions.py` are) and `subagent_timeout()` is env-backed — freezing
    it into an import-time constant is the exact regression #717 closed. Anything env-backed
    belongs on the per-call context, not here."""

    prompt_path: Path
    model: str
    effort: str | None
    trace_name: str
    label: str

    @classmethod
    def for_batch(
        cls, prompt_path: Path, model: str, effort: str | None,
        *, batch_id: str, label: str,
    ) -> StageWiring:
        """The per-spawn wiring both drain entry points build (#713).

        The trace name is unique on (batch_id, pid): `batch_id` separates concurrent spawns
        for DIFFERENT runs, `pid` separates concurrent drain PROCESSES sharing one run dir.
        Both curators derived this identically and separately before; it lives here now."""
        return cls(
            prompt_path=prompt_path, model=model, effort=effort,
            trace_name=f"{batch_id}.{os.getpid()}.trace.jsonl",
            label=f"{label}:{batch_id}",
        )


@dataclass(frozen=True)
class JudgeWiring(StageWiring):
    """The judge's wiring: the shared five plus its two per-leg knobs. Field order is
    base-then-own, which is the order `directions.py` and the test builders already pass
    positionally."""

    comparison_dirname: str
    closed_ticket_read: bool = False


@dataclass(frozen=True)
class StageContext:
    """What one spawn of a stage is about: the per-call transport `run_stage` consumes.

    Built per call, never a module constant — `wall_clock_timeout` reaches
    `subagent_timeout()` and `request_limit` its own env knob, and an import-time
    construction would freeze both (#717). `tests/test_loop_config_env.py` enforces this
    structurally.

    `repo_root` is optional because only the stages that bind a corpus or a skills tree
    (curator, lead author) need one; the pure-prediction stages bind off the run dir alone."""

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
    return env_str("LEARNING_VERIFIER_MODEL", "glm-5.2")


def verifier_effort() -> str:
    return env_str("LEARNING_VERIFIER_EFFORT", "low")


def verifier_timeout() -> int:
    return env_int("LEARNING_VERIFIER_TIMEOUT_SECONDS", 180)


def verify_batch_workers() -> int:
    n = env_int("LEARNING_VERIFY_BATCH_WORKERS", 8)
    if n < 1:
        raise FatalConfigError(f"LEARNING_VERIFY_BATCH_WORKERS must be >= 1; got {n}")
    return n


def author_model() -> str:
    return env_str("LEARNING_AUTHOR_MODEL", "glm-5.2")


def author_timeout() -> int:
    return env_int("LEARNING_AUTHOR_TIMEOUT_SECONDS", 1800)


def author_effort() -> str:
    return env_str("LEARNING_AUTHOR_EFFORT", "low")


def author_actor_model() -> str:
    return env_str("LEARNING_AUTHOR_ACTOR_MODEL", "glm-5.2")


def author_actor_timeout() -> int:
    return env_int("LEARNING_AUTHOR_ACTOR_TIMEOUT_SECONDS", 1800)


def author_actor_effort() -> str:
    return env_str("LEARNING_AUTHOR_ACTOR_EFFORT", "low")


def author_env_model() -> str:
    return env_str("LEARNING_AUTHOR_ENV_MODEL", "glm-5.2")


def author_env_timeout() -> int:
    return env_int("LEARNING_AUTHOR_ENV_TIMEOUT_SECONDS", 1800)


def author_env_effort() -> str:
    return env_str("LEARNING_AUTHOR_ENV_EFFORT", "low")


def author_request_limit() -> int:
    return env_int("LEARNING_AUTHOR_REQUEST_LIMIT", 250)


def author_actor_request_limit() -> int:
    return env_int("LEARNING_AUTHOR_ACTOR_REQUEST_LIMIT", 250)


def author_env_request_limit() -> int:
    return env_int("LEARNING_AUTHOR_ENV_REQUEST_LIMIT", 250)


def author_max_attempts() -> int:
    return env_int("LEARNING_AUTHOR_MAX_ATTEMPTS", 3)


def lead_author_model() -> str:
    return env_str("LEAD_AUTHOR_MODEL", "glm-5.2")


def lead_author_effort() -> str:
    return env_str("LEAD_AUTHOR_EFFORT", "low")


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


def pitfalls_threshold() -> int:
    return env_int("LEARNING_PITFALLS_THRESHOLD", 5)


def make_logger(prefix: str, *, flush: bool = False) -> Callable[[str], None]:
    def _log(msg: str) -> None:
        print(f"[{prefix}] {msg}", file=sys.stderr, flush=flush)
    return _log


_log = make_logger("loop")


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
        _log(f"{label}_key: {var} sourced from {src} (overrides ambient)")
        return
    if os.environ.get(var):
        _log(f"{label}_key: no .env key; using the ambient {var}")
        return
    raise FatalConfigError(
        f"the in-process PydanticAI {label} (model {model!r}) needs {var} — set it in "
        "<repo>/.env or $DEFENDER_ENV_FILE (the in-process stage bills the first-party API)."
    )
