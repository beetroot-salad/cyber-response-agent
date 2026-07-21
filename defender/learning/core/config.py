from __future__ import annotations

import os
import sys
from collections.abc import Callable
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path

from defender._clock import now_iso  # noqa: F401 — re-export: core.config stays the loop's import surface
from defender._env import env_int, env_str
from defender._env import FatalConfigError  # noqa: F401 — re-export; enrolled as stage-fatal in orchestrate
from defender._run_paths import RunPaths  # noqa: F401 — re-export
from defender._paths import DefenderPaths  # noqa: F401 — used by LoopPaths + re-export


REPO_ROOT = Path(__file__).resolve().parents[3]


@dataclass(frozen=True)
class QueueChannel:

    file: Path
    consumed: Path
    lock: Path


@dataclass(frozen=True)
class LoopPaths:

    repo_root: Path
    state_dir: Path | None = None

    @cached_property
    def defender(self) -> DefenderPaths:
        return DefenderPaths(self.repo_root)

    @property
    def learning_dir(self) -> Path:
        return self.defender.learning_dir

    @property
    def lessons_dir(self) -> Path:
        return self.defender.lessons_dir

    @property
    def lessons_actor_dir(self) -> Path:
        return self.defender.lessons_actor_dir

    @property
    def lessons_environment_dir(self) -> Path:
        return self.defender.lessons_environment_dir

    @property
    def lessons_dir_rel(self) -> str:
        return DefenderPaths.lessons_dir_rel

    @property
    def lessons_actor_dir_rel(self) -> str:
        return DefenderPaths.lessons_actor_dir_rel

    @property
    def lessons_environment_dir_rel(self) -> str:
        return DefenderPaths.lessons_environment_dir_rel

    @property
    def catalog_dir(self) -> Path:
        return self.defender.catalog_dir

    @property
    def skills_dir(self) -> Path:
        return self.defender.skills_dir

    @property
    def worktree_base(self) -> Path:
        return self.defender.worktree_base

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
        return self.pending_dir / ".findings.lock"

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

ACTOR_MODEL = os.environ.get("ACTOR_MODEL", "glm-5.2")
BENIGN_ACTOR_MODEL = os.environ.get("BENIGN_ACTOR_MODEL", "glm-5.2")
ACTOR_EFFORT = os.environ.get("ACTOR_EFFORT", "low")
BENIGN_ACTOR_EFFORT = os.environ.get("BENIGN_ACTOR_EFFORT", "low")
ORACLE_MODEL = os.environ.get("ORACLE_MODEL", "glm-5.2")
ORACLE_EFFORT = os.environ.get("ORACLE_EFFORT", "none")
ORACLE_MAX_CONCURRENCY = env_int("ORACLE_MAX_CONCURRENCY", 8)
JUDGE_MODEL = os.environ.get("JUDGE_MODEL", "glm-5.2")
BENIGN_JUDGE_MODEL = os.environ.get("BENIGN_JUDGE_MODEL", "glm-5.2")
JUDGE_EFFORT = os.environ.get("JUDGE_EFFORT", "medium")
BENIGN_JUDGE_EFFORT = os.environ.get("BENIGN_JUDGE_EFFORT", "medium")


@dataclass(frozen=True)
class JudgeWiring:

    prompt_path: Path
    model: str
    effort: str
    trace_name: str
    label: str
    comparison_dirname: str
    closed_ticket_read: bool = False


SUBAGENT_TIMEOUT = env_int("LEARNING_SUBAGENT_TIMEOUT_SECONDS", 450)


VERIFIER_MODEL = os.environ.get("LEARNING_VERIFIER_MODEL", "glm-5.2")
VERIFIER_EFFORT = os.environ.get("LEARNING_VERIFIER_EFFORT", "low")
VERIFIER_TIMEOUT = env_int("LEARNING_VERIFIER_TIMEOUT_SECONDS", 180)
VERIFY_BATCH_WORKERS = env_int("LEARNING_VERIFY_BATCH_WORKERS", 8)


def verify_batch_workers() -> int:
    n = env_int("LEARNING_VERIFY_BATCH_WORKERS", VERIFY_BATCH_WORKERS)
    if n < 1:
        raise FatalConfigError(f"LEARNING_VERIFY_BATCH_WORKERS must be >= 1; got {n}")
    return n

AUTHOR_MODEL = os.environ.get("LEARNING_AUTHOR_MODEL", "glm-5.2")
AUTHOR_TIMEOUT = env_int("LEARNING_AUTHOR_TIMEOUT_SECONDS", 1800)
AUTHOR_EFFORT = os.environ.get("LEARNING_AUTHOR_EFFORT", "low")
AUTHOR_ACTOR_MODEL = os.environ.get("LEARNING_AUTHOR_ACTOR_MODEL", "glm-5.2")
AUTHOR_ACTOR_TIMEOUT = env_int("LEARNING_AUTHOR_ACTOR_TIMEOUT_SECONDS", 1800)
AUTHOR_ACTOR_EFFORT = os.environ.get("LEARNING_AUTHOR_ACTOR_EFFORT", "low")
AUTHOR_ENV_MODEL = os.environ.get("LEARNING_AUTHOR_ENV_MODEL", "glm-5.2")
AUTHOR_ENV_TIMEOUT = env_int("LEARNING_AUTHOR_ENV_TIMEOUT_SECONDS", 1800)
AUTHOR_ENV_EFFORT = os.environ.get("LEARNING_AUTHOR_ENV_EFFORT", "low")
AUTHOR_REQUEST_LIMIT = env_int("LEARNING_AUTHOR_REQUEST_LIMIT", 250)
AUTHOR_ACTOR_REQUEST_LIMIT = env_int("LEARNING_AUTHOR_ACTOR_REQUEST_LIMIT", 250)
AUTHOR_ENV_REQUEST_LIMIT = env_int("LEARNING_AUTHOR_ENV_REQUEST_LIMIT", 250)
LEARNING_AUTHOR_MAX_ATTEMPTS = env_int("LEARNING_AUTHOR_MAX_ATTEMPTS", 3)
LEAD_AUTHOR_MODEL = os.environ.get("LEAD_AUTHOR_MODEL", "glm-5.2")
LEAD_AUTHOR_EFFORT = os.environ.get("LEAD_AUTHOR_EFFORT", "low")
LEAD_AUTHOR_TIMEOUT = env_int("LEAD_AUTHOR_TIMEOUT_SECONDS", 1800)
LEAD_AUTHOR_REQUEST_LIMIT = env_int("LEAD_AUTHOR_REQUEST_LIMIT", 250)

REPO_LOCK_WAIT_SECONDS = env_int("LEARNING_REPO_LOCK_WAIT_SECONDS", 1800)

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
