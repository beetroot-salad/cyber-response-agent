from __future__ import annotations

import os
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
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
    """One file-backed queue, with its LOCK TOPOLOGY and its row key as data.

    The two lock roles serialise different things: `append_lock` excludes concurrent
    appenders (and the drain's own read/rotate/retire window) from each other, while
    `drain_lock` is the non-blocking "one drainer per channel" gate. A channel no drain
    holds exclusively — `pitfalls`, drained inside the lead-author tick — carries `None`
    for the drain role and takes no exclusive lock."""

    file: Path
    consumed: Path
    append_lock: Path
    drain_lock: Path | None
    id_key: str


def provenance_field(id_key: str) -> str:
    """The corpus frontmatter list a lesson cites its source queue rows under.

    ONE spelling, because two gates that must agree read it: the pre-author idempotency gate
    (`existing_finding_ids` / `existing_observation_ids`), which decides a row was already
    authored, and the drain's attribution gate, which decides a corpus file is vouched for by
    this batch. A file attributable under one spelling and invisible to the other is authored
    again on every following tick — hence derived here, not hand-spelled at each site."""
    return f"source_{id_key}s"


@dataclass(frozen=True)
class LegDirs:
    """The two roots one direction leg writes across: the finished investigation it READS,
    and the per-case leg-output dir it WRITES. Both required."""

    run_dir: Path
    learning_run_dir: Path


@dataclass(frozen=True)
class LoopPaths(DefenderPaths):
    """The loop's paths: every checked-in tree `DefenderPaths` locates, PLUS the mutable
    learning state (queues, locks, run artifacts) rooted at `state_root`.

    It INHERITS the repo-tree paths rather than forwarding them, so `getattr(paths, name)`
    (drains.py resolves each curator's corpus dir that way) answers for the whole set and the
    directory NAMES stay owned by `_paths.py` alone."""

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

    def run_cycle_lock_file(self, run_id: str) -> Path:
        """One lock per RUN, held across the run cycle's box.

        The learn drain's own lease keeps two drainers apart, but it is not the only way into
        `run_one`: the single-run CLI stage calls it directly, holding no lease, and the
        run-cycle box REUSES its container name across starts (`defender-runcycle-{run_id}`).
        So a hand-run pass on a run the drain worker already picked up put two lanes on one
        container name — the collision #955 F-49's ownership check makes honest, and this
        makes not happen. Per run id rather than one global lock: two DIFFERENT runs share
        nothing and must still learn concurrently."""
        return self.state_root / "run-cycle-locks" / f"{run_id}.lock"

    @property
    def learn_drain_lock_file(self) -> Path:
        """The learn drain's own single-drainer lease. Load-bearing since the drain began
        RECLAIMING markers left in `inflight/`: without it, a second concurrent drainer reads
        a live drainer's claim as an orphan and learns the same run twice."""
        return self.state_root / ".learn-drain.lock"

    @property
    def pending_file(self) -> Path:
        return self.pending_dir / "findings.jsonl"

    @property
    def findings_lock_file(self) -> Path:
        """The findings queue's APPEND-role lock — `findings.append_lock` under another
        name, kept because the live-run appender (`persist.append_findings`) reaches it
        off `paths` rather than off a channel.

        A prohibition against folding the two lock roles into the channel once stood here;
        #719 reversed it. The roles are still distinct — they are now two FIELDS on
        `QueueChannel`, so a channel's lock topology reads off one object."""
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
    def actor_observations(self) -> QueueChannel:
        return QueueChannel(
            file=self.pending_dir / "actor_observations.jsonl",
            consumed=self.pending_dir / "actor_observations.consumed.jsonl",
            # The append-lock identity must not move: an appender running older code keeps
            # taking the same file, so a rollover needs no coordination.
            append_lock=self.pending_dir / ".actor.lock",
            drain_lock=self.pending_dir / ".actor.drain.lock",
            id_key="observation_id",
        )

    @property
    def environment_observations(self) -> QueueChannel:
        return QueueChannel(
            file=self.pending_dir / "environment_observations.jsonl",
            consumed=self.pending_dir / "environment_observations.consumed.jsonl",
            append_lock=self.pending_dir / ".environment.lock",
            drain_lock=self.pending_dir / ".environment.drain.lock",
            id_key="observation_id",
        )

    @property
    def actor_environment_observations(self) -> QueueChannel:
        return QueueChannel(
            file=self.pending_dir / "actor_environment_observations.jsonl",
            consumed=self.pending_dir / "actor_environment_observations.consumed.jsonl",
            append_lock=self.pending_dir / ".actor_environment.lock",
            drain_lock=self.pending_dir / ".actor_environment.drain.lock",
            id_key="observation_id",
        )


def _env_state_dir() -> Path | None:
    raw = os.environ.get("DEFENDER_LEARNING_STATE_DIR")
    if not raw:
        return None
    return Path(raw).resolve()


def learning_state_root() -> Path:
    return _env_state_dir() or (REPO_ROOT / "defender" / "learning")


def learning_run_paths(run_id: str) -> RunPaths:
    return RunPaths(learning_state_root() / "runs" / run_id)


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


# Which dispositions select which direction is NOT declared here — it is a field on
# `Direction` (`core/directions.py`). The enum itself lives in `defender/_artifact_schema.py`
# beside the report.md schema that mints it; core.config stays the loop's import surface.

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

# Every env-backed knob is read at CALL time, never as `X = os.environ.get(...)` at import:
# an import-time read freezes at first import and `monkeypatch.setenv` can no longer reach
# the code under test. A module-level constant BUILT from one of these still freezes at ITS
# import (the `AgentDefinition`s' `effort=`, directions.py's `JudgeWiring`s, a signature
# default) — visible at that construction site rather than hidden here.


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


# The judge is on k3 for STABILITY, not per-verdict quality: on a frozen pair, GLM at this
# effort relabelled both cases across identical reps on the caught<->survived /
# refuted<->survived axis — the axis that decides FN/FP accounting and therefore which
# findings become lessons. A judge that relabels the same frozen input injects noise into
# every lesson the author trains on, and the forward-check gate re-runs the same judge so it
# cannot catch it.
def judge_model() -> str:
    return env_str("JUDGE_MODEL", "kimi-k3")


def benign_judge_model() -> str:
    return env_str("BENIGN_JUDGE_MODEL", "kimi-k3")


def judge_effort() -> str:
    return env_str("JUDGE_EFFORT", "medium")


def benign_judge_effort() -> str:
    return env_str("BENIGN_JUDGE_EFFORT", "medium")


@dataclass(frozen=True)
class StageWiring:
    """How one in-process stage is wired, handed down to `run_stage` unchanged.

    Deliberately carries NO limits. `request_limit` and `wall_clock_timeout` live on
    `StageContext` instead, because a wiring is allowed to be a module constant (the two
    `JudgeWiring`s in `directions.py` are) and freezing an env-backed value like
    `subagent_timeout()` at import is the regression the call-time knobs above exist to
    prevent. Anything env-backed belongs on the per-call context, not here."""

    prompt_path: Path
    model: str
    effort: str | None
    trace_name: str
    label: str
    # The batch this spawn is for, retained rather than re-derived: `trace_name` and `label`
    # both encode it, so a stage that also names the batch (`run_curator_stage` logs it and
    # puts it in every AuthorError) would otherwise take it a second time with nothing
    # reconciling the two. `None` on wirings that are not per-batch (the `JudgeWiring`s, the
    # actor/oracle/forward-check spawns, which name a direction or a lead instead).
    #
    # `kw_only` so it stays off the positional tail: `JudgeWiring` extends this class with two
    # more fields and `directions.py` passes the base five positionally.
    batch_id: str | None = field(default=None, kw_only=True)

    @classmethod
    def for_batch(
        cls, prompt_path: Path, model: str, effort: str | None,
        *, batch_id: str, label: str,
    ) -> StageWiring:
        """The per-spawn wiring both drain entry points build.

        The trace name is unique on (batch_id, pid): `batch_id` separates concurrent spawns
        for DIFFERENT runs, `pid` separates concurrent drain PROCESSES sharing one run dir."""
        return cls(
            prompt_path=prompt_path, model=model, effort=effort,
            trace_name=f"{batch_id}.{os.getpid()}.trace.jsonl",
            label=f"{label}:{batch_id}",
            batch_id=batch_id,
        )


@dataclass(frozen=True)
class JudgeWiring(StageWiring):
    """The judge's wiring: the shared fields plus its two per-leg knobs. Field order is
    base-then-own, the order `directions.py` and the test builders pass positionally."""

    comparison_dirname: str
    closed_ticket_read: bool = False


@dataclass(frozen=True)
class StageContext:
    """What one spawn of a stage is about: the per-call transport `run_stage` consumes.

    Built per call, never a module constant — `wall_clock_timeout` reaches
    `subagent_timeout()` and `request_limit` its own env knob, and an import-time
    construction would freeze both. `tests/test_loop_config_env.py` enforces this
    structurally.

    `repo_root` is optional because only the stages that bind a corpus or a skills tree
    (curator, lead author) need one; the pure-prediction stages bind off the run dir alone.

    `run_stage` itself reads only the first four fields — `repo_root`/`box` are the BIND
    inputs, and every engine resolves its deps off THIS object (`bind(..., box=ctx.box)`)
    rather than off a parallel local. Set one here and pass another to `bind` and the two
    silently diverge, with the context reading as the authority it would no longer be.

    `salt` is NOT a bind input: `bind` takes none, because a tool return is framed by
    `_untrusted.wrap_fresh`, which mints its delimiter after the content is in hand. Its one
    reader left is `curator_engine.run_curator_stage`, which uses it to tell whether
    `ctx.user` is already the salted message its own prompt builder assembled."""

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


class RunAlreadyLive(Exception):
    """Another pass already holds this run's per-run lock, so this one did NO work.

    A distinct type rather than a return code, because the two callers of `run_one` must do
    two different things with it and an `int` can carry neither. `learn_drain` has to keep the
    queue marker — a refused pass has not learned the run, and its `_serve_marker` deletes the
    marker for anything that does not raise, which turned "someone else has it" into "this run
    is done and may be forgotten". The CLI has to exit 0 without a traceback: a human asking
    for a run the worker already claimed has made no error.

    TRANSIENT, and that is the whole difference from `RunUnprocessable`: the lock is released
    when the other pass ends, so the marker is RE-QUEUED, never quarantined."""


def pitfalls_threshold() -> int:
    # 3, not 5: at 5 the queue never filled — three archived runs (227 rows, 33 agent-fixable)
    # put only 2 records in front of the curator, so it never ran. A reasoned floor, not a
    # measured one; the yield oracle is deferred.
    return env_int("LEARNING_PITFALLS_THRESHOLD", 3)


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
