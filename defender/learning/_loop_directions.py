"""Direction specs — the data that distinguishes the adversarial (FN-hunting) and
benign (FP-hunting) legs, so `run_direction` has one body.

Each spec wires the seam methods, validator, observation appender, output filenames,
and the per-direction observation-curator trigger.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from defender.learning._loop_config import (
    BENIGN_JUDGE_EFFORT,
    BENIGN_JUDGE_MODEL,
    JUDGE_BENIGN_PROMPT,
    JUDGE_EFFORT,
    JUDGE_MODEL,
    JUDGE_PROMPT,
    JudgeWiring,
    LoopPaths,
)
from defender.learning._loop_persist import (
    append_actor_environment_observations,
    append_actor_observations,
    append_environment_observations,
)
from defender.learning._loop_validate import validate_judge_benign_doc, validate_judge_doc


ADVERSARIAL_WIRING = JudgeWiring(
    JUDGE_PROMPT, JUDGE_MODEL, JUDGE_EFFORT, "judge_trace.jsonl", "judge",
    "comparison", "judge-settings.resolved.json",
)
BENIGN_WIRING = JudgeWiring(
    JUDGE_BENIGN_PROMPT, BENIGN_JUDGE_MODEL, BENIGN_JUDGE_EFFORT,
    "judge_benign_trace.jsonl", "judge-benign",
    "comparison_benign", "judge-benign-settings.resolved.json",
)


@dataclass(frozen=True)
class ObsTrigger:
    """Threshold-gated trigger for a direction's observation-curator module."""

    pending_file: Callable[[LoopPaths], object]  # LoopPaths -> the queue file Path
    threshold_env: str
    module_name: str
    pending_label: str


@dataclass(frozen=True)
class Direction:
    name: str
    invoke_actor: Callable        # (agents, run_dir, lrd, alert_rule_key) -> story
    # Plain data, not a Callable like the other seams: the judge collapsed to a single
    # agents.judge(wiring, ...) method, so the per-direction variation is pure config.
    # (actor stays a Callable because actor/actor_benign differ in name and arity.)
    judge_wiring: JudgeWiring     # per-direction judge knobs, passed through agents.judge
    validate: Callable            # (doc) -> doc
    append_observations: Callable  # (doc, run_id, key, lrd, *, paths) -> int
    story_name: str
    telemetry_name: str
    judge_name: str
    judge_raw_name: str
    obs_trigger: ObsTrigger
    # Optional second observation stream from the same judge doc. The adversarial
    # direction also emits positive-polarity env facts into the SHARED
    # lessons-environment/ corpus (issue #298): `append_env_observations` queues
    # them and each entry in `extra_obs_triggers` drains a stream the same way
    # `obs_trigger` drains the primary one.
    append_env_observations: Callable | None = None
    extra_obs_triggers: tuple[ObsTrigger, ...] = ()


ADVERSARIAL = Direction(
    name="adversarial",
    invoke_actor=lambda agents, run_dir, lrd, key: agents.actor(run_dir, lrd),
    judge_wiring=ADVERSARIAL_WIRING,
    validate=validate_judge_doc,
    append_observations=append_actor_observations,
    story_name="actor_story.md",
    telemetry_name="projected_telemetry.yaml",
    judge_name="judge_findings.yaml",
    judge_raw_name="judge_findings.raw.txt",
    obs_trigger=ObsTrigger(
        pending_file=lambda p: p.actor_observations_file,
        threshold_env="LEARNING_AUTHOR_ACTOR_THRESHOLD",
        module_name="author_actor",
        pending_label="actor_pending",
    ),
    append_env_observations=append_actor_environment_observations,
    extra_obs_triggers=(
        ObsTrigger(
            pending_file=lambda p: p.actor_environment_observations_file,
            threshold_env="LEARNING_AUTHOR_ACTOR_ENV_THRESHOLD",
            module_name="author_actor_env",
            pending_label="actor_env_pending",
        ),
    ),
)

BENIGN = Direction(
    name="benign",
    invoke_actor=lambda agents, run_dir, lrd, key: agents.actor_benign(run_dir, lrd, key),
    judge_wiring=BENIGN_WIRING,
    validate=validate_judge_benign_doc,
    append_observations=append_environment_observations,
    story_name="actor_benign_story.md",
    telemetry_name="projected_telemetry_benign.yaml",
    judge_name="judge_benign_findings.yaml",
    judge_raw_name="judge_benign_findings.raw.txt",
    obs_trigger=ObsTrigger(
        pending_file=lambda p: p.environment_observations_file,
        threshold_env="LEARNING_AUTHOR_ENV_THRESHOLD",
        module_name="author_actor_benign",
        pending_label="env_pending",
    ),
)

BY_NAME = {ADVERSARIAL.name: ADVERSARIAL, BENIGN.name: BENIGN}
