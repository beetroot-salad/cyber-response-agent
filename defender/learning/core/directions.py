from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Callable
from pathlib import Path

from defender.learning.core.config import (
    ACTOR_MODEL,
    BENIGN_ACTOR_MODEL,
    BENIGN_JUDGE_EFFORT,
    BENIGN_JUDGE_MODEL,
    JUDGE_BENIGN_PROMPT,
    JUDGE_EFFORT,
    JUDGE_MODEL,
    JUDGE_PROMPT,
    JudgeWiring,
    LoopPaths,
)
from defender.learning.core.persist import (
    append_actor_environment_observations,
    append_actor_observations,
    append_environment_observations,
)
from defender.learning.core.validate import validate_judge_benign_doc, validate_judge_doc


ADVERSARIAL_WIRING = JudgeWiring(
    JUDGE_PROMPT, JUDGE_MODEL, JUDGE_EFFORT, "judge_trace.jsonl", "judge",
    "comparison",
)
BENIGN_WIRING = JudgeWiring(
    JUDGE_BENIGN_PROMPT, BENIGN_JUDGE_MODEL, BENIGN_JUDGE_EFFORT,
    "judge_benign_trace.jsonl", "judge-benign",
    "comparison_benign",
    closed_ticket_read=True,
)


@dataclass(frozen=True)
class ObsTrigger:

    pending_file: Callable[[LoopPaths], Path]
    threshold_env: str
    module_name: str
    pending_label: str


@dataclass(frozen=True)
class Direction:
    name: str
    invoke_actor: Callable
    judge_wiring: JudgeWiring
    actor_model: str
    validate: Callable
    append_observations: Callable
    story_name: str
    telemetry_name: str
    judge_name: str
    judge_raw_name: str
    obs_trigger: ObsTrigger
    append_env_observations: Callable | None = None
    extra_obs_triggers: tuple[ObsTrigger, ...] = ()


ADVERSARIAL = Direction(
    name="adversarial",
    invoke_actor=lambda agents, run_dir, lrd, key: agents.actor(run_dir, lrd),
    judge_wiring=ADVERSARIAL_WIRING,
    actor_model=ACTOR_MODEL,
    validate=validate_judge_doc,
    append_observations=append_actor_observations,
    story_name="actor_story.md",
    telemetry_name="projected_telemetry.yaml",
    judge_name="judge_findings.yaml",
    judge_raw_name="judge_findings.raw.txt",
    obs_trigger=ObsTrigger(
        pending_file=lambda p: p.actor_observations.file,
        threshold_env="LEARNING_AUTHOR_ACTOR_THRESHOLD",
        module_name="author_actor",
        pending_label="actor_pending",
    ),
    append_env_observations=append_actor_environment_observations,
    extra_obs_triggers=(
        ObsTrigger(
            pending_file=lambda p: p.actor_environment_observations.file,
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
    actor_model=BENIGN_ACTOR_MODEL,
    validate=validate_judge_benign_doc,
    append_observations=append_environment_observations,
    story_name="actor_benign_story.md",
    telemetry_name="projected_telemetry_benign.yaml",
    judge_name="judge_benign_findings.yaml",
    judge_raw_name="judge_benign_findings.raw.txt",
    obs_trigger=ObsTrigger(
        pending_file=lambda p: p.environment_observations.file,
        threshold_env="LEARNING_AUTHOR_ENV_THRESHOLD",
        module_name="author_actor_benign",
        pending_label="env_pending",
    ),
)

BY_NAME = {ADVERSARIAL.name: ADVERSARIAL, BENIGN.name: BENIGN}
