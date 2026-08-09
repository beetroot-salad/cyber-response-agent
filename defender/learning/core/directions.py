from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Callable
from pathlib import Path

from defender._vocab import normalized_disposition
from defender.learning.core.config import (
    JUDGE_BENIGN_PROMPT,
    JUDGE_PROMPT,
    JudgeWiring,
    LoopPaths,
    actor_model,
    benign_actor_model,
    benign_judge_effort,
    benign_judge_model,
    judge_effort,
    judge_model,
)
from defender.learning.core.persist import (
    append_actor_environment_observations,
    append_actor_observations,
    append_environment_observations,
)
from defender.learning.core.validate import (
    ADVERSARIAL_JUDGE_OPTIONAL_KEYS,
    BENIGN_JUDGE_OPTIONAL_KEYS,
    validate_judge_benign_doc,
    validate_judge_doc,
)


# These four env-backed knobs are read once, HERE, when the module is imported — the
# wirings and Directions below are module constants, and an A/B run pins the model for
# the whole process anyway (evals set the env before spawning). Everything else reads
# its knob at call time; this is the one place the loop still snapshots (#717).
ADVERSARIAL_WIRING = JudgeWiring(
    JUDGE_PROMPT, judge_model(), judge_effort(), "judge_trace.jsonl", "judge",
    "comparison",
)
BENIGN_WIRING = JudgeWiring(
    JUDGE_BENIGN_PROMPT, benign_judge_model(), benign_judge_effort(),
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
    judge_name: str
    # The dispositions that select this direction — the ONE home for the mapping
    # `directions_for` dispatches on and the judge view reads to tell "this direction was
    # never selected" from "it was selected and its artifacts are missing" (#716).
    dispositions: frozenset[str]
    # The optional top-level keys THIS direction's judge doc may carry, as `validate`
    # enforces them. Declared here beside the artifact names so the transcript view can ask
    # which sections a direction has instead of inferring it from which validator the
    # direction points at — three keys were accepted and only one rendered (#748).
    judge_optional_keys: frozenset[str]
    obs_trigger: ObsTrigger
    # Actor artifacts only some directions produce — declared HERE with the rest of the
    # names, so the transcript view reads them off the Direction instead of restating the
    # literals the actor pipeline writes (#716).
    archetype_name: str | None = None
    menu_name: str | None = None
    append_env_observations: Callable | None = None
    extra_obs_triggers: tuple[ObsTrigger, ...] = ()

    @property
    def status_name(self) -> str:
        """The leg's own terminal-status file (#791). Derived HERE, like every other name on
        this class, so the run cycle that writes it and the transcript view that reads it
        cannot disagree about what it is called."""
        return f"{self.name}.status"

    def artifact_names(self) -> tuple[str, ...]:
        """Every file this direction's legs leave in the learning run dir. Derived from the
        names declared above so presence and rendering read the same list: the transcript asks
        this to tell "this leg ran" from "it was never selected" (#716).

        The status file leads: it is written BEFORE the actor call, so it is the only trace a
        leg that died in that call leaves at all. Retiring the projected-telemetry names
        without putting it on this list would have made such a leg indistinguishable from one
        that was never selected — the exact confusion the status file was added to end."""
        declared = (
            self.status_name, self.story_name, self.judge_name,
            self.archetype_name, self.menu_name,
        )
        return tuple(n for n in declared if n is not None) + (
            raw_fallback_name(self.judge_name),
        )


def raw_fallback_name(artifact_name: str) -> str:
    """The pre-strip fallback written beside an artifact whose fence had to be stripped.
    Derived HERE so a writer and the transcript view cannot disagree about the name (#716)."""
    return Path(artifact_name).stem + ".raw.txt"


ADVERSARIAL = Direction(
    name="adversarial",
    invoke_actor=lambda agents, run_dir, lrd, key, *, box: agents.actor(run_dir, lrd, box=box),
    judge_wiring=ADVERSARIAL_WIRING,
    actor_model=actor_model(),
    validate=validate_judge_doc,
    append_observations=append_actor_observations,
    story_name="actor_story.md",
    judge_name="judge_findings.yaml",
    dispositions=frozenset({"benign", "inconclusive"}),
    judge_optional_keys=ADVERSARIAL_JUDGE_OPTIONAL_KEYS,
    archetype_name="actor_archetype.txt",
    menu_name="actor_menu.txt",
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
    invoke_actor=lambda agents, run_dir, lrd, key, *, box: (
        agents.actor_benign(run_dir, lrd, key, box=box)
    ),
    judge_wiring=BENIGN_WIRING,
    actor_model=benign_actor_model(),
    validate=validate_judge_benign_doc,
    append_observations=append_environment_observations,
    story_name="actor_benign_story.md",
    judge_name="judge_benign_findings.yaml",
    dispositions=frozenset({"malicious", "inconclusive"}),
    judge_optional_keys=BENIGN_JUDGE_OPTIONAL_KEYS,
    obs_trigger=ObsTrigger(
        pending_file=lambda p: p.environment_observations.file,
        threshold_env="LEARNING_AUTHOR_ENV_THRESHOLD",
        module_name="author_actor_benign",
        pending_label="env_pending",
    ),
)

BY_NAME = {ADVERSARIAL.name: ADVERSARIAL, BENIGN.name: BENIGN}

#: Dispositions that select NO direction on purpose. Named here so the drift guard below can
#: stay exact: an omission is still a bug, unless it is one this set declares.
#:
#: `false-positive` (#806) is a verdict about the RULE — it says the detection fired on a
#: different kind of behaviour than it claims, and says nothing about whether the alerted entity
#: was clean. Neither actor has a story to write from it: hunting the FN would mean disproving a
#: claim the run never made, and hunting the FP would mean re-deriving the defect the run already
#: stated. The tuning signal it carries belongs to the rule, per rule, not to this loop, which
#: learns per case. A run with something to teach about the ENTITY has three other keywords and
#: `_check_false_positive_gating` requires it to have looked before reaching this one.
UNTRAINED_DISPOSITIONS: frozenset[str] = frozenset({"false-positive"})

# INVARIANT: the union of every `dispositions` is exactly `DISPOSITION_ENUM` minus
# `UNTRAINED_DISPOSITIONS` — a typo or an omission there silently drops a leg from BOTH the
# loop's dispatch and the transcript, with nothing failing. Guarded by
# `test_every_disposition_selects_at_least_one_direction` (#716).


def directions_for(disposition: str) -> list[Direction]:
    """The directions a disposition selects — the ONE reader of `Direction.dispositions`,
    shared by the loop's dispatch and the transcript view so they cannot disagree (#716).
    An unrecognized disposition selects nothing; callers decide what that means.

    It reads the disposition through the same `normalized_disposition` every consumer of a
    completed `report.md` goes through (#785), so the #722 strip cannot be applied on the
    reading side and skipped on the dispatching one.

    An `UNTRAINED_DISPOSITIONS` member returns early rather than falling through the filter to
    the same empty list. The filter would already produce it — no `Direction` names those
    keywords — but only as an ABSENCE, which reads identically to the #716 drift bug this
    function's invariant exists to catch. Consulting the set makes "trains nothing" a decision
    the code states, and keeps the two readers of that set (here and the invariant) from being
    a live one and a test-only one."""
    disp = normalized_disposition(disposition)
    if disp is None or disp in UNTRAINED_DISPOSITIONS:
        return []
    return [d for d in BY_NAME.values() if disp in d.dispositions]
