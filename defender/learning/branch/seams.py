"""The launcher's model seam, resolved for a real episode.

`learning/branch/cli.py` takes `questioner` and `invoke` as injected callables so a
test can stand in for them. This module says what each seam is when nobody supplies one; the
launcher resolves them at its boundary and threads them inward non-`None`, so no frame
downstream asks again and no two frames can disagree about which model answered.

The two model seams are one function: `author_family` and `comparator.compare` both call
`(prompt, *, role, agent_id)` as `AgentRole.QUESTIONER`, differing only in `agent_id`. A second
builder would be a second place for them to acquire different models, and the family's
comparability stamp cannot see that — it compares the model across siblings, and these calls
all happen in the launcher.
"""

from __future__ import annotations

from defender.run_repository import WIRE_LOG_NAMES
from pathlib import Path
from typing import Any

#: The questioner's standing system prompt. The per-call task is composed into the user message
#: by the caller; only what is true of every call belongs here.
_ROLE_PROMPT = Path(__file__).resolve().parent / "questioner" / "role.md"

#: One model call per seat, no retry: a questioner that could ask again on its own would spend
#: the operator's money with no operator in the room.
_REQUEST_LIMIT = 1


def model_seam(episode_dir: Path) -> Any:
    """The production `(prompt, *, role, agent_id) -> str` for every questioner-role call.

    The reply is returned as text and parsed by the caller, since what a well-formed answer is
    differs per seat. The trace lands in the episode dir's wire-log subdirectory, beside the
    manifest it produced. `agent_id` becomes the stage label, which partitions the per-call
    trace — calls sharing an id would overwrite each other's record.
    """
    from defender.learning._pydantic_stage import run_stage
    from defender.learning.branch.questioner import (
        QuestionerDeps,
        questioner_effort,
        questioner_model,
    )
    from defender.learning.core.config import StageContext, StageWiring, subagent_timeout

    episode_dir = Path(episode_dir)

    def invoke(prompt: str, *, role: Any = None, agent_id: str = "questioner") -> str:  # noqa: ARG001 — the role is fixed by `QuestionerDeps`; taken so the seam matches the callers' signature
        return run_stage(
            stage="questioner",
            wiring=StageWiring(
                prompt_path=_ROLE_PROMPT,
                model=questioner_model(),
                effort=questioner_effort(),
                trace_name=WIRE_LOG_NAMES.agent_trace(agent_id),
                label=agent_id,
            ),
            ctx=StageContext(
                learning_run_dir=episode_dir,
                user=prompt,
                request_limit=_REQUEST_LIMIT,
                wall_clock_timeout=subagent_timeout(),
            ),
            deps=QuestionerDeps(),
        )

    return invoke
