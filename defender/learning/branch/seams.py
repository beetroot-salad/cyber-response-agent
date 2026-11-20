"""The launcher's model seam, resolved for a real episode."""

from __future__ import annotations

from defender.records import WIRE_LOG_NAMES
from pathlib import Path
from typing import Any

#: The questioner's standing system prompt. The per-call task is composed into the user message
#: by the caller; only what is true of every call belongs here.
_ROLE_PROMPT = Path(__file__).resolve().parent / "questioner" / "role.md"

#: A text call (the comparator's) is one request. A typed call's bound is the runner's: 1 + its
#: retries (#1579).
_REQUEST_LIMIT = 1


def model_seam(episode_dir: Path, *, make_model: Any = None) -> Any:
    """The production `(prompt, *, role, agent_id, output=None)` for every questioner-role call.

    With `output` (a `TypedOutput`), the call is typed (#1579): it returns `Accepted(mapping,
    requests)` or raises `ReplyUnusable`. Without it (the comparator shares this seam) it returns
    the reply's text, as before. `make_model` replaces the provider's model builder. The trace lands in the episode dir's wire-log subdirectory, beside the
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

    extra = {} if make_model is None else {"make_model": make_model}

    def invoke(prompt: str, *, role: Any = None, agent_id: str = "questioner",  # noqa: ARG001 — the role is fixed by `QuestionerDeps`; taken so the seam matches the callers' signature
               output: Any = None) -> Any:
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
            output=output,
            **extra,
        )

    return invoke
