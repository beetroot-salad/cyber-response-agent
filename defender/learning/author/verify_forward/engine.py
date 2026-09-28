from __future__ import annotations

from pathlib import Path
from typing import ClassVar

from defender._model import model
from defender.learning.core.config import (
    StageContext,
    StageWiring,
    verifier_effort,
    verifier_model,
)
from defender.learning._pydantic_stage import run_stage
from defender.runtime import providers
from defender.runtime.agent_definition import AgentDefinition, ToolSet, bind
from defender.runtime.agent_role import AgentRole
from defender.runtime.driver import MakeModel
from defender.runtime.tools import AgentDeps

VERIFY_REQUEST_LIMIT = 1

_VERIFY_DENY_REASON = (
    "Blocked: the forward-check is a pure prediction — its entire input (the transcript or story, "  # lint-run-records: ok — a message naming the record for the model or operator, not a path
    "the lesson, the disposition) is inlined in the user prompt and its entire output is two short "
    "paragraphs plus a "
    "single `VERDICT: GOOD|BAD` line. It runs no tools: no data-source adapters, no gather_raw reads, "
    "no writes, no shell. Emit the reasoning + verdict directly."
)


@model(frozen=True)
class VerifierDeps(AgentDeps):

    role: ClassVar[AgentRole] = AgentRole.VERIFIER


VERIFY_DEF = AgentDefinition(
    anchors_on_tree=True,
    requires_explicit_tree=True,
    role=AgentRole.VERIFIER,
    model=verifier_model,
    effort=verifier_effort(),
    tools=ToolSet(),
    deps_cls=VerifierDeps,
    deny_reason=_VERIFY_DENY_REASON,
)


def _run_verify_pydantic(
    wiring: StageWiring,
    *,
    user: str,
    source_run_dir: Path,
    defender_dir: Path,
    wall_clock_timeout: int,
    salt: str | None = None,
    make_model: MakeModel = providers.build_for_effort,
) -> str:
    """The request limit is stage-fixed (one turn); the timeout is the caller's env-backed
    knob, so no default is evaluated at import.

    `salt` scopes this stage's prompt frames and isn't bound; tool returns are framed by
    `wrap_fresh` with their own salt."""
    ctx = StageContext(
        learning_run_dir=source_run_dir, user=user,
        request_limit=VERIFY_REQUEST_LIMIT,
        wall_clock_timeout=wall_clock_timeout,
        salt=salt,
    )
    deps = bind(VERIFY_DEF, ctx.learning_run_dir, defender_dir=defender_dir)
    return run_stage(
        stage="verify_forward", wiring=wiring, ctx=ctx, deps=deps, make_model=make_model,
    )
