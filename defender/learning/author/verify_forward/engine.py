from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

from defender.learning.core.config import (
    VERIFIER_EFFORT,
    VERIFIER_MODEL,
    VERIFIER_TIMEOUT,
)
from defender.learning.pipeline._pydantic_stage import run_stage
from defender.runtime import providers
from defender.runtime.agent_definition import AgentDefinition, ToolSet, bind
from defender.runtime.agent_role import AgentRole
from defender.runtime.driver import MakeModel
from defender.runtime.tools import AgentDeps

VERIFY_REQUEST_LIMIT = 1

_VERIFY_DENY_REASON = (
    "Blocked: the forward-check is a pure prediction — its entire input (the transcript or story, "
    "the lesson, the disposition) is inlined in the user prompt and its entire output is two short "
    "paragraphs plus a "
    "single `VERDICT: GOOD|BAD` line. It runs no tools: no data-source adapters, no gather_raw reads, "
    "no writes, no shell. Emit the reasoning + verdict directly."
)


@dataclass(frozen=True)
class VerifierDeps(AgentDeps):

    role: ClassVar[AgentRole] = AgentRole.VERIFIER


VERIFY_DEF = AgentDefinition(
    anchors_on_tree=True,
    requires_explicit_tree=True,
    role=AgentRole.VERIFIER,
    model=lambda: VERIFIER_MODEL,
    effort=VERIFIER_EFFORT,
    tools=ToolSet(),
    deps_cls=VerifierDeps,
    deny_reason=_VERIFY_DENY_REASON,
)


def _run_verify_pydantic(  # noqa: PLR0913 — the transport signature plus the make_model test seam; every param is load-bearing per-call state
    prompt_path: Path,
    model: str,
    effort: str,
    trace_name: str,
    label: str,
    user: str,
    source_run_dir: Path,
    *,
    defender_dir: Path,
    salt: str | None = None,
    wall_clock_timeout: int = VERIFIER_TIMEOUT,
    make_model: MakeModel = providers.build_for_effort,
) -> str:
    deps = bind(VERIFY_DEF, source_run_dir, defender_dir=defender_dir, salt=salt)
    return run_stage(
        stage="verify_forward",
        prompt_path=prompt_path, model=model, effort=effort,
        trace_name=trace_name, label=label, user=user,
        learning_run_dir=source_run_dir, deps=deps,
        request_limit=VERIFY_REQUEST_LIMIT, make_model=make_model,
        wall_clock_timeout=wall_clock_timeout,
    )
