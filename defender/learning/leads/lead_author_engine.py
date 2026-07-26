from __future__ import annotations

import os
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar

from uuid import uuid4
from defender.learning.core import config
from defender.learning.core.config import RunUnprocessable
from defender.learning.leads.path_validation import SKILLS_REL
from defender.learning.pipeline._pydantic_stage import run_stage as _run_stage_fn
from defender.runtime import providers
from defender.runtime.agent_definition import AgentDefinition, ResolvedRoots, ToolSet, bind
from defender.runtime.agent_role import AgentRole
from defender.runtime.driver import MakeModel
from defender.runtime.permission import build_write_allow
from defender.runtime.permission.grant import Grant
from defender.runtime.tools import AgentDeps

_LEAD_AUTHOR_DENY_REASON = (
    "Blocked: the lead author curates the gather catalog + system skills under "
    "defender/skills only. It reads the corpus, writes and edits skill files there, and rm's a "
    "draft it promotes or discards — no data-source adapters, no gather_raw reads, no shell "
    "beyond the scoped rm, no writes outside defender/skills."
)


def _rm_skills_grant(skills_dir: Path) -> Grant:
    spellings = "|".join(re.escape(s) for s in (SKILLS_REL.rstrip("/"), str(skills_dir)))
    seg = r"(?!\.\.(?:/|$))[^/ ]+"
    return Grant(
        program="rm",
        pattern=re.compile(rf"^rm (?:{spellings})(?:/{seg})+$"),
        pins_path=True,
    )


def _lead_author_bash_shapes(roots: ResolvedRoots) -> tuple[Grant, ...]:
    return (_rm_skills_grant(roots.defender_dir / "skills"),)


def _lead_author_write_shape(roots: ResolvedRoots) -> tuple[re.Pattern[str], ...]:
    return (build_write_allow(roots.defender_dir / "skills", suffix=".md"),)


@dataclass(frozen=True)
class LeadAuthorDeps(AgentDeps):

    role: ClassVar[AgentRole] = AgentRole.LEAD_AUTHOR


LEAD_AUTHOR_DEF = AgentDefinition(
    role=AgentRole.LEAD_AUTHOR,
    model=config.lead_author_model,
    effort=config.lead_author_effort(),
    tools=ToolSet(read=True, bash=True, write=True),
    bash_shapes=(_lead_author_bash_shapes,),
    write_shapes=(_lead_author_write_shape,),
    deps_cls=LeadAuthorDeps,
    requires_explicit_tree=True,
    anchors_on_tree=True,
    deny_reason=_LEAD_AUTHOR_DENY_REASON,
)


def _run_lead_author_pydantic(  # noqa: PLR0913 — the transport signature plus the make_model test seam; every param is load-bearing per-call state
    *,
    prompt_path: Path,
    model: str,
    effort: str | None,
    trace_name: str,
    label: str,
    user: str,
    learning_run_dir: Path,
    repo_root: Path,
    request_limit: int,
    salt: str | None = None,
    box: Any = None,
    wall_clock_timeout: int,
    make_model: MakeModel = providers.build_for_effort,
    run_stage: Callable[..., Any] = _run_stage_fn,
) -> str:
    deps = bind(
        LEAD_AUTHOR_DEF, learning_run_dir, defender_dir=repo_root / "defender", salt=salt,
        box=box,
    )
    return run_stage(
        stage="lead_author",
        prompt_path=prompt_path, model=model, effort=effort,
        trace_name=trace_name, label=label, user=user,
        learning_run_dir=learning_run_dir, deps=deps,
        request_limit=request_limit, make_model=make_model,
        require_output=False,
        wall_clock_timeout=wall_clock_timeout,
    )


def run_author_stage(  # noqa: PLR0913 — the spawn contract (5 per-mode inputs + logger) + its 4 config knobs + 2 DI seams; every param is load-bearing per-call state
    *,
    system_prompt_file: Path,
    batch_id: str,
    user_prompt: str,
    repo_root: Path,
    learning_run_dir: Path,
    log_label: str,
    log: Callable[[str], None],
    # No signature defaults for the four model/effort/limit/timeout knobs: each is
    # env-backed, and a default evaluated at import would freeze it (#717).
    model: str,
    effort: str | None,
    timeout: int,
    request_limit: int,
    source_key: Callable[..., object] = config.source_first_party_key,
    run_author: Callable[..., str] = _run_lead_author_pydantic,
    salt: str | None = None,
    box: Any = None,
) -> int:
    log(f"spawn {log_label} in-process (model={model}, effort={effort}, timeout={timeout}s)")
    stage_salt = salt if salt is not None else uuid4().hex
    source_key(model, label=log_label)
    trace_name = f"{batch_id}.{os.getpid()}.trace.jsonl"
    try:
        run_author(
            prompt_path=system_prompt_file, model=model, effort=effort,
            trace_name=trace_name, label=f"{log_label}:{batch_id}", user=user_prompt,
            learning_run_dir=learning_run_dir, repo_root=repo_root,
            request_limit=request_limit, wall_clock_timeout=timeout,
            salt=stage_salt, box=box,
        )
    except RunUnprocessable as e:
        log(f"{log_label} did not complete (per-run fault): {e}")
        return 124
    log(f"{log_label} done")
    return 0
