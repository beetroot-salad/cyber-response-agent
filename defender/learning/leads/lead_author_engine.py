from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar

from defender.learning.core import config
from defender.learning.core.config import RunUnprocessable, StageContext, StageWiring
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


def _run_lead_author_pydantic(
    wiring: StageWiring,
    ctx: StageContext,
    *,
    make_model: MakeModel = providers.build_for_effort,
    run_stage: Callable[..., Any] = _run_stage_fn,
) -> str:
    """Both limits vary per spawn here, so the caller owns the whole context — this is one
    of the two stages where the transport really was threaded through three layers (#713)."""
    # `repo_root` is optional on the SHARED context (the pure-prediction stages bind off the
    # run dir alone) but required here: the skills tree is resolved off the repo. A raise,
    # not an assert — `python -O` strips asserts, and the fallout would be a `NoneType / str`
    # TypeError one frame down.
    repo_root = ctx.repo_root
    if repo_root is None:
        raise ValueError(
            "lead-author stage needs ctx.repo_root: it binds the skills tree off the repo"
        )
    deps = bind(
        LEAD_AUTHOR_DEF, ctx.learning_run_dir,
        # `ctx.salt` is NOT bound (#875): it scopes this stage's PROMPT frames — the set
        # `stage_user_message` announces as one message — while a tool return is framed by
        # `wrap_fresh`, which mints its own salt after the content is in hand.
        defender_dir=repo_root / "defender", box=ctx.box,
    )
    return run_stage(
        stage="lead_author",
        wiring=wiring, ctx=ctx, deps=deps,
        make_model=make_model, require_output=False,
    )


def run_author_stage(
    *,
    wiring: StageWiring,
    ctx: StageContext,
    log_label: str,
    log: Callable[[str], None],
    source_key: Callable[..., object] = config.source_first_party_key,
    run_author: Callable[..., str] = _run_lead_author_pydantic,
) -> int:
    """`wiring` and `ctx` are both built per spawn by the caller — the four model/effort/
    limit/timeout knobs are env-backed, so nothing here may be evaluated at import (#717)."""
    log(
        f"spawn {log_label} in-process "
        f"(model={wiring.model}, effort={wiring.effort}, "
        f"timeout={ctx.wall_clock_timeout}s)"
    )
    source_key(wiring.model, label=log_label)
    try:
        run_author(wiring, ctx)
    except RunUnprocessable as e:
        log(f"{log_label} did not complete (per-run fault): {e}")
        return 124
    log(f"{log_label} done")
    return 0
