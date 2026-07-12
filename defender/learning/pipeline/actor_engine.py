"""The actor stages on the in-process PydanticAI engine — a drop-in ``actor_fn``.

Mirror of the judge's ``pipeline/judge/engine_pydantic.py``: the actor's specifics (its deps
identity, its permission policy + the pinned-lessons-script bash patterns) live here, and the
generic in-process transport it shares with the judge lives in ``pipeline/_pydantic_stage.py``.
ONE engine serves BOTH actor directions (malicious/benign) the way one ``_run_judge_pydantic``
serves both judge directions — the per-direction variation (prompt/model/effort + which pinned
lesson scripts the leg may run) is data threaded through ``_run_actor_pydantic``'s args + an
``_ActorScope``, not two engine modules.

Imported LAZILY (pulls the pydantic-ai graph via ``_pydantic_stage``) — only when an actor
actually runs (``core/subagents.InProcessSubagents.actor``), never at loop import.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar

from defender.learning.core.config import ACTOR_EFFORT, ACTOR_MODEL, REPO_ROOT
from defender.learning.pipeline._pydantic_stage import run_stage
from defender.runtime import providers
from defender.runtime.agent_definition import (
    AgentDefinition,
    ResolvedRoots,
    RunScope,
    ToolSet,
    bind,
)
from defender.runtime.agent_role import AgentRole
from defender.runtime.driver import MakeModel
from defender.runtime.permission.grant import Grant
from defender.runtime.tools import AgentDeps

# Bounds a runaway tool loop (the twin of JUDGE_REQUEST_LIMIT). Sized for GLM's tool-hunger:
# GLM issues ~2-3 tool calls per model request and explores the lessons corpora more than the
# earlier Sonnet regime — a live smoke run saw the adversarial actor reach 18/20 on a single
# case, so 20 gave almost no headroom. Raised to 30 (still a backstop, not a budget). Reducing
# GLM's tool-call count at the source is tracked in #514.
ACTOR_REQUEST_LIMIT = 30

_ACTOR_DENY_REASON = (
    "Blocked: the actor is read-only over the lessons corpora — it may run only the pinned "
    "read-only lesson scripts (lessons_env_retrieve.py; the adversarial actor also "
    "lessons_actor_index.py) plus read_file (with an optional substring pattern) under "
    "defender/. No data-source adapters, no writes, no arbitrary shell."
)


@dataclass(frozen=True)
class _ActorScope:
    """The pinned lesson scripts this actor leg may run as ``python3 <script> …`` plus the leg's
    read ``confine`` — the actor's tool-surface scoping (the mirror of the judge's ``_ToolScope``).
    The adversarial leg carries both scripts (env-fact retrieval + tradecraft index) and a confine
    of ``{lessons-actor, lessons-environment}``; the benign leg carries only env-fact retrieval and
    a confine of ``{lessons-environment}`` (no tradecraft, no rubric — the gray-box split).

    ``read_confine`` is REQUIRED (keyword-only, no default): an empty confine falls back to the
    whole ``defender_dir`` corpus (``permission/files.py``), reopening the #510 gray-box hole #512
    closes — so an actor scope must NAME its confine explicitly. There is no unconfined actor;
    omitting it is a construction-time ``TypeError``, not a silent full-corpus read."""

    scripts: tuple[Path, ...] = ()
    read_confine: tuple[Path, ...] = field(kw_only=True)


@dataclass(frozen=True)
class ActorDeps(AgentDeps):
    """The actor's per-run deps — ``AgentDeps`` shape; its pinned-script patterns ride in
    ``policy`` (data), no extra fields. ``run_dir`` is the *learning* run dir (its own output
    dir), so budget/observability side effects land there. The actor reads only the lessons
    corpora its ``policy.read_confine`` names (that confine REPLACES the ``defender_dir`` base,
    so the judge's rubric under ``defender/`` is unreachable) and never touches ``gather_raw``
    (``raw_reads=False``) — it is gray-box by construction.
    ``role`` is an ACTOR identity label — the gate keys on ``policy``, not this."""

    role: ClassVar[AgentRole] = AgentRole.ACTOR


def _script_grant(script: Path) -> Grant:
    """The actor's read-only lessons retrieval: a single-stage ``python[3] <script> <args…>``
    whose script token is the pinned ``script`` — matched by its repo-relative form (what the
    prompts type, bash running with cwd=repo root) OR its absolute form, both ``re.escape``-d so
    a `.`/`-` in the path can't widen the match. Any other spelling fails CLOSED.

    ``pins_path=True`` — the R1 exemption: the operand IS the program. Resolving it and checking
    it against a scope buys nothing the pinned pattern didn't already have (and per #565 the
    pinned script's own argv is ungated regardless), so the path legitimately lives in the
    PATTERN. Because the pattern cannot constrain the script's internals, the pinned scripts MUST
    stay read-only — both ``lessons_env_retrieve.py`` and ``lessons_actor_index.py`` are pure
    argparse corpus scanners (no writes, no network)."""
    script_abs = script.resolve()
    rel = script_abs.relative_to(REPO_ROOT.resolve())
    spellings = "|".join(re.escape(s) for s in (str(rel), str(script_abs)))
    return Grant(
        program="python3",
        pattern=re.compile(rf"^(?:[^ ]*/)?python3? (?:{spellings})(?: .*)?$"),
        pins_path=True,
    )


def _actor_bash_shapes(roots: ResolvedRoots) -> tuple[Grant, ...]:
    """The actor's bash lane: JUST one pinned-script grant per lesson script — no viewer surface
    at all. Every non-script read goes through ``read_file``, which honours the ``read_confine``
    that REPLACES the ``defender_dir`` read base, so the actor sees only its own lesson corpora
    and never the judge's grading rubric (#512). With no ``cat`` grant it carries no read shapes
    either, leaving ``decide_read`` root-only inside that confine — which is the whole surface.

    The pinned scripts run through the reader lane like any other approved shape, so the
    substitution guard (``bash._stage_unsafe``) applies to them too (#500)."""
    return tuple(_script_grant(s) for s in roots.scripts)


# The actor's AgentDefinition (#538). Unlike the pure-prediction stages, the actor genuinely USES
# its tools — it runs the pinned read-only lesson scripts on the bash lane and reads its lesson
# corpora via ``read_file`` — so ``tools`` keeps the read + bash pair (``bash=True`` registers the
# tool; its per-leg pinned-script GRANTS are built by its own ``bash_shapes`` builder from the
# ``RunScope``'s scripts at bind). ``model``/``effort`` are the declarative stage defaults (glm-5.2 @ low); each leg
# re-binds its own per-call model/effort in ``build_stage_agent``. ``requires_confine=True`` makes
# the empty-``read_confine`` fail-loud a DATA bit checked generically in ``bind`` (#551 — no role
# branch): an empty confine widens the actor to the whole ``defender_dir``, reopening the #512
# gray-box rubric leak, so bind refuses to mint an unconfined actor.
ACTOR_DEF = AgentDefinition(
    role=AgentRole.ACTOR,
    model=lambda: ACTOR_MODEL,
    effort=ACTOR_EFFORT,
    tools=ToolSet(read=True, bash=True),
    bash_shapes=(_actor_bash_shapes,),
    deps_cls=ActorDeps,
    requires_confine=True,
    deny_reason=_ACTOR_DENY_REASON,
)


def _run_actor_pydantic(  # noqa: PLR0913 — the actor_fn protocol signature plus the make_model test seam; every param is load-bearing per-call state
    prompt_path: Path,
    model: str,
    effort: str,
    trace_name: str,
    label: str,
    user: str,
    learning_run_dir: Path,
    *,
    scope: _ActorScope,
    make_model: MakeModel = providers.build_for_effort,
) -> str:
    """The PydanticAI ``actor_fn`` — drops into ``invoke_actor``/``invoke_actor_benign`` as
    ``actor_fn=``. Builds the actor's ``ActorDeps`` via the single ``bind`` seam (#551) from a
    ``RunScope`` carrying the tool ``scope`` (the pinned lesson scripts + the leg's read
    ``confine``, which bind fail-louds on when empty via ``requires_confine``) and delegates to
    the shared ``run_stage`` (agent build + one-shot drive + error mapping + trace logging).
    Returns the model's final text VERBATIM — the story, or a ``SKIP: …`` line. A timeout /
    usage-limit / model error → ``RunUnprocessable`` (quarantines this run, the disposition a
    ``claude -p`` non-zero exit gave)."""
    deps = bind(
        ACTOR_DEF, learning_run_dir,
        scope=RunScope(scripts=scope.scripts, read_confine=scope.read_confine),
    )
    return run_stage(
        stage="actor",
        prompt_path=prompt_path, model=model, effort=effort,
        trace_name=trace_name, label=label, user=user,
        learning_run_dir=learning_run_dir, deps=deps,
        request_limit=ACTOR_REQUEST_LIMIT, make_model=make_model,
    )
