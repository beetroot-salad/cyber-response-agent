"""The actor stages on the in-process PydanticAI engine — a drop-in ``actor_fn``.

Mirror of the judge's ``pipeline/judge/engine_pydantic.py``: the actor's specifics (its deps
identity, its permission policy + the pinned-lessons-script bash patterns) live here, and the
generic in-process transport it shares with the judge lives in ``pipeline/_pydantic_stage.py``.
ONE engine serves BOTH actor directions (malicious/benign) the way one ``_run_judge_pydantic``
serves both judge directions — the per-direction variation (prompt/model/effort + which pinned
lesson scripts the leg may run) is data threaded through ``_run_actor_pydantic``'s args + an
``_ActorScope``, not two engine modules.

Imported LAZILY (pulls the pydantic-ai graph via ``_pydantic_stage``) — only when an actor
actually runs (``core/subagents.ClaudePrintSubagents.actor``), never at loop import.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar

from defender.learning.core.config import ACTOR_EFFORT, ACTOR_MODEL, REPO_ROOT
from defender.learning.pipeline._pydantic_stage import run_stage
from defender.runtime import providers
from defender.runtime.agent_definition import AgentDefinition, BashGrammar, ToolSet
from defender.runtime.agent_role import AgentRole
from defender.runtime.driver import MakeModel
from defender.runtime.permission import AgentPolicy
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
    "lessons_actor_index.py) plus read_file/grep under defender/. No data-source adapters, "
    "no writes, no arbitrary shell."
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

    @classmethod
    def for_scope(cls, scope: _ActorScope, run_dir: Path) -> ActorDeps:
        """The actor's front door: build its deps from the tool ``scope`` (the pinned lesson
        scripts + the leg's read ``confine``) over the base ``_for_run``. Mirrors the judge's
        ``JudgeDeps.for_scope`` — the required policy is the backstop, this is the front door."""
        return cls._for_run(run_dir, _actor_policy(scope.scripts, read_confine=scope.read_confine))


def _script_pattern(script: Path) -> re.Pattern[str]:
    """Allow the actor's read-only lessons retrieval: a single-stage ``python[3] <script>
    <args…>`` whose script token is the pinned ``script`` — matched by its repo-relative form
    (what the prompts type, bash running with cwd=repo root) OR its absolute form, both
    ``re.escape``-d so a `.`/`-` in the path can't widen the match. Any other spelling fails
    CLOSED. Because the pattern can't constrain the script's internals, the pinned scripts MUST
    stay read-only — both ``lessons_env_retrieve.py`` and ``lessons_actor_index.py`` are pure
    argparse corpus scanners (no writes, no network)."""
    script_abs = script.resolve()
    rel = script_abs.relative_to(REPO_ROOT.resolve())
    spellings = "|".join(re.escape(s) for s in (str(rel), str(script_abs)))
    return re.compile(rf"^(?:[^ ]*/)?python3? (?:{spellings})(?: .*)?$")


def _actor_policy(scripts: tuple[Path, ...], read_confine: tuple[Path, ...]) -> AgentPolicy:
    """The actor's declarative gate policy: read-only, NO adapters, NO raw reads (its inputs are
    all inlined in the user prompt — it never touches gather_raw), NO ``read_roots``, and a
    ``read_confine`` that REPLACES the ``defender_dir`` read base — the actor sees only its own
    lesson corpora (its confine), never the judge's grading rubric under ``defender/`` (#512).
    ``bash_allow`` is JUST one pinned-script pattern per lesson script (no viewer surface): every
    non-script read goes through ``read_file`` (which honours the confine). The pinned scripts now
    run through the reader lane like any other approved shape, so the substitution guard
    (``bash._stage_unsafe``) applies to them too — closing the #500 matcher-skips-guard gap."""
    return AgentPolicy(
        bash_allow=tuple(_script_pattern(s) for s in scripts),
        jq_operand_gated=False,
        adapters=False,
        adapter_sql_pipe=False,
        raw_reads=False,
        read_roots=(),
        read_confine=read_confine,
        deny_reason=_ACTOR_DENY_REASON,
    )


# The actor's AgentDefinition (#538). Unlike the pure-prediction stages, the actor genuinely USES
# its tools — it runs the pinned read-only lesson scripts on the bash lane and reads its lesson
# corpora via ``read_file`` — so ``tools`` keeps the read + bash pair (``BashGrammar()`` registers the
# bash tool; the per-leg pinned-script allowlist is compiled from the ``RunScope`` at bind, not
# declared here). ``model``/``effort`` are the declarative stage defaults (glm-5.2 @ low); each leg
# re-binds its own per-call model/effort in ``build_stage_agent``.
ACTOR_DEF = AgentDefinition(
    role=AgentRole.ACTOR,
    model=lambda: ACTOR_MODEL,
    effort=ACTOR_EFFORT,
    tools=ToolSet(read=True, bash=BashGrammar()),
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
    ``actor_fn=``. Builds the actor's ``ActorDeps`` with its pinned-script policy from the tool
    ``scope`` and delegates to the shared ``run_stage`` (agent build + one-shot drive + error
    mapping + trace logging). Returns the model's final text VERBATIM — the story, or a
    ``SKIP: …`` line. A timeout / usage-limit / model error → ``RunUnprocessable`` (quarantines
    this run, the disposition a ``claude -p`` non-zero exit gave)."""
    deps = ActorDeps.for_scope(scope, learning_run_dir)
    return run_stage(
        stage="actor",
        prompt_path=prompt_path, model=model, effort=effort,
        trace_name=trace_name, label=label, user=user,
        learning_run_dir=learning_run_dir, deps=deps,
        request_limit=ACTOR_REQUEST_LIMIT, make_model=make_model,
    )
