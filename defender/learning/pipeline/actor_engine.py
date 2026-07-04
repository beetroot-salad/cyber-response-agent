"""The actor stages on the in-process PydanticAI engine — a drop-in ``actor_fn``.

Mirror of the judge's ``pipeline/judge/engine_pydantic.py``: the actor's specifics (its deps
identity, its permission policy + the pinned-lessons-script matchers) live here, and the
generic in-process transport it shares with the judge lives in ``pipeline/_pydantic_stage.py``.
ONE engine serves BOTH actor directions (malicious/benign) the way one ``_run_judge_pydantic``
serves both judge directions — the per-direction variation (prompt/model/effort + which pinned
lesson scripts the leg may run) is data threaded through ``_run_actor_pydantic``'s args + an
``_ActorScope``, not two engine modules.

Imported LAZILY (pulls the pydantic-ai graph via ``_pydantic_stage``) — only when an actor
actually runs (``core/subagents.ClaudePrintSubagents.actor``), never at loop import.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

from defender.learning.core.config import REPO_ROOT
from defender.learning.pipeline._pydantic_stage import run_stage
from defender.runtime import providers
from defender.runtime.agent_role import AgentRole
from defender.runtime.driver import MakeModel
from defender.runtime.permission import AgentPolicy, BashDecision, command_shape
from defender.runtime.tools import RunDeps

if TYPE_CHECKING:
    from defender.runtime.bash_exec import Pipeline

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
    a confine of ``{lessons-environment}`` (no tradecraft, no rubric — the gray-box split)."""

    scripts: tuple[Path, ...] = ()
    read_confine: tuple[Path, ...] = ()


@dataclass(frozen=True)
class ActorDeps(RunDeps):
    """The actor's per-run deps — ``RunDeps`` shape; its pinned-script matchers ride in
    ``policy`` (data), no extra fields. ``run_dir`` is the *learning* run dir (its own output
    dir), so budget/observability side effects land there. The actor reads only the lessons
    corpora its ``policy.read_confine`` names (that confine REPLACES the ``defender_dir`` base,
    so the judge's rubric under ``defender/`` is unreachable) and never touches ``gather_raw``
    (``raw_reads=False``) — it is gray-box by construction.
    ``role`` is an ACTOR identity label — the gate keys on ``policy``, not this."""

    role: ClassVar[AgentRole] = AgentRole.ACTOR


def _make_lessons_matcher(script: Path):
    """Allow the actor's read-only lessons retrieval: a single-stage ``python[3] <script>
    <args…>`` invocation whose script resolves (against ``REPO_ROOT`` — the actor prompts type
    the bare repo-relative form and bash runs with cwd=repo root) to the pinned ``script``.
    Anything else declines (``None``) → the generic gate DENIES it (``python3`` is not a
    read-only viewer). The mirror of the judge's ``_make_ticket_matcher``. Because the matcher
    cannot constrain the script's internals, the pinned scripts MUST stay read-only — both
    ``lessons_env_retrieve.py`` and ``lessons_actor_index.py`` are pure argparse corpus scanners
    (no writes, no network)."""
    script_abs = script.resolve()

    def _match(pipelines: list[Pipeline]) -> BashDecision | None:
        argv = command_shape.single_stage_argv(pipelines)  # a single command, never a pipe/compound
        if argv is None or len(argv) < 2:
            return None
        if Path(argv[0]).name not in ("python", "python3"):
            return None
        if (REPO_ROOT / argv[1]).resolve() != script_abs:
            return None
        return BashDecision(True, pipelines=tuple(pipelines))

    return _match


def _actor_policy(scripts: tuple[Path, ...], read_confine: tuple[Path, ...]) -> AgentPolicy:
    """The actor's declarative gate policy: read-only, NO adapters, NO raw reads (its inputs are
    all inlined in the user prompt — it never touches gather_raw), NO ``read_roots``, and a
    ``read_confine`` that REPLACES the ``defender_dir`` read base — the actor sees only its own
    lesson corpora (its confine), never the judge's grading rubric under ``defender/`` (#512).
    ``bash_readers=()`` grants NO generic bash reader: every read goes through ``read_file`` (which
    honours the confine); the pinned lesson scripts still run via the custom matchers below (each
    a single pinned ``python3 <script>``), which the gate honours upstream of the reader tail."""
    return AgentPolicy(
        adapters=False,
        adapter_sql_pipe=False,
        raw_reads=False,
        read_roots=(),
        read_confine=read_confine,
        bash_readers=(),
        custom_matchers=tuple(_make_lessons_matcher(s) for s in scripts),
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
    deps = ActorDeps(
        run_dir=learning_run_dir,
        defender_dir=REPO_ROOT / "defender",
        run_id=learning_run_dir.name,
        salt=uuid.uuid4().hex,
        policy=_actor_policy(scope.scripts, read_confine=scope.read_confine),
    )
    return run_stage(
        stage="actor",
        prompt_path=prompt_path, model=model, effort=effort,
        trace_name=trace_name, label=label, user=user,
        learning_run_dir=learning_run_dir, deps=deps,
        request_limit=ACTOR_REQUEST_LIMIT, make_model=make_model,
    )
