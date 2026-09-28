"""The review roles' shared posture: the zero-grant deny reason, the model resolver, the
salt-free bind, and the live-stage factory every review role is built through.

Review roles hold no read grant and no bash grant at all. Their run dir is the live
investigation's, which both grant surfaces admit ahead of any narrowing, so any grant would
expose the working document and undo the blind projections. Their only input is what the host
inlines into the prompt.

No salt is bound: `wrap_fresh` mints each delimiter at wrap time, so a review role never holds
the delimiter of the frame its output returns inside.
"""

from __future__ import annotations

from dataclasses import fields as dc_fields, replace
from defender._model import model
from pathlib import Path
from typing import Any, ClassVar

from defender._env import env_str
from defender.runtime import observe
from defender.runtime.agent_definition import AgentDefinition, RunScope, ToolSet, bind
from defender.runtime.agent_role import REVIEW_AGENT_ID_PREFIX, AgentRole
from defender.runtime.tools import AgentDeps

__all__ = [
    "COMPOSER_DEF",
    "DEFAULT_REVIEW_MODEL",
    "REVIEW_AGENT_ID_PREFIX",
    "REVIEW_MODEL_ENV",
    "SUPPORT_DEF",
    "ComposerDeps",
    "ReviewStages",
    "live_review_stages",
    "SupportDeps",
    "UnboundReviewStage",
    "bind_review_role",
    "resolve_review_model",
]

# No slash constructions (e.g. "text-in/text-out") in this model-facing text: they read as
# program names (`jq/ls/cat`), advertising commands that do not exist.
_DENY_REASON = (
    "Blocked: this review stage is a pure projection — it receives text and returns text. Its "
    "entire input is inlined in the prompt and its entire output is one document. It holds no "
    "read grant and no bash grant of any kind."
)


REVIEW_MODEL_ENV = "DEFENDER_REVIEW_MODEL"

# `REVIEW_AGENT_ID_PREFIX` is defined in the dependency-free `agent_role` so the cost readers
# in `scripts/visualize/` can import the exact same prefix.

#: The review's default model, independent of the investigator's. On two frozen judge cases
#: the investigator's default was self-inconsistent while this one held across four reps
#: (small n: enough to pin a default, not to settle the question).
DEFAULT_REVIEW_MODEL = "kimi-k3"


def resolve_review_model(explicit: str | None = None) -> str:
    """The review model: the operator's `--model`, else `DEFENDER_REVIEW_MODEL`, else the
    review default. Does not read `DEFENDER_MODEL` (the investigator's knob).

    `explicit` must be the operator's raw override; resolving it against the main model first
    would make the review default unreachable."""
    if explicit is not None:
        return explicit
    return env_str(REVIEW_MODEL_ENV, DEFAULT_REVIEW_MODEL)


def bind_review_role(
    defn: AgentDefinition, run_dir: Path, *, defender_dir: Path | None = None,
) -> AgentDeps:
    """Bind a review role's deps with no salt; `wrap_fresh` mints delimiters at wrap time."""
    return bind(defn, run_dir, scope=RunScope(), defender_dir=defender_dir)


@model(frozen=True)
class SupportDeps(AgentDeps):
    role: ClassVar[AgentRole] = AgentRole.SUPPORT


@model(frozen=True)
class ComposerDeps(AgentDeps):
    role: ClassVar[AgentRole] = AgentRole.COMPOSER


# The deps classes exist only to carry `role`: the base defaults to `AgentRole.MAIN`, which
# would pass the close tool's MAIN gate and flip `_is_learning_role`.

# A lens reconstructs; the composer judges, so it gets more effort.
_LENS_EFFORT = "medium"
_COMPOSER_EFFORT = "high"


def _review_def(role: AgentRole, deps_cls: type[AgentDeps], effort: str) -> AgentDefinition:
    """One zero-grant review role: no tools, shapes, corpus or preconditions."""
    return AgentDefinition(
        role=role,
        model=resolve_review_model,
        effort=effort,
        tools=ToolSet(),
        deps_cls=deps_cls,
        deny_reason=_DENY_REASON,
    )


SUPPORT_DEF = _review_def(AgentRole.SUPPORT, SupportDeps, _LENS_EFFORT)
COMPOSER_DEF = _review_def(AgentRole.COMPOSER, ComposerDeps, _COMPOSER_EFFORT)


class UnboundReviewStage(RuntimeError):
    """A review stage was called from a composition root that never held a run dir.

    Substituting the source tree would write review artifacts into the checkout and anchor
    policies on it; raising makes the gate fail the review closed instead."""


def _make_live_stage(  # noqa: PLR0913 — one stage's full wiring, named once
    defn: AgentDefinition, run_dir: Path, defender_dir: Path,
    logger: observe.RequestLogger, *, agent_id: str, instructions: str, build: Any,
):
    """One live review stage: one Agent built per call.

    Uses the run's logger so review calls land in the run's accounted cost; it must not be
    closed here, since the main agent is still writing to it. `agent_id` is per lens
    (`review:{lens}`) because one role runs twice and `observe` keys records on `agent_id`.

    `build` is the agent-builder seam (default `driver.build_agent_core`), so this can be
    exercised without a provider."""

    async def call(request):
        assert defn.deps_cls is not None, f"{defn.role.name}_DEF declares no deps_cls"
        agent = build(
            defn, deps_type=defn.deps_cls, instructions=instructions,
            logger=logger, agent_id=agent_id,
        )
        deps = bind_review_role(defn, run_dir, defender_dir=defender_dir)
        result = await agent.run(request.prompt, deps=deps)
        return str(result.output or "")

    return call


@model
class ReviewStages:
    """The review-stage injection bundle.

    Fields default to `None` because one composition root (`driver.build_agent`) has no run
    dir to bind against. Read stages through `stage()`, which turns a missing one into
    `UnboundReviewStage` that the gate fails closed on."""

    support: Any = None
    #: The support role again, as a separate call under its own `review:{lens}` agent id.
    ablation: Any = None
    composer: Any = None

    def stage(self, name: str) -> Any:
        # Check against the fields: `getattr` would also answer for methods like `stage`.
        if name not in {f.name for f in dc_fields(self)}:
            raise UnboundReviewStage(
                f"{name!r} is not a review stage — this bundle carries "
                f"{sorted(f.name for f in dc_fields(self))}"
            )
        fn = getattr(self, name)
        if fn is None:
            raise UnboundReviewStage(
                f"the {name} stage is not bound — this bundle was built by a composition root "
                "that never held a run dir"
            )
        return fn


def live_review_stages(
    run_dir: Path, defender_dir: Path, *, logger: observe.RequestLogger,
    model_override: str | None = None, build: Any = None,
) -> ReviewStages:
    """The production bundle, built where the run dir and the run's logger both exist.

    `logger` is required so review calls always land in the run's accounted cost.
    `model_override` is the operator's raw `--model`, unresolved (see `resolve_review_model`)."""
    from defender.runtime.driver import build_agent_core
    from defender.runtime.review import role_prompt

    build = build if build is not None else build_agent_core  # lint-default: ok — DI seam owning its default (the live agent builder; a signature default would close an import cycle)
    name = resolve_review_model(model_override)
    # One read per role: support is dispatched twice with the same prompt.
    prompts = {
        defn.role.value: role_prompt(defn.role.value)
        for defn in (SUPPORT_DEF, COMPOSER_DEF)
    }

    def staged(defn: AgentDefinition, lens: str) -> Any:
        return _make_live_stage(
            replace(defn, model=lambda: name), run_dir, defender_dir, logger,
            agent_id=f"{REVIEW_AGENT_ID_PREFIX}{lens}",
            instructions=prompts[defn.role.value], build=build,
        )

    return ReviewStages(
        support=staged(SUPPORT_DEF, "support"),
        ablation=staged(SUPPORT_DEF, "ablation"),
        composer=staged(COMPOSER_DEF, "composer"),
    )
