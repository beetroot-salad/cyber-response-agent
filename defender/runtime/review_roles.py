"""The review roles' shared posture: the zero-grant deny reason, the model resolver, the
fresh-salt bind, and the live-stage factory every review role is built through.

#797 retired the three roles this module was written for — `CHALLENGER`,
`COHERENCE_CHECKER` and `PROJECTION`, their deps classes, their input builders, the
observation-layer cut and the two direction affordances. What is left is the POSTURE, which
outlives the roles that first needed it and which #796's lenses and composer inherit
unchanged:

Every review role holds NO file-read grant and NO bash grant at all — not narrowed roots,
zero. At write time a review role's run dir IS the live investigation's own dir, and both
grant surfaces (`decide_read`'s root check, the bash lane's operand scope) admit it
unconditionally ahead of any narrowing, so a role that could read or run bash could always
reach the live working document — undoing the projection every blind role rests on. The only
input a review role receives is what the host inlines into its prompt.

`bind_review_role` mints its OWN fresh salt on every call and never receives the
investigation's — the gather subagent bind is the ONE place in this tree that shares salt
with its parent, and a review role built on that precedent would hold the delimiter of the
frame its own output returns inside (a role that reads attacker-influenced payloads must
never hold that key).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

from defender._env import env_str
from defender.runtime.agent_definition import AgentDefinition, RunScope, ToolSet, bind
from defender.runtime.agent_role import AgentRole
from defender.runtime.tools import AgentDeps

__all__ = [
    "COMPOSER_DEF",
    "DEFAULT_REVIEW_MODEL",
    "REVIEW_MODEL_ENV",
    "DISCRIMINATION_DEF",
    "SUPPORT_DEF",
    "ComposerDeps",
    "DiscriminationDeps",
    "ReviewStages",
    "SupportDeps",
    "UnboundReviewStage",
    "bind_review_role",
    "resolve_review_model",
]

# The slash construction this used to carry ("a pure text-in/text-out projection") reads to
# `test_grant_gate_575._named_programs` as a slash-GROUP of program names — the same shape as
# `jq/ls/cat` — so a role bound to it named two programs its own lane denies. The reason is
# PROMPT SURFACE: a model reading it would have been taught a command pair that does not
# exist. It went unseen under #797 because the constant survived with no role attached to it.
_DENY_REASON = (
    "Blocked: this review stage is a pure projection — it receives text and returns text. Its "
    "entire input is inlined in the prompt and its entire output is one document. It holds no "
    "read grant and no bash grant of any kind."
)


REVIEW_MODEL_ENV = "DEFENDER_REVIEW_MODEL"

#: The review's own shipped default, PINNED APART from the investigator's. On the two frozen
#: judge cases in `experiments/judge-glm52-vs-kimik3`, the investigator's default disagreed
#: with ITSELF on both — a self-consistency floor of 0% on the label axis — where this model
#: held 100% across four reps. The learning judge was ported on the same measurement and the
#: same grounds (`learning/core/config.py:judge_model`), and the review is the same shape of
#: job: a verdict read off a frozen input. n=2, validation only; enough to pin a default, not
#: enough to close the question.
DEFAULT_REVIEW_MODEL = "kimi-k3"


def resolve_review_model(explicit: str | None = None) -> str:
    """The model every review role runs on: the operator's `--model` if there is one, then
    this review's OWN env var, then the review default.

    It deliberately does NOT read `DEFENDER_MODEL`. That is the investigator's knob, and a
    review that read it would silently un-pin its default on every run that set it — including
    every hermetic replay, which sets `DEFENDER_MODEL`/`DEFENDER_GATHER_MODEL` precisely to
    keep its two fakes distinguishable. The stability this default is chosen for would then be
    absent exactly where a run is cheapest to get wrong.

    `explicit` is the OPERATOR's raw override and must stay raw to reach here — a caller that
    resolves it against the main model first passes a non-`None` value on every run, and the
    review default becomes unreachable in production while still looking correct to a unit
    test that calls this with `None`."""
    if explicit is not None:
        return explicit
    return env_str(REVIEW_MODEL_ENV, DEFAULT_REVIEW_MODEL)


def bind_review_role(
    defn: AgentDefinition, run_dir: Path, *, defender_dir: Path | None = None,
) -> AgentDeps:
    """Bind a review role's deps with its OWN fresh salt — PR7/PR8: never the session's."""
    return bind(defn, run_dir, scope=RunScope(), salt=None, defender_dir=defender_dir)


@dataclass(frozen=True)
class DiscriminationDeps(AgentDeps):
    role: ClassVar[AgentRole] = AgentRole.DISCRIMINATION


@dataclass(frozen=True)
class SupportDeps(AgentDeps):
    role: ClassVar[AgentRole] = AgentRole.SUPPORT


@dataclass(frozen=True)
class ComposerDeps(AgentDeps):
    role: ClassVar[AgentRole] = AgentRole.COMPOSER


# Each deps class exists ONLY to carry its `role` ClassVar. `AgentDeps.role` defaults to
# `AgentRole.MAIN`, so a review role bound through the base class would hold MAIN's identity —
# which passes the close tool's `deps.role is not AgentRole.MAIN` gate and flips
# `_is_learning_role`. The override is the whole class.

# The lenses read; the composer judges. The effort split follows that: a lens reconstructs
# what a projection supports, the composer weighs three readings against the investigation's
# own account and decides whether a confident close survives.
_LENS_EFFORT = "medium"
_COMPOSER_EFFORT = "high"


def _review_def(role: AgentRole, deps_cls: type[AgentDeps], effort: str) -> AgentDefinition:
    """One review role, built the ordinary zero-grant way: no tools, no bash shapes, no write
    shapes, no corpus, none of the four `requires_*` preconditions. Everything that makes a
    review role safe is the ABSENCE of a grant, so the definition says almost nothing — and
    the one thing it must say (`deps_cls`, carrying the role identity) is the parameter."""
    return AgentDefinition(
        role=role,
        model=resolve_review_model,
        effort=effort,
        tools=ToolSet(),
        deps_cls=deps_cls,
        deny_reason=_DENY_REASON,
    )


DISCRIMINATION_DEF = _review_def(AgentRole.DISCRIMINATION, DiscriminationDeps, _LENS_EFFORT)
SUPPORT_DEF = _review_def(AgentRole.SUPPORT, SupportDeps, _LENS_EFFORT)
COMPOSER_DEF = _review_def(AgentRole.COMPOSER, ComposerDeps, _COMPOSER_EFFORT)


class UnboundReviewStage(RuntimeError):
    """A review stage was called from a composition root that never held a run dir.

    Raised by the stage rather than resolved by substituting the defender source tree for the
    missing run dir. That substitution was the shipped shape and it put each stage's live
    trace file inside the repo checkout and anchored the review roles' compiled policies on
    the source tree instead of on the run they were judging. Raising is the safer failure: the
    gate catches a stage's exception into its own stage-fault arm, so an unbound bundle fails
    the review CLOSED and names why, rather than acting confidently on the wrong tree."""


def _make_live_stage(defn: AgentDefinition, run_dir: Path, defender_dir: Path, trace_name: str):
    """One live, agent-backed review stage: built lazily, one Agent per call, mirroring the
    gather-subagent-from-tool-body pattern. NOT exercised by the hermetic suite (every
    scenario there injects a fake), so treat a bundle built from it as a best-effort live
    default."""

    async def call(request):
        from defender.runtime import observe
        from defender.runtime.driver import build_agent_core

        logger = observe.RequestLogger(run_dir / trace_name)
        assert defn.deps_cls is not None, f"{defn.role.name}_DEF declares no deps_cls"
        try:
            agent = build_agent_core(
                defn, deps_type=defn.deps_cls,
                instructions=(
                    "You are a review stage. Respond to exactly what the prompt asks; you "
                    "hold no tools, no file-read grant, and no bash grant."
                ),
                logger=logger, agent_id=defn.role.value,
            )
            deps = bind_review_role(defn, run_dir, defender_dir=defender_dir)
            result = await agent.run(request.prompt, deps=deps)
            return str(result.output or "")
        finally:
            logger.close()

    return call


@dataclass
class ReviewStages:
    """The injection bundle `run_investigation(review_stages=…)`/`close_investigation(stages=…)`
    take — the seam, held open across #797/#796.

    IT CARRIES NO STAGES. #797 retired the three it was written around
    (`challenger`/`coherence_checker`/`projection`) and #796 fills it with the lens and
    composer roles that replace them. It is rewritten to an empty shape rather than kept with
    the three dead attribute names, because a bundle whose attributes name roles that no
    longer exist reads to every caller — and to the e2e harness's sixth injection seam — as if
    those roles were still there to inject.

    Between the two changes the gate has no reviewer at all and fails every confident close
    closed; see `challenge_gate.NO_REVIEWER`."""
