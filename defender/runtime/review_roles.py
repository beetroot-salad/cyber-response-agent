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

from dataclasses import dataclass, fields as dc_fields, replace
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

# `REVIEW_AGENT_ID_PREFIX` — the `agent_id` namespace every review stage's wire records
# carry — is re-exported here rather than DEFINED here. Its home is `agent_role`, beside
# gather's, because the cost readers in `scripts/visualize/` must agree with this writer
# exactly (a prefix that drifted on one side silently drops the review out of the run's
# accounted total again, which is the whole of #787) and that module imports nothing but
# `enum` — so agreeing costs the reader no runtime edge. Re-exported so a caller that already
# holds the review's module does not have to know where the constant sleeps.

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
class SupportDeps(AgentDeps):
    role: ClassVar[AgentRole] = AgentRole.SUPPORT


@dataclass(frozen=True)
class ComposerDeps(AgentDeps):
    role: ClassVar[AgentRole] = AgentRole.COMPOSER


# Each deps class exists ONLY to carry its `role` ClassVar. `AgentDeps.role` defaults to
# `AgentRole.MAIN`, so a review role bound through the base class would hold MAIN's identity —
# which passes the close tool's `deps.role is not AgentRole.MAIN` gate and flips
# `_is_learning_role`. The override is the whole class.

# The lens reads; the composer judges. The effort split follows that: a lens reconstructs
# what a projection supports, the composer weighs the readings against the investigation's
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


SUPPORT_DEF = _review_def(AgentRole.SUPPORT, SupportDeps, _LENS_EFFORT)
COMPOSER_DEF = _review_def(AgentRole.COMPOSER, ComposerDeps, _COMPOSER_EFFORT)


class UnboundReviewStage(RuntimeError):
    """A review stage was called from a composition root that never held a run dir.

    Raised by the stage rather than resolved by substituting the defender source tree for the
    missing run dir. That substitution was the shipped shape and it wrote the review's live
    artifacts inside the repo checkout and anchored the review roles' compiled policies on
    the source tree instead of on the run they were judging. Raising is the safer failure: the
    gate catches a stage's exception into its own stage-fault arm, so an unbound bundle fails
    the review CLOSED and names why, rather than acting confidently on the wrong tree."""


def _make_live_stage(  # noqa: PLR0913 — one stage's full wiring, named once
    defn: AgentDefinition, run_dir: Path, defender_dir: Path,
    logger: observe.RequestLogger, *, agent_id: str, instructions: str, build: Any,
):
    """One live, agent-backed review stage: built lazily, one Agent per call, mirroring the
    gather-subagent-from-tool-body pattern down to the wire log it writes into.

    It takes the RUN'S logger rather than minting its own. A review role's model calls are
    calls the run made, and every operator-facing cost figure is derived from
    `llm_requests.jsonl` or from the session store — so a stage on a private logger charged a
    real provider and landed in no accounted total at all (#787). The gather subagent is the
    precedent and the whole of the shape: one shared logger, one `agent_id` namespace, and a
    reader that filters on the prefix.

    `agent_id` is `review:{lens}` — PER LENS and not per role, because one role can be
    dispatched twice and `observe` keys its sequence and id on `agent_id`, so a shared one
    would collapse two readings into one in the log and in the visualizer. The per-lens split
    that used to be a FILENAME survives here, as the id; nothing needs a file of its own.

    The logger is NOT closed on the way out, and that is load-bearing rather than an
    omission: it belongs to the run, the main agent is still writing to it, and
    `RequestLogger.close` would take `llm_requests.jsonl` down mid-investigation.

    `build` is the agent-builder seam, defaulted by `live_review_stages` to
    `driver.build_agent_core`. It exists because this function is otherwise unreachable
    without a provider — the replay harness binds a fake bundle on the `review_stages` seam
    by DEFAULT, so a replay reaching here is itself the bug — and the two properties above
    (the id namespace, and the logger surviving the call) are exactly the ones no live run is
    a reasonable place to discover."""

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


@dataclass
class ReviewStages:
    """The injection bundle `run_investigation(review_stages=…)`/`close_investigation(stages=…)`
    take.

    Every field DEFAULTS TO NONE rather than being required, because one composition root
    genuinely has no run dir to bind a stage against (`driver.build_agent`) and must still
    produce a bundle. An unfilled field is therefore not a programming error to raise on at
    construction — it is a stage that is not bound, and `stage()` is where that becomes a
    fault.

    Read every stage through `stage()`, never off the attribute. The lookup used to sit
    OUTSIDE the gate's `try`, so an `AttributeError` from a partial bundle escaped the
    fail-closed arm entirely — past the gate, past the close tool, and into a driver that does
    not classify it. Through `stage()` a missing lens is `UnboundReviewStage`, which the gate
    catches like any other stage fault."""

    support: Any = None
    #: The SUPPORT role again, as a
    #: SEPARATE call under its own `review:{lens}` agent id, because `observe` keys its
    #: sequence and its record ids on the agent id — a shared one collapses the two readings
    #: into one in the wire log and in the visualizer. One role, two calls, two records.
    ablation: Any = None
    composer: Any = None

    def stage(self, name: str) -> Any:
        # The name is checked against this bundle's OWN fields before it is looked up. A bare
        # `getattr` answers for anything on the class — `stage("stage")` handed the gate this
        # method back as if it were a bound lens — and reported every typo as "no run dir",
        # which is a diagnosis of a different fault than the one that happened.
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
    """The production bundle, buildable only where the run dir AND the run's logger are.

    `logger` is the run's own `RequestLogger` — the same object the main agent and every
    gather subagent write through. It is required rather than defaulted: a bundle that could
    mint its own would be a bundle whose calls land outside every accounted total, which is
    the defect #787 reported. That the parameter has no default is what makes the composition
    root the only place this bundle can be built, which is the point — it used to be resolved
    ten lines above where the logger is opened, and the ordering was the whole bug.

    `model_override` is the OPERATOR's raw `--model`, threaded here unresolved. Resolving it
    against the investigator's model on the way would hand `resolve_review_model` a non-`None`
    value on every run, and the review's own default would be unreachable in production while
    a unit test calling it with `None` still proved it was the default."""
    from defender.runtime.driver import build_agent_core
    from defender.runtime.review import role_prompt

    build = build if build is not None else build_agent_core  # lint-default: ok — DI seam owning its default (the live agent builder; a signature default would close an import cycle)
    name = resolve_review_model(model_override)
    # One read per ROLE, not per call: SUPPORT is dispatched twice and its asset does not
    # change between the two.
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
