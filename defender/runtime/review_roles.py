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

from defender.runtime.agent_definition import AgentDefinition, RunScope, bind
from defender.runtime.tools import AgentDeps

__all__ = [
    "ReviewStages",
    "UnboundReviewStage",
    "bind_review_role",
    "resolve_review_model",
]

_DENY_REASON = (
    "Blocked: this review stage is a pure text-in/text-out projection — its entire input is "
    "inlined in the prompt and its entire output is one document. It holds no read grant and "
    "no bash grant of any kind."
)


def resolve_review_model(explicit: str | None = None) -> str:
    """The model every review stage runs on — the INVESTIGATOR's own resolver, so an
    operator's per-run `--model` reaches the review as well as the investigation, and the
    shipped default has exactly ONE home.

    A private copy of the env var and the default id was the shipped shape, on the stated
    grounds of an import cycle. It bought a review that could not receive the override at all
    (the accessor took no parameter) and a second copy of the default that drifts the first
    time the default moves. The cycle is real but it is an IMPORT-TIME one only: `driver`
    imports this module, so the import lives in the body rather than at module scope."""
    from defender.runtime.driver import resolve_main_model

    return resolve_main_model(explicit)


def bind_review_role(
    defn: AgentDefinition, run_dir: Path, *, defender_dir: Path | None = None,
) -> AgentDeps:
    """Bind a review role's deps with its OWN fresh salt — PR7/PR8: never the session's."""
    return bind(defn, run_dir, scope=RunScope(), salt=None, defender_dir=defender_dir)


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
