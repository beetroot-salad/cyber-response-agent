"""#774 — the three review roles the live write-time gate drives from inside the close tool:
`CHALLENGER_DEF`, `COHERENCE_CHECKER_DEF` and `PROJECTION_DEF`, their bind, and their input
builders.

All three hold NO file-read grant and NO bash grant at all — not narrowed roots, zero. At
write time a review role's run dir IS the live investigation's own dir, and both grant
surfaces (`decide_read`'s root check, the bash lane's operand scope) admit it unconditionally
ahead of any narrowing, so a role that could read or run bash could always reach the live
working document — undoing the observation-layer cut the whole design rests on. The only
input either role receives is what this module inlines into its prompt, host-side — the same
pattern the two existing offline pipeline stages (`oracle`, `judge`) already use for their own
per-lead / per-case payloads.

`bind_review_role` mints its OWN fresh salt on every call and never receives the investigation's
— the gather subagent bind is the ONE place in this tree that shares salt with its parent, and
a review role built on that precedent would hold the delimiter of the frame its own output
returns inside (a role that reads attacker-influenced payloads must never hold that key)."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, ClassVar

from defender.runtime.agent_definition import AgentDefinition, RunScope, ToolSet, bind
from defender.runtime.agent_role import AgentRole
from defender.runtime.tools import AgentDeps

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


@dataclass(frozen=True)
class ChallengerDeps(AgentDeps):
    role: ClassVar[AgentRole] = AgentRole.CHALLENGER


@dataclass(frozen=True)
class CoherenceCheckerDeps(AgentDeps):
    role: ClassVar[AgentRole] = AgentRole.COHERENCE_CHECKER


@dataclass(frozen=True)
class ProjectionDeps(AgentDeps):
    role: ClassVar[AgentRole] = AgentRole.PROJECTION


CHALLENGER_DEF = AgentDefinition(
    role=AgentRole.CHALLENGER,
    model=resolve_review_model,
    effort="low",
    tools=ToolSet(),
    deps_cls=ChallengerDeps,
    deny_reason=_DENY_REASON,
)

COHERENCE_CHECKER_DEF = AgentDefinition(
    role=AgentRole.COHERENCE_CHECKER,
    model=resolve_review_model,
    effort="low",
    tools=ToolSet(),
    deps_cls=CoherenceCheckerDeps,
    deny_reason=_DENY_REASON,
)

#: R6. The projection stage's OWN role. Its blindness — one story, never told which side is
#: being challenged — is the design's whole argument for keeping it unleadable, and while it
#: was the challenger's definition re-bound at one call site that blindness lived in prompt
#: text: the challenger's direction-conditional affordance names the side being argued by
#: construction, so the next edit to the challenger's role would have leaked the direction
#: into the stage built not to know it.
PROJECTION_DEF = AgentDefinition(
    role=AgentRole.PROJECTION,
    model=resolve_review_model,
    effort="low",
    tools=ToolSet(),
    deps_cls=ProjectionDeps,
    deny_reason=_DENY_REASON,
)


def bind_review_role(
    defn: AgentDefinition, run_dir: Path, *, defender_dir: Path | None = None,
) -> AgentDeps:
    """Bind a review role's deps with its OWN fresh salt — PR7/PR8: never the session's."""
    return bind(defn, run_dir, scope=RunScope(), salt=None, defender_dir=defender_dir)


# --------------------------------------------------------------------------------------
# Input builders: the observation-layer cut (K28/K30) and the coherence checker's blindness.
# --------------------------------------------------------------------------------------

#: Kept in one place so the extraction logic and the test's own vocabulary cannot drift
#: (the test file imports the SAME tag tuples out of `_gate774`, which are transcribed from
#: here at authoring time).
OBSERVATION_TAGS: tuple[str, ...] = (":V ", ":E ", ":R attr_updates")
#: `:L findings` and NOT the bare `:L ` prefix. invlang gives every lead its own `:L`
#: SUB-blocks (`:L l-001.lead_preds`, the routing rules), and `:L findings` is the sole site
#: that declares a lead at all (`skills/invlang/validate.py`). Matching the prefix harvested
#: those sub-block rows too and read them through the findings table's column POSITIONS, so
#: the challenger was handed fabricated id/name/target triples — and the ids it then cited
#: back as `settled_by` are precisely what `_unexecuted_leads` refuses as hallucinated,
#: failing the whole review closed on the gate's own parsing.
LEAD_TAG = ":L findings"

#: RS18. The lead columns that survive the observation-layer cut. `tests` (the hypotheses the
#: lead was run to test) and `loop` (scheduling state) are belief structure and are withheld.
LEAD_IDENTITY_COLUMNS: tuple[str, ...] = ("id", "name", "target")


def _extract_observation_layer(investigation_text: str) -> str:
    """The observed graph facts and the learned-fact updates — never a hypothesis weight, a
    resolution/authorization verdict, or the conclusion. Filtering is by BLOCK TYPE (a tag
    match), not by section name — the residual is accepted and stated in the design: a kept
    block's prose can still imply the reached disposition; what's withheld is the disposition
    itself."""
    out: list[str] = []
    active = False
    for line in investigation_text.splitlines():
        if any(line.startswith(t) for t in OBSERVATION_TAGS):
            active = True
            out.append(line)
            continue
        if active:
            if not line.strip() or line.startswith((":", "`", "#")):
                active = False
                continue
            out.append(line)
    return "\n".join(out)


def _lead_data_rows(investigation_text: str) -> list[list[str]]:
    out: list[list[str]] = []
    inside = False
    for line in investigation_text.splitlines():
        if line.startswith(LEAD_TAG):
            inside = True
            continue
        if inside:
            if not line.strip() or line.startswith((":", "`", "#")):
                inside = False
                continue
            out.append([c.strip() for c in line.split("|")])
    return out


def _declared_lead_columns(investigation_text: str) -> list[str]:
    """The lead block's column names, in the order the DOCUMENT declares them.

    The investigator authors this table itself and nothing validates the column order it
    chooses, so reading the cut by fixed position makes the guarantee a convention the
    document's own author controls: reorder two columns and the wrong values go through
    silently, with no exception and no mismatch signal."""
    for line in investigation_text.splitlines():
        if line.startswith(LEAD_TAG) and "[" in line and "]" in line:
            inner = line[line.index("[") + 1: line.rindex("]")]
            return [c.strip().rstrip("?") for c in inner.split("|")]
    return []


def _projected_lead_block(investigation_text: str) -> str:
    """RS18. The lead block PROJECTED to identity columns only (`id`/`name`/`target`) — the
    hypothesis pointers (`tests`) and the scheduling state (`loop`) are belief structure, on
    the inference side of the cut, and are withheld. Lead identity has to arrive at all: the
    challenger's own output contract requires a lead id per settled assertion.

    Selection is by the DECLARED header, never by column position — see
    `_declared_lead_columns`. A document declaring none of the identity columns projects no
    block at all rather than a block of blanks attributed to names it never carried."""
    rows = _lead_data_rows(investigation_text)
    if not rows:
        return ""
    declared = _declared_lead_columns(investigation_text)
    at = {name: i for i, name in enumerate(declared)}
    if not any(column in at for column in LEAD_IDENTITY_COLUMNS):
        return ""
    lines = ["\n:L leads [" + "|".join(LEAD_IDENTITY_COLUMNS) + "]"]
    for row in rows:
        cells = []
        for column in LEAD_IDENTITY_COLUMNS:
            i = at.get(column)
            cells.append(row[i] if i is not None and i < len(row) else "")
        lines.append("|".join(cells))
    return "\n".join(lines) + "\n"


#: The lister the closed-ticket affordance is handed. The REAL one shells out to a ticket CLI
#: subprocess — fine for the offline actor's once-per-run cost, wildly wrong for a prompt
#: builder invoked (and re-invoked on every refinement round) inside the live gate's own
#: stage-deadline budget. So production hands in a lister that reaches nothing.
ClosedTicketLister = Callable[[str], list]


def _no_closed_tickets(_label: str) -> list:
    """The production lister: no ticket pool, and no subprocess to get one.

    It is a NAMED seam rather than an inline lambda because the branch that renders a history
    section is otherwise unreachable — nothing could establish that the section a cold start
    omits can exist at all, so the omission was satisfied by a fixed sentence that is present
    and empty in substance."""
    return []


def _closed_ticket_note(deps: AgentDeps, list_closed_fn: ClosedTicketLister) -> str:
    """The benign-counter-direction affordance: prior closed-ticket precedent, when any is
    eligible. The instructional sentence is unconditional (the model always knows this
    affordance class exists); the SAMPLE itself is only appended when non-empty — an empty
    sample is omitted entirely rather than sent as an empty list, because an empty menu reads
    to a model as "there are no prior closes", which is a claim the sampler never made.

    "Nobody asked" and "we asked and there were none" therefore render identically, and
    neither renders as a claim."""
    from defender.learning.tickets import ticket_seeds

    note = (
        "\nArgue the benign counter-story. Draw on closed-ticket precedent for base-rate "
        "context where it exists.\n"
    )
    try:
        alert = json.loads((deps.run_dir / "alert.json").read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001 — the affordance is best-effort
        alert = {}
    try:
        seeds = ticket_seeds.sample_seeds(
            alert, deps.run_id, deps.run_id, list_closed_fn=list_closed_fn,
        )
    except Exception:  # noqa: BLE001
        seeds = []
    if not seeds:
        return note
    return note + "\n## Closed-ticket history (base-rate context)\n" + ticket_seeds.format_seeds(seeds) + "\n"


def _technique_menu() -> str:
    """The malicious-counter-direction affordance: the MITRE technique menu, mirroring the
    existing adversarial actor's own affordance."""
    from defender.learning.pipeline.malicious_actor import mitre_corpus

    lines = [
        f"- {tid}: {name} ({tactic})"
        for tactic, tid, name in mitre_corpus.CORPUS[: mitre_corpus.MENU_SIZE]
    ]
    return "\n## Technique menu\n" + "\n".join(lines) + "\n"


def build_challenger_input(
    deps: AgentDeps, disposition: str, direction, *,
    list_closed_fn: ClosedTicketLister = _no_closed_tickets,
) -> str:
    """The challenger's whole input: the observation layer, the projected lead block, and the
    direction-conditional exploration affordance — never the hypothesis/resolution/conclusion
    blocks, and never a file-read or bash grant.

    `list_closed_fn` is DEFAULTED to the production lister: a mandatory parameter would force
    every call site that reaches this builder indirectly to name a value only a scenario ever
    supplies."""
    inv_path = deps.run_dir / "investigation.md"
    investigation_text = inv_path.read_text(encoding="utf-8") if inv_path.is_file() else ""
    observation = _extract_observation_layer(investigation_text)
    leads = _projected_lead_block(investigation_text)
    affordance = (
        _technique_menu() if direction.name == "adversarial"
        else _closed_ticket_note(deps, list_closed_fn)
    )
    return (
        f"The investigation reached a confident disposition: {disposition}.\n"
        f"Argue the counter-disposition: {direction.name}.\n\n"
        "## Observation layer\n"
        f"{observation}\n"
        f"{leads}"
        f"{affordance}\n"
        "Output ONE JSON object: either {\"counter_story\": <str>, \"requirements\": "
        "[{\"assertion\": <str>, \"settled_by\": <lead_id or null>, \"if_false\": <str>}, ...]} "
        "or a deliberate decline {\"counter_story\": null, \"declined\": true, \"reason\": <str>}."
    )


def build_refinement_input(base_prompt: str, prior_story: str, coherence_gap: str) -> str:
    """The SECOND ASK, not a retry. A refinement round exists because the coherence checker
    found the counter-story internally inconsistent, so the round carries the story that
    failed and the inconsistency that was named. Re-sending the identical prompt makes the
    grace budget a coin flip and makes the rounds-consumed count — the design's only stated
    evidence-strength signal — mean nothing.

    The gap is inlined raw rather than framed on the investigation's own salt: a review role
    must never hold the delimiter of the frame its own output returns inside (PR7/PR8)."""
    return (
        f"{base_prompt}\n\n"
        "## Refinement round\n"
        "The counter-story below was judged INTERNALLY INCONSISTENT. Rewrite it so the "
        "inconsistency named is resolved, or decline. Same output contract as above.\n\n"
        "### The counter-story that failed\n"
        f"{prior_story}\n\n"
        "### The inconsistency the coherence checker named\n"
        f"{coherence_gap}\n"
    )


def build_coherence_checker_input(counter_story: str) -> str:
    """RS10. The counter-story alone — no payload access, no run-dir access, nothing else."""
    return (
        "Check this counter-story for INTERNAL CONSISTENCY only — you cannot see the case, "
        "only whether the story contradicts itself. Reply COHERENT or INCOHERENT.\n\n"
        f"{counter_story}"
    )


def build_projection_input(deps: AgentDeps, counter_story: str, lead_ids: tuple[str, ...]) -> str:
    """RS10. A LIVE-shaped projection input built off the run's own directory — not the
    learning-run geography the existing oracle projection primitive is invoked with today."""
    ids = ", ".join(lead_ids) if lead_ids else "(none executed)"
    return (
        f"run_dir: {deps.run_dir}\n"
        f"counter_story: {counter_story}\n"
        f"executed_leads: {ids}\n"
        "For each executed lead, tag its projection against the counter-story as one of "
        "has-projection / empty-projection / no-projection."
    )


@dataclass
class ReviewStages:
    """The production, live-agent-backed shape of the injection bundle
    `run_investigation(review_stages=…)`/`close_investigation(stages=…)` take — duck-compatible
    with `_gate774.FakeReviewStages` (same three attribute names). Built lazily, one Agent per
    call, mirroring the gather-subagent-from-tool-body pattern; NOT exercised by the hermetic
    suite (every scenario there injects a fake), so treat this as a best-effort live default."""

    challenger: Any
    coherence_checker: Any
    projection: Any


def _make_live_stage(defn: AgentDefinition, run_dir: Path, defender_dir: Path, trace_name: str):
    async def call(request):
        from defender.runtime import observe
        from defender.runtime.driver import build_agent_core

        logger = observe.RequestLogger(run_dir / trace_name)
        assert defn.deps_cls is not None, f"{defn.role.name}_DEF declares no deps_cls"
        try:
            agent = build_agent_core(
                defn, deps_type=defn.deps_cls,
                instructions=(
                    "You are a #774 review stage. Respond to exactly what the prompt asks; "
                    "you hold no tools, no file-read grant, and no bash grant."
                ),
                logger=logger, agent_id=defn.role.value,
            )
            deps = bind_review_role(defn, run_dir, defender_dir=defender_dir)
            result = await agent.run(request.prompt, deps=deps)
            return str(result.output or "")
        finally:
            logger.close()

    return call


class UnboundReviewStage(RuntimeError):
    """A review stage was called from a composition root that never held a run dir."""


def unbound_review_stages(reason: str) -> ReviewStages:
    """The bundle for a build that has NO run dir to bind the stages to.

    The alternative this replaces was to bind them to the defender source tree — which put
    each stage's live trace file inside the repo checkout and anchored the review roles'
    compiled policies on the source tree instead of on the run they were judging. Raising is
    the safer failure: the gate catches a stage's exception into its own stage-fault arm, so
    an unbound bundle fails the review CLOSED and names why, rather than acting confidently
    on the wrong tree."""

    def stage(role_name: str):
        async def call(request):
            raise UnboundReviewStage(f"{role_name}: {reason}")

        return call

    return ReviewStages(
        challenger=stage("challenger"),
        coherence_checker=stage("coherence_checker"),
        projection=stage("projection"),
    )


def default_review_stages(
    run_dir: Path, defender_dir: Path, *, model: str | None = None,
) -> ReviewStages:
    """The default bundle when `run_investigation`/`close_investigation` is not handed one —
    live agent calls, one per stage, each under its OWN role.

    `model` is the operator's per-run override. It is resolved ONCE here, at the boundary,
    and threaded into all three definitions as a concrete name: the stages used to resolve
    their own model through a zero-parameter accessor, which is structurally incapable of
    receiving an override, so the operator's choice bought the review nothing and the startup
    check validated a model the run would not use."""
    name = resolve_review_model(model)

    def staged(defn: AgentDefinition, trace_name: str):
        return _make_live_stage(
            replace(defn, model=lambda: name), run_dir, defender_dir, trace_name,
        )

    return ReviewStages(
        challenger=staged(CHALLENGER_DEF, "review_challenger_live_trace.jsonl"),
        coherence_checker=staged(
            COHERENCE_CHECKER_DEF, "review_coherence_checker_live_trace.jsonl",
        ),
        projection=staged(PROJECTION_DEF, "review_projection_live_trace.jsonl"),
    )


__all__ = [
    "CHALLENGER_DEF",
    "COHERENCE_CHECKER_DEF",
    "PROJECTION_DEF",
    "ChallengerDeps",
    "CoherenceCheckerDeps",
    "ProjectionDeps",
    "ReviewStages",
    "UnboundReviewStage",
    "bind_review_role",
    "build_challenger_input",
    "build_coherence_checker_input",
    "build_projection_input",
    "build_refinement_input",
    "default_review_stages",
    "resolve_review_model",
    "unbound_review_stages",
]
