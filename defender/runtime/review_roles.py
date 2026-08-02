"""#774 — the two new review roles the live write-time gate drives from inside the close
tool: `CHALLENGER_DEF` and `COHERENCE_CHECKER_DEF`, their bind, and their input builders.

Both roles hold NO file-read grant and NO bash grant at all — not narrowed roots, zero. At
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
import os
from dataclasses import dataclass
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

#: Deliberately NOT `driver.resolve_main_model` — importing `driver` here would close a
#: module cycle (`driver` → `close_tool`/`challenge_gate` → `review_roles` → `driver`). Same
#: env var and default, read independently.
def _review_model() -> str:
    return os.environ.get("DEFENDER_MODEL") or "glm-5.2"


@dataclass(frozen=True)
class ChallengerDeps(AgentDeps):
    role: ClassVar[AgentRole] = AgentRole.CHALLENGER


@dataclass(frozen=True)
class CoherenceCheckerDeps(AgentDeps):
    role: ClassVar[AgentRole] = AgentRole.COHERENCE_CHECKER


CHALLENGER_DEF = AgentDefinition(
    role=AgentRole.CHALLENGER,
    model=_review_model,
    effort="low",
    tools=ToolSet(),
    deps_cls=ChallengerDeps,
    deny_reason=_DENY_REASON,
)

COHERENCE_CHECKER_DEF = AgentDefinition(
    role=AgentRole.COHERENCE_CHECKER,
    model=_review_model,
    effort="low",
    tools=ToolSet(),
    deps_cls=CoherenceCheckerDeps,
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
LEAD_TAG = ":L "


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


def _projected_lead_block(investigation_text: str) -> str:
    """RS18. The lead block PROJECTED to identity columns only (`id`/`name`/`target`) — the
    hypothesis pointers (`tests`) and the scheduling state (`loop`) are belief structure, on
    the inference side of the cut, and are withheld. Lead identity has to arrive at all: the
    challenger's own output contract requires a lead id per settled assertion."""
    rows = _lead_data_rows(investigation_text)
    if not rows:
        return ""
    lines = ["\n:L leads [id|name|target]"]
    for row in rows:
        lead_id = row[0] if len(row) > 0 else ""
        name = row[2] if len(row) > 2 else ""
        target = row[3] if len(row) > 3 else ""
        lines.append(f"{lead_id}|{name}|{target}")
    return "\n".join(lines) + "\n"


def _closed_ticket_note(deps: AgentDeps) -> str:
    """The benign-counter-direction affordance: prior closed-ticket precedent, when any is
    eligible. The instructional sentence is unconditional (the model always knows this
    affordance class exists); the SAMPLE itself is only appended when non-empty — an empty
    sample is omitted entirely rather than sent as an empty list, inheriting the existing
    actor's cold-start behaviour.

    The sampler (`ticket_seeds.sample_seeds`) shells out to a real ticket CLI subprocess —
    fine for the offline actor's own once-per-run cost, wildly wrong for a per-review-call
    prompt builder invoked (and re-invoked, on every refinement round) from inside the live
    write-time gate's own stage-deadline budget. `list_closed_fn=lambda _label: []` skips the
    subprocess entirely; a genuinely wired ticket-history affordance is a follow-up, not
    required by this suite (every scenario here runs against a repo with no closed-ticket
    fixtures for its alert's signature anyway)."""
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
            alert, deps.run_id, deps.run_id, list_closed_fn=lambda _label: [],
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


def build_challenger_input(deps: AgentDeps, disposition: str, direction) -> str:
    """The challenger's whole input: the observation layer, the projected lead block, and the
    direction-conditional exploration affordance — never the hypothesis/resolution/conclusion
    blocks, and never a file-read or bash grant."""
    inv_path = deps.run_dir / "investigation.md"
    investigation_text = inv_path.read_text(encoding="utf-8") if inv_path.is_file() else ""
    observation = _extract_observation_layer(investigation_text)
    leads = _projected_lead_block(investigation_text)
    affordance = _technique_menu() if direction.name == "adversarial" else _closed_ticket_note(deps)
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


def default_review_stages(run_dir: Path, defender_dir: Path) -> ReviewStages:
    """The default bundle when `run_investigation`/`close_investigation` is not handed one —
    live agent calls, one per stage. Oracle projection reuses the challenger's own role
    shape (no read/bash grant either) since #774 scopes only the two named roles; a
    dedicated projection role is a follow-up, not required by this suite."""
    return ReviewStages(
        challenger=_make_live_stage(CHALLENGER_DEF, run_dir, defender_dir, "review_challenger_live_trace.jsonl"),
        coherence_checker=_make_live_stage(
            COHERENCE_CHECKER_DEF, run_dir, defender_dir, "review_coherence_checker_live_trace.jsonl",
        ),
        projection=_make_live_stage(CHALLENGER_DEF, run_dir, defender_dir, "review_oracle_live_trace.jsonl"),
    )


__all__ = [
    "CHALLENGER_DEF",
    "COHERENCE_CHECKER_DEF",
    "ChallengerDeps",
    "CoherenceCheckerDeps",
    "ReviewStages",
    "bind_review_role",
    "build_challenger_input",
    "build_coherence_checker_input",
    "build_projection_input",
    "default_review_stages",
]
