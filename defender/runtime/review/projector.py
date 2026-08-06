"""The projections the blind lenses read — THE cut, in one definition, over the PARSED
companion.

A lens reconstructs the investigation's belief movement from what the investigation
observed. That only measures anything if the lens cannot see the movement itself, so the
cut is what the whole design rests on, and it is built in two stages on purpose:

    prune  →  render

The prune removes the withheld keys from the parsed object; the render turns what survives
into the lens's user message. A renderer is then physically incapable of leaking what the
prune removed, and "no inference reaches a lens" is a property of a DATA STRUCTURE that a
test can assert directly, rather than a substring search over rendered prose that passes
whenever the wording changes.

**The cut is the `:T` tag family.** invlang already separates the two sides and says so:
`:R` records check results and learned facts, `:T resolutions` records belief movement. So
the rule is the whole family, not a list of the sub-blocks inside it — `:T resolutions`,
`:T conclude`, `:T close` and `:T shelved` are all inference, and enumerating three of the
four is how the rule drifts the next time a fifth is added. `:V`, `:E`, `:R`, `:H` and `:L`
are what a lens sees.

The retired observation-layer cut matched tag PREFIXES over the raw document, which is the
bug rather than the tag list: `:L` prefix-matching harvested every lead's `:L
l-001.lead_preds` sub-block through the findings table's column positions and fabricated
id/name/target triples. Reading the parsed object removes the whole class — there are no
prefixes to match and no column positions to read by.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from defender.skills.invlang.parser import parse_dense_companion
from defender.skills.invlang.schema import CompanionBody

__all__ = [
    "DISCRIMINATION_WITHHELD_LEAD_KEYS",
    "INFERENCE_COMPANION_KEYS",
    "INFERENCE_LEAD_KEYS",
    "EmptyInvestigation",
    "Projection",
    "discrimination_projection",
    "observation_only",
    "parse_investigation",
    "support_projection",
]

#: The `:T`-derived keys on the companion itself. `:T conclude` lands in `conclude`;
#: `:T close` appends to `closed_loops`.
INFERENCE_COMPANION_KEYS: tuple[str, ...] = ("conclude", "closed_loops")

#: The `:T`-derived keys the parser nests under each `:L findings` lead. `:T resolutions`
#: lands in `resolutions`; `:T shelved` lands in `shelved` and `shelved_rationales`.
INFERENCE_LEAD_KEYS: tuple[str, ...] = ("resolutions", "shelved", "shelved_rationales")

#: What the DISCRIMINATION lens gives up beyond the `:T` family. It is asked what a lead's
#: possible outcomes could separate, so it must not see the outcomes (`outcome`) — and it
#: must not see `tests_hypotheses`, which is the investigator's own answer to exactly the
#: question being asked. Handing a lens the answer is the failure mode blindness exists to
#: prevent, and `tests_hypotheses` is on the `:L` side of the tag cut rather than the `:T`
#: side, so nothing above would have caught it.
DISCRIMINATION_WITHHELD_LEAD_KEYS: tuple[str, ...] = ("outcome", "tests_hypotheses")


class EmptyInvestigation(RuntimeError):
    """The document carried no parseable invlang at all.

    Its own arm rather than an empty projection, because `parse_dense_companion` reads only
    what is inside ```invlang fences and returns an empty companion — no error, no warning —
    for a document that has none. Rendered as a projection that would be a lens reconstructing
    from nothing, a composer reviewing a void, and a confident close reviewed by a review that
    never saw it. Every fixture in the tree is fenced, so nothing in the hermetic suite would
    ever show it.
    """


@dataclass(frozen=True)
class Projection:
    """One lens's whole input: the lens it was built for, and the rendered user message."""

    lens: str
    text: str


def parse_investigation(text: str) -> CompanionBody:
    """The parsed companion, or `EmptyInvestigation`. The one entry point — every projection
    is built from this rather than from the raw document."""
    companion, _warnings = parse_dense_companion(text)
    if not companion:
        raise EmptyInvestigation(
            "the investigation carried no parseable invlang — a projection built from it "
            "would ask a lens to reconstruct from nothing"
        )
    return companion


def _without(record: Any, keys: tuple[str, ...]) -> dict:
    return {k: v for k, v in record.items() if k not in keys}


def observation_only(
    companion: CompanionBody, *, also_drop_per_lead: tuple[str, ...] = (),
) -> dict:
    """THE cut: the companion with every `:T`-derived key removed, at both levels.

    `also_drop_per_lead` is the per-lens narrowing on top of the family rule. It is a
    parameter rather than a second function so that every projection in this module provably
    passes through the `:T` prune — a lens with its own builder is a lens that can be given
    its own idea of what inference is."""
    pruned = _without(companion, INFERENCE_COMPANION_KEYS)
    drop = INFERENCE_LEAD_KEYS + also_drop_per_lead
    leads = [
        _without(lead, drop) for lead in (companion.get("findings") or [])
        if isinstance(lead, dict)
    ]
    if "findings" in pruned:
        pruned["findings"] = leads
    return pruned


def _render_projection(lens: str, companion: dict, ask: str) -> Projection:
    """The pruned object as the lens's user message.

    JSON rather than re-serialised invlang: a second invlang writer is a second thing that
    can disagree with the parser, and the point of reading the parsed object was to stop
    having two accounts of the document. What a lens receives is explicitly a host rendering,
    not the document."""
    body = json.dumps(companion, indent=2, sort_keys=True, default=str)
    return Projection(lens=lens, text=f"{ask}\n\n## Investigation (host-rendered)\n{body}\n")


_DISCRIMINATION_ASK = (
    "Each lead below was run to separate competing explanations. For each one, say which of "
    "the hypotheses its possible outcomes could have told apart, and which it could not — "
    "an outcome both explanations predict separates nothing. You are not told what any lead "
    "returned, and you are not told which hypotheses the investigation aimed each lead at."
)

_SUPPORT_ASK = (
    "Below is what this investigation observed. For each hypothesis, say what the observed "
    "evidence supports, how strongly on the ++/+/-/-- scale, and for which hypothesis only — "
    "evidence that every competing explanation predicts equally supports none of them. Name "
    "the specific edges and resolutions you are reasoning from. If nothing here moves a "
    "hypothesis, say that."
)


_COMPOSER_ASK = (
    "Independent lens readings first, then the investigation's own account of how it moved "
    "and what it concluded. Each lens reached its reading without seeing that account."
)


def composer_projection(companion: CompanionBody, readings: dict[str, str]) -> Projection:
    """The composer's input: every lens reading, and then the WHOLE companion.

    The one projection that withholds nothing. The composer is allowed to be anchored by the
    investigation's own account precisely because the independent work is already banked — it
    reads a completed set of readings rather than producing one. Ordering is deliberate: the
    readings come first, so the account is what gets weighed against them rather than the
    frame they are read through."""
    lenses = "\n\n".join(
        f"### Lens: {lens}\n{reading}" for lens, reading in sorted(readings.items())
    )
    body = json.dumps(companion, indent=2, sort_keys=True, default=str)
    return Projection(
        lens="composer",
        text=(
            f"{_COMPOSER_ASK}\n\n## Lens readings\n{lenses}\n\n"
            f"## The investigation's own account (host-rendered)\n{body}\n"
        ),
    )


def discrimination_projection(companion: CompanionBody) -> Projection:
    return _render_projection(
        "discrimination",
        observation_only(companion, also_drop_per_lead=DISCRIMINATION_WITHHELD_LEAD_KEYS),
        _DISCRIMINATION_ASK,
    )


def support_projection(companion: CompanionBody, *, without_edge: str | None = None) -> Projection:
    """The support lens, and — with `without_edge` — the ablation lens.

    ONE builder for both, because the ablation reading is only interpretable as a difference
    against the support reading: the two must be the same projection under the same prompt,
    differing in exactly one edge, or the difference measures the projection rather than the
    edge. The lens is never told an edge was removed; a lens hunting for a gap is not
    reconstructing."""
    pruned = observation_only(companion)
    if without_edge is not None:
        pruned = _drop_edge(pruned, without_edge)
    return _render_projection("support", pruned, _SUPPORT_ASK)


def _drop_edge(companion: dict, edge_id: str) -> dict:
    """Remove one observed edge wherever it was recorded — the prologue's `:E` block and any
    lead's own observations."""
    out = dict(companion)
    pro = dict(out.get("prologue") or {})
    if pro.get("edges"):
        pro["edges"] = [e for e in pro["edges"] if e.get("id") != edge_id]
        out["prologue"] = pro
    leads = []
    for lead in out.get("findings") or []:
        lead = dict(lead)
        outcome = dict(lead.get("outcome") or {})
        obs = dict(outcome.get("observations") or {})
        if obs.get("edges"):
            obs["edges"] = [e for e in obs["edges"] if e.get("id") != edge_id]
            outcome["observations"] = obs
            lead["outcome"] = outcome
        leads.append(lead)
    if "findings" in out:
        out["findings"] = leads
    return out
