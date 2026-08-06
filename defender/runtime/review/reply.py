"""Reading what the lenses and the composer return.

Every refusal here lands on ONE failure kind — `unreadable`. A reply the gate never read
says nothing about the reasoning behind it, so folding "would not parse" together with
"answered inside its contract and the content was unusable" inflates the apparent
quality-failure rate; the retired gate spent a whole vocabulary member on keeping those
apart. Nothing in this module mints a quality signal, so nothing here needs a second kind.

The other rule the retired gate paid for: **no fail-open read**. Its coherence check asked
whether a reply contained one word and treated everything else — an empty string, a refusal,
a stray blob, a timeout's leftover detail — as the permissive value, and a confident
disposition then committed on a counter-story nothing had judged. A reply that answers
neither way has not completed, and that applies to a lens reading the composer cannot use
exactly as it applied there.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from defender.skills.invlang import _walkers
from defender.skills.invlang.schema import CompanionBody

__all__ = [
    "ASK_PROSE_MAX",
    "Ask",
    "Review",
    "Unreadable",
    "citable_refs",
    "read_composer_reply",
    "read_lens_reading",
]

#: The ask is model-authored text on the channel that returns to the LIVE session, so it
#: carries the bound the retired requirement text carried on that same channel. Not a limit
#: on how much a reviewer may think — a limit on how much of it is handed to another agent.
ASK_PROSE_MAX = 500


class Unreadable(RuntimeError):
    """A reply the gate cannot use. Never a finding about the evidence."""


@dataclass(frozen=True)
class Ask:
    """The one measurement a challenged close wants before it can stand."""

    target: str
    prose: str


@dataclass(frozen=True)
class Review:
    """The composer's whole output: its prose, and at most one ask."""

    review: str
    ask: Ask | None


def citable_refs(companion: CompanionBody) -> frozenset[str]:
    """Every invlang id a review may name.

    The invented-identifier guard, generalised. The retired gate refused a projection row
    naming a lead the host never sent out, because unbounded a hallucinated — or
    foreign-run — id flowed into the discriminating set and was handed back to the
    investigator as work to go do: the forced turn's economy inverted, with the gate charging
    the investigation for a hallucination. An ask's target is the same hazard on a wider
    surface, because it may name an entity or a hypothesis rather than only a lead."""
    refs = {v["id"] for v in _walkers.all_vertices(companion) if v.get("id")}
    refs |= {e["id"] for e in _walkers.all_edges(companion) if e.get("id")}
    refs |= set(_walkers.all_hypotheses(companion))
    refs |= {
        lead["id"] for lead in (companion.get("findings") or [])
        if isinstance(lead, dict) and lead.get("id")
    }
    return frozenset(refs)


def read_lens_reading(text: str | None) -> str:
    """A lens's reading, or `Unreadable`.

    A lens answers in prose, so there is no shape to check — which leaves exactly one way to
    fail, and it is the one the fail-open read used to swallow: a reply with nothing in it.
    A lens that reached no reading has not completed, and a composer handed an empty reading
    would weigh silence as agreement."""
    reading = (text or "").strip()
    if not reading:
        raise Unreadable("a lens returned no reading")
    return reading


def read_composer_reply(text: str | None, *, refs: frozenset[str]) -> Review:
    """The composer's `Review`, or `Unreadable`.

    `refs` is the citable set from the SAME parsed companion the projections were built
    from — an ask validated against a different parse is an ask validated against a
    different document."""
    try:
        obj = json.loads(text or "")
    except (json.JSONDecodeError, TypeError) as e:
        raise Unreadable(f"the composer's reply did not parse as JSON: {e}") from e
    if not isinstance(obj, dict):
        raise Unreadable("the composer's reply is not a JSON object")

    review = obj.get("review")
    if not isinstance(review, str) or not review.strip():
        raise Unreadable("the composer's reply carries no review")

    # ABSENT and NULL are the same answer here, and both are readable: "nothing measurable
    # would settle this" is a real finding the host routes on, not a reply that failed to
    # arrive. Collapsing it into the unreadable arm would lose the finding.
    raw_ask = obj.get("ask")
    if raw_ask is None:
        return Review(review=review.strip(), ask=None)
    if not isinstance(raw_ask, dict):
        raise Unreadable("the composer's ask is neither an object nor null")

    target = raw_ask.get("target")
    prose = raw_ask.get("prose")
    if not isinstance(target, str) or not isinstance(prose, str) or not prose.strip():
        raise Unreadable("the composer's ask lacks a target or a dimension to measure")
    if target not in refs:
        raise Unreadable(
            f"the composer's ask names {target!r}, which the investigation never recorded"
        )
    return Review(review=review.strip(), ask=Ask(target=target, prose=prose.strip()[:ASK_PROSE_MAX]))
