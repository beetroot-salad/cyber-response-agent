"""Reading what the lenses and the composer return.

Every refusal here is one failure kind — `unreadable` — never a quality signal about the
reasoning.

No fail-open read: a reply that answers neither way has not completed (lens readings
included), rather than defaulting to the permissive value.
"""

from __future__ import annotations

import json
import re
from defender._model import model

from defender.skills.invlang import _walkers
from defender.skills.invlang.schema import CompanionBody

__all__ = [
    "ASK_PROSE_MAX",
    "FINDINGS",
    "GAP",
    "HOLDS",
    "Ask",
    "Review",
    "Unreadable",
    "citable_refs",
    "read_composer_reply",
    "read_lens_reading",
]

#: Bound on the model-authored ask handed back to the live session.
ASK_PROSE_MAX = 500


class Unreadable(RuntimeError):
    """A reply the gate cannot use. Never a finding about the evidence."""


@model(frozen=True)
class Ask:
    """The one measurement a challenged close wants before it can stand."""

    target: str
    prose: str


#: The composer's finding, a closed two-member vocabulary the host dispatches on. Needed
#: because "holds" and "gap with nothing measurable" both carry no ask but route oppositely.
HOLDS = "holds"
GAP = "gap"
FINDINGS: frozenset[str] = frozenset({HOLDS, GAP})


@model(frozen=True)
class Review:
    """The composer's whole output: its finding, its prose, and at most one ask."""

    finding: str
    review: str
    ask: Ask | None

    @property
    def holds(self) -> bool:
        return self.finding == HOLDS


def citable_refs(companion: CompanionBody) -> frozenset[str]:
    """Every invlang id a review may name — the guard against a hallucinated or foreign id
    flowing back to the investigator as work."""
    refs = {v["id"] for v in _walkers.all_vertices(companion) if v.get("id")}
    refs |= {e["id"] for e in _walkers.all_edges(companion) if e.get("id")}
    refs |= set(_walkers.all_hypotheses(companion))
    refs |= {
        lead["id"] for lead in (companion.get("findings") or [])
        if isinstance(lead, dict) and lead.get("id")
    }
    return frozenset(refs)


def read_lens_reading(text: str | None) -> str:
    """A lens's reading, or `Unreadable` if empty (a composer would weigh silence as agreement)."""
    reading = (text or "").strip()
    if not reading:
        raise Unreadable("a lens returned no reading")
    return reading


#: A whole reply that is one markdown code fence. Models often wrap JSON this way; unwrapping
#: changes nothing that is then validated. Anchored at both ends: a fence inside prose is still
#: unreadable.
_WHOLE_FENCE_RE = re.compile(r"\A```[A-Za-z0-9_+-]*[ \t]*\r?\n(?P<body>.*)\r?\n?```\Z", re.S)


def _unfenced(text: str) -> str:
    match = _WHOLE_FENCE_RE.match(text.strip())
    return match.group("body") if match else text


def read_composer_reply(text: str | None, *, refs: frozenset[str]) -> Review:
    """The composer's `Review`, or `Unreadable`.

    `refs` must come from the same parsed companion the projections were built from."""
    try:
        obj = json.loads(_unfenced(text or ""))
    except (json.JSONDecodeError, TypeError) as e:
        raise Unreadable(f"the composer's reply did not parse as JSON: {e}") from e
    if not isinstance(obj, dict):
        raise Unreadable("the composer's reply is not a JSON object")

    review = obj.get("review")
    if not isinstance(review, str) or not review.strip():
        raise Unreadable("the composer's reply carries no review")

    # Checked, not assumed, so a misspelling cannot fall through to a permissive arm.
    finding = obj.get("finding")
    # `isinstance` first: the membership test hashes, and a list or mapping would raise
    # `TypeError`, which no caller catches.
    if not isinstance(finding, str) or finding not in FINDINGS:
        raise Unreadable(
            f"the composer's finding is {finding!r}, outside {sorted(FINDINGS)}"
        )

    # Absent and null both mean "no ask", a real answer the host routes on.
    raw_ask = obj.get("ask")
    if raw_ask is None:
        return Review(finding=finding, review=review.strip(), ask=None)
    if finding == HOLDS:
        # Self-contradictory; either half could be the intended one.
        raise Unreadable("the composer's finding is `holds` but it also returned an ask")
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
    return Review(
        finding=finding, review=review.strip(),
        ask=Ask(target=target, prose=prose.strip()[:ASK_PROSE_MAX]),
    )
