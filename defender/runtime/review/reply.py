"""Reading what the lenses and the composer return.

Every refusal here lands on ONE failure kind — `unreadable`. A reply the gate never read says
nothing about the reasoning behind it, so folding "would not parse" together with "answered
inside its contract and the content was unusable" would inflate the apparent quality-failure
rate. Nothing in this module mints a quality signal, so nothing here needs a second kind.

**No fail-open read.** A check that asks whether a reply contains one word treats everything
else — an empty string, a refusal, a stray blob, a timeout's leftover detail — as the
permissive value, and a confident disposition then commits on a counter-story nothing judged.
A reply that answers neither way has not completed, lens readings included.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

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

#: The ask is model-authored text on the channel that returns to the LIVE session, so it is
#: bounded. Not a limit on how much a reviewer may think — a limit on how much of it is handed
#: to another agent.
ASK_PROSE_MAX = 500


class Unreadable(RuntimeError):
    """A reply the gate cannot use. Never a finding about the evidence."""


@dataclass(frozen=True)
class Ask:
    """The one measurement a challenged close wants before it can stand."""

    target: str
    prose: str


#: The composer's finding, as a CLOSED two-member vocabulary the host dispatches on.
#:
#: It exists because the host cannot derive it. "The close holds" and "there is a gap, and
#: nothing measurable would settle it" both carry no ask, and they route to opposite outcomes
#: — one commits the confident disposition, the other overrides it. One bit, and the only
#: thing in this contract that is not prose. Two members, each earning its place by a DIFFERENT
#: consequence rather than by naming a different condition.
HOLDS = "holds"
GAP = "gap"
FINDINGS: frozenset[str] = frozenset({HOLDS, GAP})


@dataclass(frozen=True)
class Review:
    """The composer's whole output: its finding, its prose, and at most one ask."""

    finding: str
    review: str
    ask: Ask | None

    @property
    def holds(self) -> bool:
        return self.finding == HOLDS


def citable_refs(companion: CompanionBody) -> frozenset[str]:
    """Every invlang id a review may name.

    The invented-identifier guard: unbounded, a hallucinated — or foreign-run — id flows back
    to the investigator as work to go do, charging the investigation for a hallucination. An
    ask's target is that hazard on a wide surface, since it may name an entity or a hypothesis
    rather than only a lead."""
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
    fail: a reply with nothing in it. A lens that reached no reading has not completed, and a
    composer handed an empty reading would weigh silence as agreement."""
    reading = (text or "").strip()
    if not reading:
        raise Unreadable("a lens returned no reading")
    return reading


#: A whole reply that is one markdown code fence and nothing else. Models emit this under
#: "output JSON and nothing else" often enough that refusing it would fail a confident close
#: closed on PACKAGING rather than on content — and unlike normalising a value, unwrapping a
#: fence changes nothing the reader then validates: the object inside goes through the same
#: `finding`/`review`/`ask`/`refs` checks, character for character. Deliberately anchored at
#: both ends: a fence that is merely PRESENT somewhere in a reply of prose means the composer
#: answered outside its contract, and that is still unreadable.
_WHOLE_FENCE_RE = re.compile(r"\A```[A-Za-z0-9_+-]*[ \t]*\r?\n(?P<body>.*)\r?\n?```\Z", re.S)


def _unfenced(text: str) -> str:
    match = _WHOLE_FENCE_RE.match(text.strip())
    return match.group("body") if match else text


def read_composer_reply(text: str | None, *, refs: frozenset[str]) -> Review:
    """The composer's `Review`, or `Unreadable`.

    `refs` is the citable set from the SAME parsed companion the projections were built
    from — an ask validated against a different parse is an ask validated against a
    different document."""
    try:
        obj = json.loads(_unfenced(text or ""))
    except (json.JSONDecodeError, TypeError) as e:
        raise Unreadable(f"the composer's reply did not parse as JSON: {e}") from e
    if not isinstance(obj, dict):
        raise Unreadable("the composer's reply is not a JSON object")

    review = obj.get("review")
    if not isinstance(review, str) or not review.strip():
        raise Unreadable("the composer's reply carries no review")

    # A closed vocabulary is CHECKED, not assumed: an unchecked tag lets a misspelling fall
    # through to the permissive arm and commit an override with no failure kind — the review's
    # own breakage recorded as a finding about the evidence.
    finding = obj.get("finding")
    # `isinstance` BEFORE the membership test: `FINDINGS` is a frozenset, so a reply that
    # spells this field as a list or a mapping raises `TypeError: unhashable type` rather
    # than the `Unreadable` this branch exists to raise — and TypeError is not what any
    # caller catches, so it escapes `challenge_gate` and `run_investigation` entirely,
    # taking report.md and the review record with it and leaving this stage's trace row
    # marked `ok: true`. Same guard `review` already carries six lines up.
    if not isinstance(finding, str) or finding not in FINDINGS:
        raise Unreadable(
            f"the composer's finding is {finding!r}, outside {sorted(FINDINGS)}"
        )

    # ABSENT and NULL are the same answer here, and both are readable: "nothing measurable
    # would settle this" is a real finding the host routes on, not a reply that failed to
    # arrive. Collapsing it into the unreadable arm would lose the finding.
    raw_ask = obj.get("ask")
    if raw_ask is None:
        return Review(finding=finding, review=review.strip(), ask=None)
    if finding == HOLDS:
        # Not tolerated by dropping the ask: a composer that says the close holds AND asks
        # for a measurement has contradicted itself, and either half could be the one it
        # meant. Silently keeping one is the gate choosing for it.
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
