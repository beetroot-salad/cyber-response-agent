"""Closed vocabularies the project shares — the ones no single schema owns.

A vocabulary belongs here when more than one schema has to agree on it. Everything else stays
where it is used: invlang's entity types and relations are invlang's own domain and live in
`skills/invlang/vocab.py`, the permission gate's program lists are the gate's, and neither is
project-general just for being a set of strings.

`disposition` is the first that is. The run's headline appears in TWO model-authored artifacts
— `report.md`'s frontmatter and `investigation.md`'s `conclude` block — validated by two
different schemas, and the report schema already imports invlang's validator, so keeping the
enum there left invlang one import edge from a cycle. Below both is the only place it can sit.

Both halves live together on purpose. A vocabulary and the answer to "is this value in it"
separate the moment they are apart: #785 was six consumers borrowing the enum and each
re-deriving the membership test, and five of them lost #722's zero-width strip on the way.
Importing the set without the function is how that starts again — `lint_borrowed_vocabulary`
exists to catch it.
"""

from __future__ import annotations

from defender._text import strip_zero_width

# The canonical run-disposition vocabulary. It reached here from the report schema, which
# reached it from the learning loop's config (#714) — each move was the same correction, the
# vocabulary sitting inside one of its consumers instead of underneath all of them.
DISPOSITION_ENUM = {"benign", "inconclusive", "malicious"}

# The same vocabulary in a stable order, for the surfaces that must RENDER it: deny reasons,
# the invlang slot catalog the runtime prompt inlines. A set's iteration order is not stable
# across processes, and a prompt that reshuffles between runs is a diff with no meaning.
DISPOSITION_VALUES: tuple[str, ...] = tuple(sorted(DISPOSITION_ENUM))


def normalized_disposition(value: object) -> str | None:
    """A disposition as it RENDERS — a `DISPOSITION_ENUM` member — or `None` when it is not one
    of the three. THE single answer to what a disposition value MEANS, wherever it was read
    from: report frontmatter, an invlang `conclude` block, or a ticket's resolution line.

    The #722 zero-width strip lives here and nowhere else. Both artifacts are authored by a
    model reading attacker-influenced alert data, so a character that occupies no space must
    not decide a gate; the value is judged on what a human would see.

    A non-`str` value (a YAML list, an int) is rejected before the enum test rather than fed to
    it — `DISPOSITION_ENUM` is a set, so an unhashable value would raise `TypeError` out of
    whatever gate asked, which is how two consumers used to crash instead of deny.

    NOT applied by the write gates, deliberately. On WRITE there is an author to ask: the gate
    denies a zero-width-laced disposition with actionable retry text and the model fixes it. A
    document already on disk has no author to ask — it may have arrived from an imported run
    dir, a replayed fixture or a hand edit — so there, what it renders as is what it means.
    Strict at the boundary, forgiving about what got past it.
    """
    if not isinstance(value, str):
        return None
    disposition = strip_zero_width(value).strip()
    return disposition if disposition in DISPOSITION_ENUM else None
