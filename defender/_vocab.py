"""Closed vocabularies the project shares — the ones no single schema owns.

A vocabulary belongs here when more than one schema has to agree on it. Everything else stays
where it is used: invlang's entity types and relations are invlang's own domain and live in
`skills/invlang/vocab.py`, the permission gate's program lists are the gate's, and neither is
project-general just for being a set of strings.

`disposition` is the first that is. The run's headline appears in TWO model-authored artifacts
— `report.md`'s frontmatter and `investigation.md`'s `conclude` block — validated by two
different schemas, and the report schema already imports invlang's validator, so keeping the
enum there would leave invlang one import edge from a cycle. Below both is the only place it
can sit.

Both halves live together on purpose: a consumer that borrows the set and re-derives the
membership test loses the zero-width strip with it. `lint_borrowed_vocabulary` catches that.
"""

from __future__ import annotations

from defender._text import strip_zero_width

# The canonical run-disposition vocabulary.
#
# The AUTHORED form is the ordered tuple, because the surfaces that RENDER the vocabulary —
# deny reasons, the invlang slot catalog the runtime prompt inlines — need a stable order, and
# a set's iteration order is not stable across processes. The membership set is derived from it
# and FROZEN: a plain `set` exported to a dozen modules is one `.add()` away from not being
# closed at all.
#
# `false-positive` describes the DETECTOR rather than the world: the rule fired on a different
# kind of behaviour than its name and description claim. The other three answer "what is true
# of the alerted entity", and a run that never established that has nothing to say in their
# vocabulary — `benign` was the available lie, asserting an entity is clean when a refuted
# correlation is no evidence for it.
#
# It is reachable only through `_check_false_positive_gating` (`skills/invlang/validate.py`),
# which requires a committed lead against an entity the alert already named: a cheap exit from
# a noisy rule is the point, a cheap exit from an uninvestigated host is what the gate prevents.
#
# It selects NO learning direction, deliberately — see `learning/core/directions.py`.
DISPOSITION_VALUES: tuple[str, ...] = (
    "benign", "false-positive", "inconclusive", "malicious",
)
DISPOSITION_ENUM = frozenset(DISPOSITION_VALUES)

# What a surface shows where a disposition should be and none could be read. Beside the
# vocabulary for the same reason the normalizer is: every reader that degrades rather than
# refusing needs one, and each one that invents its own is a reader a human has to translate.
UNKNOWN_DISPOSITION = "?"


def normalized_disposition(value: object) -> str | None:
    """A disposition as it RENDERS — a `DISPOSITION_ENUM` member — or `None` when it is not one
    of them. THE single answer to what a disposition value MEANS, wherever it was read from:
    report frontmatter, an invlang `conclude` block, or a ticket's resolution line.

    The zero-width strip lives here and nowhere else. Both artifacts are authored by a model
    reading attacker-influenced alert data, so a character that occupies no space must not
    decide a gate; the value is judged on what a human would see.

    A non-`str` value (a YAML list, an int) is rejected before the enum test rather than fed to
    it — `DISPOSITION_ENUM` is a set, so an unhashable value would raise `TypeError` out of
    whatever gate asked.

    NOT applied by the write gates, deliberately. On WRITE there is an author to ask: the gate
    denies a zero-width-laced disposition with actionable retry text. A document already on
    disk has no author — it may have come from an imported run dir, a replayed fixture or a
    hand edit — so there, what it renders as is what it means.
    """
    if not isinstance(value, str):
        return None
    disposition = strip_zero_width(value).strip()
    return disposition if disposition in DISPOSITION_ENUM else None
