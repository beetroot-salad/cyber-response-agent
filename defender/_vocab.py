"""Closed vocabularies that more than one schema must agree on; domain-specific ones stay
with their owner (e.g. `skills/invlang/vocab.py`).

`disposition` lives here because both the closing record and invlang's `conclude` block
validate it, and the report schema imports invlang's validator, so either home would risk a
cycle. Each set sits beside its membership test; `lint_borrowed_vocabulary` catches consumers
that re-derive the test.
"""

from __future__ import annotations

from typing import Literal, get_args

# The canonical run-disposition vocabulary. The ordered tuple is authored because rendered
# surfaces (deny reasons, the invlang slot catalog) need a stable order; the membership set is
# derived and frozen.
#
# `false-positive` describes the detector, not the entity: the rule fired on behaviour other
# than what it claims to detect. It requires a committed lead against an alert-named entity
# (`_check_false_positive_gating`, `skills/invlang/validate.py`) and selects no learning
# direction (`learning/core/directions.py`).
#
# `unresolved` is recorded only by the host when it ends a run without a settled finding (gate
# overrule, incomplete review, run cut short); the model's own "could not settle" is
# `inconclusive`. See `HOST_ONLY_DISPOSITION`.
#
# Declared once, as a `Literal` (#1581 AP4): the value tuple, the investigations and alerts table
# checks, the API's enums and the list port's filter all derive from it.
Disposition = Literal["benign", "false-positive", "inconclusive", "malicious", "unresolved"]
DISPOSITION_VALUES: tuple[str, ...] = get_args(Disposition)
DISPOSITION_ENUM = frozenset(DISPOSITION_VALUES)


class NoOutcome:
    """The alert list's filter for alerts with no completed investigation (#1581 O2): passed as an
    instance where a `Disposition` would be. The API maps its `none` to this, so a store never
    reads the word `none` as a code."""

    def __eq__(self, other: object) -> bool:
        return isinstance(other, NoOutcome)

    def __hash__(self) -> int:
        return hash(NoOutcome)

    def __repr__(self) -> str:
        return "NoOutcome()"


#: The member only the host may commit; every model/analyst authoring surface refuses it
#: (`test_authoring_surfaces.py` enumerates them).
HOST_ONLY_DISPOSITION = "unresolved"

#: The one disposition that carries a confidence (#1545): the closing record's `confidence` is
#: set only on it.
BENIGN_DISPOSITION = "benign"

#: A benign close's confidence, best first (#1545). Here because the closing record and
#: invlang's `conclude` both read it, like the disposition vocabulary.
CONFIDENCE_VALUES: tuple[str, ...] = ("high", "medium", "low")

#: The model's own "I could not settle this", which must pay for its close with `ceiling_test`
#: receipts (`skills/invlang/validate/_gating.py`).
CEILING_DISPOSITION = "inconclusive"

# What a surface shows where a disposition should be and none could be read.
UNKNOWN_DISPOSITION = "?"


def normalized_disposition(value: object) -> str | None:
    """A `DISPOSITION_ENUM` member, or `None` — the single read-side meaning of a disposition
    from report frontmatter, an invlang `conclude` block, or a ticket resolution line.

    Exact membership after trimming whitespace: no zero-width strip or confusable fold, so a
    malformed verdict is never coerced into the member it resembles. Non-`str` values are
    rejected first (an unhashable one would raise in the set test).

    Write-side gates that must fail closed on a disguised keyword use the forgiving
    `skills/invlang/validate/_gating.py::_rendered_disposition` instead.
    """
    if not isinstance(value, str):
        return None
    disposition = value.strip()
    return disposition if disposition in DISPOSITION_ENUM else None
