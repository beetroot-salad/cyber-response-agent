"""Closed vocabularies that more than one schema must agree on; domain-specific ones stay
with their owner (e.g. `skills/invlang/vocab.py`).

`disposition` lives here because both `report.md` frontmatter and invlang's `conclude` block
validate it, and the report schema imports invlang's validator, so either home would risk a
cycle. Each set sits beside its membership test; `lint_borrowed_vocabulary` catches consumers
that re-derive the test.
"""

from __future__ import annotations

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
DISPOSITION_VALUES: tuple[str, ...] = (
    "benign", "false-positive", "inconclusive", "malicious", "unresolved",
)
DISPOSITION_ENUM = frozenset(DISPOSITION_VALUES)

#: The member only the host may commit; every model/analyst authoring surface refuses it
#: (`test_923_authoring_surfaces.py` enumerates them).
HOST_ONLY_DISPOSITION = "unresolved"

#: The model's own "I could not settle this", which must pay for its close with `ceiling_test`
#: receipts (`skills/invlang/validate/_gating.py`).
CEILING_DISPOSITION = "inconclusive"

# What a surface shows where a disposition should be and none could be read.
UNKNOWN_DISPOSITION = "?"


#: The family judge's outcome vocabulary, shared by the finding row's `judge_outcome`, the
#: family record's `verdict_word`, and the findings channel's `_gate_family` partition.
JUDGE_OUTCOME_ENUM = frozenset(
    {"caught", "corpus-contradiction", "discard", "survived", "undecidable"})


def normalized_judge_outcome(value: object) -> str | None:
    """A `JUDGE_OUTCOME_ENUM` member, case-insensitive and whitespace-trimmed, or `None`.
    No fuzzy matching onto near-misses.
    """
    if not isinstance(value, str):
        return None
    outcome = value.strip().casefold()
    return outcome if outcome in JUDGE_OUTCOME_ENUM else None


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
