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
membership test drifts from it silently. `lint_borrowed_vocabulary` catches that.
"""

from __future__ import annotations

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
#
# `unresolved` (#923) is the FIFTH member, appended LAST — the ordered tuple stays alphabetical
# up to it, and the tool schema / refusal text are read in one round trip, so a member that did
# not sort last would have to be INSERTED rather than appended. It is the verdict the HOST
# records when it terminates a run without a settled finding — a gate overrule, a review that
# could not complete, or the driver's own retry-exhaustion close — and it is never written by
# the investigating model: `inconclusive` keeps that meaning and stays the model's own "I could
# not settle this", now priced (`skills/invlang/validate/_gating.py`). No code path may hand a
# model-authored close this member; see `HOST_ONLY_DISPOSITION` below and its refusal at every
# authoring surface (the close tool, the invlang document, the ticket resolution line).
DISPOSITION_VALUES: tuple[str, ...] = (
    "benign", "false-positive", "inconclusive", "malicious", "unresolved",
)
DISPOSITION_ENUM = frozenset(DISPOSITION_VALUES)

#: The member ONLY the host may commit — never a model-authored close, an invlang document's
#: own `conclude.disposition`, or an analyst's hand-typed ticket resolution. Named once here so
#: the three authoring surfaces that refuse it share one spelling rather than three literals.
HOST_ONLY_DISPOSITION = "unresolved"

# What a surface shows where a disposition should be and none could be read. Beside the
# vocabulary for the same reason the normalizer is: every reader that degrades rather than
# refusing needs one, and each one that invents its own is a reader a human has to translate.
UNKNOWN_DISPOSITION = "?"


#: The family judge's outcome vocabulary (#921 D1). Three of the five are the family's
#: `verdict_word` when the episode is `gradable`; the other two — `discard` and
#: `corpus-contradiction` — ARE the `verdict_word` when they apply, so this is one enum, not
#: a `gradable`/degenerate split. Lives here, beside the disposition enum, because THREE
#: schemas have to agree on it: the twelve-key finding row's `judge_outcome`, the family
#: record's `verdict_word`, and the findings channel's `_gate_family` partition.
JUDGE_OUTCOME_VALUES: tuple[str, ...] = (
    "caught", "corpus-contradiction", "discard", "survived", "undecidable",
)
JUDGE_OUTCOME_ENUM = frozenset(JUDGE_OUTCOME_VALUES)


def normalized_judge_outcome(value: object) -> str | None:
    """A judge outcome as it RENDERS — a `JUDGE_OUTCOME_ENUM` member — or `None`.

    Case-insensitive and whitespace-trimmed (the reply's own YAML is a model's, and the
    queue row's `judge_outcome` is copied from it by more than one writer), but never a
    fuzzy fold onto a near-miss: `normalized_disposition`'s own rule applies here too — a
    value that only becomes a member after something guesses at it is answered exactly as
    one that was never a member at all.
    """
    if not isinstance(value, str):
        return None
    outcome = value.strip().casefold()
    return outcome if outcome in JUDGE_OUTCOME_ENUM else None


def normalized_disposition(value: object) -> str | None:
    """A disposition as it RENDERS — a `DISPOSITION_ENUM` member — or `None` when it is not one
    of them. THE single answer to what a disposition value MEANS, wherever it was read from:
    report frontmatter, an invlang `conclude` block, or a ticket's resolution line.

    EXACT membership, and nothing else — no zero-width strip, no confusable fold (#923, §7
    round 4, "a malformed verdict is never coerced"). On READ there is no author left to ask,
    so a value that only becomes a member after something strips or folds it is answered
    exactly as a value that was never a member at all: `None`, same as `NOT_A_MEMBER`, same as
    every reader's own "I could not read this run" path — never coerced into the member it
    resembles and never handed downstream as a clean answer. Before this change the zero-width
    strip lived here, and it COERCED: `malicious` with a zero-width space inside it read back
    as `malicious`, a committed close no reader could tell from a clean one. The write gates
    never used that coercion (each is exact and denies a laced value with retry text — an
    author is still there to ask); this reader now agrees with them.

    A non-`str` value (a YAML list, an int) is rejected before the enum test rather than fed to
    it — `DISPOSITION_ENUM` is a set, so an unhashable value would raise `TypeError` out of
    whatever gate asked.

    A WRITE-side gate that must keep failing CLOSED on a laced spelling of a priced keyword
    (never open) does not use this function — see
    `skills/invlang/validate/_gating.py::_rendered_disposition`, which keeps its own forgiving
    normalizer for exactly that purpose. The two are allowed to disagree on purpose: this one
    must never recognize a disguised value, that one must never fail to.
    """
    if not isinstance(value, str):
        return None
    disposition = value.strip()
    return disposition if disposition in DISPOSITION_ENUM else None
