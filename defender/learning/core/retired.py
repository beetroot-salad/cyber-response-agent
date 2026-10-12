"""The one home of the names #1234 retired (A18): every reader that refuses a retired shape by
name imports its name from here, so no other shipped file has to spell one.

A persisted record (a queue row, `judge.yaml`, a draw document) or a model reply carrying one of
these is refused BY THAT NAME at its reader (A4, A17) — never read as though it meant what the
retired design meant, and never silently dropped as an unknown key.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

#: Record fields the redesign removed: the family word on a queue row and on `judge.yaml`, the
#: per-world reply word, and the family call's majority word.
JUDGE_OUTCOME = "judge_outcome"
VERDICT_WORD = "verdict_word"
EPISODE_OUTCOME = "episode_outcome"
FAMILY_OUTCOME = "family_outcome"
RETIRED_RECORD_FIELDS: frozenset[str] = frozenset(
    {JUDGE_OUTCOME, VERDICT_WORD, EPISODE_OUTCOME, FAMILY_OUTCOME})

#: Words a judge reply (world or family scope) may no longer carry (A17).
RETIRED_REPLY_WORDS: frozenset[str] = frozenset({EPISODE_OUTCOME, VERDICT_WORD})

#: An investigator finding's pointer list before A1 replaced it with `contrast_evidence`. Still
#: the live name of a world finding's and a gap's pointer list — retired on the investigator
#: shape only.
RETIRED_INVESTIGATOR_FIELD = "evidence"

#: The defender finding type that left the defender's types (P-a: a gap is never teachable).
RETIRED_FINDING_TYPE = "observability"

#: Ledger lanes no pass writes any more.
RETIRED_LANES: frozenset[str] = frozenset({"never_eligible", "withheld"})


def retired_keys(record: Mapping[Any, Any], names: Iterable[str] = RETIRED_RECORD_FIELDS,
                 ) -> list[str]:
    """The retired names `record` carries as keys, sorted — `[]` for a record of the new shape.
    The one check every refusing reader runs, so they all refuse the same set."""
    return sorted(name for name in names if name in record)


__all__ = [
    "EPISODE_OUTCOME", "FAMILY_OUTCOME", "JUDGE_OUTCOME", "RETIRED_FINDING_TYPE",
    "RETIRED_INVESTIGATOR_FIELD", "RETIRED_LANES", "RETIRED_RECORD_FIELDS",
    "RETIRED_REPLY_WORDS", "VERDICT_WORD", "retired_keys",
]
