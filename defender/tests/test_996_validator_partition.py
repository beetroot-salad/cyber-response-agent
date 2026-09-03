"""#996 — the validator's judgment partition, and the two demands that are RED by design.

D7 rests on one question the validator must be able to answer about a refusal: is this
something the clerk can fix from the grammar and the document it already holds, or does it need
a fact only MAIN can state? The refusal STRING cannot answer it — a `Diagnostic` carries no rule
id, the decision is a flat string, and one refusal can carry lines from both classes at once —
so the partition is asked of the validator over the PROPOSED DOCUMENT and never parsed off the
text.

THE PARTITION IS ASKED WITH THE SAME INPUTS `diagnose` TAKES, and that spelling is forced
rather than chosen: `diagnose` returns EARLY when the document has no parseable companion, so a
pair of helpers keyed on a companion could not be asked about that case at all — and assigning
that early return is itself a demand here.

TWO DEMANDS IN THIS FILE ARE KNOWN-RED BY DESIGN. The human chose this base over re-basing onto
`main` (`spine-decisions.md`), and `main`'s validator has moved since the fork. Those two are
marked, and whoever rebases runs them FIRST. They must not be weakened to go green here — that
would hide the exact defect the base choice accepted.
"""
from __future__ import annotations

import pytest

from defender.skills.invlang.validate import diagnose  # noqa: E402
from defender.tests import _clerk_996 as C  # noqa: E402

#: Documents whose refusals span the classes the partition has to separate, each EXECUTED
#: against the real validator while this file was written: a clean one, a structural-only one,
#: a judgment-only one, a mixed one, one with no parseable companion at all, and the #986-era
#: class-cell refusal that is `7fa49f04`'s own gate.
CORPUS = {
    "clean": (C.PROLOGUE, None),
    "structural": (C.PROLOGUE + C.UNDECLARED_TARGET_ROWS, C.PROLOGUE),
    "judgment": (C.OPEN_SLOT_PROLOGUE + C.JUDGMENT_ONLY_ROWS, C.OPEN_SLOT_PROLOGUE),
    "mixed": (C.OPEN_SLOT_PROLOGUE + C.MIXED_ROWS, C.OPEN_SLOT_PROLOGUE),
    "warn": (C.PROLOGUE + C.WARN_ROWS, C.PROLOGUE),
    "class-cell": (C.VOCAB_CLASS_CELL_DOC, None),
    "no-companion": ("## ORIENT\n\nprose only, no fence at all\n", None),
    "collision": (C.ID_COLLISION_ROWS, None),
}


def _structural(proposed: str, current: str | None):
    return list(C.sym("skills.invlang.validate", "structural_diagnostics")(proposed, current))


def _judgment(proposed: str, current: str | None):
    return list(C.sym("skills.invlang.validate", "judgment_diagnostics")(proposed, current))


@pytest.mark.parametrize("name", sorted(CORPUS))
def test_996_diagnose_equals_structural_plus_judgment(name: str) -> None:
    """PARITY: for every document in the corpus, `diagnose`'s output is byte-identical to the
    structural half followed by the judgment half — same diagnostics, same order, nothing
    dropped and nothing duplicated.

    The concatenation being byte-identical is what makes the split safe to introduce at all:
    every existing caller of the validator gets exactly what it got before, and `record` is the
    only caller that asks the two halves separately. A split that merely PARTITIONS the set
    without preserving order would change the refusal string every other caller renders.

    Parametrized over the whole corpus rather than over one document, because a partition is
    only a partition if it holds for the mixed case and for the empty one too."""
    proposed, current = CORPUS[name]
    whole = diagnose(proposed, current)
    halves = _structural(proposed, current) + _judgment(proposed, current)
    assert [str(d) for d in whole] == [str(d) for d in halves], (
        f"the partition is not the whole for {name!r}: {len(whole)} vs {len(halves)}"
    )


def test_996_structural_owns_the_no_companion_early_return() -> None:
    """The structural half OWNS `diagnose`'s no-companion early return, and the judgment half
    answers empty there.

    With no parseable companion, `diagnose` returns after the surface, append-only and parse
    checks and never reaches the tail at all. That leaves the early return's diagnostics
    unassigned, and the parity the split promises is only achievable under one assignment: the
    structural half carries them and the judgment half is empty. The other assignment makes
    `diagnose == structural + judgment` false for every document that fails to parse — which is
    every document a clerk round has just broken, the exact case the loop is about.

    It constrains implementation SHAPE and not just output, and that is the accepted cost."""
    proposed, current = CORPUS["no-companion"]
    assert _judgment(proposed, current) == [], (
        "the judgment half claims diagnostics for a document with no companion, so the tail is "
        "being asked about a document it never sees"
    )
    assert [str(d) for d in _structural(proposed, current)] == [
        str(d) for d in diagnose(proposed, current)
    ]

    collision, collision_current = CORPUS["collision"]
    assert _judgment(collision, collision_current) == [], (
        "a parse-error document reached the judgment half"
    )
    assert _structural(collision, collision_current), (
        "the parse error reached neither half, so the partition drops it"
    )


def test_996_a_judgment_line_is_never_in_the_structural_half() -> None:
    """The two halves are DISJOINT, and the disposition price is on the judgment side.

    The loop's whole decision is "structural lines remain → retry; only judgment lines →
    stop", so a judgment line that also appeared structurally would make the loop retry
    forever on a fact the clerk cannot supply — which is precisely the refusal D7 exists to
    stop. Asserted on the price, because that is the family the design names as the class's
    exemplar and the one the experiment's clerk actually hit."""
    proposed, current = CORPUS["judgment"]
    structural = [str(d) for d in _structural(proposed, current)]
    judgment = [str(d) for d in _judgment(proposed, current)]
    assert judgment, "the disposition price landed in neither half"
    assert set(structural) & set(judgment) == set(), "the two halves overlap"
    assert any("disposition benign blocked" in line for line in judgment), judgment
    assert not any("disposition benign blocked" in line for line in structural), structural


# ---------------------------------------------------------------------------------------
# KNOWN RED BY DESIGN — owed for `main`'s shape, unrunnable at `7fa49f04`
# ---------------------------------------------------------------------------------------


def test_996_the_judgment_partition_survives_mains_grounding_dedup() -> None:
    """KNOWN RED ON `main` BY DESIGN — carried, marked, and not corrected here.

    At `7fa49f04` this demand goes green as soon as the split lands: the tail is a clean suffix
    on this base, which is why its sibling parity demand passes here at all. It is RED the
    moment the port reaches `main`, and it is written now so the rebase meets a failing test
    rather than a silent behaviour change.

    On `main` the validator emits the authz row-grounding check inside the STRUCTURAL region
    and then emits the gating result filtered against the grounding it already reported, so the
    judgment tail is not a clean suffix there and the byte-identical concatenation cannot hold
    as written. Worse than the parity failure: grounding lines are POSITIONALLY structural yet
    need a fact only MAIN can state, so the clerk would retry them every round — the exact
    refusal D7 exists to stop.

    The base is `7fa49f04` by the human's decision on the record, taken over re-basing, so this
    is carried rather than absorbed. Whoever rebases runs this demand FIRST, and fixes it by
    moving the grounding family into the judgment half and preserving the dedup — never by
    weakening the parity assertion below, which would hide the defect the base choice
    accepted."""
    doc = C.OPEN_SLOT_PROLOGUE + C.JUDGMENT_ONLY_ROWS
    structural = [str(d) for d in _structural(doc, C.OPEN_SLOT_PROLOGUE)]
    judgment = [str(d) for d in _judgment(doc, C.OPEN_SLOT_PROLOGUE)]
    assert [str(d) for d in diagnose(doc, C.OPEN_SLOT_PROLOGUE)] == structural + judgment

    grounding = [line for line in structural if "grounding" in line or "grounded" in line]
    assert grounding == [], (
        "a grounding line is in the STRUCTURAL half, so the clerk will retry every round on a "
        "fact only MAIN can state — the refusal D7 exists to stop. This is the known-red "
        f"demand: fix it at the rebase by moving the family, not by relaxing this: {grounding}"
    )
