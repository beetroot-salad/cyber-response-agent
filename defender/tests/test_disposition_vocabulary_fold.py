"""One disposition vocabulary across report.md and investigation.md: invlang slot, validator, invisible-character gate bypass, write gates."""
from __future__ import annotations

import pytest

from defender._artifact_schema import validate_artifact, validate_report
from defender._vocab import (
    DISPOSITION_ENUM,
    DISPOSITION_VALUES,
    HOST_ONLY_DISPOSITION,
    normalized_disposition,
)
from defender.skills.invlang import vocab
from defender.skills.invlang.validate import _DISPOSITION_GATES, validate_companion

#: The keywords that carry a structural price, read off the OWNER's table so this file
#: cannot drift into asserting a priced keyword is clean (#879).
_PRICED = frozenset(_DISPOSITION_GATES)

ZWSP = "​"


def _companion(disposition: str) -> str:
    return (
        "```invlang\n"
        ":T conclude\n"
        f"disposition            {disposition}\n"
        "confidence             high\n"
        "```\n"
    )


# one definition, imported rather than restated

def test_invlang_carries_the_project_vocabulary_not_a_copy():
    """invlang defines its own schema — its entity types, its relations — but not this. The
    disposition slot IS the project vocabulary object, so a fourth keyword added at the source
    reaches the invlang grammar catalog with no second edit, and neither schema can drift."""
    assert vocab.get_enum("disposition") is DISPOSITION_VALUES
    assert set(DISPOSITION_VALUES) == DISPOSITION_ENUM


def test_the_slot_order_is_stable():
    """The slot list is inlined into the runtime's ORIENT prompt. A set's iteration order is
    not stable across processes, and a prompt that reshuffles between runs is a diff that means
    nothing to whoever reads it."""
    assert vocab.get_enum("disposition") == (
        "benign", "false-positive", "inconclusive", "malicious", "unresolved",
    )


# invlang now enforces it

@pytest.mark.parametrize("disposition", sorted(DISPOSITION_ENUM))
def test_every_keyword_clears_the_vocabulary_check(disposition):
    """Every keyword is a KNOWN disposition — none of them draws the "not a known disposition"
    error that `spicy` draws below.

    Asserted as "no vocabulary error" rather than "no errors at all", which is what this said
    before #806. A disposition may carry structural obligations on top of being spelled right
    — `false-positive` requires the entity check that makes it reachable — and a bare companion
    does not satisfy them. Reading those denials as a vocabulary failure would have forced the
    gate to be weakened to keep this test passing."""
    errors = validate_companion(_companion(disposition), None)
    assert not any("is not a known disposition" in e for e in errors)


@pytest.mark.parametrize(
    "disposition", sorted(DISPOSITION_ENUM - set(_PRICED) - {HOST_ONLY_DISPOSITION}),
)
def test_an_ungated_keyword_draws_no_error_at_all(disposition):
    """The `== []` half the test above used to carry, kept for every keyword that is NOT
    priced. Narrowing the assertion to "no vocabulary error" for ALL FOUR would have let a gate
    that spuriously fires on `malicious` ship green.

    `benign` left this set with #879. It used to pass here VACUOUSLY — a bare `conclude` has no
    vertices and no live hypotheses, so both of its checks had nothing to refuse — which is the
    same shape #806 exists to stop `false-positive` from inheriting, sitting unremarked on the
    keyword next to it. `_check_benign_grounding` is what ended that, so a bare conclude is now
    denied under either priced keyword and this list is the two that are not.

    `unresolved` (#923) also left this set, for a third reason neither `_PRICED` nor its
    complement has a bucket for: it is unpriced AND refused, because it is the HOST's own
    verdict and no invlang document may conclude it — see
    `test_923_authoring_surfaces.py::test_every_authoring_surface_refuses_the_host_only_verdict`
    for that assertion."""
    assert validate_companion(_companion(disposition), None) == []


@pytest.mark.parametrize("disposition", sorted(_PRICED))
def test_a_bare_conclude_cannot_reach_a_priced_keyword(disposition):
    """The counterpart: neither priced keyword is reachable from a `:T conclude` alone.

    Parametrized off `_DISPOSITION_GATES` rather than a list spelled here, so a third priced
    keyword joins this test and leaves the one above without either being edited — the two
    sets are complements of the same table, which is what stops them drifting into a keyword
    that is priced and asserted clean at the same time."""
    errors = validate_companion(_companion(disposition), None)
    assert any(f"{disposition} blocked" in e for e in errors), errors


def test_an_out_of_enum_disposition_is_an_error_not_a_skipped_gate():
    """Before the fold this was accepted, and its only consequence was that the benign
    structural checks silently did not run."""
    errors = validate_companion(_companion("spicy"), None)
    assert any("disposition" in e for e in errors)


def test_an_absent_disposition_stays_absent():
    """`conclude` is optional and partial by design — the check is a vocabulary check, not a
    requirement, so an investigation still under way does not fail validation."""
    assert validate_companion("```invlang\n:T conclude\nconfidence             high\n```\n", None) == []


_UNRESOLVED_VERTEX = (
    ":V prologue.vertices [id|type|class|ident|attrs?]\n"
    "v-001|process|process:bash|bash[pid=42]|user=??\n"
)

_BENIGN_BLOCKED = "disposition benign blocked"


def _unresolved_companion(disposition: str) -> str:
    """A document that CONCLUDES benign while leaving an attribute unresolved — the shape the
    benign structural checks exist to reject."""
    return (
        "```invlang\n"
        f"{_UNRESOLVED_VERTEX}\n"
        ":T conclude\n"
        f"disposition            {disposition}\n"
        "```\n"
    )


def test_the_benign_gate_cannot_be_switched_off_with_an_invisible_character():
    """The live bug this fold closes, pinned on the gate's OUTPUT rather than on the compare.

    A document concluding `benign` with an unresolved attribute is blocked. Spell that same
    `benign` with a trailing zero-width space and the whole benign gate used to fall silent —
    the document committed with the unresolved slot still in it. The blocking error now appears
    for both spellings, and the laced one additionally fails the vocabulary check.

    Note the two rules are independent on purpose: the vocabulary check is what a write gate
    owes its author, and the normalized gate decision is what keeps the structural checks
    running even if the vocabulary check is ever relaxed. Either alone would leave a hole."""
    clean = validate_companion(_unresolved_companion("benign"), None)
    laced = validate_companion(_unresolved_companion(f"benign{ZWSP}"), None)
    assert any(_BENIGN_BLOCKED in e for e in clean)
    assert any(_BENIGN_BLOCKED in e for e in laced)
    assert any("not a known disposition" in e for e in laced)


# the write gates stay exact

def test_the_report_write_gate_still_refuses_what_the_reader_understands():
    """The one place the normalizer must NOT be used. On write there is still an author to ask,
    so the gate denies with retry text the model can act on.

    #923 (§7 round 4) makes the READ side agree instead of diverge: a malformed verdict is
    never coerced, so the reader now answers exactly what the write gate does — unreadable,
    not the member it resembles."""
    laced = f"---\ndisposition: benign{ZWSP}\n---\nbody\n"
    assert validate_report(laced) is not None
    assert normalized_disposition(f"benign{ZWSP}") is None


def test_the_investigation_write_gate_denies_an_out_of_enum_disposition():
    """The same refusal reaching the model through the artifact-level entry point the
    permission gate actually calls, not just the validator underneath it."""
    reason = validate_artifact("investigation.md", _companion("spicy"), None)
    assert reason is not None
    assert "disposition" in reason
