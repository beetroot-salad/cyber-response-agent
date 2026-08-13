"""One vocabulary for the run's disposition, across both model-authored artifacts.

#785 folded six readers of `report.md`'s disposition onto one accessor. The census that sized
the follow-up lint found the same question asked again one container over: `investigation.md`'s
invlang `conclude` block carries the same headline, and invlang treated it as free text — no
vocabulary check at all, and a raw `!= "benign"` deciding whether the benign structural checks
run. That is #722's mechanism inside a WRITE gate: an invisible character turns the checks off.

What these tests pin:

  * the vocabulary has ONE definition, and invlang imports it rather than restating it — the
    two schemas cannot drift into disagreeing about which keywords exist;
  * invlang enforces it, so an out-of-enum disposition is an error rather than a document that
    quietly skips the benign gate;
  * the benign gate matches on what the value RENDERS as, so it can no longer be switched off
    with a zero-width character;
  * the write gates stay exact, which is the one place the normalizer must NOT be used.
"""
from __future__ import annotations

import pytest

from defender._artifact_schema import validate_artifact, validate_report
from defender._vocab import (
    DISPOSITION_ENUM,
    DISPOSITION_VALUES,
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


# ═══════════════════════════════════════════════════════════════════════════
# one definition, imported rather than restated
# ═══════════════════════════════════════════════════════════════════════════

def test_invlang_carries_the_project_vocabulary_not_a_copy():
    """invlang defines its own schema — its entity types, its relations — but not this. The
    disposition slot IS the project vocabulary object, so a fourth keyword added at the source
    reaches the invlang grammar catalog with no second edit, and neither schema can drift."""
    assert vocab.get_enum("disposition") is DISPOSITION_VALUES
    assert set(DISPOSITION_VALUES) == DISPOSITION_ENUM


def test_no_module_stands_between_the_vocabulary_and_its_readers():
    """One owner has to mean one HOP. #714 moved the enum to the report schema and left the
    loop's config re-exporting it; #785 moved it again to `_vocab` and left the report schema
    re-exporting it to the config and the ticket lane. Each hop was cheap on its own and the
    stack was four modules deep — a reader chasing where a disposition is decided had three
    forwarding addresses to walk before reaching an answer.

    A module that USES the vocabulary imports it; a module that only PASSED IT ON no longer
    names it at all. Asserted as absence of the attribute, because that is what a re-export is
    — an importable name a module does not use.
    """
    import defender._artifact_schema as schema
    import defender.learning.core.config as loop_config
    from defender.scripts.case_history import case_ticket as ticket

    assert not hasattr(loop_config, "DISPOSITION_ENUM")
    assert not hasattr(ticket, "DISPOSITION_ENUM")
    # The report SCHEMA still holds the enum — its write gate tests membership on it exactly.
    # What it must not hold is the normalizer, which it never called and only forwarded.
    assert schema.DISPOSITION_ENUM is DISPOSITION_ENUM
    assert not hasattr(schema, "normalized_disposition")


def test_the_slot_order_is_stable():
    """The slot list is inlined into the runtime's ORIENT prompt. A set's iteration order is
    not stable across processes, and a prompt that reshuffles between runs is a diff that means
    nothing to whoever reads it."""
    assert vocab.get_enum("disposition") == (
        "benign", "false-positive", "inconclusive", "malicious",
    )


def test_the_slot_is_advertised_to_the_model():
    """A vocabulary the validator enforces but the grammar catalog never shows is a rule the
    author cannot see — the model learns it only by being denied."""
    assert "disposition" in vocab.list_slots()


# ═══════════════════════════════════════════════════════════════════════════
# invlang now enforces it
# ═══════════════════════════════════════════════════════════════════════════

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


@pytest.mark.parametrize("disposition", sorted(DISPOSITION_ENUM - set(_PRICED)))
def test_an_ungated_keyword_draws_no_error_at_all(disposition):
    """The `== []` half the test above used to carry, kept for every keyword that is NOT
    priced. Narrowing the assertion to "no vocabulary error" for ALL FOUR would have let a gate
    that spuriously fires on `malicious` ship green.

    `benign` left this set with #879. It used to pass here VACUOUSLY — a bare `conclude` has no
    vertices and no live hypotheses, so both of its checks had nothing to refuse — which is the
    same shape #806 exists to stop `false-positive` from inheriting, sitting unremarked on the
    keyword next to it. `_check_benign_grounding` is what ended that, so a bare conclude is now
    denied under either priced keyword and this list is the two that are not."""
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


def test_the_benign_gate_still_only_fires_on_benign():
    """The positive control the test above needs: the same unresolved document concluding
    `malicious` is not blocked, so the assertions above are the gate firing rather than an
    error every document gets."""
    assert validate_companion(_unresolved_companion("malicious"), None) == []


# ═══════════════════════════════════════════════════════════════════════════
# the write gates stay exact
# ═══════════════════════════════════════════════════════════════════════════

def test_the_report_write_gate_still_refuses_what_the_reader_understands():
    """The one place the normalizer must NOT be used. On write there is still an author to ask,
    so the gate denies with retry text the model can act on; normalizing here would accept it
    and commit a document no reader could tell from a clean one."""
    laced = f"---\ndisposition: benign{ZWSP}\n---\nbody\n"
    assert validate_report(laced) is not None
    assert normalized_disposition(f"benign{ZWSP}") == "benign"


def test_the_investigation_write_gate_denies_an_out_of_enum_disposition():
    """The same refusal reaching the model through the artifact-level entry point the
    permission gate actually calls, not just the validator underneath it."""
    reason = validate_artifact("investigation.md", _companion("spicy"), None)
    assert reason is not None
    assert "disposition" in reason
