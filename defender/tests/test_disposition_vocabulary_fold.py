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

from defender._artifact_schema import DISPOSITION_ENUM, validate_artifact, validate_report
from defender._vocab import (
    DISPOSITION_VALUES,
    normalized_disposition,
)
from defender.skills.invlang import vocab
from defender.skills.invlang.validate import validate_companion

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


def test_the_slot_order_is_stable():
    """The slot list is inlined into the runtime's ORIENT prompt. A set's iteration order is
    not stable across processes, and a prompt that reshuffles between runs is a diff that means
    nothing to whoever reads it."""
    assert vocab.get_enum("disposition") == ("benign", "inconclusive", "malicious")


def test_the_slot_is_advertised_to_the_model():
    """A vocabulary the validator enforces but the grammar catalog never shows is a rule the
    author cannot see — the model learns it only by being denied."""
    assert "disposition" in vocab.list_slots()


# ═══════════════════════════════════════════════════════════════════════════
# invlang now enforces it
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("disposition", sorted(DISPOSITION_ENUM))
def test_every_keyword_validates(disposition):
    assert validate_companion(_companion(disposition), None) == []


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
