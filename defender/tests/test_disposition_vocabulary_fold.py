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
    assert vocab.get_enum("disposition") is DISPOSITION_VALUES
    assert set(DISPOSITION_VALUES) == DISPOSITION_ENUM


def test_the_slot_order_is_stable():
    assert vocab.get_enum("disposition") == (
        "benign", "false-positive", "inconclusive", "malicious", "unresolved",
    )


# invlang now enforces it

@pytest.mark.parametrize("disposition", sorted(DISPOSITION_ENUM))
def test_every_keyword_clears_the_vocabulary_check(disposition):
    """Every keyword is a KNOWN disposition — none of them draws the "not a known disposition" error
    that `spicy` draws below."""
    errors = validate_companion(_companion(disposition), None)
    assert not any("is not a known disposition" in e for e in errors)


@pytest.mark.parametrize(
    "disposition", sorted(DISPOSITION_ENUM - set(_PRICED) - {HOST_ONLY_DISPOSITION}),
)
def test_an_ungated_keyword_draws_no_error_at_all(disposition):
    """The `== []` half the test above used to carry, kept for every keyword that is NOT priced."""
    assert validate_companion(_companion(disposition), None) == []


@pytest.mark.parametrize("disposition", sorted(_PRICED))
def test_a_bare_conclude_cannot_reach_a_priced_keyword(disposition):
    """The counterpart: neither priced keyword is reachable from a `:T conclude` alone."""
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
    """The live bug this fold closes, pinned on the gate's OUTPUT rather than on the compare."""
    clean = validate_companion(_unresolved_companion("benign"), None)
    laced = validate_companion(_unresolved_companion(f"benign{ZWSP}"), None)
    assert any(_BENIGN_BLOCKED in e for e in clean)
    assert any(_BENIGN_BLOCKED in e for e in laced)
    assert any("not a known disposition" in e for e in laced)


# the write gates stay exact

def test_the_report_write_gate_still_refuses_what_the_reader_understands():
    """The one place the normalizer must NOT be used. On write there is still an author to ask, so
    the gate denies with retry text the model can act on."""
    laced = f"---\ndisposition: benign{ZWSP}\n---\nbody\n"
    assert validate_report(laced) is not None
    assert normalized_disposition(f"benign{ZWSP}") is None


def test_the_investigation_write_gate_denies_an_out_of_enum_disposition():
    """The same refusal reaching the model through the artifact-level entry point the
    permission gate actually calls, not just the validator underneath it."""
    reason = validate_artifact("investigation.md", _companion("spicy"), None)
    assert reason is not None
    assert "disposition" in reason
