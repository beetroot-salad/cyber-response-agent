"""`:L findings` is the sole site that declares a lead.

The projector opens a bucket for any lead id it meets, so before this rule a
typo, a forward reference, and a comma-joined pair of real ids all became leads
of their own. That is how a lead named `l-004,l-005` — carrying a real authz
verdict — reached the corpus without a single warning.

Correlation is the legitimate need behind that comma: some verdicts only hold
because two leads' results combine. It is expressed as grounding
(`cites_leads`), not as ownership, because `resolved_by` is the projection
target and a plural target files the row on two outcomes or none.
"""

from __future__ import annotations

import pytest

from defender.skills.invlang.validate import validate_companion

_LEAD_HEADER = ":L findings [id|loop|name|target|tests|system|window]"
_AUTHZ_HEADER = (
    ":R authz [resolved_by|cites_leads?|edge|fulfills|verdict|anchor_kind|reasoning]"
)


def _doc(body: str) -> str:
    return "```invlang\n" + body + "\n```"


def _two_leads() -> str:
    return (
        _LEAD_HEADER + "\n"
        "l-004|2|cmdb-source-ip-lookup|v-003|h-001|cmdb|n/a\n"
        "l-005|2|change-mgmt-check|v-001|h-001|change-mgmt|±1d\n"
    )


def _lead_ref_errors(text: str) -> list[str]:
    return [
        e for e in validate_companion(text)
        if "undeclared lead" in e or "cites_leads" in e
    ]


def test_comma_joined_resolved_by_is_rejected_as_an_undeclared_lead():
    errors = _lead_ref_errors(_doc(
        _two_leads() + "\n"
        + _AUTHZ_HEADER + "\n"
        "l-004,l-005||e-002|ac1|unauthorized|approved-source-list|\"x\""
    ))
    assert len(errors) == 1
    assert "'l-004,l-005'" in errors[0]
    assert "cites_leads" in errors[0], "the error must point at the right field"


def test_correlated_verdict_is_expressible_as_owner_plus_citation():
    """The shape the comma was reaching for: l-005 closed the contract, but the
    verdict rests on l-004's identification of the source host too."""
    assert _lead_ref_errors(_doc(
        _two_leads() + "\n"
        + _AUTHZ_HEADER + "\n"
        "l-005|l-004|e-002|ac1|unauthorized|approved-source-list|\"x\""
    )) == []


# Every row plants ONE bad lead reference and asserts the same two things: exactly one error
# (a single defect must not report as several), and that the error quotes the offending id —
# an error that does not name the token is one the author cannot act on.
@pytest.mark.parametrize(("case", "block", "fragment"), [
    # `cites_leads` must name leads the document DECLARED: l-004 exists, l-009 does not.
    ("cites-an-undeclared-lead",
     _AUTHZ_HEADER + "\n"
     'l-005|l-004,l-009|e-002|ac1|unauthorized|approved-source-list|"x"',
     "'l-009'"),

    # A row citing its OWN owner is circular — the citation would rest on itself.
    ("row-cites-its-own-owner",
     _AUTHZ_HEADER + "\n"
     'l-005|l-005|e-002|ac1|unauthorized|approved-source-list|"x"',
     "itself"),

    # `l-oo4` is a TYPO for l-004 (letter o for zero). Before this rule the unknown id was
    # taken at face value and quietly invented a lead nobody declared.
    ("typo-in-resolved-by-invents-a-lead",
     _AUTHZ_HEADER + "\n"
     'l-oo4||e-002|ac1|unauthorized|approved-source-list|"x"',
     "'l-oo4'"),

    # The same rule reaches a lead SUB-BLOCK: `:V l-007.observations.vertices` is owned by a
    # lead that was never declared.
    ("lead-subblock-owned-by-an-undeclared-lead",
     ":V l-007.observations.vertices [id|type|class|ident|attrs?]\n"
     "v-009|endpoint|endpoint:linux|host|",
     "'l-007'"),
], ids=lambda v: v if isinstance(v, str) and len(v) < 50 and "|" not in v else "")
def test_a_reference_to_an_undeclared_lead_is_caught_and_named(case, block, fragment):
    """A lead id is only meaningful if the document declared it. Whatever the spelling —
    a citation list, a self-reference, a typo, or the owner of a sub-block — an id with no
    `:L` row behind it is one error that quotes the id it could not resolve."""
    errors = _lead_ref_errors(_doc(_two_leads() + "\n" + block))
    assert len(errors) == 1
    assert fragment in errors[0]


def test_citations_are_checked_on_consultations_and_impact_too():
    errors = _lead_ref_errors(_doc(
        _two_leads() + "\n"
        ":R consultations [resolved_by|cites_leads?|anchor_kind|result]\n"
        "l-004|l-009|cmdb|confirmed\n"
        "\n"
        ":R impact [resolved_by|cites_leads?|dim|verdict]\n"
        "l-005|l-042|confidentiality|exceeds"
    ))
    assert {"'l-009'", "'l-042'"} == {
        e.split("names ")[1].split(",")[0] for e in errors
    }
