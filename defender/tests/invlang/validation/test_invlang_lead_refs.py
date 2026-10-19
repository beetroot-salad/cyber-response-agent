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
