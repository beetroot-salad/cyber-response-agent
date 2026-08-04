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


def test_cites_leads_must_name_declared_leads():
    errors = _lead_ref_errors(_doc(
        _two_leads() + "\n"
        + _AUTHZ_HEADER + "\n"
        "l-005|l-004,l-009|e-002|ac1|unauthorized|approved-source-list|\"x\""
    ))
    assert len(errors) == 1
    assert "'l-009'" in errors[0]


def test_a_row_may_not_cite_its_own_owner():
    errors = _lead_ref_errors(_doc(
        _two_leads() + "\n"
        + _AUTHZ_HEADER + "\n"
        "l-005|l-005|e-002|ac1|unauthorized|approved-source-list|\"x\""
    ))
    assert len(errors) == 1
    assert "itself" in errors[0]


def test_a_typo_in_resolved_by_no_longer_invents_a_lead():
    errors = _lead_ref_errors(_doc(
        _two_leads() + "\n"
        + _AUTHZ_HEADER + "\n"
        "l-oo4||e-002|ac1|unauthorized|approved-source-list|\"x\""
    ))
    assert len(errors) == 1
    assert "'l-oo4'" in errors[0]


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


def test_a_lead_subblock_referencing_an_undeclared_lead_is_caught():
    errors = _lead_ref_errors(_doc(
        _two_leads() + "\n"
        ":V l-007.observations.vertices [id|type|class|ident|attrs?]\n"
        "v-009|endpoint|endpoint:linux|host|"
    ))
    assert len(errors) == 1
    assert "'l-007'" in errors[0]
