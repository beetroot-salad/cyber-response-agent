"""#1221 O2 — rule #27: a benign verdict cannot rest on past cases alone.

The design (issue #1221, D2/M3): a comment a model wrote is a PAST CASE, cited
`grounding past-case`, `cites_past_case <run id>`. An `authorized` row grounded that way does
not discharge an authz contract unless the same contract also has an `authorized` row with a
different grounding (or no grounding cell at all). The grounding cell is read case- and
separator-folded, as `_folded_grounding` reads it for the telemetry-baseline refusal. The rule
lives in the one reading of "discharged" (`outstanding_authz_contracts`), so a benign close over
such a contract is refused with an error. It covers `benign` only (N9).

Every document here is the shipped example `defender/examples/example-b-parallel-iam-cmdb.md`'s
own invlang, whose one `:R authz` row discharges `ac1` on the live `h-001` and which closes
`benign`. The probe rewrites that row's header to carry the two optional cells
(`grounding|cites_past_case`) and nothing else, so every control differs from its negative in
exactly the cell under test. The entry point is the validator's own, `diagnose`, and its string
surface `validate_companion` (what the production close reads).
"""
from __future__ import annotations

import re

import pytest

from defender._paths import PATHS
from defender._vocab import DISPOSITION_VALUES
from defender.skills.invlang.validate import diagnose, validate_companion

EXAMPLE_B = PATHS.defender_dir / "examples" / "example-b-parallel-iam-cmdb.md"

AUTHZ_HEADER = ":R authz [resolved_by|edge|fulfills|verdict|anchor_kind|reasoning]"
GROUNDED_HEADER = (
    ":R authz [resolved_by|edge|fulfills|verdict|anchor_kind|grounding|cites_past_case|reasoning]"
)
ROW_HEAD = "l-003|e-001|ac1|authorized|iam-policy|"
CONCLUDE_BENIGN = "disposition            benign"
PRIOR_RUN = "20261001T000000Z-5710-sshd-prior"

#: A second `authorized` row on the same contract, grounded on an affirmative record.
ORG_AUTHORITY_ROW = (
    'l-003|e-001|ac1|authorized|iam-policy|org-authority||'
    '"the IAM binding for metrics-shipper names sre-iam-team as its owner"'
)


def _example_b() -> str:
    """The example's invlang blocks, as one document."""
    blocks = re.findall(r"```invlang\n(.*?)```", EXAMPLE_B.read_text(encoding="utf-8"), re.S)
    assert blocks, f"no invlang blocks in {EXAMPLE_B}"
    doc = "".join(f"```invlang\n{b}```\n\n" for b in blocks)
    assert doc.count(AUTHZ_HEADER) == 1, "example-b's `:R authz` header moved"
    assert doc.count(ROW_HEAD) == 1, "example-b's `:R authz` row moved"
    assert doc.count(CONCLUDE_BENIGN) == 1, "example-b no longer concludes benign"
    return doc


def _grounded(grounding: str, cites: str = PRIOR_RUN, *, extra_row: str | None = None) -> str:
    """example-b with its one `:R authz` row grounded `grounding`, citing `cites`."""
    doc = _example_b().replace(AUTHZ_HEADER, GROUNDED_HEADER)
    doc = doc.replace(ROW_HEAD, f"{ROW_HEAD}{grounding}|{cites}|")
    if extra_row is not None:
        lines = doc.split("\n")
        at = next(i for i, line in enumerate(lines) if line.startswith(ROW_HEAD))
        doc = "\n".join([*lines[: at + 1], extra_row, *lines[at + 1:]])
    return doc


def _with_disposition(doc: str, disposition: str) -> str:
    return doc.replace(CONCLUDE_BENIGN, f"disposition            {disposition}")


def _errors(doc: str) -> list[str]:
    return sorted(d.message for d in diagnose(doc) if d.severity == "error")


@pytest.mark.parametrize("spelling", ["past-case", "Past_Case", "past case", "PAST-CASE"])
def test_1221_a_benign_close_resting_on_past_cases_alone_is_refused(spelling):
    """NEGATIVE, with its controls on the same address. A benign document whose authz contract
    (`ac1` on the live `h-001`) is discharged ONLY by an `authorized` row grounded `past-case` —
    in any case or separator spelling — draws an error diagnostic naming that contract, and the
    string surface the production close reads refuses it too.

    Controls, each the same document with one cell changed:
      * the row grounded `org-authority` validates clean;
      * the row as example-b ships it (no grounding cell) validates clean;
      * the past-case row PLUS a second `authorized` row on `ac1` grounded on an affirmative
        record validates clean — a past case may still be cited beside real evidence."""
    past_case = _grounded(spelling)
    org_authority = _grounded("org-authority", cites="")

    assert _errors(org_authority) == [], (
        f"the control failed: the org-authority twin draws errors {_errors(org_authority)}"
    )
    assert _errors(_example_b()) == [], "the control failed: example-b as shipped draws errors"
    assert _errors(_grounded(spelling, extra_row=ORG_AUTHORITY_ROW)) == [], (
        "a past-case row beside an org-authority row on the same contract was refused — "
        "#27 forbids resting on past cases ALONE"
    )

    refusals = [m for m in _errors(past_case) if "ac1" in m]
    assert refusals, (
        f"a benign close whose only discharge of ac1 is grounded {spelling!r} validated "
        f"clean: {_errors(past_case)}"
    )
    assert any(re.search(r"past.case", m, re.I) for m in refusals), (
        f"the refusal does not say the discharge was a past case: {refusals}"
    )
    assert validate_companion(past_case), (
        "the production close's string surface accepted the past-case-only benign document"
    )


@pytest.mark.parametrize(
    "disposition", [d for d in DISPOSITION_VALUES if d != "benign"],
)
def test_1221_the_past_case_rule_is_benign_only(disposition):
    """The complementary condition: under every disposition but `benign`, grounding the row
    `past-case` changes nothing the validator says (N9: #27 covers benign only). Asserted as
    equality with the same document grounded `org-authority`, so a disposition whose own gates
    already refuse example-b (`false-positive`, `inconclusive`, `unresolved`) still pins that
    the rule adds nothing there; `malicious` validates clean either way."""
    past_case = _with_disposition(_grounded("past-case"), disposition)
    org_authority = _with_disposition(_grounded("org-authority", cites=""), disposition)
    assert _errors(past_case) == _errors(org_authority), (
        f"grounding the row past-case changed the {disposition} verdict's diagnostics: "
        f"{sorted(set(_errors(past_case)) ^ set(_errors(org_authority)))}"
    )
    if disposition == "malicious":
        assert _errors(past_case) == [], (
            f"a malicious close citing a past case was refused: {_errors(past_case)}"
        )


# =======================================================================================
# Adversary-pass additions: what the rule keys on, where it lives, how far it reaches
# =======================================================================================

AC1_DECL = 'ac1|e-001|iam-policy|"metrics-shipper is provisioned and authorized for this source→target SSH path"|escalate|escalate'
AC2_DECL = 'ac2|e-001|iam-policy|"the SSH path is inside the monitoring role\'s approved scope"|escalate|escalate'


def _row(contract: str, grounding: str, cites: str = "") -> str:
    return f'l-003|e-001|{contract}|authorized|iam-policy|{grounding}|{cites}|"{contract} {grounding or "ungrounded"}"'


def _open_contract_ids(doc: str) -> set[str]:
    from defender.skills.invlang.frontier import frontier_from_text
    return {c.contract_id for c in frontier_from_text(doc).contracts}


@pytest.mark.parametrize("spelling", ["past  case", "past\tcase", "past_ case", " Past-Case "])
def test_1221_every_separator_run_folds_to_past_case(spelling):
    """The fold is `_folded_grounding`'s — runs of whitespace and underscores read as one
    hyphen — not a character-by-character replace."""
    refusals = [m for m in _errors(_grounded(spelling)) if "ac1" in m]
    assert refusals, f"grounding {spelling!r} is a past case and validated clean"


def test_1221_the_rule_keys_on_grounding_not_on_the_citation():
    """A past-case row with an EMPTY `cites_past_case` is still a past case and is refused;
    an `org-authority` row that happens to carry a citation is still an authority and is
    clean. The cite cell is not what decides."""
    assert [m for m in _errors(_grounded("past-case", cites="")) if "ac1" in m], (
        "a past-case row with no citation discharged ac1"
    )
    assert _errors(_grounded("org-authority", cites=PRIOR_RUN)) == [], (
        "an org-authority row carrying a citation was refused"
    )


def test_1221_two_past_case_rows_are_still_past_cases_alone():
    """Two `authorized` past-case rows on one contract are past cases alone — the count of
    rows is not the test."""
    doc = _grounded("past-case", extra_row=_row("ac1", "past-case", "20261002T000000Z-other"))
    assert [m for m in _errors(doc) if "ac1" in m], "two past-case rows discharged ac1"


def test_1221_an_ungrounded_authorized_row_beside_a_past_case_discharges():
    """The rescue is any grounding other than past-case, or none: an `authorized` row with an
    empty grounding cell beside the past-case row discharges the contract."""
    doc = _grounded("past-case", extra_row=_row("ac1", ""))
    assert _errors(doc) == [], f"an ungrounded authorized row did not rescue ac1: {_errors(doc)}"


def test_1221_the_rule_is_per_contract():
    """Two contracts on the same live hypothesis: ac1 rests on a past case only, ac2 on an
    authority. Benign is refused, naming ac1 and not ac2. The control: both on authorities
    validates clean."""
    def two(g1: str) -> str:
        doc = _grounded(g1, cites=PRIOR_RUN if g1 == "past-case" else "",
                        extra_row=_row("ac2", "org-authority"))
        assert doc.count(AC1_DECL) == 1, "example-b's ac1 declaration moved"
        return doc.replace(AC1_DECL, f"{AC1_DECL}\n{AC2_DECL}")

    assert _errors(two("org-authority")) == [], (
        f"the control failed: two authority-grounded contracts draw {_errors(two('org-authority'))}"
    )
    refused = _errors(two("past-case"))
    assert any("ac1" in m and re.search(r"past.case", m, re.I) for m in refused), (
        f"ac1 rests on a past case alone beside an authorized ac2 and validated: {refused}"
    )
    assert not any("ac2" in m for m in refused), f"ac2 was refused too: {refused}"


def test_1221_a_past_case_only_contract_stays_on_the_frontier():
    """The rule lives in the one reading of "discharged", so the retrieval frontier agrees
    with the gate: a contract resting on a past case alone is still open there (and keeps
    drawing retrieval), while the same contract on an authority is not."""
    assert "ac1" in _open_contract_ids(_grounded("past-case")), (
        "the frontier dropped a contract the benign gate still refuses"
    )
    assert "ac1" not in _open_contract_ids(_grounded("org-authority", cites="")), (
        "the control failed: an authority-discharged contract is still open on the frontier"
    )
