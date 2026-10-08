"""#1221 O2 — rule #27: a benign verdict cannot rest on past cases alone.

The design (issue #1221, D2/M3, as amended 2026-10-08): a comment a model wrote is a PAST CASE,
cited `grounding past-case`, `cites_past_case <run id>`. What makes an `:R authz` row a past
case for #27 is its CITATION, not its grounding word: a row is a past case iff its
`cites_past_case` cell is non-empty — citing a run IS leaning on it, whatever the grounding cell
says. An authz contract whose `authorized` rows all cite a past case is not discharged, so a
benign close over it is refused with an error naming the contract; any `authorized` row on that
contract without a citation rescues it. The rule lives in the one reading of "discharged"
(`outstanding_authz_contracts`), so the retrieval frontier keeps such a contract open too. It
covers `benign` only (N9).

Two row-structure rules make the citation the honest signal, and they hold under EVERY
disposition (they are about the row, not the verdict):
  * a non-empty `cites_past_case` must be a run id (`defender._run_id.is_valid_run_id`);
  * a row whose grounding folds to `past-case` (case- and separator-insensitive) must cite the
    run it leans on — a past case written uncited would otherwise slip past #27.

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
from defender._run_id import is_valid_run_id
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

#: A second `authorized` row on the same contract, grounded on an affirmative record, uncited.
ORG_AUTHORITY_ROW = (
    'l-003|e-001|ac1|authorized|iam-policy|org-authority||'
    '"the IAM binding for metrics-shipper names sre-iam-team as its owner"'
)

#: Every way the grounding cell may spell `past-case`: the fold reads case and any run of
#: whitespace, underscores and hyphens between the two words as one hyphen.
PAST_CASE_SPELLINGS = [
    "past-case", "Past_Case", "past case", "PAST-CASE",
    "past  case", "past\tcase", "past_ case", " Past-Case ", "past - case",
]

#: Groundings that are NOT past-case — what a row citing a run may still be labelled.
OTHER_GROUNDINGS = ["org-authority", ""]

#: Citations that are not run ids (`is_valid_run_id` refuses each).
NOT_RUN_IDS = ["../x", "not a run", "a/b", "-leading-dash"]


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


def _refusals_of_ac1(doc: str) -> list[str]:
    """The #27 refusals: errors naming `ac1` that say its discharge was a past case."""
    return [m for m in _errors(doc) if "ac1" in m and re.search(r"past.case", m, re.I)]


def _row_errors(doc: str) -> list[str]:
    """Errors about the row's citation: they name the `cites_past_case` cell and the row (its
    lead `l-003` or the contract `ac1` it fulfils)."""
    return [m for m in _errors(doc)
            if "cites_past_case" in m and ("l-003" in m or "ac1" in m)]


# =======================================================================================
# #27 — what makes a past case is the citation
# =======================================================================================


@pytest.mark.parametrize("grounding", PAST_CASE_SPELLINGS + OTHER_GROUNDINGS)
def test_1221_a_benign_close_resting_on_past_cases_alone_is_refused(grounding):
    """NEGATIVE, with its controls on the same address. A benign document whose authz contract
    (`ac1` on the live `h-001`) is discharged ONLY by an `authorized` row that cites a past run
    draws an error diagnostic naming that contract — whatever the row's grounding cell says,
    `org-authority` and no grounding at all included: citing a run is leaning on it. The string
    surface the production close reads refuses it too.

    Controls, each the same document with one cell changed:
      * the row grounded `org-authority` with NO citation validates clean;
      * the row as example-b ships it (no grounding, no citation cell) validates clean;
      * the citing row PLUS a second, uncited `authorized` row on `ac1` grounded on an
        affirmative record validates clean — a past case may still be cited beside real
        evidence."""
    cited = _grounded(grounding, cites=PRIOR_RUN)
    uncited_authority = _grounded("org-authority", cites="")

    assert _errors(uncited_authority) == [], (
        f"the control failed: the uncited org-authority twin draws {_errors(uncited_authority)}"
    )
    assert _errors(_example_b()) == [], "the control failed: example-b as shipped draws errors"
    assert _errors(_grounded(grounding, extra_row=ORG_AUTHORITY_ROW)) == [], (
        "a cited row beside an uncited org-authority row on the same contract was refused — "
        "#27 forbids resting on past cases ALONE"
    )

    assert _refusals_of_ac1(cited), (
        f"a benign close whose only discharge of ac1 cites {PRIOR_RUN} (grounding "
        f"{grounding!r}) validated without a past-case refusal of ac1: {_errors(cited)}"
    )
    assert validate_companion(cited), (
        "the production close's string surface accepted the past-case-only benign document"
    )


def test_1221_the_rule_keys_on_the_citation_not_on_the_grounding():
    """The amendment's whole point, side by side on one contract: an `org-authority` row that
    cites a run is a past case and is refused; the same row without the citation is an
    authority and is clean. The grounding cell did not move between the two."""
    assert _refusals_of_ac1(_grounded("org-authority", cites=PRIOR_RUN)), (
        "an org-authority row citing a prior run discharged ac1 — the citation, not the "
        "grounding word, decides whether a row is a past case"
    )
    assert _errors(_grounded("org-authority", cites="")) == [], (
        "the control failed: the uncited org-authority row was refused"
    )


@pytest.mark.parametrize(
    "disposition", [d for d in DISPOSITION_VALUES if d != "benign"],
)
def test_1221_the_past_case_rule_is_benign_only(disposition):
    """The complementary condition: under every disposition but `benign`, a well-formed citation
    (a valid run id) changes nothing the validator says, whatever the row's grounding (N9: #27
    covers benign only). Asserted as equality with the same document's uncited `org-authority`
    row, so a disposition whose own gates already refuse example-b (`false-positive`,
    `inconclusive`, `unresolved`) still pins that the rule adds nothing there; `malicious`
    validates clean either way."""
    baseline = _errors(_with_disposition(_grounded("org-authority", cites=""), disposition))
    for grounding in ("past-case", "org-authority"):
        cited = _errors(_with_disposition(_grounded(grounding, cites=PRIOR_RUN), disposition))
        assert cited == baseline, (
            f"a {grounding} row citing {PRIOR_RUN} changed the {disposition} verdict's "
            f"diagnostics: {sorted(set(cited) ^ set(baseline))}"
        )
        if disposition == "malicious":
            assert cited == [], f"a malicious close citing a past case was refused: {cited}"


# =======================================================================================
# The row-structure rules: a past case names the run it cites, and the cite is a run id
# =======================================================================================


def _row_error_everywhere(doc: str, why: str) -> list[str]:
    """The citation errors `doc` draws under `malicious` — where #27 has nothing to say — after
    checking that each of them is drawn under EVERY disposition: a row-structure rule is about
    the row, not the verdict, so the same message stands whatever the close says."""
    found = _row_errors(_with_disposition(doc, "malicious"))
    assert found, (
        f"{why} drew no error naming `cites_past_case` and the row under malicious: "
        f"{_errors(_with_disposition(doc, 'malicious'))}"
    )
    for disposition in DISPOSITION_VALUES:
        under = set(_errors(_with_disposition(doc, disposition)))
        assert under & set(found), (
            f"{why}: the citation error drawn under malicious ({found}) is not drawn under "
            f"{disposition} — a row-structure rule fires under any disposition: {sorted(under)}"
        )
    return found


@pytest.mark.parametrize("spelling", PAST_CASE_SPELLINGS)
def test_1221_an_uncited_past_case_is_an_error(spelling):
    """A row whose grounding folds to `past-case` — in any case, with any run of whitespace,
    underscores or hyphens between the words — but whose `cites_past_case` is empty is an error
    on that row: a past case names the run it cites. Without this a past case could be written
    uncited and slip past #27, which keys on the citation.

    A row-structure rule, so it fires under any disposition: found under `malicious`, where #27
    has nothing to say, and then required under every disposition, `benign` included.

    Controls on the same address, under `malicious`: the same spelling WITH a citation validates
    clean, and an uncited row grounded `org-authority`, or not grounded at all, is not a past
    case and validates clean too."""
    _row_error_everywhere(_grounded(spelling, cites=""),
                          f"a row grounded {spelling!r} with no cites_past_case")

    cited = _with_disposition(_grounded(spelling, cites=PRIOR_RUN), "malicious")
    assert _errors(cited) == [], (
        f"the control failed: a row grounded {spelling!r} citing {PRIOR_RUN} draws "
        f"{_errors(cited)} under malicious"
    )
    for other in OTHER_GROUNDINGS:
        not_past = _with_disposition(_grounded(other, cites=""), "malicious")
        assert _errors(not_past) == [], (
            f"an uncited row grounded {other!r} is not a past case and draws "
            f"{_errors(not_past)} under malicious"
        )


@pytest.mark.parametrize("cite", NOT_RUN_IDS)
def test_1221_a_citation_that_is_not_a_run_id_is_an_error(cite):
    """A non-empty `cites_past_case` must be a run id (`is_valid_run_id`): anything else is an
    error on that row naming the cell and the value, under any disposition. The positive
    control is the same row citing a real run id — `PRIOR_RUN`, whose upper-case `T`/`Z` a run
    id admits — which validates clean under `malicious`."""
    assert not is_valid_run_id(cite), f"fixture bug: {cite!r} is a valid run id"
    assert is_valid_run_id(PRIOR_RUN), f"fixture bug: {PRIOR_RUN!r} is not a valid run id"

    found = _row_error_everywhere(_grounded("past-case", cites=cite),
                                  f"cites_past_case {cite!r}, which is not a run id,")
    assert any(cite in m for m in found), (
        f"the citation error does not name the value {cite!r}: {found}"
    )

    good = _with_disposition(_grounded("past-case", cites=PRIOR_RUN), "malicious")
    assert _errors(good) == [], f"the control failed: a valid run id draws {_errors(good)}"


def test_1221_a_valid_citation_under_org_authority_is_still_a_past_case():
    """A valid run id under an `org-authority` grounding is a well-formed row — clean under
    `malicious` — and #27 still applies to it on a benign close: a well-formed citation is
    exactly what makes the row lean on a past run."""
    doc = _grounded("org-authority", cites=PRIOR_RUN)
    assert _errors(_with_disposition(doc, "malicious")) == [], (
        f"a valid citation under org-authority draws "
        f"{_errors(_with_disposition(doc, 'malicious'))} under malicious"
    )
    assert _refusals_of_ac1(doc), (
        f"an org-authority row citing {PRIOR_RUN} discharged ac1 on a benign close: "
        f"{_errors(doc)}"
    )


# =======================================================================================
# How far #27 reaches: several rows, several contracts, the frontier
# =======================================================================================

AC1_DECL = 'ac1|e-001|iam-policy|"metrics-shipper is provisioned and authorized for this source→target SSH path"|escalate|escalate'
AC2_DECL = 'ac2|e-001|iam-policy|"the SSH path is inside the monitoring role\'s approved scope"|escalate|escalate'


def _row(contract: str, grounding: str, cites: str = "") -> str:
    return f'l-003|e-001|{contract}|authorized|iam-policy|{grounding}|{cites}|"{contract} {grounding or "ungrounded"}"'


def _open_contract_ids(doc: str) -> set[str]:
    from defender.skills.invlang.frontier import frontier_from_text
    return {c.contract_id for c in frontier_from_text(doc).contracts}


@pytest.mark.parametrize("second_grounding", ["past-case", "org-authority"])
def test_1221_two_citing_rows_are_still_past_cases_alone(second_grounding):
    """Two `authorized` rows on one contract, each citing a run, are past cases alone — the
    count of rows is not the test, and neither is the second row's grounding word."""
    doc = _grounded("past-case",
                    extra_row=_row("ac1", second_grounding, "20261002T000000Z-other"))
    assert _refusals_of_ac1(doc), (
        f"two citing rows (the second grounded {second_grounding!r}) discharged ac1: "
        f"{_errors(doc)}"
    )


@pytest.mark.parametrize("rescue_grounding", ["", "org-authority"])
def test_1221_an_uncited_authorized_row_beside_a_past_case_discharges(rescue_grounding):
    """The rescue is any `authorized` row on the contract without a citation — grounded on an
    authority or not grounded at all — beside the citing row."""
    doc = _grounded("past-case", extra_row=_row("ac1", rescue_grounding))
    assert _errors(doc) == [], (
        f"an uncited authorized row (grounding {rescue_grounding!r}) did not rescue ac1: "
        f"{_errors(doc)}"
    )


@pytest.mark.parametrize("grounding", ["past-case", "org-authority"])
def test_1221_the_rule_is_per_contract(grounding):
    """Two contracts on the same live hypothesis: ac1 rests on a citing row only, ac2 on an
    uncited authority. Benign is refused, naming ac1 and not ac2. The control: ac1 on an
    uncited authority too validates clean."""
    def two(cites: str) -> str:
        doc = _grounded(grounding if cites else "org-authority", cites=cites,
                        extra_row=_row("ac2", "org-authority"))
        assert doc.count(AC1_DECL) == 1, "example-b's ac1 declaration moved"
        return doc.replace(AC1_DECL, f"{AC1_DECL}\n{AC2_DECL}")

    assert _errors(two("")) == [], (
        f"the control failed: two authority-grounded contracts draw {_errors(two(''))}"
    )
    refused = _errors(two(PRIOR_RUN))
    assert any("ac1" in m and re.search(r"past.case", m, re.I) for m in refused), (
        f"ac1 rests on a citing {grounding} row alone beside an authorized ac2 and "
        f"validated: {refused}"
    )
    assert not any("ac2" in m for m in refused), f"ac2 was refused too: {refused}"


def test_1221_a_past_case_only_contract_stays_on_the_frontier():
    """The rule lives in the one reading of "discharged", so the retrieval frontier agrees
    with the gate: a contract resting on citing rows alone is still open there (and keeps
    drawing retrieval) — grounded `past-case` or `org-authority` alike — while the same
    contract on an uncited authority is not."""
    for grounding in ("past-case", "org-authority"):
        assert "ac1" in _open_contract_ids(_grounded(grounding, cites=PRIOR_RUN)), (
            f"the frontier dropped a contract resting on a {grounding} row citing "
            f"{PRIOR_RUN} — one the benign gate still refuses"
        )
    assert "ac1" not in _open_contract_ids(_grounded("org-authority", cites="")), (
        "the control failed: an authority-discharged contract is still open on the frontier"
    )
