"""disposition unsanctioned-benign: harmless activity with no authorization record behind it.

The keyword is `benign`'s price with one exception, decided before the search: a contract the
plan declared `on_indet process-gap` is discharged by a PAID `basis=exhausted` search of the
system that holds its anchor kind. Three things are owed beyond that, all read off the record:

- at least one contract was discharged that way, and none is `unauthorized`;
- one story is left standing, it holds that contract, and a measurement supports it — the
  stolen-credential reading of an unrecorded admin action has to be measured away, not outvoted,
  even when it carries a planned process gap of its own;
- every declared impact predicate is graded `within`, none deferred.
"""
from __future__ import annotations

from defender.tests.support.runtime.engine._spec992 import never_closed

import pytest

from defender._vocab import DISPOSITION_ENUM
from defender.skills.invlang import vocab
from defender.skills.invlang.validate import _DISPOSITION_GATES, validate_companion
from defender.tests.support.invlang.validation._process_gap import (
    _H2_TWIN,
    _IMPACT_PREDS,
    _IP2,
    KEYWORD,
    REFUTE_H2,
    authz,
    authz_row,
    document,
    impact,
)


_H2_OWN_GAP = """
:H h-002.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
ac2|e-001|change-mgmt|"an approved change let an outside party use alice.ops's account"|escalate|process-gap
"""


def _blocked(doc: str) -> list[str]:
    return [e for e in validate_companion(doc, None) if f"{KEYWORD} blocked" in e]


# the keyword exists, priced, and the plan's choice is a closed vocabulary

def test_the_keyword_is_a_priced_disposition():
    assert KEYWORD in DISPOSITION_ENUM
    assert KEYWORD in _DISPOSITION_GATES, "the close would commit it for free"
    assert vocab.get_enum("authz.on_indet") == ("escalate", "process-gap")


def test_a_planned_process_gap_searched_empty_with_the_attack_refuted_closes():
    assert validate_companion(document(), None) == []


def test_the_same_record_cannot_close_benign():
    """The keyword relieves `benign`; it does not loosen it."""
    errors = validate_companion(document(disposition="benign"), None)
    assert any("benign blocked" in e and "ac1" in e for e in errors), errors


def test_an_unknown_on_indet_is_refused_on_write():
    errors = validate_companion(document(on_indet="process_gap"), None)
    assert any("on_indet" in e and "authz.on_indet" in e for e in errors), errors


# the ways the close could be faked

@pytest.mark.parametrize(("case", "doc", "fragment"), [
    # The search has to have been worked, to a paid exhausted basis.
    ("contract-never-resolved", document(rows=impact("within")), "ac1"),
    ("contract-still-worth-a-loop", document(rows=authz(basis="") + impact("within")), "ac1"),
    ("contract-unauthorized",
     document(rows=authz(verdict="unauthorized", basis="") + impact("within")), "unauthorized"),
    # `l-004` queried elastic; the contract asks change-mgmt, so nothing was exhausted.
    ("exhausted-on-the-wrong-system", document(rows=authz(lead="l-004") + impact("within")),
     "ac1"),
    # Every contract authorized: nothing was unsanctioned, and the close is `benign`.
    ("nothing-unsanctioned",
     document(rows=authz(verdict="authorized", basis="") + impact("within")), "`benign`"),
    # The plan did not allow an empty search to end as a process gap.
    ("plan-said-escalate", document(on_indet="escalate"), "process-gap"),
    # An anchor kind with no home system cannot have its exhaustion checked against one.
    ("anchor-kind-without-a-home-system",
     document(anchor_kind="gpo", rows=authz(anchor_kind="gpo") + impact("within")),
     "home system"),
    # The stolen-credential story is still standing.
    ("attack-story-left-standing", document(refute_h2=False),
     "h-002"),
    # ... or confirmed, carrying its own planned process gap: holding a gap is no exemption.
    ("attack-story-confirmed-with-its-own-gap",
     document(h2_contract=_H2_OWN_GAP,
              rows=authz() + authz_row(fulfills="ac2") + impact("within"))
     .replace(REFUTE_H2, REFUTE_H2.replace("null → --", "null → ++")),
     "h-002"),
    # The one story left was never measured toward: unrefuted is not supported.
    ("gap-holder-unsupported",
     document().replace("h-001  null → ++", "h-001  null → -"), "h-001"),
    # A record that says the activity WAS authorized is not a missing record.
    ("authorized-beside-exhausted",
     document(rows=authz(verdict="authorized", basis="") + authz_row() + impact("within")),
     "indeterminate"),
    # Harm: graded over what was DECLARED.
    ("impact-exceeded", document(rows=authz() + impact("within", "exceeds")), "exceeds"),
    ("impact-indeterminate", document(rows=authz() + impact("indeterminate")), "ip1"),
    ("impact-deferred", document(extra_pred=_IP2, deferred_impact="l-004.ip2"), "ip2"),
    ("impact-never-declared", document(rows=authz()).replace(_IMPACT_PREDS, ""), "impact"),
    # A paid exhaustion of h-002's iam-policy twin is not a search for h-001's change record.
    ("twin-exhausted-under-another-anchor",
     document(h2_contract=_H2_TWIN,
              rows=authz(lead="l-006", anchor_kind="iam-policy") + impact("within")),
     "ac1"),
    # Same, with h-001's own question answered too, but only `retry`: the twin's paid search
    # still does not count as exhausting the change-mgmt question.
    ("twin-paid-beside-an-unworked-own-row",
     document(h2_contract=_H2_TWIN,
              rows=authz(basis="") + authz_row(lead="l-006", anchor_kind="iam-policy")
              + impact("within")),
     "ac1"),
], ids=lambda v: v if isinstance(v, str) and len(v) < 50 and "\n" not in v else "")
def test_an_unearned_unsanctioned_benign_close_is_refused(case, doc, fragment):
    blocked = _blocked(doc)
    assert any(fragment in e for e in blocked), (case, blocked or validate_companion(doc, None))


def test_a_verdict_on_a_refuted_storys_twin_contract_does_not_block_the_live_one():
    """`ac1` under refuted h-002 is a different question (iam-policy): its `unauthorized` row
    is about that question, and h-001's change-mgmt search still discharges h-001."""
    rows = (authz() + authz_row(verdict="unauthorized", basis="", lead="l-006",
                                anchor_kind="iam-policy") + impact("within"))
    doc = document(h2_contract=_H2_TWIN, rows=rows)
    assert _blocked(doc) == [], _blocked(doc)


def test_an_open_contract_is_refused_once_not_twice():
    """The closure rule stands down for a contract the close's own price already names."""
    errors = validate_companion(document(rows=impact("within")), None)
    assert [e for e in errors if "ac1" in e and "deferred_authz" in e] == [], errors


def test_an_ungraded_predicate_is_refused_once_not_told_to_defer():
    """The closure rule would say "defer it", which the price says does not pay."""
    errors = validate_companion(document(rows=authz()), None)
    assert any(f"{KEYWORD} blocked" in e and "ip1" in e for e in errors), errors
    assert [e for e in errors if "deferred_impact" in e] == [], errors


def test_a_bare_conclude_owes_the_price():
    bare = "```invlang\n:T conclude\ndisposition            unsanctioned-benign\n```\n"
    assert _blocked(bare), validate_companion(bare, None)


def test_the_price_is_scoped_to_the_keyword():
    errors = validate_companion(document(rows=impact("within"), disposition="malicious"), None)
    assert not any(f"{KEYWORD} blocked" in e for e in errors), errors


# the real close: the same price at the commit, and the reviewer told what the close claims

def test_the_close_commits_a_paid_record_and_asks_the_reviewer_the_process_gap_question(tmp_path):
    from defender.tests.support.runtime.engine._spec923 import committed
    from defender.tests.support.runtime.engine._spec992 import (
        close_with, deps_over, holds, recording,
    )

    rec = recording(holds())
    deps, run_dir = deps_over(tmp_path, document())
    result = close_with(deps, KEYWORD, rec)
    assert result.outcome == "stands", result
    assert committed(run_dir)["disposition"] == KEYWORD
    prompt = rec.prompt("composer")
    assert "closed `unsanctioned-benign`" in prompt
    assert "not a gap" in prompt, "the reviewer is not told the missing record is the claim"


def test_the_close_refuses_an_unpaid_record(tmp_path):
    from pydantic_ai.exceptions import ModelRetry

    from defender.tests.support.runtime.engine._spec923 import close, main_deps

    deps, run_dir = main_deps(tmp_path, document(on_indet="escalate"))
    with pytest.raises(ModelRetry) as refused:
        close(deps, KEYWORD)
    assert "process-gap" in str(refused.value)
    assert never_closed(run_dir), "a refused close still committed a report"
