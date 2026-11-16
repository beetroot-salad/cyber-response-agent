"""disposition unsanctioned-benign: harmless activity with no authorization record behind it.

The keyword is `benign`'s price with one exception, decided before the search: a contract the
plan declared `on_indet process-gap` is discharged by a PAID `basis=exhausted` search of the
system that holds its anchor kind. Three things are owed beyond that, all read off the record:

- at least one contract was discharged that way, and none is `unauthorized`;
- every story other than the one holding that contract is refuted — the stolen-credential reading
  of an unrecorded admin action has to be measured away, not outvoted;
- every declared impact predicate is graded `within`, none deferred.
"""
from __future__ import annotations

import pytest

from defender._vocab import DISPOSITION_ENUM
from defender.skills.invlang import vocab
from defender.skills.invlang.validate import _DISPOSITION_GATES, validate_companion

KEYWORD = "unsanctioned-benign"
REFUTE_H2 = "h-002  null → --   [l-003 r1 severe ⟂ e-001 :: source is the actor's own workstation]\n"

_PROLOGUE = """\
```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|compute|database-server/internal/known-corp|db-1.prod|os=linux
v-002|identity|user/known-corp|alice.ops|

:E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-001|attempted_auth|v-002|v-001|2026-05-05T03:42:11Z|siem-event:elastic|method=ssh

:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]
h-001|?unticketed-maintenance|v-002|initiated_by|identity|user/known-corp||null|active
h-002|?stolen-admin-credential|v-002|initiated_by|identity|user/external||null|active

:H h-001.preds [id|subject|claim]
p1|proposed_parent|"the session came from alice.ops's usual admin workstation"

:H h-001.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
ac1|e-001|{anchor_kind}|"alice.ops's maintenance login to db-1.prod was covered by an approved change"|escalate|{on_indet}

:H h-002.preds [id|subject|claim]
p1|proposed_parent|"the session came from a source alice.ops has never used"

:H h-002.refuts [id|refutes|claim]
r1|p1|"the source is alice.ops's own workstation, seen every week for 90 days"
{h2_contract}
:L findings [id|loop|name|target|tests|system|window]
l-001|1|change-record-search|v-001|h-001|change-mgmt|7d
l-003|1|actor-session-history|v-002|h-001,h-002|elastic|90d
l-004|1|query-volume-on-db|v-001|h-001|elastic|1d
l-006|1|iam-binding-search|v-002|h-002|identity|n/a

:L l-004.impact_preds [id|dim|claim|on_match|on_mismatch|on_indeterminate|escalation_on]
ip1|confidentiality|"rows read during the session within the 30d baseline"|within|exceeds|indeterminate|exceeds
{extra_pred}```
"""

_RESOLVED = """\
```invlang
:R attr_updates [resolved_by|target|key|value]
l-001|v-001|attrs.change_window|none-recorded
l-003|v-002|attrs.source_history|usual-workstation
l-006|v-002|attrs.iam_binding|none
{rows}
:T resolutions
h-001  null → ++   [l-003 p1 severe ⟂ e-001 :: usual admin workstation, usual hours]
{refute_h2}
:T close
loop  1
```
"""

_AUTHZ_HEADER = (
    ":R authz [resolved_by|edge|fulfills|verdict|anchor_kind|grounding|anchor_id|basis|reasoning]"
)
_IMPACT_HEADER = (
    ":R impact [resolved_by|pred_ref|dim|observed|verdict|grounding|anchor_id|anchor_kind|"
    "authority|as_of|reasoning]"
)


def authz_row(*, verdict: str = "indeterminate", basis: str = "exhausted", lead: str = "l-001",
              anchor_kind: str = "change-mgmt", fulfills: str = "ac1") -> str:
    return (
        f"{lead}|e-001|{fulfills}|{verdict}|{anchor_kind}|org-authority||"
        f'{basis}|"no record covers alice.ops on db-1.prod in the window"\n'
    )


def authz(**kwargs) -> str:
    return f"{_AUTHZ_HEADER}\n{authz_row(**kwargs)}"


def impact(*verdicts: str, pred: str = "ip1") -> str:
    rows = "".join(
        f'l-004|{pred}|confidentiality|"1.2k rows"|{v}|telemetry-baseline|db-30d|'
        f'approved-source-list|partial|2026-05-05T04:00Z|"inside the 30d band"\n'
        for v in verdicts
    )
    return f"{_IMPACT_HEADER}\n{rows}" if rows else ""


def conclude(*, disposition: str, surviving: tuple[str, ...], deferred_impact: str) -> str:
    rows = "".join(f"{h}|++\n" for h in surviving)
    deferred = (
        f'\n:T conclude.deferred_impact [prediction_ref|rationale]\n{deferred_impact}|'
        f'"the audit log was not reachable"\n' if deferred_impact else ""
    )
    return (
        "```invlang\n:T conclude\n"
        "termination.category   adversarial-refuted\n"
        f"disposition            {disposition}\n"
        "impact_verdict         within\n"
        "impact_severity        null\n"
        "confidence             high\n"
        'summary                "routine maintenance by alice.ops with no change record"\n'
        f"\n:T conclude.surviving [hyp_id|final_weight]\n{rows}{deferred}```\n"
    )


def document(*, rows: str | None = None, anchor_kind: str = "change-mgmt",
             on_indet: str = "process-gap", refute_h2: bool = True, h2_contract: str = "",
             extra_pred: str = "", deferred_impact: str = "", disposition: str = KEYWORD) -> str:
    """The case; with `refute_h2=False` the stolen-credential story is carried as standing."""
    surviving = ("h-001",) if refute_h2 else ("h-001", "h-002")
    if rows is None:
        rows = authz() + impact("within")
    return (
        _PROLOGUE.format(anchor_kind=anchor_kind, on_indet=on_indet,
                         h2_contract=h2_contract, extra_pred=extra_pred)
        + "\n" + _RESOLVED.format(rows=f"\n{rows}" if rows else "",
                                  refute_h2=REFUTE_H2 if refute_h2 else "")
        + "\n" + conclude(disposition=disposition, surviving=surviving,
                          deferred_impact=deferred_impact)
    )


#: A contract under the REFUTED stolen-credential story that reuses the id `ac1` under a
#: different anchor kind: a row for it says nothing about h-001's change-mgmt question.
_H2_TWIN = """
:H h-002.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
ac1|e-001|iam-policy|"an IAM binding lets an external identity sign in as alice.ops"|escalate|escalate
"""

_IP2 = (
    'ip2|integrity|"no schema change during the session"|within|exceeds|indeterminate|exceeds\n'
)

_IMPACT_PREDS = (
    ":L l-004.impact_preds [id|dim|claim|on_match|on_mismatch|on_indeterminate|escalation_on]\n"
    'ip1|confidentiality|"rows read during the session within the 30d baseline"|within|'
    "exceeds|indeterminate|exceeds\n"
)


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
    assert not (run_dir / "report.md").exists(), "a refused close still committed a report"
