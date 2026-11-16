"""disposition unsanctioned-benign: harmless activity with no authorization record behind it.

The keyword sits between `benign` (every authorization question answered `authorized`) and an
escalation. It says three things at once, and each one is priced from the record rather than
taken on the model's word:

- the authorization question was WORKED and came back empty (an `indeterminate` contract with a
  paid `basis=exhausted`), not merely left open;
- the alerted entity was checked for suspicion on its own (`entity_check`, the same receipt
  `false-positive` owes), by a lead other than the one that searched for the record;
- the consequence was measured and stayed inside its threshold (`:R impact` rows, all `within`).

Anything `unauthorized`, any contract still worth another retrieval loop, and any unmeasured or
exceeded impact is an escalation, never this close.
"""
from __future__ import annotations

import pytest

from defender._vocab import DISPOSITION_ENUM
from defender.skills.invlang.validate import _DISPOSITION_GATES, validate_companion

KEYWORD = "unsanctioned-benign"

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
ac1|e-001|{anchor_kind}|"alice.ops's maintenance login to db-1.prod was covered by an approved change"|escalate|escalate

:H h-002.preds [id|subject|claim]
p1|proposed_parent|"the session came from a source alice.ops has never used"

:H h-002.refuts [id|refutes|claim]
r1|p1|"the source is alice.ops's own workstation, seen every week for 90 days"

:L findings [id|loop|name|target|tests|system|window]
l-001|1|change-record-search|v-001|h-001|change-mgmt|7d
l-002|1|planned-never-dispatched|v-002|h-001|identity|n/a
l-003|1|actor-session-history|v-002|h-001,h-002|elastic|90d
l-004|1|query-volume-on-db|v-001|h-001|elastic|1d
l-005|1|session-on-a-new-entity|v-009|h-002|elastic|90d

:L l-004.impact_preds [id|dim|claim|on_match|on_mismatch|on_indeterminate|escalation_on]
ip1|confidentiality|"rows read during the session within the 30d baseline"|within|exceeds|indeterminate|exceeds
```
"""

_RESOLVED = """\
```invlang
:R attr_updates [resolved_by|target|key|value]
l-001|v-001|attrs.change_window|none-recorded
l-003|v-002|attrs.source_history|usual-workstation
{rows}
:V l-005.observations.vertices [id|type|class|ident|attrs?]
v-009|compute|workstation/internal/known-corp|ws-77|

:E l-005.observations.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-009|attempted_auth|v-009|v-001||siem-event:elastic|

:T resolutions
h-001  null → ++   [l-003 p1 severe ⟂ e-001 :: usual admin workstation, usual hours]
h-002  null → --   [l-003 r1 severe ⟂ e-001 :: source is the actor's own workstation]

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


def authz(*, verdict: str = "indeterminate", basis: str = "exhausted", lead: str = "l-001",
          anchor_kind: str = "change-mgmt", fulfills: str = "ac1") -> str:
    return (
        f"{_AUTHZ_HEADER}\n{lead}|e-001|{fulfills}|{verdict}|{anchor_kind}|org-authority||"
        f'{basis}|"no change record covers alice.ops on db-1.prod in the window"\n'
    )


def impact(*verdicts: str) -> str:
    rows = "".join(
        f'l-004|ip1|confidentiality|"1.2k rows"|{v}|telemetry-baseline|db-30d|'
        f'approved-source-list|partial|2026-05-05T04:00Z|"inside the 30d band"\n'
        for v in verdicts
    )
    return f"{_IMPACT_HEADER}\n{rows}" if rows else ""


def conclude(*, disposition: str = KEYWORD, entity_check: str | None = "l-003",
             impact_verdict: str = "within") -> str:
    check = f"entity_check           {entity_check}\n" if entity_check else ""
    return (
        "```invlang\n:T conclude\n"
        "termination.category   adversarial-refuted\n"
        f"disposition            {disposition}\n"
        f"impact_verdict         {impact_verdict}\n"
        "impact_severity        null\n"
        "confidence             high\n"
        f"{check}"
        'summary                "routine maintenance by alice.ops with no change record"\n'
        "\n:T conclude.surviving [hyp_id|final_weight]\nh-001|++\n```\n"
    )


def document(*, rows: str | None = None, anchor_kind: str = "change-mgmt", **conclude_kwargs) -> str:
    if rows is None:
        rows = authz() + impact("within")
    return (
        _PROLOGUE.format(anchor_kind=anchor_kind)
        + "\n" + _RESOLVED.format(rows=f"\n{rows}" if rows else "")
        + "\n" + conclude(**conclude_kwargs)
    )


def _blocked(doc: str) -> list[str]:
    return [e for e in validate_companion(doc, None) if f"{KEYWORD} blocked" in e]


# the keyword exists, and is priced at both boundaries

def test_the_keyword_is_a_priced_disposition():
    assert KEYWORD in DISPOSITION_ENUM
    assert KEYWORD in _DISPOSITION_GATES, "the close would commit it for free"


def test_a_worked_empty_authorization_on_a_clean_entity_with_measured_impact_closes():
    """The case the keyword exists for: no change record anywhere the run could ask, the actor's
    own session checked out, and the consequence stayed inside its threshold."""
    assert validate_companion(document(), None) == []


def test_the_same_record_cannot_close_benign():
    """The new keyword relieves `benign`; it does not loosen it. The exhausted contract still
    blocks a plain `benign` close."""
    errors = validate_companion(document(disposition="benign"), None)
    assert any("benign blocked" in e and "ac1" in e for e in errors), errors


# the ways the close could be faked

@pytest.mark.parametrize(("case", "doc", "fragment"), [
    # The disposition says a record was LOOKED FOR. A contract nobody worked is not that.
    ("contract-never-resolved", document(rows=impact("within")), "ac1"),
    ("contract-still-worth-a-loop", document(rows=authz(basis="") + impact("within")), "ac1"),
    # `unauthorized` is a finding that the activity was NOT allowed: always an escalation.
    ("contract-unauthorized",
     document(rows=authz(verdict="unauthorized", basis="") + impact("within")), "unauthorized"),
    # Every contract authorized means nothing was unsanctioned: that close is `benign`.
    ("nothing-unsanctioned",
     document(rows=authz(verdict="authorized", basis="") + impact("within")), "benign"),
    # An exhausted claim whose lead never went to the system that answers the anchor kind
    # (`l-004` queried elastic, the contract asks change-mgmt) has not been paid for. The
    # basis receipt refuses it on write too; the close has to charge it as well, because
    # the close reads only its own price.
    ("exhausted-on-the-wrong-system",
     document(rows=authz(lead="l-004") + impact("within")), "without paying"),
    # No measured consequence: "no harm detected" is a claim about a measurement.
    ("impact-never-measured", document(rows=authz()), "impact"),
    ("impact-exceeded", document(rows=authz() + impact("within", "exceeds")), "exceeds"),
    ("impact-indeterminate", document(rows=authz() + impact("indeterminate")), "indeterminate"),
    # The entity check: the same receipt `false-positive` owes.
    ("no-entity-check", document(entity_check=None), "entity_check"),
    ("entity-check-names-no-lead", document(entity_check="l-404"), "not a lead"),
    ("entity-check-never-dispatched", document(entity_check="l-002"), "committed no result"),
    ("entity-check-on-an-introduced-entity", document(entity_check="l-005"), "prologue"),
    # One lead cannot pay both halves: the lead that searched for the record did not test
    # whether the actor's session was clean.
    ("entity-check-is-the-record-search", document(entity_check="l-001"), "l-001"),
], ids=lambda v: v if isinstance(v, str) and len(v) < 50 and "\n" not in v else "")
def test_an_unearned_unsanctioned_benign_close_is_refused(case, doc, fragment):
    blocked = _blocked(doc)
    assert any(fragment in e for e in blocked), (case, blocked or validate_companion(doc, None))


def test_a_bare_conclude_owes_the_price():
    bare = "```invlang\n:T conclude\ndisposition            unsanctioned-benign\n```\n"
    assert _blocked(bare), validate_companion(bare, None)


def test_the_price_is_scoped_to_the_keyword():
    """A `malicious` close over the same record owes none of it."""
    errors = validate_companion(document(rows=impact("within"), disposition="malicious",
                                         entity_check=None), None)
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

    deps, run_dir = main_deps(tmp_path, document(rows=authz()))
    with pytest.raises(ModelRetry) as refused:
        close(deps, KEYWORD)
    assert "impact" in str(refused.value)
    assert not (run_dir / "report.md").exists(), "a refused close still committed a report"
