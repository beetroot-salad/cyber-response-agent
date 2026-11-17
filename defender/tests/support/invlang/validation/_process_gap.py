"""The process-gap case `unsanctioned-benign` is priced against: alice.ops logs into db-1.prod
with no change record, the change-record search comes back empty, the stolen-credential story is
refuted by her session history, and the session's impact stays inside its baseline.

Shared because no one document pays every disposition's price any more: the open process-gap
contract this close needs is exactly what blocks `benign`.
"""
from __future__ import annotations

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
