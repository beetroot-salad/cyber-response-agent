from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from defender.skills.invlang.parser import (
    RowError,
    _resolution_record,
    _split_cells,
    parse_dense_companion,
)
from defender.skills.invlang.validate import validate_companion
from defender.tests._alert_plant import plant_alert


def test_split_cells_honors_quoted_pipe():
    row = 'v-002|process|process:bash|bash[pid=42]|flags="EXE_WRITABLE|EXE_LOWER_LAYER";user=root'
    cells = _split_cells(row)
    assert len(cells) == 5
    assert cells[4] == 'flags="EXE_WRITABLE|EXE_LOWER_LAYER";user=root'


_CONFORMANT = """\
```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|container|endpoint:linux|target-endpoint|id=2a124a5fc6d9
v-002|process|process:bash|bash[pid=42]|cmdline="bash -c whoami";flags="EXE_WRITABLE|EXE_LOWER_LAYER";user=root

:E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-001|execve|v-002|v-001|2026-05-07T14:25:22.570Z|siem-event:wazuh-falco|rule=100001

:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]
h-001|?authorized-exec|v-002|execve|identity|operator||null|active
h-002|?adversary-pivot|v-002|execve|identity|adversary-shell||null|active

:H h-001.preds [id|subject|claim]
p1|proposed_parent|"workload documented as managed infrastructure"
p2|proposed_edge|"exec arrived via the bastion path"

:H h-001.refuts [id|refutes|claim]
r1|p1|"workload undocumented"

:H h-001.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
ac1|proposed|cmdb|"operator session traces to a documented owner"|escalate|escalate

:H h-002.preds [id|subject|claim]
p1|proposed_parent|"exec arrived via an unattributed host-side path"

:H h-002.refuts [id|refutes|claim]
r1|p1|"exec attributable to a documented operator"

:L findings [id|loop|name|target|tests|system|template|query|window]
l-001|1|cmdb-lookup|v-001|h-001,h-002|stub-cmdb|host-lookup|hostname=foo|n/a

:T resolutions
h-001  null → --   [l-001 r1 severe ⟂ e-001 :: r1 ⟺ ¬p1; pivot signal observed]

:T conclude
disposition            malicious
matched_archetype      compromised-container
summary                "exec via host pivot"

:T conclude.surviving [hyp_id|final_weight]
h-001|--
```
"""


def test_conformant_parse_produces_no_warnings():
    body, warnings = parse_dense_companion(_CONFORMANT)
    assert warnings == []
    hyps = body["hypothesize"]["hypotheses"]
    assert [h["id"] for h in hyps] == ["h-001", "h-002"]
    h1 = next(h for h in hyps if h["id"] == "h-001")
    assert [p["id"] for p in h1["predictions"]] == ["p1", "p2"]
    assert h1["refutation_shape"][0]["refutes_predictions"] == ["p1"]
    assert h1["authorization_contract"][0]["anchor_kind"] == "cmdb"
    h2 = next(h for h in hyps if h["id"] == "h-002")
    assert len(h2["predictions"]) == 1
    assert "authorization_contract" not in h2
    v2 = next(v for v in body["prologue"]["vertices"] if v["id"] == "v-002")
    assert v2["attributes"]["flags"] == "EXE_WRITABLE|EXE_LOWER_LAYER"
    res = body["findings"][0]["resolutions"][0]
    assert res["after"] == "--"
    assert res["supporting_edges"] == ["e-001"]
    assert body["conclude"]["disposition"] == "malicious"


def test_conclude_carries_detection_notes():
    """#806 — what the DETECTOR got wrong is its own row, not a clause inside `summary`."""
    text = """\
```invlang
:T conclude
disposition            malicious
summary                "root authorized_keys carries three attacker@elsewhere keys"
detection_notes        "Rule joins on host.name only; failures and success are different users"
```
"""
    body, warnings = parse_dense_companion(text)
    assert warnings == []
    assert body["conclude"]["detection_notes"] == (
        "Rule joins on host.name only; failures and success are different users"
    )
    assert body["conclude"]["summary"].startswith("root authorized_keys")


def test_conclude_without_detection_notes_is_clean_and_invents_no_key():
    text = """\
```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|compute|bastion/internal/known-corp|bastion-01.corp|kind=physical

:T conclude
disposition            benign
confidence             high
summary                "Login matched established bastion usage"
```
"""
    body, warnings = parse_dense_companion(text)
    assert warnings == []
    assert "detection_notes" not in body["conclude"]
    assert validate_companion(text) == []


def test_conclude_records_every_ceiling_test_row_in_order():
    """The gaps a run could not close are recorded, repeated, and in order."""
    text = """\
```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|compute|bastion/internal/known-corp|bastion-01.corp|kind=physical

:T conclude
disposition            benign
ceiling_test           "l-009 Zeek HTTP detail for curl events not retrieved (request limit)"
ceiling_test           "79.177.137.245 absent from the threat-intel catalog"
ceiling_rationale      "both gaps are corroboration, not the load-bearing check"
```
"""
    body, warnings = parse_dense_companion(text)
    assert warnings == [], f"repeated list rows were flagged as duplicates: {warnings!r}"
    assert validate_companion(text) == []
    assert body["conclude"]["ceiling_test"] == [
        "l-009 Zeek HTTP detail for curl events not retrieved (request limit)",
        "79.177.137.245 absent from the threat-intel catalog",
    ]
    assert body["conclude"]["ceiling_rationale"].startswith("both gaps")


def test_conclude_row_spanning_two_lines_warns_instead_of_truncating():
    """A value written across two lines used to keep line one — opening quote and all — and drop the rest in SILENCE."""
    text = """\
```invlang
:T conclude
disposition            malicious
detection_notes        "Rule joins on host.name only.
                        Failures and success are different users."
```
"""
    body, warnings = parse_dense_companion(text)
    rows_warned = {w.row_index for w in warnings if "does not close on this row" in w.reason}
    assert rows_warned == {1, 2}, (
        f"both halves of the spilled value must warn — got rows {sorted(rows_warned)} from "
        f"{[(w.row_index, w.reason[:60]) for w in warnings]!r}"
    )
    assert body["conclude"]["detection_notes"].startswith('"')
    assert validate_companion(text), (
        "the truncated write was not denied — parse warnings must reach the write gate"
    )


def test_conclude_row_without_a_value_is_not_silently_dropped():
    """`<key>` alone matches no `<key> <value>` row, and the projector used to `continue` past it."""
    text = """\
```invlang
:T conclude
disposition
malicious
```
"""
    body, warnings = parse_dense_companion(text)
    assert body["conclude"] == {}
    assert warnings, "a conclude row carrying no value vanished in silence"
    assert validate_companion(text)


def test_conclude_key_set_twice_names_the_clobbered_field():
    text = """\
```invlang
:T conclude
disposition            benign
summary                "Login matched established bastion usage"
termination.rationale  "host-query unavailable, so the
summary of h-002 cannot reach --"
```
"""
    _body, warnings = parse_dense_companion(text)
    assert any("'summary' is set twice" in w.reason for w in warnings), (
        f"the clobbered field was not named — warnings were "
        f"{[w.reason for w in warnings]!r}"
    )


def test_quoted_word_inside_a_one_line_value_is_not_a_truncation():
    text = """\
```invlang
:T conclude
disposition            benign
summary                "sensu" login from the monitoring host is sanctioned
```
"""
    body, warnings = parse_dense_companion(text)
    assert warnings == []
    assert body["conclude"]["summary"].startswith('"sensu"')


def test_a_misspelled_conclude_key_is_silently_ignored():
    """The cost of the `ceiling_test` rule above, pinned so it is a decision and not a surprise."""
    text = """\
```invlang
:T conclude
disposition            benign
detectoin_notes        "typo in the key name"
```
"""
    body, warnings = parse_dense_companion(text)
    assert warnings == []
    assert "detectoin_notes" not in body["conclude"]
    assert "detection_notes" not in body["conclude"]


_WITH_PARENT_ATTRS = """\
```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-010|object|object:s3-key|bucket/key|

:E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-001|read|v-010|v-010|2026-05-07T00:00:00Z|siem-event:wazuh|outcome=success

:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]
h-003|?approved-service-read|v-010|read|identity|service-account||null|active

:H h-003.parent_attrs [key|value]
kind|service-account
team|data-platform

:L findings [id|loop|name|target|tests|system|template|query|window]
l-001|1|n|v-010|h-003|iam|account|n=x|n/a

:T resolutions
h-003  null → +    [l-001 p1 weak ⟂ e-001 :: p1]

:T conclude
disposition            benign
matched_archetype      approved-service-read
summary                "x"

:T conclude.surviving [hyp_id|final_weight]
h-003|+
```
"""


def test_parent_attrs_subblock_attaches_to_proposed_edge():
    body, warnings = parse_dense_companion(_WITH_PARENT_ATTRS)
    assert warnings == []
    h = body["hypothesize"]["hypotheses"][0]
    pv = h["proposed_edge"]["parent_vertex"]
    assert pv["attributes"] == {"kind": "service-account", "team": "data-platform"}


_LEGACY_14_COL_H = """\
```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|endpoint|endpoint:linux|host|

:E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-001|attempted_auth|v-001|v-001|2026-05-07T00:00:00Z|siem-event:wazuh|rule=5710

:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|parent_attrs?|preds|attr_preds?|refuts?|authz?|integrity_waived?|weight|status]
h-001|?old-schema|v-001|attempted_auth|endpoint|monitor||p1:proposed_parent:"x"||r1[p1]:"y"|||null|active

:L findings [id|loop|name|target|tests|system|template|query|window]
l-001|1|n|v-001|h-001|s|t|q|w

:T resolutions
h-001  null → ++   [l-001 p1 severe ⟂ e-001 :: p1]

:T conclude
disposition            benign
matched_archetype      foo
summary                "x"

:T conclude.surviving [hyp_id|final_weight]
h-001|++
```
"""


def test_legacy_h_header_block_rejected_with_one_warning():
    body, warnings = parse_dense_companion(_LEGACY_14_COL_H)
    assert body.get("hypothesize", {}).get("hypotheses") in (None, [])
    h_warnings = [w for w in warnings if w.block.startswith(":H ")]
    assert len(h_warnings) == 1
    assert "does not match the current schema" in h_warnings[0].reason
    assert body["conclude"]["disposition"] == "benign"


_UNQUOTED_PIPE_IN_ATTRS = """\
```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|container|endpoint:linux|target|id=abc
v-002|process|process:bash|bash[pid=42]|flags=EXE_WRITABLE|EXE_LOWER_LAYER

:E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-001|execve|v-002|v-001|2026-05-07T00:00:00Z|siem-event:wazuh|rule=100001

:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]
h-001|?h|v-002|execve|identity|op||null|active

:L findings [id|loop|name|target|tests|system|template|query|window]
l-001|1|n|v-001|h-001|s|t|q|w

:T resolutions
h-001  null → --   [l-001 r1 severe ⟂ e-001 :: x]

:T conclude
disposition            malicious
matched_archetype      foo
summary                "x"

:T conclude.surviving [hyp_id|final_weight]
h-001|--
```
"""


def test_unquoted_pipe_in_attrs_drops_row_and_keeps_rest():
    body, warnings = parse_dense_companion(_UNQUOTED_PIPE_IN_ATTRS)
    assert [v["id"] for v in body["prologue"]["vertices"]] == ["v-001"]
    bad = next(w for w in warnings if w.block == ":V prologue.vertices")
    assert bad.row_index == 1
    assert "6 cells but 5 expected" in bad.reason
    assert "for [id|type|class|ident|attrs]" in bad.reason
    assert body["hypothesize"]["hypotheses"][0]["id"] == "h-001"
    assert body["conclude"]["disposition"] == "malicious"


def test_resolution_missing_perp_raises():
    with pytest.raises(RowError, match="`⟂`"):
        _resolution_record(
            "h-001  null → +    "
            "[inline alert context: matching key from multiple corp IPs]"
        )


def test_resolution_extracts_matched_ids_from_iff_annotation():
    lead_id, rec = _resolution_record(
        "h-001  null → ++   "
        "[l-001 p1,p2 severe ⟂ e-002 :: p1 ⟺ src=monitor; p2 ⟺ cadence=5m]"
    )
    assert lead_id == "l-001"
    assert rec["hypothesis"] == "h-001"
    assert rec["hypothesis_id"] == "h-001"
    assert rec["matched_prediction_ids"] == ["p1", "p2"]
    assert rec["matched_refutation_ids"] == []


def test_a_supporting_marker_is_not_mined_for_edge_ids():
    """The `⟂` cell is free text, and its non-id spelling lands in `supporting_marker`."""
    _lead, rec = _resolution_record(
        "h-001  null → --   [l-001 r1 severe ⟂ inference-only :: no observed edge]"
    )
    assert rec["supporting_edges"] == [], (
        f"prose in the ⟂ cell was mined for an edge id: {rec['supporting_edges']}"
    )
    assert rec["supporting_marker"] == "inference-only"

    _lead, real = _resolution_record(
        "h-001  null → --   [l-001 r1 severe ⟂ e-001,e-002 e-001 :: two edges, one twice]"
    )
    assert real["supporting_edges"] == ["e-001", "e-002"]


_AUTHZ_R_BLOCK = """\
```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|endpoint|endpoint:linux|host|

:E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-001|read|v-001|v-001|2026-05-07T00:00:00Z|siem-event:wazuh|outcome=success

:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]
h-001|?service-read|v-001|read|identity|service-account||null|active

:H h-001.preds [id|subject|claim]
p1|proposed_parent|"x"

:H h-001.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
ac1|e-001|iam-policy|"service account configured reader"|escalate|escalate

:L findings [id|loop|name|target|tests|system|template|query|window]
l-001|1|iam-policy-lookup|v-001|h-001|iam|policy-by-account|account=svc-x|n/a

:R authz [resolved_by|edge|fulfills|verdict|grounding|authority|anchor_kind|anchor_id|conditioning|concerns]
l-001|e-001|ac1|authorized|policy-check|iam-system|iam-policy|policy-742|effective_window=2026-05-01_to_2026-05-31;principal=svc-x|

:T resolutions
h-001  null → ++   [l-001 p1 severe ⟂ e-001 :: p1]

:T conclude
disposition            benign
matched_archetype      approved-service-read
summary                "x"

:T conclude.surviving [hyp_id|final_weight]
h-001|++
```
"""


def test_authz_block_emits_canonical_field_names():
    body, warnings = parse_dense_companion(_AUTHZ_R_BLOCK)
    assert warnings == []
    lead = next(f for f in body["findings"] if f["id"] == "l-001")
    authz_rows = lead["outcome"]["authorization_resolutions"]
    assert len(authz_rows) == 1
    row = authz_rows[0]
    assert row["fulfills_contract"] == "ac1"
    assert row["resolved_by_lead"] == "l-001"
    assert row["grounding_kind"] == "policy-check"
    assert row["authority_for_question"] == "iam-system"
    assert row["conditioning_context"] == [
        "effective_window=2026-05-01_to_2026-05-31",
        "principal=svc-x",
    ]
    assert row["verdict"] == "authorized"
    assert row["anchor_kind"] == "iam-policy"
    assert row["anchor_id"] == "policy-742"
    assert "concerns" not in row


_AUTHZ_R_BLOCK_SLIM = """\
```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|compute|ip-only/internal/anonymous|10.0.0.1|knowledge=partial
v-002|compute|unknown/internal/known-corp|target-host|

:E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-001|attempted_auth|v-001|v-002|2026-05-07T00:00:00Z|siem-event:wazuh|outcome=failed

:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]
h-001|?monitoring-probe|v-001|attempted_auth|compute|monitoring-agent/internal/known-corp||null|active

:H h-001.preds [id|subject|claim]
p1|proposed_parent|"source is documented monitoring infra"

:H h-001.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
ac1|e-001|approved-source-list|"source authorized to probe target"|escalate|escalate
ac2|e-001|iam-policy|"account authorized for SSH from source"|escalate|escalate

:L findings [id|loop|name|target|tests|system|template|query|window]
l-001|1|cmdb-lookup|v-001|h-001|stub-cmdb|host-lookup|ip=10.0.0.1|n/a
l-002|1|iam-lookup|v-001|h-001|stub-iam|account-lookup|name=probe|n/a

:R authz [resolved_by|edge|fulfills|verdict|anchor_kind|reasoning]
l-001|e-001|ac1|unauthorized|approved-source-list|"10.0.0.1 absent from CMDB"
l-002|e-001|ac2|unauthorized|iam-policy|"probe account marked inactive"

:T resolutions
h-001  null → --   [l-001 r1 severe ⟂ e-001 :: ac1=unauthorized, ac2=unauthorized]

:T conclude
disposition            malicious
matched_archetype      scan
summary                "x"

:T conclude.surviving [hyp_id|final_weight]
```
"""


def test_authz_slim_column_form_round_trips():
    """Defender's documented column subset (the form taught in skills/invlang/SKILL.md) parses without warnings and both contracts land as distinct authorization_resolutions rows on the right leads."""
    body, warnings = parse_dense_companion(_AUTHZ_R_BLOCK_SLIM)
    assert warnings == []

    l1 = next(f for f in body["findings"] if f["id"] == "l-001")
    l2 = next(f for f in body["findings"] if f["id"] == "l-002")
    rows1 = l1["outcome"]["authorization_resolutions"]
    rows2 = l2["outcome"]["authorization_resolutions"]
    assert len(rows1) == 1
    assert len(rows2) == 1
    assert rows1[0]["fulfills_contract"] == "ac1"
    assert rows1[0]["verdict"] == "unauthorized"
    assert rows1[0]["anchor_kind"] == "approved-source-list"
    assert rows1[0]["edge"] == "e-001"
    assert rows1[0]["reasoning"] == '"10.0.0.1 absent from CMDB"'
    assert rows2[0]["fulfills_contract"] == "ac2"
    assert rows2[0]["verdict"] == "unauthorized"


_MIXED_RESOLUTIONS = """\
```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|endpoint|endpoint:linux|host|

:E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-001|attempted_auth|v-001|v-001|2026-05-07T00:00:00Z|siem-event:wazuh|rule=5710

:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]
h-001|?inline|v-001|attempted_auth|endpoint|monitor||null|active

:L findings [id|loop|name|target|tests|system|template|query|window]
l-001|1|inline|v-001|h-001|wazuh|alerts|q|w

:T resolutions
h-001  null → +    [inline context only, no cited edges]
h-001  null → ++   [l-001 p1 severe ⟂ e-001 :: p1 matches]

:T conclude
disposition            inconclusive
matched_archetype      foo
summary                "x"

:T conclude.surviving [hyp_id|final_weight]
h-001|+
```
"""


def test_no_perp_resolution_logs_warning_and_keeps_good_sibling():
    body, warnings = parse_dense_companion(_MIXED_RESOLUTIONS)
    lead = next(f for f in body["findings"] if f["id"] == "l-001")
    assert len(lead["resolutions"]) == 1
    assert lead["resolutions"][0]["after"] == "++"
    bad = next(w for w in warnings if w.block == ":T resolutions")
    assert "`⟂`" in bad.reason


_DANGLING_SUBBLOCK = """\
```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|endpoint|endpoint:linux|host|

:E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-001|attempted_auth|v-001|v-001|2026-05-07T00:00:00Z|siem-event:wazuh|rule=5710

:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]
h-001|?a|v-001|attempted_auth|endpoint|monitor||null|active

:H h-999.preds [id|subject|claim]
p1|proposed_parent|"belongs to a hypothesis that doesn't exist"

:L findings [id|loop|name|target|tests|system|template|query|window]
l-001|1|n|v-001|h-001|s|t|q|w

:T resolutions
h-001  null → +    [l-001 p1 weak ⟂ e-001 :: p1]

:T conclude
disposition            benign
matched_archetype      foo
summary                "x"

:T conclude.surviving [hyp_id|final_weight]
h-001|+
```
"""


def test_subblock_with_unknown_parent_logs_warning():
    body, warnings = parse_dense_companion(_DANGLING_SUBBLOCK)
    assert any("unknown hypothesis" in w.reason for w in warnings)
    assert body["hypothesize"]["hypotheses"][0]["id"] == "h-001"


_H_VERTEX_ANCHOR = """\
```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|endpoint|endpoint:linux|host|

:E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-001|attempted_auth|v-001|v-001|2026-05-07T00:00:00Z|siem-event:wazuh|rule=5710

:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]
h-001|?routine|v-001|attempted_auth|compute|bastion/internal/known-corp||null|active

:L findings [id|loop|name|target|tests|system|template|query|window]
l-001|1|n|v-001|h-001|s|t|q|w

:T resolutions
h-001  null → ++   [l-001 p1 severe ⟂ e-001 :: p1]

:T conclude
disposition            benign
matched_archetype      foo
summary                "x"

:T conclude.surviving [hyp_id|final_weight]
h-001|++
```
"""


def test_hypothesis_canonical_key_is_anchor():
    body, warnings = parse_dense_companion(_H_VERTEX_ANCHOR)
    assert warnings == []
    h = body["hypothesize"]["hypotheses"][0]
    assert h["anchor"] == "v-001"
    assert "attached_to_vertex" not in h


_H_EDGE_ANCHOR = """\
```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|endpoint|endpoint:linux|host|

:E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-001|attempted_auth|v-001|v-001|2026-05-07T00:00:00Z|siem-event:wazuh|rule=5710

:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]
h-007|?edge-anchored|e-001|attempted_auth|identity|user/known-corp||null|active

:L findings [id|loop|name|target|tests|system|template|query|window]
l-001|1|n|v-001|h-007|s|t|q|w

:T resolutions

:T conclude
disposition            inconclusive
matched_archetype      foo
summary                "x"

:T conclude.surviving [hyp_id|final_weight]
```
"""


def test_hypothesis_rejects_edge_anchor():
    body, warnings = parse_dense_companion(_H_EDGE_ANCHOR)
    assert body.get("hypothesize", {}).get("hypotheses", []) == []
    h_warnings = [w for w in warnings if w.block.startswith(":H ")]
    assert len(h_warnings) == 1
    reason = h_warnings[0].reason
    assert "h-007" in reason
    assert "??" in reason


def _wrap_prologue(vertex_row: str) -> str:
    return (
        "```invlang\n"
        ":V prologue.vertices [id|type|class|ident|attrs?]\n"
        f"{vertex_row}\n"
        "```\n"
    )


def _mixed_corpus(tmp_path):
    """One clean case, one that loses a row to a parse warning, one that loads no rows at all."""
    case_a = tmp_path / "case-a"
    case_a.mkdir()
    (case_a / "investigation.md").write_text(_CONFORMANT)
    plant_alert(case_a, {"rule": {"id": "100001"}})

    case_b = tmp_path / "case-b"
    case_b.mkdir()
    (case_b / "investigation.md").write_text(_UNQUOTED_PIPE_IN_ATTRS)
    plant_alert(case_b, {"rule": {"id": "100001"}})

    case_c = tmp_path / "case-c"
    case_c.mkdir()
    (case_c / "investigation.md").write_text("# no fences here\n")
    plant_alert(case_c, {"rule": {"id": "5710"}})
    return tmp_path


def test_load_report_separates_skipped_files_from_partial_loads(tmp_path):
    from defender.skills.invlang.corpus import load_corpus

    companions, report = load_corpus(_mixed_corpus(tmp_path))
    assert report.scanned == 3
    assert report.loaded == 2
    assert [p.parent.name for p, _ in report.skipped] == ["case-c"]
    partial_names = [p.parent.name for p, _ in report.partial]
    assert partial_names == ["case-b"]
    assert report.total_warnings == 1
    _, warnings = report.partial[0]
    assert "case-b" in warnings[0].file_path


def test_load_report_detail_names_the_case_behind_each_count(tmp_path):
    """The counts say a case is missing;"""
    from defender.skills.invlang.corpus import load_corpus

    _, report = load_corpus(_mixed_corpus(tmp_path))

    terse = report.detail_lines(verbose=False)
    assert terse == [
        "  skipped 'case-c': no ```invlang fences found",
        "  partial 'case-b': 1 row(s) skipped",
    ]

    verbose = report.detail_lines(verbose=True)
    assert verbose[:2] == terse
    # The extra line is the row-level warning itself: which block, which row, why it was dropped.
    ((_, warnings),) = report.partial
    assert verbose[2:] == [f"    [{warnings[0].block} row {warnings[0].row_index}] "
                           f"{warnings[0].reason}"]


def test_cli_prints_the_load_detail_to_stderr_and_quiet_suppresses_it(tmp_path):
    """The CLI is the surface that gives the detail a reader — assert it through the real process."""
    _mixed_corpus(tmp_path)
    argv = [sys.executable, "-m", "defender.skills.invlang.cli", str(tmp_path)]
    repo_root = str(Path(__file__).resolve().parents[2])

    loud = subprocess.run([*argv, "--verbose", "sequence"], capture_output=True, text=True,
                          check=False, cwd=repo_root)
    assert loud.returncode == 0, loud.stderr
    assert "skipped 'case-c': no ```invlang fences found" in loud.stderr
    assert "partial 'case-b': 1 row(s) skipped" in loud.stderr

    quiet = subprocess.run([*argv, "--quiet", "sequence"], capture_output=True, text=True,
                           check=False, cwd=repo_root)
    assert quiet.returncode == 0, quiet.stderr
    assert "case-c" not in quiet.stderr
