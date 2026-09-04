"""Defender invlang parser tests (current schema).

Covers:
  - The slim `:H hypothesize.hypotheses` 9-col header (identity only).
  - `:H h-NNN.{preds,refuts,authz,attr_preds,parent_attrs}` sub-blocks.
  - Quoted attrs values so cell values can contain a literal `|`.
  - Strict rejection (with logged ParseWarning) of legacy 14-col or
    11-col `:H` headers, missing `⟂` on resolutions, etc.
  - Per-row recovery: one bad row never takes down the rest of a file.
"""

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




def test_split_cells_honors_quoted_pipe():
    row = 'v-002|process|process:bash|bash[pid=42]|flags="EXE_WRITABLE|EXE_LOWER_LAYER";user=root'
    cells = _split_cells(row)
    assert len(cells) == 5
    assert cells[4] == 'flags="EXE_WRITABLE|EXE_LOWER_LAYER";user=root'


def test_split_cells_backslash_escape_still_works():
    cells = _split_cells(r"a|b\|c|d")
    assert cells == ["a", "b|c", "d"]




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
    """#806 — what the DETECTOR got wrong is its own row, not a clause inside `summary`.

    The run that motivated it concluded `malicious` on a host that was genuinely compromised
    while the alert's own correlation was false; both are true, and `disposition` holds one.
    """
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
    """The field is for a detection defect that was FOUND. Most runs find none, so its absence
    is the ordinary case and must stay silent — and the key must not be conjured empty, since a
    reader cannot tell an empty note from a defect nobody looked for."""
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
    # The prologue is here to carry `benign`'s grounding clause, not for the projection under
    # test: a `:T conclude` block alone is a document that recorded no alerted entity, which
    # `_check_benign_grounding` refuses independently of anything about `detection_notes`.
    assert validate_companion(text) == []


def test_conclude_records_every_ceiling_test_row_in_order():
    """The gaps a run could not close are recorded, repeated, and in order.

    Eleven checked-in lessons instruct this field ("name them by host and source type in
    `ceiling_test`") and the projection dropped every row a run authored, so the judge could not
    tell a benign close that checked everything from one that named a load-bearing gap. It is a
    LIST because a run names each unreachable source separately; golden-case-018 writes three,
    and the duplicate-key guard must not read the second and third as a key being overwritten.
    """
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


def test_conclude_ceiling_test_none_projects_as_absence():
    """`none` is how the format spells "no ceiling", so it must not arrive as a one-item list a
    reader has to filter — `conclude.get("ceiling_test")` is the whole question."""
    text = """\
```invlang
:T conclude
disposition            benign
ceiling_test           none
```
"""
    body, warnings = parse_dense_companion(text)
    assert warnings == []
    assert "ceiling_test" not in body["conclude"]


def test_ceiling_test_reaches_the_judge_prompt():
    """The point of recording it: the stage that grades a benign close can now see what the run
    could not reach. `render_synthesis` dumps the conclude dict, so this needs no other plumbing
    — and before this commit the rows existed in 49 files and reached nothing."""
    from defender.learning.pipeline.judge.compare import render_synthesis

    text = """\
```invlang
:T conclude
disposition            benign
ceiling_test           "authorized_keys FIM on web-1 (auditd write events) not retrieved"
```
"""
    body, _warnings = parse_dense_companion(text)
    rendered = render_synthesis(body)
    assert "authorized_keys FIM on web-1" in rendered


def test_conclude_row_spanning_two_lines_warns_instead_of_truncating():
    """A value written across two lines used to keep line one — opening quote and all — and drop
    the rest in SILENCE. That is the #806 failure reproduced inside the fix for it: a conclusion
    that loses half of itself is worse than one never written. Both halves are asserted, because
    the continuation row and the row that opened the quote fail for different reasons and a fix
    that catches only one still ships the truncation.

    Both are caught by quote PARITY rather than by key membership: the opening row holds one
    `"` and the orphaned tail holds its partner, so each is odd on its own. That matters because
    membership cannot be the test — the lessons corpus instructs conclude keys this projection
    does not carry (`ceiling_test`), and denying those would deny runs for obeying a lesson.
    """
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
    # The fragment is still projected; the DENIAL is what stops it reaching disk, and it comes
    # from validate_companion turning these warnings into write-gate errors. Assert the denial
    # itself — warnings nobody converts would let the truncation ship with the suite green.
    assert body["conclude"]["detection_notes"].startswith('"')
    assert validate_companion(text), (
        "the truncated write was not denied — parse warnings must reach the write gate"
    )


def test_one_line_rule_holds_outside_conclude():
    """The truncation is a property of the line-oriented surface, not of `:T conclude`.

    A `:L findings` name spilled onto a second line loses the lead's target, loop, mode and
    system exactly as quietly, so the guard sits on every block's rows rather than inside one
    projector — otherwise the `:T conclude` fix reads as a fix for the whole format and is not.
    """
    text = """\
```invlang
:L findings [id|name|target|loop|mode|system|status]
l-001|"check the source ip against
the cmdb registry"|v-003|1|scoped|cmdb|done
```
"""
    _body, warnings = parse_dense_companion(text)
    assert any("does not close on this row" in w.reason for w in warnings), (
        f"a two-line `:L findings` row truncated in silence — warnings were "
        f"{[w.reason for w in warnings]!r}"
    )
    assert validate_companion(text)


def test_conclude_row_without_a_value_is_not_silently_dropped():
    """`<key>` alone matches no `<key> <value>` row, and the projector used to `continue` past
    it. A `disposition` line whose value slipped onto the next line then produced an EMPTY
    conclude with zero warnings — no headline, and the disposition vocab and benign gates both
    no-op on a key that isn't there."""
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
    """The continuation of a two-line value lands on whatever key its first word names, so the
    damage is not always a dropped row — here the tail of `termination.rationale` overwrites the
    run's `summary`. The warning has to name the field that was lost, not just the opener."""
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
    """The test is quote PARITY, not a leading `"`. A value that opens with a quoted word and
    continues in prose is a valid one line; denying it would block a conclusion whose author has
    no rewrite that satisfies the check."""
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
    """The cost of the `ceiling_test` rule above, pinned so it is a decision and not a surprise.

    `detectoin_notes` records nothing and nothing says so. Membership cannot distinguish a typo
    from a key the lessons instruct and this projection has yet to carry, and denying the second
    is the worse failure — it dead-letters a run for obeying a lesson. Quote parity still covers
    the spilled-value case that motivated #806; a typo'd key does not spill, so it slips.
    """
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


def test_conclude_subtable_is_accepted_and_ignored():
    text = """\
```invlang
:T conclude
disposition            benign
confidence             high

:T conclude.ceiling_test [kind|subject]
out-of-band-human-contact|owner|extra-cell
```
"""
    body, warnings = parse_dense_companion(text)
    assert warnings == []
    assert body["conclude"]["disposition"] == "benign"
    assert set(body["conclude"]) == {"disposition", "confidence"}




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


def test_parent_attrs_subblock_without_header_uses_key_value_default():
    """A `:H ...parent_attrs` block written without the explicit
    `[key|value]` header must still project (the `[key, value]` fallback),
    exactly like the other headerless `:H` sub-blocks. Regression guard for
    the row-projection dedupe, which routes parent_attrs through
    `_for_each_row`."""
    body, warnings = parse_dense_companion(
        _WITH_PARENT_ATTRS.replace(
            ":H h-003.parent_attrs [key|value]", ":H h-003.parent_attrs"
        )
    )
    assert warnings == []
    pv = body["hypothesize"]["hypotheses"][0]["proposed_edge"]["parent_vertex"]
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
    import pytest
    with pytest.raises(RowError, match="`⟂`"):
        _resolution_record(
            "h-001  null → +    "
            "[inline alert context: matching key from multiple corp IPs]"
        )




def test_resolution_extracts_matched_ids_from_iff_annotation():
    """The iff RHS literal set names which predictions / refutations the
    lead actually tested. Downstream Class 8 / Class 13 queries depend on
    these fields; they cannot be silently dropped."""
    lead_id, rec = _resolution_record(
        "h-001  null → ++   "
        "[l-001 p1,p2 severe ⟂ e-002 :: p1 ⟺ src=monitor; p2 ⟺ cadence=5m]"
    )
    assert lead_id == "l-001"
    assert rec["hypothesis"] == "h-001"
    assert rec["hypothesis_id"] == "h-001"
    assert rec["matched_prediction_ids"] == ["p1", "p2"]
    assert rec["matched_refutation_ids"] == []


def test_resolution_falls_back_to_head_tokens_when_no_iff():
    """Rows without iff annotation should still attribute matched ids
    via the pre-`⟂` head tokens (`r1,r2 severe` form)."""
    lead_id, rec = _resolution_record(
        "h-001  null → --   [l-001 r1,r2 severe ⟂ e-002 :: refutation triggered]"
    )
    assert lead_id == "l-001"
    assert rec["matched_refutation_ids"] == ["r1", "r2"]
    assert rec["matched_prediction_ids"] == []
    assert rec["reasoning"] == "refutation triggered"


def test_a_supporting_marker_is_not_mined_for_edge_ids():
    """The `⟂` cell is free text, and its non-id spelling lands in `supporting_marker`. An
    UNANCHORED `e-[A-Za-z0-9]+` finds an id inside that prose — `inference-only` yields
    `e-only` — and a phantom is worse than no citation: `_check_strong_provenance` then
    answers "cites e-only, which carries no strong authority" instead of "cites no supporting
    edge", and `projector.ablation_target` can pick it as the narrowest-supported edge, after
    which `_drop_edge` removes nothing and the ablation lens reads the FULL world while the
    composer is told that edge was withheld."""
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


def test_resolution_negated_iff_literal_still_attributes():
    """Polarity is reasoning-prose only; `¬p1` still counts as 'p1 was
    tested' for downstream attribution purposes."""
    _lead, rec = _resolution_record(
        "h-001  null → --   [l-001 r1 severe ⟂ e-001 :: r1 ⟺ ¬p1]"
    )
    assert rec["matched_refutation_ids"] == ["r1"]
    assert rec["matched_prediction_ids"] == ["p1"]




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
    """Defender's documented column subset (the form taught in
    skills/invlang/SKILL.md) parses without warnings and both contracts
    land as distinct authorization_resolutions rows on the right leads.
    """
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
    """`:H attached_to=v-*` canonicalizes to `anchor` (not the legacy
    `attached_to_vertex`); downstream queries (hypothesis_shape_match)
    index off the new key."""
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
    """`:H` is discovery-only — anchors must be `v-*` ids. Edge anchors
    surface as a ParseWarning (row dropped) with the offending hyp id
    plus a pointer to `??` notation as the alternative."""
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


# The two uncertainty spellings the vocabulary admits — `??` (unknown) and a `{a, b}` enum
# (one of these) — are legal in BOTH a classification and an attribute value. Each row parses
# one prologue vertex and pins the value through verbatim: the parser records uncertainty, it
# does not resolve or normalise it.
@pytest.mark.parametrize(("case", "row", "path", "expected"), [
    # a wholly-unknown classification
    ("classification-all-double-question-marks",
     "v-001|compute|endpoint:??/??/??|host|",
     ("classification",), "endpoint:??/??/??"),
    # ... and one where only the middle facet is unknown
    ("classification-partial-double-question-mark",
     "v-001|compute|endpoint:monitoring-agent/??/known-corp|host|",
     ("classification",), "endpoint:monitoring-agent/??/known-corp"),
    # a curly enum in the classification slot, spaces and all
    ("classification-curly-enum",
     "v-001|compute|endpoint:{monitoring-agent/internal/known-corp, "
     "ip-only/internet/novel}|host|",
     ("classification",),
     "endpoint:{monitoring-agent/internal/known-corp, ip-only/internet/novel}"),
    # the same two spellings in an ATTRIBUTE value, where `=` and `,` are also delimiters
    ("attrs-value-double-question-mark",
     "v-001|process|process:bash|bash[pid=42]|signing=??",
     ("attributes", "signing"), "??"),
    ("attrs-value-curly-enum",
     "v-001|process|process:bash|bash[pid=42]|signing={signed:microsoft, unsigned}",
     ("attributes", "signing"), "{signed:microsoft, unsigned}"),
], ids=lambda v: v if isinstance(v, str) and len(v) < 50 and "|" not in v else "")
def test_the_parser_admits_an_uncertain_value_verbatim(case, row, path, expected):
    """`??` and `{a, b}` are vocabulary, not defects: a vertex carrying either parses without
    a warning and the value survives byte-for-byte, in a classification and in an attribute
    alike. A parser that split on the enum's `,` or choked on `??` would drop the row."""
    body, warnings = parse_dense_companion(_wrap_prologue(row))
    assert warnings == []
    value = body["prologue"]["vertices"][0]
    for key in path:
        value = value[key]
    assert value == expected


def _mixed_corpus(tmp_path):
    """One clean case, one that loses a row to a parse warning, one that loads no rows at all."""
    case_a = tmp_path / "case-a"
    case_a.mkdir()
    (case_a / "investigation.md").write_text(_CONFORMANT)
    (case_a / "alert.json").write_text('{"rule": {"id": "100001"}}')

    case_b = tmp_path / "case-b"
    case_b.mkdir()
    (case_b / "investigation.md").write_text(_UNQUOTED_PIPE_IN_ATTRS)
    (case_b / "alert.json").write_text('{"rule": {"id": "100001"}}')

    case_c = tmp_path / "case-c"
    case_c.mkdir()
    (case_c / "investigation.md").write_text("# no fences here\n")
    (case_c / "alert.json").write_text('{"rule": {"id": "5710"}}')
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
    """The counts say a case is missing; only the detail says which one and why.

    `skipped`'s reason and `partial`'s per-row warnings had no reader outside the tests once the
    second corpus CLI was retired, so a short corpus answered queries silently. Both levels are
    reachable from the surviving CLI now, and this pins what each one carries."""
    from defender.skills.invlang.corpus import load_corpus

    _, report = load_corpus(_mixed_corpus(tmp_path))

    terse = report.detail_lines(verbose=False)
    assert terse == [
        "  skipped case-c: no ```invlang fences found",
        "  partial case-b: 1 row(s) skipped",
    ]

    verbose = report.detail_lines(verbose=True)
    assert verbose[:2] == terse
    # The extra line is the row-level warning itself: which block, which row, why it was dropped.
    ((_, warnings),) = report.partial
    assert verbose[2:] == [f"    [{warnings[0].block} row {warnings[0].row_index}] "
                           f"{warnings[0].reason}"]


def test_load_report_detail_is_empty_for_a_clean_corpus(tmp_path):
    """A healthy corpus stays silent — the detail is a fault report, not a per-run inventory."""
    from defender.skills.invlang.corpus import load_corpus

    case = tmp_path / "case-a"
    case.mkdir()
    (case / "investigation.md").write_text(_CONFORMANT)
    (case / "alert.json").write_text('{"rule": {"id": "100001"}}')

    _, report = load_corpus(tmp_path)

    assert report.loaded == 1
    assert report.detail_lines(verbose=True) == []


def test_cli_prints_the_load_detail_to_stderr_and_quiet_suppresses_it(tmp_path):
    """The CLI is the surface that gives the detail a reader — assert it through the real process.

    `--quiet` covers the whole load report, detail included; without it the operator sees the bad
    cases named alongside the summary they qualify."""
    _mixed_corpus(tmp_path)
    argv = [sys.executable, "-m", "defender.skills.invlang.cli", str(tmp_path)]
    repo_root = str(Path(__file__).resolve().parents[2])

    loud = subprocess.run([*argv, "--verbose", "sequence"], capture_output=True, text=True,
                          check=False, cwd=repo_root)
    assert loud.returncode == 0, loud.stderr
    assert "skipped case-c: no ```invlang fences found" in loud.stderr
    assert "partial case-b: 1 row(s) skipped" in loud.stderr

    quiet = subprocess.run([*argv, "--quiet", "sequence"], capture_output=True, text=True,
                           check=False, cwd=repo_root)
    assert quiet.returncode == 0, quiet.stderr
    assert "case-c" not in quiet.stderr
