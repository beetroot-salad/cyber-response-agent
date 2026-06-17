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

from defender.skills.invlang.parser import (
    RowError,
    _resolution_record,
    _split_cells,
    parse_dense_companion,
)


# ---------------------------------------------------------------------------
# Cell tokenizer: quoted spans suppress `|` as a delimiter
# ---------------------------------------------------------------------------


def test_split_cells_honors_quoted_pipe():
    row = 'v-002|process|process:bash|bash[pid=42]|flags="EXE_WRITABLE|EXE_LOWER_LAYER";user=root'
    cells = _split_cells(row)
    assert len(cells) == 5
    # The `|` inside the quoted attrs value stays put.
    assert cells[4] == 'flags="EXE_WRITABLE|EXE_LOWER_LAYER";user=root'


def test_split_cells_backslash_escape_still_works():
    cells = _split_cells(r"a|b\|c|d")
    assert cells == ["a", "b|c", "d"]


# ---------------------------------------------------------------------------
# Current-schema baseline: parses cleanly, no warnings
# ---------------------------------------------------------------------------


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
    # Header projects identity only.
    hyps = body["hypothesize"]["hypotheses"]
    assert [h["id"] for h in hyps] == ["h-001", "h-002"]
    h1 = next(h for h in hyps if h["id"] == "h-001")
    # Sub-blocks attach to the parent hypothesis by id.
    assert [p["id"] for p in h1["predictions"]] == ["p1", "p2"]
    assert h1["refutation_shape"][0]["refutes_predictions"] == ["p1"]
    assert h1["authorization_contract"][0]["anchor_kind"] == "cmdb"
    # h-002 has its own preds/refuts but no authz — schema allows omission.
    h2 = next(h for h in hyps if h["id"] == "h-002")
    assert len(h2["predictions"]) == 1
    assert "authorization_contract" not in h2
    # Quoted attrs value with `|` round-trips intact.
    v2 = next(v for v in body["prologue"]["vertices"] if v["id"] == "v-002")
    assert v2["attributes"]["flags"] == "EXE_WRITABLE|EXE_LOWER_LAYER"
    # Resolution lands cleanly.
    res = body["findings"][0]["resolutions"][0]
    assert res["after"] == "--"
    assert res["supporting_edges"] == ["e-001"]
    assert body["conclude"]["disposition"] == "malicious"


def test_conclude_subtable_is_accepted_and_ignored():
    # `:T conclude.*` sub-tables have no machine consumer in defender; a stray
    # one (here a malformed ceiling_test) must neither warn nor project,
    # rather than trigger format-fighting against the validator.
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
    # No sub-table key leaks into the projected conclude dict.
    assert set(body["conclude"]) == {"disposition", "confidence"}


# ---------------------------------------------------------------------------
# Parent-attrs sub-block (rare but supported)
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Strict rejection of legacy `:H` header (14-col or 11-col)
# ---------------------------------------------------------------------------


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
    # No hypotheses land; the rest of the file (prologue, findings, conclude)
    # still parses, so the case is still partially usable.
    assert body.get("hypothesize", {}).get("hypotheses") in (None, [])
    h_warnings = [w for w in warnings if w.block.startswith(":H ")]
    assert len(h_warnings) == 1
    assert "does not match the current schema" in h_warnings[0].reason
    assert body["conclude"]["disposition"] == "benign"


# ---------------------------------------------------------------------------
# Unescaped `|` in attrs is now a hard schema violation
# (must be quoted under the current schema)
# ---------------------------------------------------------------------------


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
    # v-002 is dropped; v-001 still lands.
    assert [v["id"] for v in body["prologue"]["vertices"]] == ["v-001"]
    bad = next(w for w in warnings if w.block == ":V prologue.vertices")
    assert bad.row_index == 1
    assert "6 cells but 5 expected" in bad.reason
    # The expected header is echoed so the mismatch is self-correcting
    # without a spec lookup.
    assert "for [id|type|class|ident|attrs]" in bad.reason
    # The hypothesis and the conclude still land — file remains useful.
    assert body["hypothesize"]["hypotheses"][0]["id"] == "h-001"
    assert body["conclude"]["disposition"] == "malicious"


# ---------------------------------------------------------------------------
# `:T resolutions` missing `⟂` is rejected per row
# ---------------------------------------------------------------------------


def test_resolution_missing_perp_raises():
    import pytest
    with pytest.raises(RowError, match="`⟂`"):
        _resolution_record(
            "h-001  null → +    "
            "[inline alert context: matching key from multiple corp IPs]"
        )


# ---------------------------------------------------------------------------
# Matched-id extraction on :T resolutions (review note #1)
# ---------------------------------------------------------------------------


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
    # Alias matches the soc-agent canonical shape.
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


def test_resolution_negated_iff_literal_still_attributes():
    """Polarity is reasoning-prose only; `¬p1` still counts as 'p1 was
    tested' for downstream attribution purposes."""
    _lead, rec = _resolution_record(
        "h-001  null → --   [l-001 r1 severe ⟂ e-001 :: r1 ⟺ ¬p1]"
    )
    assert rec["matched_refutation_ids"] == ["r1"]
    assert rec["matched_prediction_ids"] == ["p1"]


# ---------------------------------------------------------------------------
# Canonical :R block key mapping (review note #2)
# ---------------------------------------------------------------------------


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
    # Short dense names get rewritten to the canonical companion-dict
    # forms so downstream consumers indexing on the long names work.
    assert row["fulfills_contract"] == "ac1"
    assert row["resolved_by_lead"] == "l-001"
    assert row["grounding_kind"] == "policy-check"
    assert row["authority_for_question"] == "iam-system"
    # Semicolon-packed conditioning lands as a list.
    assert row["conditioning_context"] == [
        "effective_window=2026-05-01_to_2026-05-31",
        "principal=svc-x",
    ]
    # Empty cells are dropped; verdict/anchor still land.
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
h-001|?monitoring-probe|v-001|attempted_auth|compute|monitoring/internal/known-corp||null|active

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


# ---------------------------------------------------------------------------
# Sub-block references an unknown hypothesis — logged, doesn't crash
# ---------------------------------------------------------------------------


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
    # h-001 still gets through unaffected.
    assert body["hypothesize"]["hypotheses"][0]["id"] == "h-001"


# ---------------------------------------------------------------------------
# Corpus loader: partial vs whole-file rejects still surface correctly
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# `:H attached_to` canonicalizes to `anchor`; edge ids rejected
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# `??` and `{...}` notation round-trips as literal strings (no parser-side
# decomposition — downstream consumers parse on demand)
# ---------------------------------------------------------------------------


def _wrap_prologue(vertex_row: str) -> str:
    return (
        "```invlang\n"
        ":V prologue.vertices [id|type|class|ident|attrs?]\n"
        f"{vertex_row}\n"
        "```\n"
    )


def test_vertex_classification_admits_double_question_mark():
    body, warnings = parse_dense_companion(
        _wrap_prologue("v-001|compute|endpoint:??/??/??|host|")
    )
    assert warnings == []
    v = body["prologue"]["vertices"][0]
    assert v["classification"] == "endpoint:??/??/??"


def test_vertex_classification_admits_partial_question_mark():
    body, warnings = parse_dense_companion(
        _wrap_prologue("v-001|compute|endpoint:monitoring-agent/??/known-corp|host|")
    )
    assert warnings == []
    v = body["prologue"]["vertices"][0]
    assert v["classification"] == "endpoint:monitoring-agent/??/known-corp"


def test_vertex_classification_admits_curly_enum():
    body, warnings = parse_dense_companion(
        _wrap_prologue(
            "v-001|compute|endpoint:{monitoring-agent/internal/known-corp, "
            "ip-only/internet/novel}|host|"
        )
    )
    assert warnings == []
    v = body["prologue"]["vertices"][0]
    assert v["classification"] == (
        "endpoint:{monitoring-agent/internal/known-corp, "
        "ip-only/internet/novel}"
    )


def test_attrs_value_admits_double_question_mark():
    body, warnings = parse_dense_companion(
        _wrap_prologue("v-001|process|process:bash|bash[pid=42]|signing=??")
    )
    assert warnings == []
    v = body["prologue"]["vertices"][0]
    assert v["attributes"]["signing"] == "??"


def test_attrs_value_admits_curly_enum():
    body, warnings = parse_dense_companion(
        _wrap_prologue(
            "v-001|process|process:bash|bash[pid=42]|"
            "signing={signed:microsoft, unsigned}"
        )
    )
    assert warnings == []
    v = body["prologue"]["vertices"][0]
    assert v["attributes"]["signing"] == "{signed:microsoft, unsigned}"


def test_load_report_separates_skipped_files_from_partial_loads(tmp_path):
    from defender.skills.invlang.corpus import load_corpus

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

    companions, report = load_corpus(tmp_path)
    assert report.scanned == 3
    assert report.loaded == 2
    assert [p.parent.name for p, _ in report.skipped] == ["case-c"]
    partial_names = [p.parent.name for p, _ in report.partial]
    assert partial_names == ["case-b"]
    assert report.total_warnings == 1
    _, warnings = report.partial[0]
    assert "case-b" in warnings[0].file_path
