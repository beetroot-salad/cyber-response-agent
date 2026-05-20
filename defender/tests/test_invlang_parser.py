"""Defender invlang parser tests (strict, current-schema-aligned).

The parser refuses to absorb LLM hiccups (unescaped `|` in attrs,
extra empty cells in `:H` rows, missing `⟂` on resolutions). Instead
it logs them as `ParseWarning`s and continues past, so a single bad
row in a file doesn't break the rest.

Each drift below has a positive and a negative test:

  - schema-conformant version parses cleanly, no warnings
  - non-conformant version produces a structured warning with the
    block/row/reason; the rest of the file is unaffected
"""

from __future__ import annotations

from defender.scripts.invlang.parser import (
    ParseWarning,
    parse_dense_companion,
    _resolution_record,
    RowError,
)


# ---------------------------------------------------------------------------
# Schema-conformant baseline — should parse fully, no warnings
# ---------------------------------------------------------------------------


_CONFORMANT = """\
```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|container|endpoint:linux|target-endpoint|id=2a124a5fc6d9
v-002|process|process:bash|bash[pid=42]|cmdline=bash;user=root

:E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-001|execve|v-002|v-001|2026-05-07T14:25:22.570Z|siem-event:wazuh-falco|rule=100001

:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|parent_attrs?|preds|attr_preds?|refuts?|authz?|integrity_waived?|weight|status]
h-001|?authorized-exec|v-002|execve|identity|operator||p1:proposed_parent:"workload documented"||r1[p1]:"no auth path"|ac1:proposed:cmdb:"authorized":esc/esc||null|active

:L findings [id|loop|name|target|tests|system|template|query|window]
l-001|1|cmdb-lookup|v-001|h-001|stub-cmdb|host-lookup|hostname=foo|n/a

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
    assert len(body["prologue"]["vertices"]) == 2
    assert len(body["prologue"]["edges"]) == 1
    h = body["hypothesize"]["hypotheses"][0]
    assert h["name"] == "?authorized-exec"
    assert h["refutation_shape"][0]["refutes_predictions"] == ["p1"]
    assert h["authorization_contract"][0]["anchor_kind"] == "cmdb"
    assert body["conclude"]["disposition"] == "malicious"
    res = body["findings"][0]["resolutions"][0]
    assert res["before"] == "null"
    assert res["after"] == "--"
    assert res["supporting_edges"] == ["e-001"]


# ---------------------------------------------------------------------------
# Drift #1 — unescaped `|` inside attrs (vertex). Reject + log.
# ---------------------------------------------------------------------------


_PIPE_IN_ATTRS = """\
```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|container|endpoint:linux|target|id=abc
v-002|process|process:bash|bash[pid=42]|flags=EXE_WRITABLE|EXE_LOWER_LAYER

:E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-001|execve|v-002|v-001|2026-05-07T00:00:00Z|siem-event:wazuh|rule=100001

:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|parent_attrs?|preds|attr_preds?|refuts?|authz?|integrity_waived?|weight|status]
h-001|?h|v-002|execve|identity|op||p1:proposed_parent:"x"||r1[p1]:"y"|||null|active

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


def test_unescaped_pipe_in_attrs_logs_warning_and_continues():
    body, warnings = parse_dense_companion(_PIPE_IN_ATTRS)
    # The bad v-002 row is dropped; v-001 still lands.
    verts = body["prologue"]["vertices"]
    assert [v["id"] for v in verts] == ["v-001"]
    # A single warning, with structured location and a remediation hint.
    assert len(warnings) == 1
    w = warnings[0]
    assert isinstance(w, ParseWarning)
    assert w.block == ":V prologue.vertices"
    assert w.row_index == 1
    assert "6 cells but 5 expected" in w.reason
    assert "unescaped" in w.reason  # remediation hint present
    # Rest of file still loads (the case stays usable for advisory queries).
    assert body["conclude"]["disposition"] == "malicious"


# ---------------------------------------------------------------------------
# Drift #2 — `:H` row with 15 cells (extra empty between refuts and authz).
# ---------------------------------------------------------------------------


_EXTRA_H_CELL = """\
```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|endpoint|endpoint:linux|host|

:E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-001|attempted_auth|v-001|v-001|2026-05-07T00:00:00Z|siem-event:wazuh|rule=5710

:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|parent_attrs?|preds|attr_preds?|refuts?|authz?|integrity_waived?|weight|status]
h-001|?good-row|v-001|attempted_auth|endpoint|monitor||p1:proposed_parent:"a"||r1[p1]:"b"|ac1:proposed:cmdb:"c":esc/esc||null|active
h-002|?bad-row|v-001|attempted_auth|endpoint|monitor||p1:proposed_parent:"a"||r1[p1]:"b"||ac1:proposed:cmdb:"c":esc/esc||null|active

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


def test_extra_cell_hypothesis_row_logs_and_keeps_good_sibling():
    body, warnings = parse_dense_companion(_EXTRA_H_CELL)
    hyps = body["hypothesize"]["hypotheses"]
    # The 15-cell row (h-002) is rejected; the 14-cell sibling (h-001) lands.
    assert [h["id"] for h in hyps] == ["h-001"]
    bad = next(w for w in warnings if w.block == ":H hypothesize.hypotheses")
    assert bad.row_index == 1
    assert "15 cells but 14 expected" in bad.reason


# ---------------------------------------------------------------------------
# Drift #3 — `:T resolutions` row without the `⟂` separator.
# ---------------------------------------------------------------------------


def test_resolution_missing_perp_raises_rowerror():
    import pytest
    with pytest.raises(RowError, match="`⟂`"):
        _resolution_record(
            "h-001  null → +    "
            "[inline alert context: matching key from multiple corp IPs]"
        )


_NO_PERP_RESOLUTION = """\
```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|endpoint|endpoint:linux|host|

:E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-001|attempted_auth|v-001|v-001|2026-05-07T00:00:00Z|siem-event:wazuh|rule=5710

:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|parent_attrs?|preds|attr_preds?|refuts?|authz?|integrity_waived?|weight|status]
h-001|?inline|v-001|attempted_auth|endpoint|monitor||p1:proposed_parent:"x"|||||null|active

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
    body, warnings = parse_dense_companion(_NO_PERP_RESOLUTION)
    leads = body["findings"]
    lead = next(l for l in leads if l["id"] == "l-001")
    # The good (⟂-bearing) resolution lands; the bad one is dropped.
    assert len(lead["resolutions"]) == 1
    assert lead["resolutions"][0]["after"] == "++"
    bad = next(w for w in warnings if w.block == ":T resolutions")
    assert "`⟂`" in bad.reason


# ---------------------------------------------------------------------------
# Corpus loader: per-file warnings thread through; partial loads are visible.
# ---------------------------------------------------------------------------


def test_load_report_separates_skipped_files_from_partial_loads(tmp_path):
    from defender.scripts.invlang.corpus import load_corpus

    # Case A: fully conformant.
    case_a = tmp_path / "case-a"
    case_a.mkdir()
    (case_a / "investigation.md").write_text(_CONFORMANT)
    (case_a / "alert.json").write_text('{"rule": {"id": "100001"}}')

    # Case B: one bad vertex row, rest conformant — should be a partial load.
    case_b = tmp_path / "case-b"
    case_b.mkdir()
    (case_b / "investigation.md").write_text(_PIPE_IN_ATTRS)
    (case_b / "alert.json").write_text('{"rule": {"id": "100001"}}')

    # Case C: file has no ```invlang fences — whole-file reject.
    case_c = tmp_path / "case-c"
    case_c.mkdir()
    (case_c / "investigation.md").write_text("# no fences here\n")
    (case_c / "alert.json").write_text('{"rule": {"id": "5710"}}')

    companions, report = load_corpus(tmp_path)
    assert report.scanned == 3
    assert report.loaded == 2
    # case-c is the only whole-file skip.
    assert [p.parent.name for p, _ in report.skipped] == ["case-c"]
    # case-b is the only partial load.
    partial_names = [p.parent.name for p, _ in report.partial]
    assert partial_names == ["case-b"]
    assert report.total_warnings == 1
    # Warning carries the file path so post-mortem debug knows where to look.
    _, warnings = report.partial[0]
    assert "case-b" in warnings[0].file_path
