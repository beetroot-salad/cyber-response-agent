"""Defender invlang parser tests.

Covers the three drift patterns that broke the soc-agent strict parser
against defender-emitted investigation.md:

1. Unescaped `|` inside `attrs` (Falco flags).
2. Extra empty cells on `:H` hypothesize rows.
3. `:T resolutions` rows without a `⟂` separator.
"""

from __future__ import annotations

from defender.scripts.invlang.parser import (
    parse_dense_companion,
    _normalize_hypothesis_cells,
    _collapse_extra_cells_into_attrs,
    _parse_resolution_line,
)


# ---------------------------------------------------------------------------
# Cell-level normalization
# ---------------------------------------------------------------------------


def test_collapse_extras_into_attrs_joins_with_pipe():
    cells = ["v-002", "process", "process:bash", "bash[pid=?]",
             "cmdline=bash", "user=root", "flags=EXE_WRITABLE", "EXE_LOWER_LAYER"]
    out = _collapse_extra_cells_into_attrs(cells, 5)
    assert len(out) == 5
    # The final attrs cell rejoins the over-cells with `|` separators,
    # restoring the literal flags=A|B form.
    assert out[4] == "cmdline=bash|user=root|flags=EXE_WRITABLE|EXE_LOWER_LAYER"


def test_collapse_extras_pads_short_row():
    out = _collapse_extra_cells_into_attrs(["v-001", "container"], 5)
    assert out == ["v-001", "container", "", "", ""]


def test_normalize_hypothesis_drops_extra_empty_cells():
    cells = [
        "h-001", "?name", "v-002", "rel", "endpoint", "monitoring-server",
        "",   # parent_attrs
        "p1:proposed_parent:\"...\"",
        "",   # attr_preds
        "r1[p1,p2]:\"...\"",
        "",   # EXTRA empty (defender pattern)
        "ac1:proposed:cmdb:\"...\":esc/esc",
        "",   # integrity_waived
        "null",
        "active",
    ]
    out = _normalize_hypothesis_cells(cells, 14)
    assert len(out) == 14
    # Cell at position 9 (refuts) must still hold the refuts content, not
    # have been shifted into attr_preds.
    assert out[9].startswith("r1[")
    assert out[10].startswith("ac1:")


# ---------------------------------------------------------------------------
# End-to-end parse over each defender-drift sample
# ---------------------------------------------------------------------------


_VERTEX_WITH_PIPE_IN_ATTRS = """\
```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|container|endpoint:linux|target-endpoint|id=2a124a5fc6d9
v-002|process|process:bash|bash[pid=?]|cmdline=bash -c whoami;user=root;flags=EXE_WRITABLE|EXE_LOWER_LAYER

:E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-001|execve|v-002|v-001|2026-05-07T14:25:22.570Z|siem-event:wazuh-falco|rule=100001;tags=T1059,mitre

:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|parent_attrs?|preds|attr_preds?|refuts?|authz?|integrity_waived?|weight|status]
h-001|?auth-exec|v-002|execve|identity|operator-or-automation||p1:proposed_parent:"workload is documented"||r1[p1]:"no auth path"|ac1:proposed:cmdb:"authorized":esc/esc||null|active

:L findings [id|loop|name|target|tests|system|template|query|window]
l-001|1|cmdb-lookup|v-001|h-001|stub-cmdb|host-lookup|hostname=foo|n/a

:T resolutions
h-001  null → --   [l-001 r1 severe ⟂ e-001 :: r1 ⟺ ¬p1; observed pivot signal]

:T conclude
disposition            malicious
matched_archetype      compromised-container
summary                "exec via host pivot"

:T conclude.surviving [hyp_id|final_weight]
h-001|--
```
"""


def test_parse_vertex_with_pipe_inside_attrs():
    body = parse_dense_companion(_VERTEX_WITH_PIPE_IN_ATTRS)
    verts = body["prologue"]["vertices"]
    assert len(verts) == 2
    v = next(v for v in verts if v["id"] == "v-002")
    # The unescaped `|` in flags=EXE_WRITABLE|EXE_LOWER_LAYER must round-trip
    # as part of the flags value, not corrupt the column count.
    assert v["attributes"]["flags"] == "EXE_WRITABLE|EXE_LOWER_LAYER"
    assert v["attributes"]["user"] == "root"


def test_parse_hypothesis_extracts_refuts_and_authz():
    body = parse_dense_companion(_VERTEX_WITH_PIPE_IN_ATTRS)
    hyps = body["hypothesize"]["hypotheses"]
    assert len(hyps) == 1
    h = hyps[0]
    assert h["name"] == "?auth-exec"
    assert h["predictions"][0]["id"] == "p1"
    assert h["refutation_shape"][0]["id"] == "r1"
    assert h["refutation_shape"][0]["refutes_predictions"] == ["p1"]
    assert h["authorization_contract"][0]["anchor_kind"] == "cmdb"


_EXTRA_CELL_HYPOTHESIS = """\
```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|endpoint|endpoint:linux|target

:E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-001|attempted_auth|v-001|v-001|2026-05-07T00:00:00Z|siem-event:wazuh|rule=5710

:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|parent_attrs?|preds|attr_preds?|refuts?|authz?|integrity_waived?|weight|status]
h-001|?monitoring-misconfig|v-001|attempted_auth|endpoint|monitoring-server||p1:proposed_parent:"src is documented monitor"||r1[p1]:"src has no monitor role"||ac1:proposed:cmdb:"authorized":esc/esc||null|active

:L findings [id|loop|name|target|tests|system|template|query|window]
l-001|1|cmdb|v-001|h-001|stub-cmdb|host-lookup|host=foo|n/a

:T resolutions
h-001  null → ++   [l-001 p1 strong ⟂ e-001 :: p1 ⟺ src=monitor]

:T conclude
disposition            benign
matched_archetype      monitoring-probe
summary                "monitor"

:T conclude.surviving [hyp_id|final_weight]
h-001|++
```
"""


def test_parse_hypothesis_with_extra_empty_cell():
    """The defender pattern: an extra `||` between refuts and authz produces
    15 cells where the spec declares 14. Tolerant normalization collapses
    the extra empty so refuts content stays in the refuts column.
    """
    body = parse_dense_companion(_EXTRA_CELL_HYPOTHESIS)
    hyps = body["hypothesize"]["hypotheses"]
    h = hyps[0]
    assert h["refutation_shape"][0]["claim"].startswith("src has no monitor role")
    assert h["authorization_contract"][0]["anchor_kind"] == "cmdb"


_NO_PERP_RESOLUTION = """\
```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|endpoint|endpoint:linux|target

:E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-001|attempted_auth|v-001|v-001|2026-05-07T00:00:00Z|siem-event:wazuh|rule=5710

:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|parent_attrs?|preds|attr_preds?|refuts?|authz?|integrity_waived?|weight|status]
h-001|?inline-anchor|v-001|attempted_auth|endpoint|monitor||p1:proposed_parent:"src=monitor"||||||null|active

:L findings [id|loop|name|target|tests|system|template|query|window]
l-001|1|inline|v-001|h-001|wazuh|alerts|n/a|n/a

:T resolutions
h-001  null → +    [inline alert context: matching key from multiple corp IPs, corp-internal geoloc, INC-8821 16min prior — consistent but non-exclusive; agent-forwarding produces identical surface]

:T conclude
disposition            inconclusive
matched_archetype      uncertain
summary                "inline-only context"

:T conclude.surviving [hyp_id|final_weight]
h-001|+
```
"""


def test_parse_resolution_without_perp_keeps_annotation():
    body = parse_dense_companion(_NO_PERP_RESOLUTION)
    leads = body["findings"]
    assert leads, "expected at least one lead bucket"
    lead = next(l for l in leads if l["id"] == "l-001")
    resolutions = lead.get("resolutions", [])
    assert len(resolutions) == 1
    r = resolutions[0]
    assert r["hypothesis"] == "h-001"
    assert r["before"] == "null"
    assert r["after"] == "+"
    assert r["supporting_edges"] == []
    # The bracket body lands as reasoning so query code can still surface it.
    assert "inline alert context" in r["reasoning"]


def test_parse_resolution_line_returns_none_on_garbage():
    assert _parse_resolution_line("not a resolution line at all") is None


# ---------------------------------------------------------------------------
# Corpus-level smoke test (runs against /tmp/defender-runs if available)
# ---------------------------------------------------------------------------


def test_corpus_loads_all_defender_runs(tmp_path):
    """Synthetic corpus of two minimal investigations — sanity-check the
    full load+report pipeline. /tmp/defender-runs is exercised by the
    dev workflow but not assumed present here.
    """
    from defender.scripts.invlang.corpus import load_corpus

    case_a = tmp_path / "case-a"
    case_a.mkdir()
    (case_a / "investigation.md").write_text(_VERTEX_WITH_PIPE_IN_ATTRS)
    (case_a / "alert.json").write_text('{"rule": {"id": "100001"}}')

    case_b = tmp_path / "case-b"
    case_b.mkdir()
    (case_b / "investigation.md").write_text(_EXTRA_CELL_HYPOTHESIS)
    (case_b / "alert.json").write_text('{"rule": {"id": "5710"}}')

    companions, report = load_corpus(tmp_path)
    assert report.scanned == 2
    assert report.loaded == 2
    assert report.skipped == []
    by_id = {c.case_id: c for c in companions}
    assert by_id["case-a"].signature_id == "wazuh-rule-100001"
    assert by_id["case-b"].signature_id == "wazuh-rule-5710"
    assert by_id["case-a"].conclude.get("disposition") == "malicious"
    assert by_id["case-b"].conclude.get("matched_archetype") == "monitoring-probe"
