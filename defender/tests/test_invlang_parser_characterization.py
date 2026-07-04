"""Characterization suite for the invlang dense-companion parser (issue #453).

This is a **behavior-preserving refactor guard**, not a fresh spec. The #453
refactor moves the schema-free cell tokenizer into a new `_cells.py`, lifts the
shared `Block`/`RowError` types into a new `_types.py`, and gives
`companion_from_blocks` a `_Projector` state object. None of that may change a
single observable output. So every test here is GREEN against HEAD and must
STAY green through the refactor — a red is a regression, never an "unimplemented"
signal.

It deliberately pins the four surfaces the refactor puts at risk, none of which
the existing `test_invlang_parser.py` covers end-to-end:

  A. Full-output identity on the two real `investigation.md` corpus files
     (existing tests assert individual fields; a whole-dict freeze catches drift
     in any field nobody thought to assert on).
  B. The import surface — every name today's production importers and the two
     invlang test modules pull from `parser`. The module split is exactly what
     threatens these; per the locked design the moved names stay importable
     from `parser` (re-exported).
  C. The schema-free lexer functions, called directly. Today only `_split_cells`
     has a direct unit test; the whole point of `_cells.py` is that these become
     independently testable, so their current behavior is pinned here.
  D. The ParseWarning block-label + reason strings at every reachable
     construction site. The refactor consolidates ~12 hand-built warnings behind
     one `_warn` helper; if the label spelling drifts at any site, a downstream
     consumer that greps `warning.block` breaks silently. (Site 1094,
     ":T resolutions" / "resolution has no lead attribution", is unreachable —
     `_resolution_record` always returns a non-empty lead id or raises first —
     so it is documented here but not pinned.)

Plus (E) the projection paths that neither corpus nor the existing suite hits.

The names imported below (the lexer helpers, `Block`) live in `parser` at HEAD.
Post-refactor they live in `_cells.py`/`_types.py` but remain importable from
`parser` per the locked re-export decision, so these imports stay valid without
edits. Expected values were all captured by executing the parser at HEAD.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from defender.skills.invlang import parser
from defender.skills.invlang.parser import (
    Block,
    ParseWarning,
    RowError,
    _parse_attrs,
    _parse_auth,
    _require,
    _row_cells,
    _row_dict,
    _split_cells,
    _split_csv,
    _split_csv_or_semi,
    _split_quoted,
    _split_subcells,
    _unquote,
    parse_dense_companion,
)

_HERE = Path(__file__).parent
_GOLDEN_DIR = _HERE / "_golden_invlang"
_CORPUS_DIR = _HERE.parent / "fixtures-e2e"


def _fence(body: str) -> str:
    return "```invlang\n" + body + "\n```\n"


# Reusable minimal `:H` header so sub-block fixtures have a parent to attach to.
_HYP_HEADER = (
    ":H hypothesize.hypotheses "
    "[id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]\n"
    "h-001|?a|v-001|rel|identity|op||null|active"
)


# ---------------------------------------------------------------------------
# A. Full-output identity on the real corpus (the strongest drift guard)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("case", ["golden-v2sshd", "golden-sshpivot-ab3"])
def test_real_corpus_companion_is_byte_identical(case):
    """Parsing a real, warning-free `investigation.md` must yield exactly the
    companion dict frozen from HEAD. Any refactor that perturbs a field —
    even one no targeted test asserts on — trips this."""
    src = (_CORPUS_DIR / case / "investigation.md").read_text()
    expected = json.loads((_GOLDEN_DIR / f"{case}.companion.json").read_text())
    body, warnings = parse_dense_companion(src)
    assert warnings == []
    assert body == expected


# ---------------------------------------------------------------------------
# B. Import-surface contract — the names the refactor must keep re-exported
# ---------------------------------------------------------------------------


# Exactly the names imported from `defender.skills.invlang.parser` today by
# production consumers (validate.py, corpus.py, lead_repository.py, compare.py,
# compaction.py) and by the two invlang test modules. This is the observable
# re-export contract the module split must preserve.
_PRODUCTION_SURFACE = ["parse_dense_companion", "ParseWarning", "INVLANG_FENCE_RE"]
_TEST_SURFACE = [
    "RowError",
    "_resolution_record",
    "_split_cells",
    "_VERTEX_COLS",
    "_EDGE_COLS",
    "_HYP_HEADER_COLS",
    "_HYP_PRED_COLS",
    "_HYP_ATTR_PRED_COLS",
    "_HYP_REFUT_COLS",
    "_HYP_AUTHZ_COLS",
]


@pytest.mark.parametrize("name", _PRODUCTION_SURFACE + _TEST_SURFACE)
def test_parser_reexports_name(name):
    """Every name external importers pull stays importable from `parser`."""
    assert hasattr(parser, name), f"{name} no longer importable from parser"


def test_reexported_symbols_keep_their_kind():
    """The re-exported names keep their observable kind (callable / regex /
    column-list), so `from parser import X` gives consumers the same thing."""
    assert callable(parser.parse_dense_companion)
    assert callable(parser._resolution_record)
    assert callable(parser._split_cells)
    assert issubclass(parser.RowError, ValueError)
    # INVLANG_FENCE_RE is a compiled pattern used with .finditer by validate.py.
    assert hasattr(parser.INVLANG_FENCE_RE, "finditer")
    # The grammar-pin test indexes these as ordered column lists / a set.
    assert parser._VERTEX_COLS == ["id", "type", "class", "ident", "attrs"]
    assert parser._EDGE_COLS[:2] == ["id", "rel"]
    assert isinstance(parser._HYP_HEADER_COLS, set)
    assert parser._HYP_PRED_COLS == ["id", "subject", "claim"]


# ---------------------------------------------------------------------------
# C. Schema-free lexer, called directly (the _cells.py extraction target)
# ---------------------------------------------------------------------------


def test_split_quoted_cell_form_keeps_empty_and_honors_quotes():
    # Cell form: unescape_delim + keep_empty. A `|` inside quotes is not a
    # delimiter; the trailing empty token is retained.
    assert _split_quoted('a|"b|c"|', "|", unescape_delim=True, keep_empty=True) == [
        "a",
        '"b|c"',
        "",
    ]


def test_split_quoted_subcell_form_drops_empty_and_honors_quotes():
    # Sub-cell form: no unescape, drop empties. `;` inside quotes is inert.
    assert _split_quoted('x;"y;z";', ";") == ["x", '"y;z"']


def test_split_quoted_backslash_depends_on_unescape_knob():
    # unescape_delim=False: `\|` passes through verbatim (two chars).
    assert _split_quoted(r"a\|b", "|") == [r"a\|b"]
    # unescape_delim=True: `\|` collapses to a literal `|` inside the token.
    assert _split_quoted(r"a\|b", "|", unescape_delim=True, keep_empty=True) == ["a|b"]


def test_split_cells_quoted_pipe_and_backslash():
    row = 'v-002|process|process:bash|bash[pid=42]|flags="EXE_WRITABLE|EXE_LOWER_LAYER"'
    cells = _split_cells(row)
    assert len(cells) == 5
    assert cells[4] == 'flags="EXE_WRITABLE|EXE_LOWER_LAYER"'
    assert _split_cells(r"a|b\|c|d") == ["a", "b|c", "d"]


def test_split_subcells_honors_quoted_semicolon():
    assert _split_subcells('k1=v1;k2="a;b"') == ["k1=v1", 'k2="a;b"']


def test_parse_attrs_splits_and_unquotes_dropping_keyless():
    assert _parse_attrs('k1=v1;k2="a;b";bad') == {"k1": "v1", "k2": "a;b"}
    assert _parse_attrs("") == {}


def test_unquote_strips_wrapping_quotes_and_unescapes():
    assert _unquote('"x\\"y"') == 'x"y'
    assert _unquote("plain") == "plain"


def test_parse_auth_splits_kind_source_on_first_colon():
    assert _parse_auth("siem-event:wazuh") == {"kind": "siem-event", "source": "wazuh"}
    assert _parse_auth("bare") == {"kind": "bare", "source": ""}


def test_split_csv_trims_and_drops_empties():
    assert _split_csv("a, b ,,c") == ["a", "b", "c"]


def test_split_csv_or_semi_prefers_semicolon_when_present():
    assert _split_csv_or_semi("a;b;") == ["a", "b"]
    assert _split_csv_or_semi("a,b") == ["a", "b"]
    assert _split_csv_or_semi("") == []


def test_row_cells_pads_short_and_raises_on_overflow():
    blk = Block(tag="V", name="prologue.vertices", columns=["id", "type", "class", "ident", "attrs"])
    assert _row_cells(blk, "v-1|process", 5) == ["v-1", "process", "", "", ""]
    with pytest.raises(RowError, match="6 cells but 5 expected"):
        _row_cells(blk, "a|b|c|d|e|f", 5)


def test_row_dict_zips_columns_preferring_block_header():
    blk = Block(tag="V", name="prologue.vertices", columns=["id", "type", "class", "ident", "attrs"])
    assert _row_dict(blk, "v-1|process|c|i|k=v") == {
        "id": "v-1",
        "type": "process",
        "class": "c",
        "ident": "i",
        "attrs": "k=v",
    }
    # Headerless block falls back to default_cols.
    headerless = Block(tag="H", name="h-1.parent_attrs", columns=None)
    assert _row_dict(headerless, "k|v", ["key", "value"]) == {"key": "k", "value": "v"}


def test_require_raises_its_message_on_missing_or_falsy_key():
    with pytest.raises(RowError, match="need id"):
        _require({"id": "", "name": "x"}, "id", msg="need id")
    # Present-and-truthy passes silently.
    _require({"id": "x"}, "id", msg="need id")


# ---------------------------------------------------------------------------
# D. ParseWarning block-label + reason at every reachable construction site
# ---------------------------------------------------------------------------


# (label, invlang-body, expected block, reason substring, expected row_index)
_WARNING_SITES = [
    (
        "unknown-block",
        ":Z mystery\nfoo bar",
        ":Z mystery",
        "unknown block — no projection rule",
        -1,
    ),
    (
        "project-rows-overflow",
        ":V prologue.vertices [id|type|class|ident|attrs?]\nv-1|process|c|i|k=v|EXTRA",
        ":V prologue.vertices",
        "row has 6 cells but 5 expected",
        0,
    ),
    (
        "for-each-row-overflow",
        ":L findings [id|loop|name|target|tests|system|template|query|window]\n"
        "l-001|1|n|v-001|h-001|s|t|q|w|EXTRA",
        ":L findings",
        "row has 10 cells but 9 expected",
        0,
    ),
    (
        "findings-missing-id",
        ":L findings [id|loop|name|target|tests|system|template|query|window]\n"
        "|1|n|v-001|h-001|s|t|q|w",
        ":L findings",
        "findings row missing id/name",
        0,
    ),
    (
        "legacy-h-header",
        ":H hypothesize.hypotheses [a|b|c]\nx|y|z",
        ":H hypothesize.hypotheses",
        "does not match the current schema",
        -1,
    ),
    (
        "unknown-hyp-subblock",
        ':H h-999.preds [id|subject|claim]\np1|x|"y"',
        ":H h-999.preds",
        "sub-block references unknown hypothesis 'h-999'",
        -1,
    ),
    (
        "parent-attrs-missing-key",
        _HYP_HEADER + "\n:H h-001.parent_attrs [key|value]\n|orphanvalue",
        ":H h-001.parent_attrs",
        "parent_attrs row missing key",
        0,
    ),
    (
        "resolution-missing-perp",
        ":T resolutions\nh-001 null → -- [l-001 p1 severe :: p1]",
        ":T resolutions",
        "resolution missing `⟂` supporting-edges separator",
        0,
    ),
    (
        "close-missing-loop",
        ":T close\nloop abc",
        ":T close",
        "needs a `loop N`",
        -1,
    ),
    (
        "r-block-no-attribution",
        ":R authz [edge|fulfills|verdict|anchor_kind]\ne-001|ac1|authorized|iam",
        ":R authz",
        "row has no lead attribution",
        0,
    ),
    (
        "attr-updates-missing-target",
        ":R attr_updates [resolved_by|target|key|value]\nl-001||somekey|someval",
        ":R attr_updates",
        "attr_updates missing target/key",
        0,
    ),
]


@pytest.mark.parametrize(
    ("label", "body", "exp_block", "exp_reason", "exp_row_index"),
    _WARNING_SITES,
    ids=[c[0] for c in _WARNING_SITES],
)
def test_warning_site_block_label_and_reason(label, body, exp_block, exp_reason, exp_row_index):
    """Each reachable ParseWarning site keeps its exact block label + reason.
    These strings are the contract the `_warn` consolidation must reproduce."""
    _, warnings = parse_dense_companion(_fence(body))
    assert len(warnings) == 1, f"{label}: expected exactly one warning, got {warnings}"
    w = warnings[0]
    assert isinstance(w, ParseWarning)
    assert w.block == exp_block
    assert w.row_index == exp_row_index
    assert exp_reason in w.reason


# ---------------------------------------------------------------------------
# E. Projection paths neither the real corpus nor test_invlang_parser.py hits
# ---------------------------------------------------------------------------


def test_r_consultations_bucket_projects_canonically():
    body, warnings = parse_dense_companion(
        _fence(":R consultations [resolved_by|anchor_kind|verdict]\nl-001|cmdb|consulted")
    )
    assert warnings == []
    lead = next(f for f in body["findings"] if f["id"] == "l-001")
    assert lead["outcome"]["anchor_consultations"] == [
        {"resolved_by_lead": "l-001", "anchor_kind": "cmdb", "verdict": "consulted"}
    ]


def test_r_impact_bucket_maps_dim_to_dimension():
    body, warnings = parse_dense_companion(
        _fence(":R impact [resolved_by|dim|verdict]\nl-001|confidentiality|high")
    )
    assert warnings == []
    lead = next(f for f in body["findings"] if f["id"] == "l-001")
    assert lead["outcome"]["impact_resolutions"] == [
        {"resolved_by_lead": "l-001", "dimension": "confidentiality", "verdict": "high"}
    ]


def test_attr_updates_merge_into_one_target_entry():
    body, warnings = parse_dense_companion(
        _fence(
            ":R attr_updates [resolved_by|target|key|value]\n"
            "l-001|v-001|a|1\n"
            "l-001|v-001|b|2"
        )
    )
    assert warnings == []
    lead = next(f for f in body["findings"] if f["id"] == "l-001")
    assert lead["outcome"]["attribute_updates"] == [
        {"target": "v-001", "updates": {"a": "1", "b": "2"}}
    ]


def test_t_shelved_records_hyp_and_rationale_on_lead():
    body, warnings = parse_dense_companion(
        _fence(':T shelved [hyp_id|by_lead|rationale]\nh-002|l-001|"weak signal"')
    )
    assert warnings == []
    lead = next(f for f in body["findings"] if f["id"] == "l-001")
    assert lead["shelved"] == ["h-002"]
    assert lead["shelved_rationales"] == {"h-002": "weak signal"}


def test_lead_scoped_new_hypotheses_project_onto_the_lead():
    body, warnings = parse_dense_companion(
        _fence(
            ":H l-001.new_hypotheses "
            "[id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]\n"
            "h-010|?new|v-001|rel|identity|op||null|active"
        )
    )
    assert warnings == []
    lead = next(f for f in body["findings"] if f["id"] == "l-001")
    assert [h["id"] for h in lead["new_hypotheses"]] == ["h-010"]
    assert lead["new_hypotheses"][0]["anchor"] == "v-001"


def test_lead_scoped_observation_vertices_land_under_outcome():
    body, warnings = parse_dense_companion(
        _fence(
            ":V l-001.observations.vertices [id|type|class|ident|attrs?]\n"
            "v-005|process|process:bash|sh|"
        )
    )
    assert warnings == []
    lead = next(f for f in body["findings"] if f["id"] == "l-001")
    verts = lead["outcome"]["observations"]["vertices"]
    assert [v["id"] for v in verts] == ["v-005"]
    assert verts[0]["classification"] == "process:bash"


def test_hyp_attr_preds_subblock_attaches_attribute_predictions():
    body, warnings = parse_dense_companion(
        _fence(_HYP_HEADER + '\n:H h-001.attr_preds [id|target|attribute|claim]\nap1|v-001|signing|"unsigned"')
    )
    assert warnings == []
    h = body["hypothesize"]["hypotheses"][0]
    assert h["attribute_predictions"] == [
        {"id": "ap1", "target": "v-001", "attribute": "signing", "claim": "unsigned"}
    ]


def test_t_close_valid_loop_records_closed_loop_number():
    body, warnings = parse_dense_companion(_fence(":T close\nloop 3"))
    assert warnings == []
    assert body["closed_loops"] == [3]
