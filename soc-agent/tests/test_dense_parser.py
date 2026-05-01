"""Unit tests for the unified dense-block tokenizer/projector.

The parser lives at `scripts/handlers/_dense_parser.py` and produces the
canonical companion dict shape (matches `schema.md`). Validator rules and
`invlang_walkers.py` consume the dict; their behavior is unaffected by
the YAML→dense migration.

Tests cover:
- Tokenizer: fence detection, header parsing, row splitting, escape, errors.
- Schema-mapping projection: every block tag emits the expected dict shape.
- Round-trip: a small worked-example investigation in dense form produces
  the expected dict.
"""

from __future__ import annotations

import textwrap

import pytest

from scripts.handlers._dense_parser import (
    DenseBlock,
    DenseParseError,
    INVLANG_BLOCK_RE,
    companion_dict_from_blocks,
    parse_dense_blocks_in_text,
    parse_dense_companion,
)


# ---------------------------------------------------------------------------
# Fence detection + tokenization
# ---------------------------------------------------------------------------


def test_invlang_block_re_matches_basic_fence():
    text = "before\n```invlang\n:V prologue.vertices [id|type|class|ident]\nv-001|endpoint|host|h1\n```\nafter"
    matches = list(INVLANG_BLOCK_RE.finditer(text))
    assert len(matches) == 1
    body = matches[0].group(1)
    assert body.startswith(":V prologue.vertices")
    assert "v-001|endpoint|host|h1" in body


def test_no_fence_returns_no_blocks():
    text = "## CONTEXTUALIZE\n\nSome prose, no fences.\n"
    assert parse_dense_blocks_in_text(text) == []


def test_single_block_in_fence():
    text = "```invlang\n:V prologue.vertices [id|type|class|ident]\nv-001|endpoint|host|h1\n```"
    blocks = parse_dense_blocks_in_text(text)
    assert len(blocks) == 1
    assert blocks[0].tag == "V"
    assert blocks[0].name == "prologue.vertices"
    assert blocks[0].columns == ["id", "type", "class", "ident"]
    assert blocks[0].rows == ["v-001|endpoint|host|h1"]


def test_multiple_blocks_in_one_fence():
    text = textwrap.dedent("""\
        ```invlang
        :V prologue.vertices [id|type|class|ident]
        v-001|endpoint|host|h1

        :E prologue.edges [id|rel|src|tgt|when|auth_kind:source]
        e-001|attempted_auth|v-001|v-002|2026-04-20T09:00:00Z|siem-event:wazuh
        ```
    """)
    blocks = parse_dense_blocks_in_text(text)
    assert len(blocks) == 2
    assert (blocks[0].tag, blocks[0].name) == ("V", "prologue.vertices")
    assert (blocks[1].tag, blocks[1].name) == ("E", "prologue.edges")


def test_blocks_across_multiple_fences():
    text = textwrap.dedent("""\
        ## CONTEXTUALIZE

        ```invlang
        :V prologue.vertices [id|type|class|ident]
        v-001|endpoint|host|h1
        ```

        Some narrative prose here.

        ```invlang
        :E prologue.edges [id|rel|src|tgt|when|auth_kind:source]
        e-001|attempted_auth|v-001|v-002|2026-04-20T09:00:00Z|siem-event:wazuh
        ```
    """)
    blocks = parse_dense_blocks_in_text(text)
    assert len(blocks) == 2
    assert blocks[0].fence_index == 0
    assert blocks[1].fence_index == 1


def test_optional_question_mark_stripped_from_columns():
    text = "```invlang\n:V prologue.vertices [id|type|class|ident|attrs?|placeholder?]\nv-001|endpoint|host|h1||\n```"
    blocks = parse_dense_blocks_in_text(text)
    assert blocks[0].columns == ["id", "type", "class", "ident", "attrs", "placeholder"]


def test_unknown_tag_raises():
    text = "```invlang\n:Z foo [a|b]\nx|y\n```"
    with pytest.raises(DenseParseError, match="unknown dense block tag"):
        parse_dense_blocks_in_text(text)


def test_malformed_header_raises():
    text = "```invlang\n:V[no-space]name\nrow\n```"
    with pytest.raises(DenseParseError, match="malformed dense block header"):
        parse_dense_blocks_in_text(text)


def test_row_before_header_raises():
    text = "```invlang\nrow-with-no-block-header\n```"
    with pytest.raises(DenseParseError, match="row appears before any block header"):
        parse_dense_blocks_in_text(text)


# ---------------------------------------------------------------------------
# Projection: prologue (vertices + edges)
# ---------------------------------------------------------------------------


def test_project_prologue_vertices():
    text = textwrap.dedent("""\
        ```invlang
        :V prologue.vertices [id|type|class|ident|attrs?]
        v-001|endpoint|monitoring-host|172.22.0.10|
        v-002|endpoint|internal-server|target-endpoint|kind=server
        ```
    """)
    out = parse_dense_companion(text)
    assert out["prologue"]["vertices"] == [
        {"id": "v-001", "type": "endpoint",
         "classification": "monitoring-host", "identifier": "172.22.0.10"},
        {"id": "v-002", "type": "endpoint",
         "classification": "internal-server", "identifier": "target-endpoint",
         "attributes": {"kind": "server"}},
    ]


def test_project_prologue_edges():
    text = textwrap.dedent("""\
        ```invlang
        :E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
        e-001|attempted_auth|v-001|v-002|2026-04-20T09:00:00Z|siem-event:wazuh-rule-5710|target_user=sensu;outcome=failed
        ```
    """)
    out = parse_dense_companion(text)
    assert out["prologue"]["edges"] == [{
        "id": "e-001",
        "relation": "attempted_auth",
        "source_vertex": "v-001",
        "target_vertex": "v-002",
        "when": {"timestamp": "2026-04-20T09:00:00Z"},
        "authority": {"kind": "siem-event", "source": "wazuh-rule-5710"},
        "attributes": {"target_user": "sensu", "outcome": "failed"},
    }]


def test_vertex_missing_required_cell_raises():
    text = "```invlang\n:V prologue.vertices [id|type|class|ident]\nv-001|endpoint||\n```"
    with pytest.raises(DenseParseError, match="missing required cell"):
        parse_dense_companion(text)


def test_edge_missing_auth_raises():
    text = textwrap.dedent("""\
        ```invlang
        :E prologue.edges [id|rel|src|tgt|when|auth_kind:source]
        e-001|attempted_auth|v-001|v-002|2026-04-20T09:00:00Z|
        ```
    """)
    with pytest.raises(DenseParseError, match="auth_kind:source"):
        parse_dense_companion(text)


def test_attrs_bare_token_without_equals_raises():
    text = "```invlang\n:V prologue.vertices [id|type|class|ident|attrs?]\nv-001|endpoint|host|h1|barekey\n```"
    with pytest.raises(DenseParseError, match="bare token without"):
        parse_dense_companion(text)


# ---------------------------------------------------------------------------
# Projection: hypotheses with packed sub-cells
# ---------------------------------------------------------------------------


def test_project_hypothesis_with_predictions_and_refutations():
    text = textwrap.dedent("""\
        ```invlang
        :H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|preds|refuts|authz?|weight|status]
        h-001|?monitoring-probe|v-001|initiated_by|identity|approved-monitoring-service-account|p1:proposed_parent:"triple in approved-monitoring-sources"|r1[p1]:"triple absent"||null|active
        ```
    """)
    out = parse_dense_companion(text)
    assert out["hypothesize"]["hypotheses"] == [{
        "id": "h-001",
        "name": "?monitoring-probe",
        "attached_to_vertex": "v-001",
        "proposed_edge": {
            "relation": "initiated_by",
            "parent_type": "identity",
            "parent_class": "approved-monitoring-service-account",
        },
        "predictions": [{
            "id": "p1",
            "subject": "proposed_parent",
            "claim": "triple in approved-monitoring-sources",
        }],
        "refutation_shape": [{
            "id": "r1",
            "claim": "triple absent",
            "refutes": ["p1"],
        }],
        "weight": None,
        "status": "active",
    }]


def test_project_hypothesis_with_authz_contract():
    text = textwrap.dedent("""\
        ```invlang
        :H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|preds|refuts|authz?|weight|status]
        h-001|?probe|v-001|initiated_by|identity|sa|p1:proposed_parent:"triple listed"|r1[p1]:"absent"|ac1:proposed:approved-monitoring-sources:"triple listed as active":esc/esc|null|active
        ```
    """)
    out = parse_dense_companion(text)
    assert out["hypothesize"]["hypotheses"][0]["authorization_contract"] == [{
        "id": "ac1",
        "edge_ref": "proposed",
        "anchor_kind": "approved-monitoring-sources",
        "predicate": "triple listed as active",
        "on_unauthorized": "esc",
        "on_indeterminate": "esc",
    }]


def test_malformed_pred_subcell_raises():
    text = textwrap.dedent("""\
        ```invlang
        :H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|preds|weight|status]
        h-001|?x|v-001|initiated_by|identity|sa|p1-no-colon|null|active
        ```
    """)
    with pytest.raises(DenseParseError, match="prediction sub-cell malformed"):
        parse_dense_companion(text)


# ---------------------------------------------------------------------------
# Projection: lead findings (header + lead-scoped sub-blocks)
# ---------------------------------------------------------------------------


def test_project_lead_header():
    text = textwrap.dedent("""\
        ```invlang
        :L findings [id|loop|name|target|tests|system|template|query|window]
        l-001|1|approved-monitoring-sources-lookup|v-001|h-001,h-002|approved-monitoring-sources|triple-lookup|src=172.22.0.10 user=sensu dst=target-endpoint|
        ```
    """)
    out = parse_dense_companion(text)
    assert len(out["findings"]) == 1
    lead = out["findings"][0]["lead"]
    assert lead["id"] == "l-001"
    assert lead["loop"] == 1
    assert lead["name"] == "approved-monitoring-sources-lookup"
    assert lead["target_vertex"] == "v-001"
    assert lead["tests_hypotheses"] == ["h-001", "h-002"]
    assert lead["system"] == "approved-monitoring-sources"
    assert lead["query"] == "src=172.22.0.10 user=sensu dst=target-endpoint"


def test_project_lead_observations():
    text = textwrap.dedent("""\
        ```invlang
        :L findings [id|loop|name|target|tests]
        l-001|1|lookup|v-001|h-001
        ```

        ```invlang
        :V l-001.observations.vertices [id|type|class|ident|attrs?]
        v-003|identity|service-account|sensu-svc|kind=service-account
        ```

        ```invlang
        :E l-001.observations.edges [id|rel|src|tgt|when|auth_kind:source]
        e-010|initiated_by|v-003|v-001||authoritative-source:approved-monitoring-sources
        ```
    """)
    out = parse_dense_companion(text)
    finding = out["findings"][0]
    assert finding["outcome"]["observations"]["vertices"][0]["id"] == "v-003"
    assert finding["outcome"]["observations"]["edges"][0]["id"] == "e-010"
    assert finding["outcome"]["observations"]["edges"][0]["authority"] == {
        "kind": "authoritative-source", "source": "approved-monitoring-sources"
    }


def test_project_substitutions():
    text = textwrap.dedent("""\
        ```invlang
        :L findings [id|loop|name|target|tests]
        l-001|1|lookup|v-001|h-001
        ```

        ```invlang
        :L l-001.substitutions [key|value]
        src|172.22.0.10
        user|sensu
        ```
    """)
    out = parse_dense_companion(text)
    subs = out["findings"][0]["lead"]["query_details"]["substitutions"]
    assert subs == {"src": "172.22.0.10", "user": "sensu"}


# ---------------------------------------------------------------------------
# Projection: resolutions (:R authz + :T resolutions)
# ---------------------------------------------------------------------------


def test_project_authz_resolution():
    text = textwrap.dedent("""\
        ```invlang
        :L findings [id|loop|name|target|tests]
        l-001|1|lookup|v-001|h-001
        ```

        ```invlang
        :R authz [edge|verdict|anchor_kind|anchor_id|grounding|authority|as_of|fulfills|resolved_by]
        e-010|authorized|approved-monitoring-sources|ams-registry-2026-01|org-authority|full|2026-04-23T14:00Z|h-001.ac1|l-001
        ```
    """)
    out = parse_dense_companion(text)
    finding = out["findings"][0]
    # Canonical YAML field names: dense `grounding` → `grounding_kind`,
    # `authority` → `authority_for_question`, `fulfills` → `fulfills_contract`,
    # `resolved_by` → `resolved_by_lead`. The validator's required-field
    # constants in invlang_common.py use these long names.
    assert finding["outcome"]["authorization_resolutions"] == [{
        "edge": "e-010",
        "verdict": "authorized",
        "anchor_kind": "approved-monitoring-sources",
        "anchor_id": "ams-registry-2026-01",
        "grounding_kind": "org-authority",
        "authority_for_question": "full",
        "as_of": "2026-04-23T14:00Z",
        "fulfills_contract": "h-001.ac1",
        "resolved_by_lead": "l-001",
    }]


def test_project_resolution_trace_line():
    text = textwrap.dedent("""\
        ```invlang
        :L findings [id|loop|name|target|tests]
        l-001|1|lookup|v-001|h-001
        ```

        ```invlang
        :T resolutions
        h-001  ∅ → +    [l-001 p1 moderate ⟂ e-010 :: authz authorized; identity-of-use open]
        ```
    """)
    out = parse_dense_companion(text)
    res = out["findings"][0]["resolutions"][0]
    assert res["hypothesis_id"] == "h-001"
    assert res["before"] == "∅"
    assert res["after"] == "+"
    assert res["severity_of_test"] == "moderate"
    assert res["matched_prediction_ids"] == ["p1"]
    assert res["supporting_edges"] == ["e-010"]
    assert "authz authorized" in res["reasoning"]


def test_resolution_line_missing_supp_separator_raises():
    text = textwrap.dedent("""\
        ```invlang
        :L findings [id|loop|name|target|tests]
        l-001|1|lookup|v-001|h-001
        ```

        ```invlang
        :T resolutions
        h-001  ∅ → +    [l-001 p1 moderate :: missing-perp-symbol]
        ```
    """)
    with pytest.raises(DenseParseError, match="supp-edges separator"):
        parse_dense_companion(text)


# ---------------------------------------------------------------------------
# Projection: conclude (scalars + sub-tables)
# ---------------------------------------------------------------------------


def test_project_conclude_scalars():
    text = textwrap.dedent("""\
        ```invlang
        :T conclude
        termination.category   exhaustion-escalation
        termination.rationale  "host-query unavail; h-002 cannot reach --"
        disposition            benign
        impact_verdict         within
        impact_severity        null
        confidence             medium
        matched_archetype      monitoring-probe
        ceiling_rationale      n/a
        summary                "SSH login confirmed sanctioned."
        ```
    """)
    out = parse_dense_companion(text)
    assert out["conclude"] == {
        "termination": {
            "category": "exhaustion-escalation",
            "rationale": "host-query unavail; h-002 cannot reach --",
        },
        "disposition": "benign",
        "impact_verdict": "within",
        "impact_severity": None,
        "confidence": "medium",
        "matched_archetype": "monitoring-probe",
        "ceiling_rationale": "n/a",
        "summary": "SSH login confirmed sanctioned.",
    }


def test_project_conclude_with_subtables():
    text = textwrap.dedent("""\
        ```invlang
        :T conclude
        termination.category   exhaustion-escalation
        termination.rationale  "blocked"
        disposition            benign
        confidence             medium
        ```

        ```invlang
        :T conclude.surviving [hyp_id|final_weight]
        h-001|+
        h-002|-
        ```

        ```invlang
        :T conclude.deferred_authz [contract_ref|rationale]
        none
        ```

        ```invlang
        :T conclude.ceiling_test [kind|subject]
        none
        ```
    """)
    out = parse_dense_companion(text)
    assert out["conclude"]["surviving_hypotheses"] == ["h-001", "h-002"]
    assert out["conclude"]["deferred_authorizations"] == []
    assert "ceiling_test" not in out["conclude"]


def test_unknown_conclude_subtable_raises():
    text = textwrap.dedent("""\
        ```invlang
        :T conclude
        disposition  benign

        :T conclude.bogus [a|b]
        x|y
        ```
    """)
    with pytest.raises(DenseParseError, match="unknown sub-table"):
        parse_dense_companion(text)


# ---------------------------------------------------------------------------
# Round-trip: the spec's stress-1 worked example
# ---------------------------------------------------------------------------


def test_round_trip_stress_1_minimal():
    """A minimal end-to-end traversal: all six block kinds in one investigation
    parse to a coherent companion dict.
    """
    text = textwrap.dedent("""\
        ## CONTEXTUALIZE

        ```invlang
        :V prologue.vertices [id|type|class|ident|attrs?]
        v-001|endpoint|monitoring-host|172.22.0.10|
        v-002|endpoint|internal-server|target-endpoint|
        ```

        ```invlang
        :E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
        e-001|attempted_auth|v-001|v-002|2026-04-20T09:00:00Z|siem-event:wazuh-rule-5710|target_user=sensu;outcome=failed
        ```

        ## PREDICT (loop 1)

        ```invlang
        :H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|preds|refuts|authz?|weight|status]
        h-001|?monitoring-probe|v-001|initiated_by|identity|approved-monitoring-service-account|p1:proposed_parent:"triple in approved-monitoring-sources"|r1[p1]:"triple absent"|ac1:proposed:approved-monitoring-sources:"triple listed":esc/esc|null|active
        h-002|?adversary|v-001|initiated_by|process|non-monitoring-process-on-source|p1:proposed_parent:"no scheduler entry"|r1[p1]:"scheduler entry"||null|active
        ```

        ## GATHER (loop 1)

        ```invlang
        :L findings [id|loop|name|target|tests|system|template]
        l-001|1|approved-monitoring-sources-lookup|v-001|h-001,h-002|approved-monitoring-sources|triple-lookup
        ```

        ```invlang
        :V l-001.observations.vertices [id|type|class|ident|attrs?]
        v-003|identity|approved-monitoring-service-account|sensu-svc|kind=service-account
        ```

        ```invlang
        :E l-001.observations.edges [id|rel|src|tgt|when|auth_kind:source]
        e-010|initiated_by|v-003|v-001||authoritative-source:approved-monitoring-sources
        ```

        ```invlang
        :R authz [edge|verdict|anchor_kind|anchor_id|grounding|authority|as_of|fulfills|resolved_by]
        e-010|authorized|approved-monitoring-sources|ams-registry-2026-01|org-authority|full|2026-04-23T14:00Z|h-001.ac1|l-001
        ```

        ## ANALYZE (loop 1)

        ```invlang
        :T resolutions
        h-001  ∅ → +    [l-001 p1 moderate ⟂ e-010 :: authz authorized; identity-of-use open]
        h-002  ∅ → -    [l-001 weak ⟂ no-authority :: host-query unavail; h-002.p1 ungraded]
        ```

        ## REPORT

        ```invlang
        :T conclude
        termination.category   exhaustion-escalation
        termination.rationale  "host-query unavail"
        disposition            benign
        confidence             medium
        matched_archetype      monitoring-probe
        ```

        ```invlang
        :T conclude.surviving [hyp_id|final_weight]
        h-001|+
        h-002|-
        ```
    """)
    out = parse_dense_companion(text)

    # Prologue
    assert len(out["prologue"]["vertices"]) == 2
    assert len(out["prologue"]["edges"]) == 1

    # Hypotheses
    assert len(out["hypothesize"]["hypotheses"]) == 2
    assert out["hypothesize"]["hypotheses"][0]["id"] == "h-001"

    # Findings (one lead, with observations + authz)
    assert len(out["findings"]) == 1
    lead = out["findings"][0]
    assert lead["lead"]["name"] == "approved-monitoring-sources-lookup"
    assert lead["outcome"]["observations"]["vertices"][0]["id"] == "v-003"
    assert lead["outcome"]["authorization_resolutions"][0]["verdict"] == "authorized"

    # Resolutions
    assert len(lead["resolutions"]) == 2
    assert lead["resolutions"][0]["hypothesis_id"] == "h-001"
    assert lead["resolutions"][0]["after"] == "+"
    assert lead["resolutions"][1]["after"] == "-"

    # Conclude
    assert out["conclude"]["disposition"] == "benign"
    assert out["conclude"]["matched_archetype"] == "monitoring-probe"
    assert out["conclude"]["surviving_hypotheses"] == ["h-001", "h-002"]


# ---------------------------------------------------------------------------
# Escape handling
# ---------------------------------------------------------------------------


def test_escaped_pipe_inside_cell():
    text = textwrap.dedent("""\
        ```invlang
        :T conclude
        termination.category   exhaustion-escalation
        termination.rationale  "pipe \\| inside"
        disposition            benign
        confidence             medium
        ```
    """)
    out = parse_dense_companion(text)
    # Scalar values aren't pipe-split, but the unquoter should preserve content.
    assert "pipe \\| inside" in out["conclude"]["termination"]["rationale"]
