"""Unit tests for the contextualize-prologue dense-format parser."""

import sys
import textwrap
from pathlib import Path

import pytest

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from scripts.handlers._prologue_dense import (  # noqa: E402
    PrologueOutputError,
    parse_prologue_dense,
)


# ---------------------------------------------------------------------------
# Round-trip
# ---------------------------------------------------------------------------


class TestRoundTrip:
    def test_minimal_two_vertex_one_edge(self):
        text = textwrap.dedent("""
        :V prologue.vertices [id|type|class|ident|attrs?]
        v-001|endpoint|monitoring-host|172.22.0.10|
        v-002|endpoint|internal-server|target-endpoint|

        :E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
        e-001|attempted_auth|v-001|v-002|2026-04-20T09:00:00Z|siem-event:wazuh-rule-5710|target_user=sensu;outcome=failed
        """).strip()

        out = parse_prologue_dense(text)
        assert out["prologue"]["vertices"] == [
            {
                "id": "v-001",
                "type": "endpoint",
                "classification": "monitoring-host",
                "identifier": "172.22.0.10",
            },
            {
                "id": "v-002",
                "type": "endpoint",
                "classification": "internal-server",
                "identifier": "target-endpoint",
            },
        ]
        assert out["prologue"]["edges"] == [
            {
                "id": "e-001",
                "relation": "attempted_auth",
                "source_vertex": "v-001",
                "target_vertex": "v-002",
                "when": {"timestamp": "2026-04-20T09:00:00Z"},
                "attributes": {"target_user": "sensu", "outcome": "failed"},
                "authority": {
                    "kind": "siem-event",
                    "source": "wazuh-rule-5710",
                },
            }
        ]

    def test_vertex_with_attrs(self):
        text = textwrap.dedent("""
        :V prologue.vertices [id|type|class|ident|attrs?]
        v-001|identity|service-account|sensu|kind=user

        :E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
        """).strip()

        out = parse_prologue_dense(text)
        assert out["prologue"]["vertices"][0]["attributes"] == {"kind": "user"}
        assert out["prologue"]["edges"] == []

    def test_edge_without_when_or_attrs(self):
        text = textwrap.dedent("""
        :V prologue.vertices [id|type|class|ident|attrs?]
        v-001|identity|service-account|sensu|
        v-002|endpoint|monitoring-host|172.22.0.10|

        :E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
        e-001|initiated_by|v-002|v-001||authoritative-source:approved-monitoring-sources|
        """).strip()

        out = parse_prologue_dense(text)
        edge = out["prologue"]["edges"][0]
        assert "when" not in edge
        assert "attributes" not in edge
        assert edge["authority"] == {
            "kind": "authoritative-source",
            "source": "approved-monitoring-sources",
        }

    def test_empty_blocks(self):
        text = textwrap.dedent("""
        :V prologue.vertices [id|type|class|ident|attrs?]

        :E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
        """).strip()

        out = parse_prologue_dense(text)
        assert out == {"prologue": {"vertices": [], "edges": []}}

    def test_tolerates_outer_fence(self):
        text = textwrap.dedent("""
        ```
        :V prologue.vertices [id|type|class|ident|attrs?]
        v-001|endpoint|monitoring-host|172.22.0.10|

        :E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
        ```
        """).strip()

        out = parse_prologue_dense(text)
        assert out["prologue"]["vertices"][0]["id"] == "v-001"
        assert out["prologue"]["edges"] == []

    def test_multi_attr_packed(self):
        text = textwrap.dedent("""
        :V prologue.vertices [id|type|class|ident|attrs?]
        v-001|identity|service-account|sensu|kind=user;source=ldap

        :E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
        """).strip()

        out = parse_prologue_dense(text)
        assert out["prologue"]["vertices"][0]["attributes"] == {
            "kind": "user",
            "source": "ldap",
        }


# ---------------------------------------------------------------------------
# Negative cases
# ---------------------------------------------------------------------------


class TestNegative:
    def test_empty_input(self):
        with pytest.raises(PrologueOutputError, match="empty"):
            parse_prologue_dense("")

    def test_missing_vertices_block(self):
        text = textwrap.dedent("""
        :E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
        """).strip()
        with pytest.raises(PrologueOutputError, match="prologue.vertices"):
            parse_prologue_dense(text)

    def test_missing_edges_block(self):
        text = textwrap.dedent("""
        :V prologue.vertices [id|type|class|ident|attrs?]
        v-001|endpoint|monitoring-host|172.22.0.10|
        """).strip()
        with pytest.raises(PrologueOutputError, match="prologue.edges"):
            parse_prologue_dense(text)

    def test_unknown_block_tag(self):
        text = textwrap.dedent("""
        :V prologue.vertices [id|type|class|ident|attrs?]

        :E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]

        :R bogus [a|b]
        """).strip()
        with pytest.raises(PrologueOutputError, match="unknown dense block tag"):
            parse_prologue_dense(text)

    def test_wrong_block_name(self):
        text = textwrap.dedent("""
        :V wrong.name [id|type|class|ident|attrs?]

        :E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
        """).strip()
        with pytest.raises(PrologueOutputError, match="prologue.vertices"):
            parse_prologue_dense(text)

    def test_wrong_columns(self):
        text = textwrap.dedent("""
        :V prologue.vertices [id|type|ident]

        :E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
        """).strip()
        with pytest.raises(PrologueOutputError, match="columns must be"):
            parse_prologue_dense(text)

    def test_row_too_many_cells(self):
        text = textwrap.dedent("""
        :V prologue.vertices [id|type|class|ident|attrs?]
        v-001|endpoint|monitoring-host|172.22.0.10||extra|tail

        :E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
        """).strip()
        with pytest.raises(PrologueOutputError, match="more cells than columns"):
            parse_prologue_dense(text)

    def test_vertex_missing_required_cell(self):
        text = textwrap.dedent("""
        :V prologue.vertices [id|type|class|ident|attrs?]
        v-001|endpoint||172.22.0.10|

        :E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
        """).strip()
        with pytest.raises(PrologueOutputError, match="missing required cell"):
            parse_prologue_dense(text)

    def test_edge_missing_auth(self):
        text = textwrap.dedent("""
        :V prologue.vertices [id|type|class|ident|attrs?]
        v-001|endpoint|monitoring-host|172.22.0.10|
        v-002|endpoint|internal-server|target-endpoint|

        :E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
        e-001|attempted_auth|v-001|v-002|2026-04-20T09:00:00Z||
        """).strip()
        with pytest.raises(PrologueOutputError, match="missing required cell"):
            parse_prologue_dense(text)

    def test_edge_malformed_auth_no_colon(self):
        text = textwrap.dedent("""
        :V prologue.vertices [id|type|class|ident|attrs?]
        v-001|endpoint|monitoring-host|172.22.0.10|
        v-002|endpoint|internal-server|target-endpoint|

        :E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
        e-001|attempted_auth|v-001|v-002|2026-04-20T09:00:00Z|siem-event-no-colon|
        """).strip()
        with pytest.raises(PrologueOutputError, match="missing `:`"):
            parse_prologue_dense(text)

    def test_edge_malformed_auth_empty_half(self):
        text = textwrap.dedent("""
        :V prologue.vertices [id|type|class|ident|attrs?]
        v-001|endpoint|monitoring-host|172.22.0.10|
        v-002|endpoint|internal-server|target-endpoint|

        :E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
        e-001|attempted_auth|v-001|v-002|2026-04-20T09:00:00Z|:wazuh-rule-5710|
        """).strip()
        with pytest.raises(PrologueOutputError, match="empty kind or source"):
            parse_prologue_dense(text)

    def test_attrs_bare_token(self):
        text = textwrap.dedent("""
        :V prologue.vertices [id|type|class|ident|attrs?]
        v-001|identity|service-account|sensu|bare_no_equals

        :E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
        """).strip()
        with pytest.raises(PrologueOutputError, match="bare token"):
            parse_prologue_dense(text)

    def test_row_before_any_header(self):
        text = textwrap.dedent("""
        v-001|endpoint|monitoring-host|172.22.0.10|

        :V prologue.vertices [id|type|class|ident|attrs?]

        :E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
        """).strip()
        with pytest.raises(PrologueOutputError, match="row appears before any block header"):
            parse_prologue_dense(text)

    def test_duplicate_vertices_block(self):
        text = textwrap.dedent("""
        :V prologue.vertices [id|type|class|ident|attrs?]
        v-001|endpoint|monitoring-host|172.22.0.10|

        :V prologue.vertices [id|type|class|ident|attrs?]
        v-002|endpoint|internal-server|target-endpoint|

        :E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
        """).strip()
        with pytest.raises(PrologueOutputError, match="more than once"):
            parse_prologue_dense(text)
