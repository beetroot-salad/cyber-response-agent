"""Unit tests for the gather / gather-composite dense-block parser."""

import sys
import textwrap
from pathlib import Path

import pytest

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from scripts.handlers._gather_dense import (  # noqa: E402
    GatherDenseError,
    parse_gather_dense,
    split_dense_and_yaml,
)


# ---------------------------------------------------------------------------
# Round-trip
# ---------------------------------------------------------------------------


class TestRoundTrip:
    def test_single_lead_ok(self):
        text = textwrap.dedent("""
        :L findings [id|name|status]
        l-001|approved-monitoring-sources-lookup|ok
        """).strip()

        out = parse_gather_dense(text)
        assert out == [
            {"id": "l-001", "name": "approved-monitoring-sources-lookup", "status": "ok"},
        ]

    def test_multi_lead_mixed_statuses(self):
        text = textwrap.dedent("""
        :L findings [id|name|status]
        l-001|authentication-history|ok
        l-002|process-lineage|dropped_attempt
        l-003|monitoring-host-state|data_missing
        """).strip()

        out = parse_gather_dense(text)
        assert [r["id"] for r in out] == ["l-001", "l-002", "l-003"]
        assert [r["status"] for r in out] == ["ok", "dropped_attempt", "data_missing"]

    @pytest.mark.parametrize("status", [
        "ok", "partial", "data_missing", "dropped_attempt",
        "probe_broken", "siem_error", "error",
    ])
    def test_each_status_accepted(self, status):
        text = f":L findings [id|name|status]\nl-001|the-lead|{status}"
        out = parse_gather_dense(text)
        assert out[0]["status"] == status

    def test_whitespace_tolerance(self):
        text = "\n\n  :L findings [id|name|status]  \n\n  l-001|foo|ok  \n\n"
        out = parse_gather_dense(text)
        assert out == [{"id": "l-001", "name": "foo", "status": "ok"}]

    def test_order_preservation(self):
        # Rows preserve emission order (callers join by id, but order is the
        # default fallback for tests that read positionally).
        text = textwrap.dedent("""
        :L findings [id|name|status]
        l-005|fifth|ok
        l-001|first|partial
        l-009|ninth|dropped_attempt
        """).strip()

        out = parse_gather_dense(text)
        assert [r["id"] for r in out] == ["l-005", "l-001", "l-009"]

    def test_long_lead_name_with_hyphens_and_dots(self):
        text = (
            ":L findings [id|name|status]\n"
            "l-100|approved-monitoring-sources.triple-lookup.v2|ok"
        )
        out = parse_gather_dense(text)
        assert out[0]["name"] == "approved-monitoring-sources.triple-lookup.v2"

    def test_dispatch_unparseable_error_row(self):
        text = textwrap.dedent("""
        :L findings [id|name|status]
        l-001|the-lead|error
        """).strip()
        out = parse_gather_dense(text)
        assert out[0]["status"] == "error"

    def test_optional_column_marker_in_header_tolerated(self):
        # `?` suffix on column names is a noop here (only id/name/status).
        # Mirrors `_prologue_dense._HEADER_RE` behaviour for forward compat.
        text = textwrap.dedent("""
        :L findings [id|name|status?]
        l-001|foo|ok
        """).strip()
        out = parse_gather_dense(text)
        assert out[0]["status"] == "ok"

    def test_outer_fence_tolerated(self):
        text = textwrap.dedent("""
        ```
        :L findings [id|name|status]
        l-001|foo|ok
        ```
        """).strip()
        out = parse_gather_dense(text)
        assert out == [{"id": "l-001", "name": "foo", "status": "ok"}]


# ---------------------------------------------------------------------------
# Negative — block / header shape
# ---------------------------------------------------------------------------


class TestNegativeBlockShape:
    def test_empty_input(self):
        with pytest.raises(GatherDenseError, match="empty"):
            parse_gather_dense("")

    def test_missing_findings_header(self):
        text = "l-001|foo|ok"
        with pytest.raises(GatherDenseError, match="row before"):
            parse_gather_dense(text)

    def test_no_block_at_all(self):
        text = "just some prose, no dense markers"
        with pytest.raises(GatherDenseError, match="row before"):
            parse_gather_dense(text)

    def test_wrong_block_tag(self):
        text = ":V findings [id|name|status]\nv-001|foo|ok"
        with pytest.raises(GatherDenseError, match="unrecognized block header"):
            parse_gather_dense(text)

    def test_wrong_block_name(self):
        text = ":L leads [id|name|status]\nl-001|foo|ok"
        with pytest.raises(GatherDenseError, match="unrecognized block header"):
            parse_gather_dense(text)

    def test_wrong_columns_missing_name(self):
        text = ":L findings [id|status]\nl-001|ok"
        with pytest.raises(GatherDenseError, match="columns must be"):
            parse_gather_dense(text)

    def test_reordered_columns(self):
        text = ":L findings [id|status|name]\nl-001|ok|foo"
        with pytest.raises(GatherDenseError, match="columns must be"):
            parse_gather_dense(text)

    def test_extra_column(self):
        text = ":L findings [id|name|status|extra]\nl-001|foo|ok|x"
        with pytest.raises(GatherDenseError, match="columns must be"):
            parse_gather_dense(text)

    def test_two_findings_blocks(self):
        text = textwrap.dedent("""
        :L findings [id|name|status]
        l-001|foo|ok

        :L findings [id|name|status]
        l-002|bar|ok
        """).strip()
        with pytest.raises(GatherDenseError, match="more than once"):
            parse_gather_dense(text)

    def test_empty_block_no_rows(self):
        text = ":L findings [id|name|status]"
        with pytest.raises(GatherDenseError, match="at least one row"):
            parse_gather_dense(text)


# ---------------------------------------------------------------------------
# Negative — row shape
# ---------------------------------------------------------------------------


class TestNegativeRowShape:
    def test_too_few_cells(self):
        text = ":L findings [id|name|status]\nl-001|foo"
        with pytest.raises(GatherDenseError, match="must have 3 cells"):
            parse_gather_dense(text)

    def test_too_many_cells(self):
        text = ":L findings [id|name|status]\nl-001|foo|ok|extra"
        with pytest.raises(GatherDenseError, match="must have 3 cells"):
            parse_gather_dense(text)

    def test_empty_id(self):
        text = ":L findings [id|name|status]\n|foo|ok"
        with pytest.raises(GatherDenseError, match="missing required cell"):
            parse_gather_dense(text)

    def test_empty_name(self):
        text = ":L findings [id|name|status]\nl-001||ok"
        with pytest.raises(GatherDenseError, match="missing required cell"):
            parse_gather_dense(text)

    def test_empty_status(self):
        text = ":L findings [id|name|status]\nl-001|foo|"
        with pytest.raises(GatherDenseError, match="missing required cell"):
            parse_gather_dense(text)

    def test_invalid_status_completed(self):
        text = ":L findings [id|name|status]\nl-001|foo|completed"
        with pytest.raises(GatherDenseError, match="status='completed' not in"):
            parse_gather_dense(text)

    def test_invalid_status_success(self):
        text = ":L findings [id|name|status]\nl-001|foo|success"
        with pytest.raises(GatherDenseError, match="status='success' not in"):
            parse_gather_dense(text)

    def test_duplicate_id(self):
        text = textwrap.dedent("""
        :L findings [id|name|status]
        l-001|foo|ok
        l-001|bar|ok
        """).strip()
        with pytest.raises(GatherDenseError, match="duplicates a prior row"):
            parse_gather_dense(text)


# ---------------------------------------------------------------------------
# split_dense_and_yaml
# ---------------------------------------------------------------------------


class TestSplit:
    def test_split_at_yaml_fence(self):
        stdout = textwrap.dedent("""
        :L findings [id|name|status]
        l-001|foo|ok

        ```yaml
        gather:
          loop: 1
          leads:
            - id: l-001
        ```
        """).strip() + "\n"

        dense, yaml_text = split_dense_and_yaml(stdout)
        assert ":L findings" in dense
        assert "```yaml" in yaml_text
        assert "gather:" in yaml_text

    def test_split_at_unfenced_top_level(self):
        stdout = textwrap.dedent("""
        :L findings [id|name|status]
        l-001|foo|ok

        gather:
          loop: 1
          leads:
            - id: l-001
        """).strip() + "\n"

        dense, yaml_text = split_dense_and_yaml(stdout)
        assert ":L findings" in dense
        assert yaml_text.lstrip().startswith("gather:")

    def test_split_no_envelope_raises(self):
        stdout = ":L findings [id|name|status]\nl-001|foo|ok\n"
        with pytest.raises(GatherDenseError, match="no `gather:` YAML envelope"):
            split_dense_and_yaml(stdout)
