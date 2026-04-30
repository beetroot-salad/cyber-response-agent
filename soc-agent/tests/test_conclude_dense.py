"""Unit tests for the REPORT-phase dense conclude emitter + parser."""

import sys
import textwrap
from pathlib import Path

import pytest

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from scripts.handlers._conclude_dense import (  # noqa: E402
    ConcludeOutputError,
    emit_conclude_dense,
    parse_conclude_dense,
)


# ---------------------------------------------------------------------------
# Round-trip
# ---------------------------------------------------------------------------


class TestRoundTrip:
    def test_handler_minimal_emit_set(self):
        """Mirrors the ANALYZE-routing compose site in
        scripts/handlers/report.py:1370-1411 — termination + disposition
        + confidence + matched_archetype + summary."""
        d = {
            "termination": {
                "category": "trust-root",
                "rationale": "approved-monitoring-sources confirmed",
            },
            "disposition": "benign",
            "confidence": "high",
            "matched_archetype": "monitoring-probe",
            "summary": "SSH login from monitoring host confirmed sanctioned.",
        }
        rendered = emit_conclude_dense(d)
        parsed = parse_conclude_dense(rendered)
        assert parsed == d

    def test_screen_minimal_emit_set(self):
        """Mirrors the SCREEN compose site in
        scripts/handlers/report.py:476-501."""
        d = {
            "termination": {
                "category": "trust-root",
                "rationale": "SCREEN matched approved-monitoring-probe.",
            },
            "disposition": "benign",
            "confidence": "high",
            "matched_archetype": "approved-monitoring-probe",
            "summary": "Pattern match grounded by precedent SEC-2026-001.",
        }
        rendered = emit_conclude_dense(d)
        parsed = parse_conclude_dense(rendered)
        assert parsed == d

    def test_full_schema_round_trip(self):
        """Round-trip every schema-declared field including all sub-tables."""
        d = {
            "termination": {
                "category": "exhaustion-escalation",
                "rationale": "host-query unavail; h-002 cannot reach --",
            },
            "disposition": "unclear",
            "impact_verdict": "exceeds",
            "impact_severity": "moderate",
            "confidence": "medium",
            "matched_archetype": None,
            "ceiling_rationale": "n/a",
            "summary": "Investigation halted on telemetry ceiling.",
            "surviving_hypotheses": ["h-001", "h-002"],
            "deferred_authorizations": [
                {"contract_ref": "h-001.ac1", "rationale": "anchor unavailable"},
            ],
            "deferred_impact_predictions": [
                {"prediction_ref": "l-002.ip1", "rationale": "baseline null"},
            ],
            "deferred_predictions": [
                {"prediction_ref": "h-001.p2", "rationale": "process unreachable"},
            ],
            "ceiling_test": {
                "kind": "tool-unavailable",
                "subject": "host-query DEGRADED",
            },
        }
        rendered = emit_conclude_dense(d)
        parsed = parse_conclude_dense(rendered)
        assert parsed == d

    def test_empty_arrays_emit_none_round_trip(self):
        d = {
            "termination": {"category": "adversarial-refuted", "rationale": "x"},
            "disposition": "benign",
            "confidence": "high",
            "matched_archetype": "noisy-syscheck",
            "summary": "Bulk syscheck pattern matched.",
            "surviving_hypotheses": [],
            "deferred_authorizations": [],
            "deferred_impact_predictions": [],
            "deferred_predictions": [],
        }
        rendered = emit_conclude_dense(d)
        assert ":T conclude.surviving" in rendered
        # Each empty sub-table emits the single-line `none` row.
        assert rendered.count("\nnone") == 4
        parsed = parse_conclude_dense(rendered)
        assert parsed == d

    def test_absent_subtable_omits_block_and_round_trips(self):
        """When the dict lacks a sub-table key, the emitter omits the block
        entirely; the parser correctly omits the key on the way back."""
        d = {
            "termination": {"category": "trust-root", "rationale": "ok"},
            "disposition": "benign",
            "confidence": "high",
            "matched_archetype": "x",
            "summary": "ok",
        }
        rendered = emit_conclude_dense(d)
        assert ":T conclude.surviving" not in rendered
        assert ":T conclude.deferred_authz" not in rendered
        parsed = parse_conclude_dense(rendered)
        assert parsed == d


# ---------------------------------------------------------------------------
# Parser-only behaviour
# ---------------------------------------------------------------------------


class TestParser:
    def test_returns_none_when_no_dense_block(self):
        text = "## REPORT\n\n**Verdict:** resolved / benign / high\n"
        assert parse_conclude_dense(text) is None

    def test_finds_block_inside_full_markdown_document(self):
        text = textwrap.dedent("""
        ## REPORT

        **Verdict:** resolved / benign / high
        **Confirmed hypothesis:** ?monitoring-probe
        **Trace:** approved-monitoring-sources(confirmed) → disposition:benign

        :T conclude
        termination.category   trust-root
        termination.rationale  "approved-monitoring-sources confirmed"
        disposition            benign
        confidence             high
        matched_archetype      monitoring-probe
        summary                "ok"
        """).strip()
        out = parse_conclude_dense(text)
        assert out["disposition"] == "benign"
        assert out["termination"]["category"] == "trust-root"
        assert out["matched_archetype"] == "monitoring-probe"

    def test_null_matched_archetype_parses_to_none(self):
        text = textwrap.dedent("""
        :T conclude
        termination.category   exhaustion-escalation
        termination.rationale  "x"
        disposition            unclear
        confidence             low
        matched_archetype      null
        summary                "y"
        """).strip()
        out = parse_conclude_dense(text)
        assert out["matched_archetype"] is None

    def test_quoted_string_with_embedded_escaped_quote(self):
        text = textwrap.dedent('''
        :T conclude
        summary                "she said \\"go\\""
        ''').strip()
        out = parse_conclude_dense(text)
        assert out["summary"] == 'she said "go"'

    def test_escaped_pipe_in_cell(self):
        text = textwrap.dedent("""
        :T conclude
        disposition            benign
        confidence             high
        summary                "ok"

        :T conclude.deferred_preds [prediction_ref|rationale]
        h-001.p1|"pred uses a \\| literal"
        """).strip()
        out = parse_conclude_dense(text)
        assert out["deferred_predictions"][0]["rationale"].startswith('"pred uses a |')


# ---------------------------------------------------------------------------
# Error surface
# ---------------------------------------------------------------------------


class TestParserErrors:
    def test_unknown_subtable(self):
        text = textwrap.dedent("""
        :T conclude
        disposition            benign

        :T conclude.bogus [a|b]
        x|y
        """).strip()
        with pytest.raises(ConcludeOutputError, match="unknown sub-table"):
            parse_conclude_dense(text)

    def test_subtable_without_main_block(self):
        text = textwrap.dedent("""
        :T conclude.surviving [hyp_id|final_weight]
        h-001|+
        """).strip()
        with pytest.raises(ConcludeOutputError, match="no `:T conclude`"):
            parse_conclude_dense(text)

    def test_wrong_subtable_columns(self):
        text = textwrap.dedent("""
        :T conclude
        disposition            benign

        :T conclude.surviving [hyp_id|status]
        h-001|active
        """).strip()
        with pytest.raises(ConcludeOutputError, match="columns must be"):
            parse_conclude_dense(text)

    def test_duplicate_main_block(self):
        text = textwrap.dedent("""
        :T conclude
        disposition            benign

        :T conclude
        disposition            unclear
        """).strip()
        with pytest.raises(ConcludeOutputError, match="duplicate"):
            parse_conclude_dense(text)

    def test_unknown_scalar_key(self):
        text = textwrap.dedent("""
        :T conclude
        disposition            benign
        bogus_field            wat
        """).strip()
        with pytest.raises(ConcludeOutputError, match="unknown key"):
            parse_conclude_dense(text)


# ---------------------------------------------------------------------------
# Emitter shape
# ---------------------------------------------------------------------------


class TestEmitter:
    def test_scalars_aligned(self):
        d = {
            "termination": {"category": "trust-root", "rationale": "ok"},
            "disposition": "benign",
            "confidence": "high",
            "summary": "ok",
        }
        out = emit_conclude_dense(d)
        # Every scalar row has at least two spaces between key column and value.
        for line in out.splitlines():
            if not line or line.startswith(":T") or line == "none":
                continue
            assert "  " in line, f"row has no value padding: {line!r}"

    def test_quoted_only_when_phrase(self):
        d = {
            "disposition": "benign",
            "matched_archetype": "monitoring-probe",
            "summary": "two words",
        }
        out = emit_conclude_dense(d)
        assert "disposition" in out and " benign" in out
        assert "matched_archetype" in out and " monitoring-probe" in out
        # Multi-word string is quoted; single-token bare.
        assert '"two words"' in out

    def test_null_renders_for_none_value(self):
        d = {
            "disposition": "unclear",
            "matched_archetype": None,
            "summary": "x",
        }
        out = emit_conclude_dense(d)
        assert "matched_archetype" in out and " null" in out

    def test_rejects_non_dict_input(self):
        with pytest.raises(ConcludeOutputError):
            emit_conclude_dense([])  # type: ignore[arg-type]
