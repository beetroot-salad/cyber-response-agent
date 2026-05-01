"""Unit tests for the SCREEN phase handler.

The merged `screen` subagent's invocation (`_invoke_screen`) is mocked via
monkeypatch. Exercised paths: playbook parsing, empty-screen short-circuit,
prompt assembly (prologue inlined), terminal YAML parsing (single block
carrying both `screen_result` fields and the invlang `gather` key), the
structural verifier, markdown+yaml composition, invlang library-mode
validation, routing, and orchestrator integration. No Claude subprocess.
"""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path

import pytest

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from schemas.state import Phase  # noqa: E402
from scripts.handlers import screen as screen_handler  # noqa: E402
from scripts.orchestrate import Context, OrchestrationError, PhaseResult, run  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures + helpers
# ---------------------------------------------------------------------------


PROLOGUE_YAML = textwrap.dedent("""\
    prologue:
      vertices:
      - id: v-001
        type: endpoint
        classification: internal-monitoring-host
        identifier: 172.22.0.10
      - id: v-002
        type: endpoint
        classification: unclassified-endpoint
        identifier: target-endpoint
      - id: v-003
        type: identity
        classification: monitoring-pattern
        identifier: nagios
      edges:
      - id: e-001
        relation: attempted_auth
        source_vertex: v-001
        target_vertex: v-002
        when:
          timestamp: '2026-04-20T19:25:01.616Z'
        attributes:
          target_user: nagios
        authority:
          kind: siem-event
          source: Wazuh (rule 5710)
""")


SEED_CONTEXTUALIZE = (
    "## CONTEXTUALIZE\n\n"
    "**Alert:** SEC-2026-042 — wazuh-rule-5710\n\n"
    "```yaml\n"
    + PROLOGUE_YAML
    + "```\n"
)


def make_ctx(
    tmp_path: Path,
    *,
    signature_id: str = "wazuh-rule-5710",
    seed_investigation: bool = True,
    contextualize: dict | None = None,
) -> Context:
    run_dir = tmp_path / "run-test"
    run_dir.mkdir()
    if seed_investigation:
        (run_dir / "investigation.md").write_text(SEED_CONTEXTUALIZE)
    outputs: dict[Phase, dict] = {}
    if contextualize is not None:
        outputs[Phase.CONTEXTUALIZE] = contextualize
    return Context(
        run_dir=run_dir,
        signature_id=signature_id,
        ticket_id="SEC-2026-042",
        alert={"id": "alert-1"},
        outputs=outputs,
    )


def stub_invoke(captured: list[str], response: str):
    def fn(prompt, *, timeout=None):
        captured.append(prompt)
        return response
    return fn


# Canonical merged screen subagent output — pattern match + invlang gather
# block in a single terminal YAML.
SCREEN_MATCH_YAML = textwrap.dedent("""\
    ```yaml
    screen_result: match
    matched_pattern: monitoring-probe fast-path
    disposition: benign
    matched_archetype: monitoring-probe
    matched_ticket_id: SEC-2024-001
    confidence: high
    leads_run:
      - lead: source-classification
        observation: "172.22.0.10 -> internal-monitoring-host"
      - lead: username-classification
        observation: "nagios -> monitoring-pattern"
      - lead: approved-monitoring-sources
        observation: "(172.22.0.10, nagios, target-endpoint) -> authorized"
      - lead: authentication-history
        observation: "cluster_count=5, max_cluster_size=2, no successful logins after"
    evidence_summary: "approved monitoring triple with periodic cadence and no successful login follow-up"
    reason: null
    findings:
      - id: l-001
        loop: 0
        name: source-classification
        target: v-001
        mode: screen
        query_details:
          system: classification-lookup
        outcome:
          attribute_updates:
            - target: v-001
              updates:
                classification: internal-monitoring-host
        resolutions: []
      - id: l-002
        loop: 0
        name: username-classification
        target: v-003
        mode: screen
        query_details:
          system: classification-lookup
        outcome:
          attribute_updates:
            - target: v-003
              updates:
                classification: monitoring-pattern
        resolutions: []
      - id: l-003
        loop: 0
        name: approved-monitoring-sources
        target: e-001
        mode: screen
        query_details:
          system: authority-consult
        outcome:
          anchor_consultations:
            - anchor_id: approved-monitoring-sources
              anchor_kind: approved-monitoring-sources
              grounding_kind: org-authority
              result: confirmed
              as_of: '2026-04-20T19:25:01Z'
              authority_for_question: full
        resolutions: []
      - id: l-004
        loop: 0
        name: authentication-history
        target: v-001
        mode: screen
        query_details:
          system: wazuh-indexer
          template: auth-history-cluster-stats
        outcome:
          observations:
            vertices: []
            edges: []
          screen_result: match
        resolutions: []
    ```
""").strip()


SCREEN_NOMATCH_YAML = textwrap.dedent("""\
    ```yaml
    screen_result: no_match
    matched_pattern: null
    disposition: null
    matched_archetype: null
    matched_ticket_id: null
    confidence: null
    leads_run:
      - lead: source-classification
        observation: "172.22.0.10 -> internal-monitoring-host"
      - lead: username-classification
        observation: "admin -> unclassified-identity"
    evidence_summary: "username does not match monitoring-pattern sentinels"
    reason: "username_classification did not match"
    findings:
      - id: l-001
        loop: 0
        name: source-classification
        target: v-001
        mode: screen
        query_details: {system: classification-lookup}
        outcome:
          attribute_updates:
            - target: v-001
              updates:
                classification: internal-monitoring-host
        resolutions: []
      - id: l-002
        loop: 0
        name: username-classification
        target: v-003
        mode: screen
        query_details: {system: classification-lookup}
        outcome:
          attribute_updates:
            - target: v-003
              updates:
                classification: unclassified-identity
          screen_result: no_match
        resolutions: []
    ```
""").strip()


SCREEN_ERROR_EMPTY_LEADS = textwrap.dedent("""\
    ```yaml
    screen_result: error
    matched_pattern: null
    disposition: null
    matched_archetype: null
    matched_ticket_id: null
    confidence: null
    leads_run: []
    evidence_summary: null
    reason: "missing required substitution: signature_id"
    ```
""").strip()


# ---------------------------------------------------------------------------
# Playbook parsing
# ---------------------------------------------------------------------------


class TestPlaybookParsing:
    def test_rule_5710_has_monitoring_probe_row(self):
        rows = screen_handler.load_screen_rows("wazuh-rule-5710")
        assert len(rows) == 1
        row = rows[0]
        assert row["pattern"] == "monitoring-probe fast-path"
        assert "source-classification" in row["leads"]
        assert "authentication-history" in row["leads"]

    @pytest.mark.parametrize(
        "signature_id",
        ["wazuh-rule-100001", "wazuh-rule-100110"],
    )
    def test_signatures_without_screen_return_empty(self, signature_id):
        rows = screen_handler.load_screen_rows(signature_id)
        assert rows == []

    def test_missing_playbook_raises(self):
        with pytest.raises(OrchestrationError, match="playbook not found"):
            screen_handler.load_screen_rows("wazuh-rule-does-not-exist")

    def test_leads_column_parses_anchor_suffix(self):
        raw = "source-classification, username-classification, approved-monitoring-sources anchor"
        parsed = screen_handler._parse_leads_column(raw)
        assert parsed == [
            "source-classification",
            "username-classification",
            "approved-monitoring-sources",
        ]

    def test_leads_column_handles_empty_and_whitespace(self):
        assert screen_handler._parse_leads_column("") == []
        assert screen_handler._parse_leads_column("  ,  ") == []
        assert screen_handler._parse_leads_column("foo , bar") == ["foo", "bar"]


# ---------------------------------------------------------------------------
# Empty-screen short-circuit
# ---------------------------------------------------------------------------


class TestPlaybookEmptyShortCircuit:
    def test_empty_section_routes_to_hypothesize_without_subagent_calls(
        self, tmp_path, monkeypatch,
    ):
        ctx = make_ctx(tmp_path)
        monkeypatch.setattr(screen_handler, "load_screen_rows", lambda _sig: [])
        screen_calls: list[str] = []
        monkeypatch.setattr(
            screen_handler, "_invoke_screen", stub_invoke(screen_calls, ""),
        )

        result = screen_handler.handle(ctx)

        assert result.next_phase == Phase.PREDICT
        assert result.payload["screen_result"] == "skipped"
        assert result.payload["reason"] == "empty_screen_section"
        assert screen_calls == []
        # Handler must not have touched investigation.md either.
        assert (ctx.run_dir / "investigation.md").read_text() == SEED_CONTEXTUALIZE

    def test_real_signature_without_screen_short_circuits(self, tmp_path, monkeypatch):
        """Integration-style: use a real playbook that lacks ## Screen."""
        ctx = make_ctx(tmp_path, signature_id="wazuh-rule-100001")
        screen_calls: list[str] = []
        monkeypatch.setattr(
            screen_handler, "_invoke_screen", stub_invoke(screen_calls, ""),
        )
        result = screen_handler.handle(ctx)
        assert result.next_phase == Phase.PREDICT
        assert result.payload["reason"] == "empty_screen_section"
        assert screen_calls == []


# ---------------------------------------------------------------------------
# Screen subagent dispatch
# ---------------------------------------------------------------------------


class TestScreenDispatch:
    def test_prompt_carries_run_dir_signature_and_prologue(self, tmp_path, monkeypatch):
        ctx = make_ctx(tmp_path)
        captured: list[str] = []
        monkeypatch.setattr(
            screen_handler, "_invoke_screen", stub_invoke(captured, SCREEN_MATCH_YAML),
        )
        screen_handler.handle(ctx)
        assert len(captured) == 1
        prompt = captured[0]
        assert f"run_dir={ctx.run_dir}" in prompt
        assert "signature_id=wazuh-rule-5710" in prompt
        # Prologue is inlined so the merged subagent can pick `target: v-*`
        # without reading investigation.md.
        assert "prologue_yaml:" in prompt
        assert "v-001" in prompt
        assert "attempted_auth" in prompt

    def test_unknown_screen_result_raises(self, tmp_path, monkeypatch):
        ctx = make_ctx(tmp_path)
        bad = textwrap.dedent("""\
            ```yaml
            screen_result: bogus
            leads_run: []
            ```
        """).strip()
        monkeypatch.setattr(
            screen_handler, "_invoke_screen", stub_invoke([], bad),
        )
        with pytest.raises(OrchestrationError, match="unknown screen_result"):
            screen_handler.handle(ctx)

    def test_missing_yaml_block_raises(self, tmp_path, monkeypatch):
        ctx = make_ctx(tmp_path)
        monkeypatch.setattr(
            screen_handler, "_invoke_screen", stub_invoke([], "no yaml here"),
        )
        with pytest.raises(OrchestrationError, match="no terminal YAML"):
            screen_handler.handle(ctx)


# ---------------------------------------------------------------------------
# Structural verifier (unit)
# ---------------------------------------------------------------------------


class TestStructuralVerifier:
    ROW = {
        "pattern": "monitoring-probe fast-path",
        "leads": "source-classification, username-classification, approved-monitoring-sources anchor, authentication-history",
    }

    def _parsed_match(self, leads):
        return {
            "screen_result": "match",
            "matched_pattern": "monitoring-probe fast-path",
            "leads_run": leads,
        }

    def test_match_with_all_leads_passes(self):
        parsed = self._parsed_match([
            {"lead": "source-classification", "observation": "x"},
            {"lead": "username-classification", "observation": "y"},
            {"lead": "approved-monitoring-sources", "observation": "z"},
            {"lead": "authentication-history", "observation": "w"},
        ])
        _, reason = screen_handler._structural_verify(parsed, [self.ROW])
        assert reason is None

    def test_matched_pattern_not_in_table_downgrades(self):
        parsed = self._parsed_match([])
        parsed["matched_pattern"] = "ghost-pattern"
        _, reason = screen_handler._structural_verify(parsed, [self.ROW])
        assert reason is not None
        assert "ghost-pattern" in reason

    def test_missing_indicator_lead_downgrades(self):
        parsed = self._parsed_match([
            {"lead": "source-classification", "observation": "x"},
            # username-classification missing
            {"lead": "approved-monitoring-sources", "observation": "z"},
            {"lead": "authentication-history", "observation": "w"},
        ])
        _, reason = screen_handler._structural_verify(parsed, [self.ROW])
        assert reason is not None
        assert "username-classification" in reason

    def test_empty_observation_treated_as_not_run(self):
        parsed = self._parsed_match([
            {"lead": "source-classification", "observation": ""},
            {"lead": "username-classification", "observation": "y"},
            {"lead": "approved-monitoring-sources", "observation": "z"},
            {"lead": "authentication-history", "observation": "w"},
        ])
        _, reason = screen_handler._structural_verify(parsed, [self.ROW])
        assert reason is not None
        assert "source-classification" in reason

    def test_no_match_passes_through_unchecked(self):
        parsed = {"screen_result": "no_match", "leads_run": []}
        result, reason = screen_handler._structural_verify(parsed, [self.ROW])
        assert reason is None
        assert result is parsed


# ---------------------------------------------------------------------------
# Gather extraction (unit)
# ---------------------------------------------------------------------------


class TestGatherExtraction:
    def test_extracts_gather_from_parsed(self):
        parsed = {
            "findings": [
                {"id": "l-001", "loop": 0, "name": "x", "target": "v-001",
                 "mode": "screen", "outcome": {}, "resolutions": []},
                {"id": "l-002", "loop": 0, "name": "y", "target": "v-002",
                 "mode": "screen", "outcome": {}, "resolutions": []},
            ],
        }
        out = screen_handler._extract_findings_dense_from_parsed(parsed)
        assert out.startswith(":L findings ")
        assert "l-001" in out and "l-002" in out

    def test_empty_when_gather_absent(self):
        assert screen_handler._extract_findings_dense_from_parsed({}) == ""
        assert screen_handler._extract_findings_dense_from_parsed({"findings": []}) == ""


# ---------------------------------------------------------------------------
# Prologue extraction
# ---------------------------------------------------------------------------


class TestPrologueExtraction:
    def test_extracts_from_seeded_investigation(self, tmp_path):
        ctx = make_ctx(tmp_path)
        block = screen_handler._extract_prologue_yaml(ctx.run_dir)
        assert "prologue:" in block
        assert "v-001" in block

    def test_missing_investigation_raises(self, tmp_path):
        ctx = make_ctx(tmp_path, seed_investigation=False)
        with pytest.raises(OrchestrationError, match="investigation.md not found"):
            screen_handler._extract_prologue_yaml(ctx.run_dir)

    def test_no_prologue_block_raises(self, tmp_path):
        ctx = make_ctx(tmp_path, seed_investigation=False)
        (ctx.run_dir / "investigation.md").write_text(
            "## CONTEXTUALIZE\n\nno yaml block here\n"
        )
        with pytest.raises(OrchestrationError, match="no prologue"):
            screen_handler._extract_prologue_yaml(ctx.run_dir)

    def test_extracts_from_tilde_fence(self, tmp_path):
        """A ``~~~yaml`` fenced block is an equally valid CommonMark fence;
        markdown-it-py handles it natively."""
        ctx = make_ctx(tmp_path, seed_investigation=False)
        (ctx.run_dir / "investigation.md").write_text(
            "## CONTEXTUALIZE\n\n"
            "~~~yaml\n"
            "prologue:\n"
            "  vertices:\n"
            "    - id: v-001\n"
            "      kind: ip\n"
            "~~~\n"
        )
        block = screen_handler._extract_prologue_yaml(ctx.run_dir)
        assert "prologue:" in block
        assert "v-001" in block


# ---------------------------------------------------------------------------
# Investigation.md write + library invlang validation
# ---------------------------------------------------------------------------


class TestInvestigationWrite:
    def test_append_on_match_includes_screen_section_and_gather_yaml(
        self, tmp_path, monkeypatch,
    ):
        ctx = make_ctx(tmp_path)
        monkeypatch.setattr(
            screen_handler, "_invoke_screen", stub_invoke([], SCREEN_MATCH_YAML),
        )
        screen_handler.handle(ctx)
        text = (ctx.run_dir / "investigation.md").read_text()
        assert "## SCREEN" in text
        assert "**Result:** match" in text
        assert "monitoring-probe fast-path" in text
        assert "source-classification" in text
        assert "authentication-history" in text
        # Final lead carries screen_result on the dense :L findings row
        # (last column per `_screen_dense._LEAD_COLS`).
        assert "```invlang" in text
        assert "|match\n" in text or text.rstrip().endswith("|match")

    def test_no_match_write_has_no_match_section(self, tmp_path, monkeypatch):
        ctx = make_ctx(tmp_path)
        monkeypatch.setattr(
            screen_handler, "_invoke_screen", stub_invoke([], SCREEN_NOMATCH_YAML),
        )
        screen_handler.handle(ctx)
        text = (ctx.run_dir / "investigation.md").read_text()
        assert "**Result:** no_match" in text
        assert "```invlang" in text
        assert "|no_match" in text

    def test_malformed_invlang_rejected_before_write(self, tmp_path, monkeypatch):
        """A gather block with invalid invlang shape must surface before the
        file write, not after — library-mode validate_companion is the guard."""
        ctx = make_ctx(tmp_path)
        original = (ctx.run_dir / "investigation.md").read_text()
        # Merged subagent emits screen verdict + gather block; the gather
        # references a nonexistent vertex v-999.
        bad = textwrap.dedent("""\
            ```yaml
            screen_result: match
            matched_pattern: monitoring-probe fast-path
            disposition: benign
            matched_archetype: monitoring-probe
            matched_ticket_id: SEC-2024-001
            confidence: high
            leads_run:
              - lead: source-classification
                observation: "172.22.0.10 -> internal-monitoring-host"
              - lead: username-classification
                observation: "nagios -> monitoring-pattern"
              - lead: approved-monitoring-sources
                observation: "(triple) -> authorized"
              - lead: authentication-history
                observation: "n=1"
            evidence_summary: fake
            reason: null
            findings:
              - id: l-001
                loop: 0
                name: source-classification
                target: v-001
                mode: screen
                query_details:
                  system: classification-lookup
                outcome:
                  attribute_updates:
                    - target: v-999
                      updates:
                        classification: x
                resolutions: []
            ```
        """).strip()
        monkeypatch.setattr(
            screen_handler, "_invoke_screen", stub_invoke([], bad),
        )
        with pytest.raises(OrchestrationError, match="invlang validation failed"):
            screen_handler.handle(ctx)
        assert (ctx.run_dir / "investigation.md").read_text() == original


# ---------------------------------------------------------------------------
# Routing
# ---------------------------------------------------------------------------


class TestRouting:
    def test_match_routes_to_conclude_with_match_payload(self, tmp_path, monkeypatch):
        ctx = make_ctx(tmp_path)
        monkeypatch.setattr(
            screen_handler, "_invoke_screen", stub_invoke([], SCREEN_MATCH_YAML),
        )
        result = screen_handler.handle(ctx)
        assert result.next_phase == Phase.REPORT
        assert result.payload["screen_result"] == "match"
        assert result.payload["matched_archetype"] == "monitoring-probe"
        assert result.payload["matched_ticket_id"] == "SEC-2024-001"
        assert result.payload["disposition"] == "benign"
        assert len(result.payload["leads_run"]) == 4

    def test_no_match_routes_to_hypothesize(self, tmp_path, monkeypatch):
        ctx = make_ctx(tmp_path)
        monkeypatch.setattr(
            screen_handler, "_invoke_screen", stub_invoke([], SCREEN_NOMATCH_YAML),
        )
        result = screen_handler.handle(ctx)
        assert result.next_phase == Phase.PREDICT
        assert result.payload["screen_result"] == "no_match"

    def test_structural_downgrade_routes_to_hypothesize(self, tmp_path, monkeypatch):
        """Merged subagent claims match but is missing a required lead —
        handler must downgrade, drop the gather block, and fall through."""
        ctx = make_ctx(tmp_path)
        broken = textwrap.dedent("""\
            ```yaml
            screen_result: match
            matched_pattern: monitoring-probe fast-path
            disposition: benign
            matched_archetype: monitoring-probe
            matched_ticket_id: SEC-2024-001
            confidence: high
            leads_run:
              - lead: source-classification
                observation: "172.22.0.10 -> internal-monitoring-host"
              - lead: username-classification
                observation: "nagios -> monitoring-pattern"
              - lead: approved-monitoring-sources
                observation: "(triple) -> authorized"
            evidence_summary: "fake match"
            reason: null
            findings:
              - id: l-001
                loop: 0
                name: source-classification
                target: v-001
                mode: screen
                query_details: {system: classification-lookup}
                outcome:
                  attribute_updates:
                    - target: v-001
                      updates:
                        classification: internal-monitoring-host
                resolutions: []
              - id: l-002
                loop: 0
                name: username-classification
                target: v-003
                mode: screen
                query_details: {system: classification-lookup}
                outcome:
                  attribute_updates:
                    - target: v-003
                      updates:
                        classification: monitoring-pattern
                resolutions: []
              - id: l-003
                loop: 0
                name: approved-monitoring-sources
                target: e-001
                mode: screen
                query_details: {system: authority-consult}
                outcome:
                  anchor_consultations:
                    - anchor_id: approved-monitoring-sources
                      anchor_kind: approved-monitoring-sources
                      grounding_kind: org-authority
                      result: confirmed
                      as_of: '2026-04-20T19:25:01Z'
                      authority_for_question: full
                resolutions: []
            ```
        """).strip()
        monkeypatch.setattr(
            screen_handler, "_invoke_screen", stub_invoke([], broken),
        )
        result = screen_handler.handle(ctx)
        assert result.next_phase == Phase.PREDICT
        assert result.payload["screen_result"] == "error"
        assert "authentication-history" in result.payload["reason"]
        # Gather block dropped on downgrade — investigation.md has the SCREEN
        # markdown but no fenced yaml block.
        text = (ctx.run_dir / "investigation.md").read_text()
        assert "## SCREEN" in text
        # The only `````yaml block already present is the CONTEXTUALIZE
        # prologue; no new one was appended.
        assert text.count("```yaml") == 1

    def test_error_routes_to_hypothesize(self, tmp_path, monkeypatch):
        ctx = make_ctx(tmp_path)
        monkeypatch.setattr(
            screen_handler, "_invoke_screen",
            stub_invoke([], SCREEN_ERROR_EMPTY_LEADS),
        )
        result = screen_handler.handle(ctx)
        assert result.next_phase == Phase.PREDICT
        assert result.payload["screen_result"] == "error"


# ---------------------------------------------------------------------------
# Orchestrator integration
# ---------------------------------------------------------------------------


class TestOrchestratorIntegration:
    def test_match_path_drives_contextualize_to_conclude(self, tmp_path, monkeypatch):
        run_dir = tmp_path / "run-1"
        run_dir.mkdir()
        (run_dir / "investigation.md").write_text(SEED_CONTEXTUALIZE)
        ctx = Context(
            run_dir=run_dir,
            signature_id="wazuh-rule-5710",
            ticket_id="SEC-2026-042",
            alert={"id": "alert-1"},
        )

        def ctx_handler(_c):
            return PhaseResult(next_phase=Phase.SCREEN, payload={"dedup": False})

        from scripts.handlers import report as report_handler
        conclude_response = textwrap.dedent("""\
            ```yaml
            status: written
            report_path: /runs/run-1/report.md
            disposition: benign
            confidence: high
            matched_archetype: monitoring-probe
            status_frontmatter: resolved
            ```
        """).strip()
        monkeypatch.setattr(
            report_handler, "_invoke_subagent",
            stub_invoke([], conclude_response),
        )
        monkeypatch.setattr(
            screen_handler, "_invoke_screen", stub_invoke([], SCREEN_MATCH_YAML),
        )

        handlers = {
            Phase.CONTEXTUALIZE: ctx_handler,
            Phase.SCREEN: screen_handler.handle,
            Phase.REPORT: report_handler.handle,
        }
        result = run(ctx, handlers)

        assert result["status"] == "complete"
        assert result["history"] == ["CONTEXTUALIZE", "SCREEN", "REPORT"]
        assert result["outputs"]["SCREEN"]["screen_result"] == "match"
        assert result["outputs"]["REPORT"]["status"] == "written"
