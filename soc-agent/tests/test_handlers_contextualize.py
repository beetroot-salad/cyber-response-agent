"""Unit tests for the CONTEXTUALIZE phase handler.

All three subagent invocations are mocked — these tests exercise:
    - playbook metadata loading (against real knowledge/signatures/wazuh-rule-5710/)
    - markdown composition
    - investigation.md validation + write (real invlang_validate, not mocked)
    - routing (SCREEN when playbook has_screen, PREDICT default; dedup retired)
    - payload keys required downstream by conclude.py
"""

import json
import sys
import textwrap
from pathlib import Path

import pytest

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from schemas.state import Phase  # noqa: E402
from scripts.handlers import contextualize as ctx_handler  # noqa: E402
from scripts.orchestrate import Context, OrchestrationError  # noqa: E402


# ---------------------------------------------------------------------------
# Canned subagent responses (the prologue is the worked example from SKILL.md
# to guarantee the invlang validator accepts it)
# ---------------------------------------------------------------------------


TICKET_RESPONSE_NO_DEDUP = textwrap.dedent("""
```yaml
ticket_context:
  entities:
    data.srcip: "203.0.113.47"
    data.srcuser: "root"
    agent.name: "web-01.corp.local"
  high_volume_dimensions: []
  repeats: []
  related: []
  dedup_candidate: null
```
""").strip()


TICKET_RESPONSE_WITH_DEDUP = textwrap.dedent("""
```yaml
ticket_context:
  entities:
    data.srcip: "203.0.113.47"
    data.srcuser: "root"
    agent.name: "web-01.corp.local"
  high_volume_dimensions: []
  repeats:
    - count: 1
      first_seen: "2026-04-19T12:00:00Z"
      last_seen: "2026-04-19T12:00:00Z"
      alert_ids: ["1776500000.11111111"]
  related: []
  dedup_candidate: "1776500000.11111111"
```
""").strip()


PROLOGUE_RESPONSE = textwrap.dedent("""
```yaml
prologue:
  vertices:
    - id: v-001
      type: endpoint
      classification: unclassified-endpoint
      identifier: "203.0.113.47"
    - id: v-002
      type: endpoint
      classification: internal-server
      identifier: "web-01.corp.local"
    - id: v-003
      type: identity
      classification: generic-account
      identifier: "root"
      attributes:
        kind: user
  edges:
    - id: e-001
      relation: attempted_auth
      source_vertex: v-001
      target_vertex: v-002
      when:
        timestamp: "2026-04-19T14:22:08Z"
      attributes:
        target_user: "root"
        outcome: failed
      authority:
        kind: siem-event
        source: "wazuh-indexer (rule 5710)"
```
""").strip()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def make_ctx(tmp_path: Path) -> Context:
    run_dir = tmp_path / "run-test"
    run_dir.mkdir()
    alert = {
        "id": "alert-1",
        "ticket_id": "1776600000.12345678",
        "timestamp": "2026-04-19T14:22:08Z",
    }
    (run_dir / "alert.json").write_text(json.dumps(alert))
    return Context(
        run_dir=run_dir,
        signature_id="wazuh-rule-5710",
        ticket_id="1776600000.12345678",
        alert=alert,
    )


def _wire_subagents(monkeypatch, ticket=TICKET_RESPONSE_NO_DEDUP,
                    prologue=PROLOGUE_RESPONSE, preflight=None):
    monkeypatch.setattr(ctx_handler, "_invoke_ticket", lambda _p: ticket)
    monkeypatch.setattr(ctx_handler, "_invoke_prologue", lambda _p: prologue)
    # Default preflight: one reachable system — tests exercising preflight
    # explicitly override via the `preflight` kwarg.
    default_preflight = preflight or {
        "systems": [
            {"system": "wazuh", "connected": True, "error": None},
        ],
    }
    monkeypatch.setattr(ctx_handler, "_run_preflight", lambda: default_preflight)


# ---------------------------------------------------------------------------
# Playbook metadata
# ---------------------------------------------------------------------------


class TestPlaybookMetadata:
    def test_loads_rule_5710_archetypes_and_screen(self):
        meta = ctx_handler.load_playbook_metadata("wazuh-rule-5710")
        assert "monitoring-probe" in meta.archetype_names
        assert "external-bruteforce" in meta.archetype_names
        assert meta.has_screen is True
        assert meta.archetype_story_paths[0].endswith(
            "archetypes/monitoring-probe/story.md"
        )

    def test_missing_playbook_raises(self):
        with pytest.raises(OrchestrationError, match="playbook not found"):
            ctx_handler.load_playbook_metadata("wazuh-rule-does-not-exist")

    def test_benign_action_classes_loaded_for_100001(self):
        meta = ctx_handler.load_playbook_metadata("wazuh-rule-100001")
        # Spot-check: the playbook lists `whoami`, `id`, `hostname`, etc.
        assert "whoami" in meta.benign_action_classes
        assert "id" in meta.benign_action_classes
        assert "cat /etc/os-release" in meta.benign_action_classes

    def test_benign_action_classes_empty_when_section_absent(self):
        meta = ctx_handler.load_playbook_metadata("wazuh-rule-5710")
        # 5710 playbook has no `## Benign action classes` section — list empty.
        assert meta.benign_action_classes == []


# ---------------------------------------------------------------------------
# Routing
# ---------------------------------------------------------------------------


class TestRouting:
    def test_has_screen_routes_to_screen(self, tmp_path, monkeypatch):
        """5710 playbook has a ## Screen section → SCREEN when no dedup."""
        _wire_subagents(monkeypatch)
        ctx = make_ctx(tmp_path)
        result = ctx_handler.handle(ctx)
        assert result.next_phase == Phase.SCREEN
        assert result.payload["dedup"] is False
        assert result.payload["dedup_matched_ticket_id"] is None

    def test_no_screen_section_routes_to_hypothesize(self, tmp_path, monkeypatch):
        _wire_subagents(monkeypatch)
        ctx = make_ctx(tmp_path)

        original = ctx_handler.load_playbook_metadata
        def fake_meta(sig):
            meta = original(sig)
            meta.has_screen = False
            return meta
        monkeypatch.setattr(ctx_handler, "load_playbook_metadata", fake_meta)

        result = ctx_handler.handle(ctx)
        assert result.next_phase == Phase.PREDICT

    def test_dedup_candidate_no_longer_routes_to_conclude(self, tmp_path, monkeypatch):
        """Dedup fast-path is retired — see tasks/dedup-fast-path.md. A
        dedup_candidate in the ticket-context payload is kept as telemetry but
        must not steer routing: the 5710 playbook has a Screen section so we
        still go to SCREEN."""
        _wire_subagents(monkeypatch, ticket=TICKET_RESPONSE_WITH_DEDUP)
        ctx = make_ctx(tmp_path)

        result = ctx_handler.handle(ctx)
        assert result.next_phase == Phase.SCREEN
        assert result.payload["dedup"] is False
        assert result.payload["dedup_matched_ticket_id"] == "1776500000.11111111"


# ---------------------------------------------------------------------------
# Investigation.md composition + write
# ---------------------------------------------------------------------------


class TestInvestigationWrite:
    def test_writes_contextualize_section_with_prologue(self, tmp_path, monkeypatch):
        _wire_subagents(monkeypatch)
        ctx = make_ctx(tmp_path)

        ctx_handler.handle(ctx)

        inv = (ctx.run_dir / "investigation.md").read_text()
        assert "## CONTEXTUALIZE" in inv
        assert "**Alert:** 1776600000.12345678 — wazuh-rule-5710" in inv
        assert "```yaml" in inv
        assert "prologue:" in inv
        assert "v-001" in inv
        assert "attempted_auth" in inv

    def test_initial_write_stamps_created_header(self, tmp_path, monkeypatch):
        """First write to investigation.md prepends a `<!-- created: ... -->`
        header. The corpus loader's recency filter reads this back."""
        from scripts.invlang.corpus import _read_created_header
        _wire_subagents(monkeypatch)
        ctx = make_ctx(tmp_path)
        ctx_handler.handle(ctx)
        inv = (ctx.run_dir / "investigation.md").read_text()
        assert inv.startswith("<!-- created: ")
        ts = _read_created_header(inv)
        assert ts is not None
        # Parses cleanly as ISO-8601 with offset.
        from datetime import datetime
        datetime.fromisoformat(ts)

    def test_markdown_omits_archetype_block(self, tmp_path, monkeypatch):
        """Archetype ranking moved to the REPORT phase. The CONTEXTUALIZE
        markdown must not carry archetype candidate / ruled-out / adversarial
        lines — those biased the investigation in the old flow."""
        _wire_subagents(monkeypatch)
        ctx = make_ctx(tmp_path)
        ctx_handler.handle(ctx)
        inv = (ctx.run_dir / "investigation.md").read_text()
        assert "Plausible archetypes" not in inv
        assert "Ruled-out archetypes" not in inv
        assert "Adversarial archetype" not in inv

    def test_markdown_surfaces_partial_query_failure(self, tmp_path, monkeypatch):
        ticket = textwrap.dedent("""
        ```yaml
        ticket_context:
          entities:
            data.srcip: "203.0.113.47"
          high_volume_dimensions: []
          repeats: []
          related: []
          dedup_candidate: null
          queries_partial: "data.srcuser dimension timed out"
        ```
        """).strip()
        _wire_subagents(monkeypatch, ticket=ticket)
        ctx = make_ctx(tmp_path)
        ctx_handler.handle(ctx)
        inv = (ctx.run_dir / "investigation.md").read_text()
        assert "data.srcuser dimension timed out" in inv


# ---------------------------------------------------------------------------
# Preflight integration
# ---------------------------------------------------------------------------


class TestPreflightIntegration:
    def test_all_reachable_summarized(self, tmp_path, monkeypatch):
        _wire_subagents(monkeypatch, preflight={
            "systems": [
                {"system": "wazuh", "connected": True, "error": None},
                {"system": "host_query", "connected": True, "error": None},
            ],
        })
        ctx = make_ctx(tmp_path)
        ctx_handler.handle(ctx)
        inv = (ctx.run_dir / "investigation.md").read_text()
        assert "all systems reachable" in inv
        assert "wazuh" in inv and "host_query" in inv

    def test_degraded_system_named(self, tmp_path, monkeypatch):
        _wire_subagents(monkeypatch, preflight={
            "systems": [
                {"system": "wazuh", "connected": False,
                 "error": "health-check timed out after 15s"},
                {"system": "host_query", "connected": True, "error": None},
            ],
        })
        ctx = make_ctx(tmp_path)
        ctx_handler.handle(ctx)
        inv = (ctx.run_dir / "investigation.md").read_text()
        assert "degraded" in inv
        assert "wazuh" in inv
        assert "health-check timed out" in inv

    def test_preflight_failure_does_not_break_handler(self, tmp_path, monkeypatch):
        _wire_subagents(monkeypatch, preflight={
            "error": "preflight JSON parse failed: ...",
            "systems": [],
        })
        ctx = make_ctx(tmp_path)
        ctx_handler.handle(ctx)  # must not raise
        inv = (ctx.run_dir / "investigation.md").read_text()
        assert "preflight skipped" in inv


# ---------------------------------------------------------------------------
# Payload contract with conclude.py
# ---------------------------------------------------------------------------


class TestPayloadContract:
    """The `dedup` + `dedup_matched_ticket_id` keys are retained as telemetry
    for future re-introduction of the dedup fast-path (tasks/dedup-fast-path.md).
    They MUST stay in the payload, but `dedup` is always False while the
    fast-path is retired."""

    def test_payload_has_dedup_false_when_no_dedup(self, tmp_path, monkeypatch):
        _wire_subagents(monkeypatch)
        ctx = make_ctx(tmp_path)
        result = ctx_handler.handle(ctx)
        assert "dedup" in result.payload
        assert result.payload["dedup"] is False
        assert result.payload["dedup_matched_ticket_id"] is None

    def test_payload_has_dedup_false_even_when_candidate_present(self, tmp_path, monkeypatch):
        _wire_subagents(monkeypatch, ticket=TICKET_RESPONSE_WITH_DEDUP)
        ctx = make_ctx(tmp_path)
        result = ctx_handler.handle(ctx)
        assert result.payload["dedup"] is False
        assert result.payload["dedup_matched_ticket_id"] == "1776500000.11111111"

    def test_payload_has_no_archetype_keys(self, tmp_path, monkeypatch):
        """Archetype dispatch moved to the REPORT phase — CONTEXTUALIZE's
        payload must not carry `archetype_ranking` or `adversarial_archetype`."""
        _wire_subagents(monkeypatch)
        ctx = make_ctx(tmp_path)
        result = ctx_handler.handle(ctx)
        assert "archetype_ranking" not in result.payload
        assert "adversarial_archetype" not in result.payload


# ---------------------------------------------------------------------------
# Validation failure
# ---------------------------------------------------------------------------


class TestValidationFailure:
    def test_invalid_prologue_yaml_raises(self, tmp_path, monkeypatch):
        # Prologue missing top-level `prologue:` key — our _extract_yaml_block
        # should raise on that before the validator even sees the text.
        bad_prologue = textwrap.dedent("""
        ```yaml
        # no `prologue:` wrapper
        vertices: []
        edges: []
        ```
        """).strip()
        _wire_subagents(monkeypatch, prologue=bad_prologue)
        ctx = make_ctx(tmp_path)
        with pytest.raises(OrchestrationError, match="prologue"):
            ctx_handler.handle(ctx)

    def test_guard_on_empty_ticket_id(self, tmp_path):
        run_dir = tmp_path / "run-test"
        run_dir.mkdir()
        ctx = Context(
            run_dir=run_dir,
            signature_id="wazuh-rule-5710",
            ticket_id="",
            alert={"id": "alert-1"},
        )
        with pytest.raises(OrchestrationError, match="ticket_id"):
            ctx_handler.handle(ctx)
