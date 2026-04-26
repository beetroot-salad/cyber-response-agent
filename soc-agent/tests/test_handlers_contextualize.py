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
import uuid
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


def _parse_prompt_fields(prompt: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in prompt.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            fields[k.strip()] = v.strip()
    return fields


def _stage_record_file(run_dir_str: str, record: dict | None) -> str:
    """Simulate the save_raw_tool_output hook: write the LookupContract JSON
    to a unique file under {run_dir}/raw_query_outputs and return its
    absolute path.
    """
    out_dir = Path(run_dir_str) / "raw_query_outputs"
    out_dir.mkdir(parents=True, exist_ok=True)
    nonce = uuid.uuid4().hex[:8]
    path = out_dir / f"0-{nonce}.json"
    payload = {
        "found": record is not None,
        "record": record,
        "key_field": "ip",
        "key_value": "stub",
        "error": None,
    }
    path.write_text(json.dumps(payload))
    return str(path)


def _envelope(lead: str, target: str, target_kind: str, classification: str,
              record_path: str, observation: str) -> str:
    return textwrap.dedent(f"""
    ```yaml
    contextualize_lead:
      lead_name: {lead}
      target: "{target}"
      target_kind: "{target_kind}"
      status: ok
      updates:
        classification: {classification}
        record_path: "{record_path}"
      observation: "{observation}"
    ```
    """).strip()


def _default_contextualize_lead(prompt: str) -> str:
    """Generic mock for `_invoke_contextualize_lead`.

    Stages a LookupContract JSON file (mimicking the save_raw_tool_output
    hook) and emits an envelope referencing it via `record_path`. Tests that
    need a specific record or classification override `contextualize_lead`
    in `_wire_subagents`.
    """
    fields = _parse_prompt_fields(prompt)
    lead = fields.get("lead_name", "")
    target = fields.get("target_vertex_id", "")
    target_kind = fields.get("target_vertex_kind", "")
    run_dir = fields.get("run_dir", "")
    if lead == "endpoint-context":
        record = {"hostname": "stub", "role": "workload",
                  "owner_team": "platform-sre", "env": "prod"}
        path = _stage_record_file(run_dir, record)
        return _envelope(
            lead, target, target_kind, "internal-server", path,
            f"stub endpoint enrichment for {target}",
        )
    if lead == "identity-context":
        record = {"display_name": "Stub User", "type": "service",
                  "owner_team": "platform-sre", "mfa": False}
        path = _stage_record_file(run_dir, record)
        return _envelope(
            lead, target, target_kind, "service-account", path,
            f"stub identity enrichment for {target}",
        )
    # Unknown lead — emit a minimal noop envelope (no record).
    path = _stage_record_file(run_dir, None)
    return _envelope(lead, target, target_kind, "unknown", path, "noop")


def _wire_subagents(monkeypatch, ticket=TICKET_RESPONSE_NO_DEDUP,
                    prologue=PROLOGUE_RESPONSE, preflight=None,
                    contextualize_lead=None):
    monkeypatch.setattr(ctx_handler, "_invoke_ticket", lambda _p: ticket)
    monkeypatch.setattr(ctx_handler, "_invoke_prologue", lambda _p: prologue)
    monkeypatch.setattr(
        ctx_handler, "_invoke_contextualize_lead",
        contextualize_lead or _default_contextualize_lead,
    )
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
        # Prologue missing top-level `prologue:` key — the handler should
        # raise on that before the validator even sees the text.
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


# ---------------------------------------------------------------------------
# Contextualize-leads dispatch
# ---------------------------------------------------------------------------


class TestContextualizeLeads:
    """The 5710 playbook now declares ## Contextualize leads. Each lead runs
    once per matching prologue vertex and updates the vertex in-memory before
    the prologue YAML is serialized to investigation.md."""

    def test_playbook_metadata_carries_contextualize_leads(self):
        meta = ctx_handler.load_playbook_metadata("wazuh-rule-5710")
        assert "endpoint-context" in meta.contextualize_leads
        assert "identity-context" in meta.contextualize_leads

    def test_signature_without_section_has_empty_list(self):
        meta = ctx_handler.load_playbook_metadata("wazuh-rule-100001")
        assert meta.contextualize_leads == []

    def test_dispatches_once_per_matching_vertex(self, tmp_path, monkeypatch):
        """5710's prologue has 2 endpoint vertices + 1 identity vertex →
        endpoint-context fires twice, identity-context fires once."""
        captured: list[str] = []

        def capture(prompt: str) -> str:
            captured.append(prompt)
            return _default_contextualize_lead(prompt)

        _wire_subagents(monkeypatch, contextualize_lead=capture)
        ctx = make_ctx(tmp_path)
        ctx_handler.handle(ctx)

        # 2 endpoints + 1 identity = 3 dispatches.
        assert len(captured) == 3
        endpoint_calls = [p for p in captured if "lead_name=endpoint-context" in p]
        identity_calls = [p for p in captured if "lead_name=identity-context" in p]
        assert len(endpoint_calls) == 2
        assert len(identity_calls) == 1

    def test_lead_updates_merge_into_prologue_vertices(self, tmp_path, monkeypatch):
        """Lead `updates` override the prologue subagent's initial
        classification, and the verbatim record from the saved JSON file
        lands under vertex.attributes.{cmdb,idp}_record."""

        def deterministic_lead(prompt: str) -> str:
            fields = _parse_prompt_fields(prompt)
            lead = fields.get("lead_name", "")
            target = fields.get("target_vertex_id", "")
            ident = fields.get("target_identifier", "")
            run_dir = fields.get("run_dir", "")
            if lead == "endpoint-context":
                if ident == "203.0.113.47":
                    cls = "external"
                    record = {"hostname": "unknown", "role": "external", "env": "n/a"}
                else:
                    cls = "internal-server"
                    record = {"hostname": "web-01", "role": "workload", "env": "prod"}
                path = _stage_record_file(run_dir, record)
                return _envelope(lead, target, "endpoint", cls, path,
                                 f"{ident} -> {cls}")
            if lead == "identity-context":
                path = _stage_record_file(run_dir, None)
                return _envelope(lead, target, "identity", "generic-account",
                                 path,
                                 f"{ident} -> generic-account (no IdP record)")
            return ""

        _wire_subagents(monkeypatch, contextualize_lead=deterministic_lead)
        ctx = make_ctx(tmp_path)
        ctx_handler.handle(ctx)

        inv = (ctx.run_dir / "investigation.md").read_text()

        # Vertex classifications were overridden by the contextualize-leads.
        assert "classification: external" in inv          # v-001 from lead
        assert "classification: internal-server" in inv   # v-002 from lead
        assert "classification: generic-account" in inv   # v-003 from lead

        # CMDB records landed under vertex.attributes.cmdb_record from the
        # saved JSON file (verbatim, handler-extracted).
        assert "cmdb_record:" in inv
        assert "hostname: web-01" in inv
        assert "role: external" in inv

        # IdP record was null in the saved JSON — null gets serialized.
        assert "idp_record: null" in inv

        # Markdown audit summary lists the lead invocations.
        assert "**Contextualize leads:**" in inv
        assert "endpoint-context" in inv
        assert "identity-context" in inv

    def test_signature_without_contextualize_leads_skips_dispatch(
        self, tmp_path, monkeypatch,
    ):
        """wazuh-rule-100001 has no ## Contextualize leads section → no
        dispatches; the markdown omits the audit bullet."""
        captured: list[str] = []

        def capture(prompt: str) -> str:
            captured.append(prompt)
            return ""  # never reached

        _wire_subagents(monkeypatch, contextualize_lead=capture)
        ctx = make_ctx(tmp_path)
        ctx.signature_id = "wazuh-rule-100001"
        ctx_handler.handle(ctx)

        assert captured == []
        inv = (ctx.run_dir / "investigation.md").read_text()
        assert "**Contextualize leads:**" not in inv

    def test_lead_targeting_unknown_vertex_id_raises(self, tmp_path, monkeypatch):
        def bad_lead(_prompt: str) -> str:
            return textwrap.dedent("""
            ```yaml
            contextualize_lead:
              lead_name: endpoint-context
              target: v-999
              target_kind: endpoint
              status: ok
              updates: {classification: x}
              observation: "lying about the target"
            ```
            """).strip()

        _wire_subagents(monkeypatch, contextualize_lead=bad_lead)
        ctx = make_ctx(tmp_path)
        with pytest.raises(OrchestrationError, match="v-999"):
            ctx_handler.handle(ctx)

    def test_missing_record_path_file_raises(self, tmp_path, monkeypatch):
        """Handler reads `record_path` from disk and merges the verbatim
        record. A bogus path is a loud failure — never silently skipped."""

        def lying_lead(prompt: str) -> str:
            fields = _parse_prompt_fields(prompt)
            lead = fields.get("lead_name", "")
            target = fields.get("target_vertex_id", "")
            target_kind = fields.get("target_vertex_kind", "")
            return _envelope(
                lead, target, target_kind, "x",
                "/tmp/nope-does-not-exist.json", "lying about path",
            )

        _wire_subagents(monkeypatch, contextualize_lead=lying_lead)
        ctx = make_ctx(tmp_path)
        with pytest.raises(OrchestrationError, match="record_path"):
            ctx_handler.handle(ctx)

    def test_errored_lead_skipped_without_breaking_handler(
        self, tmp_path, monkeypatch,
    ):
        def errored_lead(prompt: str) -> str:
            if "lead_name=endpoint-context" in prompt:
                return textwrap.dedent("""
                ```yaml
                contextualize_lead:
                  lead_name: endpoint-context
                  target: v-001
                  target_kind: endpoint
                  status: error
                  reason: "asset CLI not configured"
                ```
                """).strip()
            return _default_contextualize_lead(prompt)

        _wire_subagents(monkeypatch, contextualize_lead=errored_lead)
        ctx = make_ctx(tmp_path)
        ctx_handler.handle(ctx)  # must not raise

        inv = (ctx.run_dir / "investigation.md").read_text()
        # The audit summary surfaces the error; identity-context still ran.
        assert "endpoint-context → v-001: error — asset CLI not configured" in inv
        assert "identity-context" in inv

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
