"""Unit tests for the GATHER phase handler.

Subagent invocation is mocked via `monkeypatch.setattr` on the module-level
`_invoke_gather` / `_invoke_gather_composite` wrappers. The tests cover:

    - single-lead happy path (template present → `gather` subagent)
    - composite-by-inference (no template → `gather-composite` ad-hoc)
    - escalate-trigger fallback (single → composite redispatch)
    - silent-termination recovery via checkpoint (`status: complete`)
    - silent-termination recovery via resume re-dispatch
    - invlang validation failure on appended section
    - routing: always Phase.ANALYZE
    - PREDICT-payload precondition checks
    - scope derivation (vendor, reporting_agent, entity_bindings, window)
"""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path

import pytest
import yaml

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from schemas.state import Phase  # noqa: E402
from scripts.handlers import gather as gather_handler  # noqa: E402
from scripts.orchestrate import Context, OrchestrationError  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def make_ctx(
    tmp_path: Path,
    *,
    alert: dict | None = None,
    selected_lead: str = "authentication-history",
    loop_n: int = 1,
    history: list[str] | None = None,
    existing_investigation: str | None = None,
) -> Context:
    run_dir = tmp_path / "run-test"
    run_dir.mkdir()
    if existing_investigation is None:
        existing_investigation = "## CONTEXTUALIZE\n\nsome existing content\n"
    (run_dir / "investigation.md").write_text(existing_investigation)

    default_alert = {
        "agent": {"name": "target-endpoint", "id": "002"},
        "data": {"srcip": "172.22.0.10", "srcuser": "nagios", "srcport": "44688"},
        "@timestamp": "2026-04-20T19:25:00.000Z",
    }
    ctx = Context(
        run_dir=run_dir,
        signature_id="wazuh-rule-5710",
        ticket_id="SEC-2026-042",
        alert=alert if alert is not None else default_alert,
        history=history or [
            Phase.CONTEXTUALIZE.value,
            Phase.PREDICT.value,
            Phase.GATHER.value,
        ],
        current_phase=Phase.GATHER,
        outputs={
            Phase.PREDICT: {
                "mode": "fork",
                "selected_lead": selected_lead,
                "loop_n": loop_n,
                "block_type": "hypothesize",
            },
        },
    )
    return ctx


def stub_invoke(captured: list[str], responses: list[str]):
    iterator = iter(responses)

    def fn(prompt, *, timeout=None):
        captured.append(prompt)
        try:
            return next(iterator)
        except StopIteration:
            raise AssertionError(
                "stub exhausted — handler called subagent more times than scripted"
            )
    return fn


_SINGLE_FINDING = textwrap.dedent("""
```yaml
result: finding
lead: "authentication-history"
reporting_agent: "target-endpoint"
query: "rule.groups:sshd AND data.srcip:172.22.0.10"
time_range: {start: "2026-04-20T18:25:00Z", end: "2026-04-20T19:25:00Z"}
health_probe: null
characterization:
  distinct_users: 1
  distinct_srcports: 1
  total_events: 11
  time_distribution: "periodic, 5min intervals ±3s"
notes: ""
```
""").strip()


_SINGLE_ESCALATE_EMPTY = textwrap.dedent("""
```yaml
result: escalate
trigger: empty_result
health_probe: null
context: "rule.groups:sshd AND data.srcip:172.22.0.10 returned 0 events"
```
""").strip()


_COMPOSITE_OK = textwrap.dedent("""
```yaml
gather_composite:
  mode: "redispatch"
  time_range: {start: "2026-04-20T18:25:00Z", end: "2026-04-20T19:25:00Z"}
  leads:
    - lead: "authentication-history"
      reporting_agent: "target-endpoint"
      query: "rule.groups:sshd AND data.srcuser:nagios"
      query_source: "template"
      entity_bindings: {user: "nagios", host: "target-endpoint"}
      refinements_applied: "original srcip empty; rebound to srcuser"
      health_probe: null
      characterization:
        distinct_sources: 3
        total_events: 47
      status: ok
      status_detail: ""
  cross_lead_notes: ""
  notes: ""
```
""").strip()


_COMPOSITE_AD_HOC = textwrap.dedent("""
```yaml
gather_composite:
  mode: "ad-hoc"
  time_range: {start: "2026-04-20T18:25:00Z", end: "2026-04-20T19:25:00Z"}
  leads:
    - lead: "custom-query"
      reporting_agent: "target-endpoint"
      query: "freeform query"
      query_source: "ad-hoc"
      entity_bindings: {}
      refinements_applied: ""
      health_probe: null
      characterization:
        result_count: 5
      status: ok
      status_detail: ""
  cross_lead_notes: ""
  notes: ""
```
""").strip()


# ---------------------------------------------------------------------------
# Scope derivation
# ---------------------------------------------------------------------------


class TestScopeDerivation:
    def test_vendor_from_signature_prefix(self):
        assert gather_handler._derive_vendor("wazuh-rule-5710") == "wazuh"
        assert gather_handler._derive_vendor("crowdstrike-detect-42") == "crowdstrike"

    def test_vendor_missing_separator_raises(self):
        with pytest.raises(OrchestrationError, match="cannot derive vendor"):
            gather_handler._derive_vendor("rule5710")

    def test_reporting_agent_from_agent_name(self):
        alert = {"agent": {"name": "host-1"}}
        assert gather_handler._derive_reporting_agent(alert) == "host-1"

    def test_reporting_agent_falls_back_to_predecoder(self):
        alert = {"predecoder": {"hostname": "host-pre"}}
        assert gather_handler._derive_reporting_agent(alert) == "host-pre"

    def test_reporting_agent_missing_raises(self):
        with pytest.raises(OrchestrationError):
            gather_handler._derive_reporting_agent({})

    def test_incident_window_from_atsign_timestamp(self):
        alert = {"@timestamp": "2026-04-20T19:25:00.000Z"}
        start, end = gather_handler._derive_incident_window(alert)
        assert end == "2026-04-20T19:25:00Z"
        assert start == "2026-04-20T18:25:00Z"

    def test_incident_window_falls_back_to_now_when_missing(self):
        start, end = gather_handler._derive_incident_window({})
        # Just verify ISO shape and ordering — not the exact value.
        assert start < end
        assert end.endswith("Z")

    def test_entity_bindings_from_template(self, tmp_path, monkeypatch):
        # authentication-history has entity_fields: ip/user/host in its real
        # template. Use the real knowledge tree.
        alert = {
            "data": {"srcip": "10.0.0.1", "srcuser": "alice"},
            "agent": {"name": "host-x"},
        }
        bindings, exists = gather_handler._derive_entity_bindings(
            alert, "authentication-history", "wazuh",
        )
        assert exists is True
        assert bindings == {"ip": "10.0.0.1", "user": "alice", "host": "host-x"}

    def test_entity_bindings_absent_template_returns_false(self):
        bindings, exists = gather_handler._derive_entity_bindings(
            {}, "made-up-lead", "wazuh",
        )
        assert exists is False
        assert bindings == {}


# ---------------------------------------------------------------------------
# Dispatch routing
# ---------------------------------------------------------------------------


class TestDispatchRouting:
    def test_single_lead_with_template_dispatches_gather(self, tmp_path, monkeypatch):
        ctx = make_ctx(tmp_path, selected_lead="authentication-history")
        captured_single: list[str] = []
        captured_composite: list[str] = []
        monkeypatch.setattr(
            gather_handler, "_invoke_gather",
            stub_invoke(captured_single, [_SINGLE_FINDING]),
        )
        monkeypatch.setattr(
            gather_handler, "_invoke_gather_composite",
            stub_invoke(captured_composite, []),
        )

        result = gather_handler.handle(ctx)

        assert result.next_phase == Phase.ANALYZE
        assert result.payload["mode"] == "single"
        assert result.payload["status"] == "ok"
        assert result.payload["characterization"]["total_events"] == 11
        assert len(captured_single) == 1
        assert len(captured_composite) == 0
        # Prompt carries the expected scope.
        prompt = captured_single[0]
        assert "lead_name=authentication-history" in prompt
        assert "vendor=wazuh" in prompt
        assert "reporting_agent=target-endpoint" in prompt
        assert "incident_end=2026-04-20T19:25:00Z" in prompt
        assert "entity_bindings=" in prompt
        assert "loop_n=1" in prompt

    def test_missing_template_dispatches_composite_ad_hoc(
        self, tmp_path, monkeypatch,
    ):
        ctx = make_ctx(tmp_path, selected_lead="nonexistent-lead")
        captured_single: list[str] = []
        captured_composite: list[str] = []
        monkeypatch.setattr(
            gather_handler, "_invoke_gather",
            stub_invoke(captured_single, []),
        )
        monkeypatch.setattr(
            gather_handler, "_invoke_gather_composite",
            stub_invoke(captured_composite, [_COMPOSITE_AD_HOC]),
        )

        result = gather_handler.handle(ctx)

        assert result.next_phase == Phase.ANALYZE
        assert result.payload["mode"] == "composite"
        assert len(captured_single) == 0
        assert len(captured_composite) == 1
        assert "mode=ad-hoc" in captured_composite[0]


# ---------------------------------------------------------------------------
# Escalate-trigger fallback
# ---------------------------------------------------------------------------


class TestEscalateFallback:
    @pytest.mark.parametrize(
        "trigger",
        sorted(gather_handler._COMPOSITE_FALLBACK_TRIGGERS),
    )
    def test_every_fallback_trigger_re_dispatches_composite(
        self, tmp_path, monkeypatch, trigger,
    ):
        ctx = make_ctx(tmp_path, selected_lead="authentication-history")
        escalate = textwrap.dedent(f"""
        ```yaml
        result: escalate
        trigger: {trigger}
        health_probe: null
        context: "test-trigger {trigger}"
        ```
        """).strip()
        captured_single: list[str] = []
        captured_composite: list[str] = []
        monkeypatch.setattr(
            gather_handler, "_invoke_gather",
            stub_invoke(captured_single, [escalate]),
        )
        monkeypatch.setattr(
            gather_handler, "_invoke_gather_composite",
            stub_invoke(captured_composite, [_COMPOSITE_OK]),
        )

        result = gather_handler.handle(ctx)

        assert result.next_phase == Phase.ANALYZE
        assert result.payload["mode"] == "composite"
        assert len(captured_single) == 1
        assert len(captured_composite) == 1
        # Redispatch carries the composite `mode=redispatch`.
        assert "mode=redispatch" in captured_composite[0]

    def test_unrecognized_escalate_trigger_surfaces_as_payload(
        self, tmp_path, monkeypatch,
    ):
        ctx = make_ctx(tmp_path, selected_lead="authentication-history")
        escalate = textwrap.dedent("""
        ```yaml
        result: escalate
        trigger: some_unknown_trigger
        context: "unknown"
        ```
        """).strip()
        monkeypatch.setattr(
            gather_handler, "_invoke_gather",
            stub_invoke([], [escalate]),
        )
        monkeypatch.setattr(
            gather_handler, "_invoke_gather_composite",
            stub_invoke([], []),
        )

        result = gather_handler.handle(ctx)

        assert result.next_phase == Phase.ANALYZE
        assert result.payload["mode"] == "single"
        assert result.payload["status"] == "escalate"


# ---------------------------------------------------------------------------
# Silent-termination recovery
# ---------------------------------------------------------------------------


class TestRecovery:
    def test_truncated_single_with_complete_checkpoint_transcribes(
        self, tmp_path, monkeypatch,
    ):
        ctx = make_ctx(tmp_path, selected_lead="authentication-history", loop_n=2)
        ckpt_dir = ctx.run_dir / "subagent_checkpoints"
        ckpt_dir.mkdir()
        ckpt = {
            "subagent": "gather",
            "loop_n": 2,
            "lead_name": "authentication-history",
            "status": "complete",
            "result": {
                "kind": "finding",
                "query": "cached-query",
                "health_probe": None,
                "characterization": {"distinct_users": 5, "total_events": 99},
                "notes": "",
            },
        }
        (ckpt_dir / "gather-loop-2-authentication-history.yaml").write_text(
            yaml.safe_dump(ckpt),
        )

        # Subagent returns an empty / truncated stdout.
        monkeypatch.setattr(
            gather_handler, "_invoke_gather",
            stub_invoke([], ["(subagent terminated silently)"]),
        )

        result = gather_handler.handle(ctx)

        assert result.payload["mode"] == "single"
        assert result.payload["status"] == "ok"
        assert result.payload["characterization"]["total_events"] == 99

    def test_truncated_single_with_in_progress_checkpoint_resumes(
        self, tmp_path, monkeypatch,
    ):
        ctx = make_ctx(tmp_path, selected_lead="authentication-history", loop_n=2)
        ckpt_dir = ctx.run_dir / "subagent_checkpoints"
        ckpt_dir.mkdir()
        ckpt = {
            "subagent": "gather",
            "loop_n": 2,
            "lead_name": "authentication-history",
            "status": "in_progress",
            "result": {"kind": "pending"},
        }
        (ckpt_dir / "gather-loop-2-authentication-history.yaml").write_text(
            yaml.safe_dump(ckpt),
        )
        captured: list[str] = []
        monkeypatch.setattr(
            gather_handler, "_invoke_gather",
            stub_invoke(captured, ["(truncated)", _SINGLE_FINDING]),
        )

        result = gather_handler.handle(ctx)

        assert result.payload["characterization"]["total_events"] == 11
        assert len(captured) == 2
        assert "resume_from_checkpoint=true" in captured[1]

    def test_truncated_single_no_checkpoint_raises(self, tmp_path, monkeypatch):
        ctx = make_ctx(tmp_path, selected_lead="authentication-history")
        monkeypatch.setattr(
            gather_handler, "_invoke_gather",
            stub_invoke([], ["(truncated)"]),
        )
        with pytest.raises(OrchestrationError, match="cannot recover"):
            gather_handler.handle(ctx)


# ---------------------------------------------------------------------------
# Output & routing
# ---------------------------------------------------------------------------


class TestHandleOutput:
    def test_appends_markdown_to_investigation(self, tmp_path, monkeypatch):
        ctx = make_ctx(tmp_path, selected_lead="authentication-history", loop_n=3)
        monkeypatch.setattr(
            gather_handler, "_invoke_gather",
            stub_invoke([], [_SINGLE_FINDING]),
        )

        gather_handler.handle(ctx)

        text = (ctx.run_dir / "investigation.md").read_text()
        assert "## GATHER (loop 3)" in text
        assert "**Lead:** authentication-history" in text
        assert "**Status:** ok" in text
        assert "total_events: 11" in text
        # No YAML fence for the gather: block at this phase — ANALYZE owns it.
        assert "```yaml" not in text.split("## GATHER")[-1]

    def test_routes_to_analyze_always(self, tmp_path, monkeypatch):
        ctx = make_ctx(tmp_path, selected_lead="authentication-history")
        monkeypatch.setattr(
            gather_handler, "_invoke_gather",
            stub_invoke([], [_SINGLE_FINDING]),
        )
        result = gather_handler.handle(ctx)
        assert result.next_phase == Phase.ANALYZE


# ---------------------------------------------------------------------------
# Precondition failures
# ---------------------------------------------------------------------------


class TestPreconditions:
    def test_missing_hypothesize_payload_raises(self, tmp_path):
        ctx = make_ctx(tmp_path)
        ctx.outputs.pop(Phase.PREDICT, None)
        with pytest.raises(OrchestrationError, match="PREDICT payload not found"):
            gather_handler.handle(ctx)

    def test_empty_selected_lead_raises(self, tmp_path):
        ctx = make_ctx(tmp_path)
        ctx.outputs[Phase.PREDICT]["selected_lead"] = ""
        with pytest.raises(OrchestrationError, match="selected_lead"):
            gather_handler.handle(ctx)

    def test_non_int_loop_n_raises(self, tmp_path):
        ctx = make_ctx(tmp_path)
        ctx.outputs[Phase.PREDICT]["loop_n"] = "2"
        with pytest.raises(OrchestrationError, match="int loop_n"):
            gather_handler.handle(ctx)
