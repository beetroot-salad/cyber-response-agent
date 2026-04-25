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
        # Default includes a declared hypothesis so ANALYZE is the routing
        # target. Tests exercising the shape-E short-circuit pass their own
        # `existing_investigation` without a `hypothesize:` block.
        existing_investigation = textwrap.dedent("""
            ## CONTEXTUALIZE

            some existing content

            ```yaml
            hypothesize:
              hypotheses:
                - id: h-001
                  name: "?default-test-hypothesis"
            ```
        """).strip() + "\n"
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
                "selected_lead": selected_lead,
                "loop_n": loop_n,
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
gather:
  loop: 1
  mode: "single"
  leads:
    - id: "l-001"
      name: "authentication-history"
      reporting_agent: "target-endpoint"
      status: ok
      query:
        system: "wazuh-indexer"
        template: "source-ip-lookup"
        query: "rule.groups:sshd AND data.srcip:172.22.0.10"
        time_window: {start: "2026-04-20T18:25:00Z", end: "2026-04-20T19:25:00Z"}
        substitutions: {ip: "172.22.0.10"}
      health_probe: null
      characterization:
        distinct_users: 1
        distinct_srcports: 1
        total_events: 11
        time_distribution: "periodic, 5min intervals ±3s"
      baseline:
        scope: same-entity-7d
        distinct_users: 1
        distinct_srcports: 1
        total_events: 320
        time_distribution: "periodic, 5min ±3s, continuous"
      notes: ""
      raw:
        siem_response: |
          [{"ts": "2026-04-20T19:20:00Z", "srcip": "172.22.0.10", "user": "nagios"}]
```
""").strip()


_SINGLE_ESCALATE_EMPTY = textwrap.dedent("""
```yaml
gather:
  loop: 1
  mode: "single"
  leads:
    - id: "l-001"
      name: "authentication-history"
      reporting_agent: "target-endpoint"
      status: error
      escalate_trigger: empty_result
      escalate_context: "rule.groups:sshd AND data.srcip:172.22.0.10 returned 0 events"
      health_probe: null
      raw:
        siem_response: ""
```
""").strip()


_COMPOSITE_OK = textwrap.dedent("""
```yaml
gather:
  loop: 1
  mode: "redispatch"
  leads:
    - id: "l-001"
      name: "authentication-history"
      reporting_agent: "target-endpoint"
      status: ok
      status_detail: ""
      query:
        system: "wazuh-indexer"
        query: "rule.groups:sshd AND data.srcuser:nagios"
        query_source: "template"
        substitutions: {user: "nagios", host: "target-endpoint"}
        refinements_applied: "original srcip empty; rebound to srcuser"
        time_window: {start: "2026-04-20T18:25:00Z", end: "2026-04-20T19:25:00Z"}
      health_probe: null
      characterization:
        distinct_sources: 3
        total_events: 47
      baseline:
        scope: same-entity-7d
        distinct_sources: 3
        total_events: 700
      raw:
        siem_response: "(47 rows)"
  cross_lead_notes: ""
  notes: ""
```
""").strip()


_COMPOSITE_AD_HOC = textwrap.dedent("""
```yaml
gather:
  loop: 1
  mode: "ad-hoc"
  leads:
    - id: "l-001"
      name: "nonexistent-lead"
      reporting_agent: "target-endpoint"
      status: ok
      status_detail: ""
      query:
        system: "wazuh-indexer"
        query: "freeform query"
        query_source: "ad-hoc"
        substitutions: {}
        refinements_applied: "no definition; constructed ad-hoc from slug"
        time_window: {start: "2026-04-20T18:25:00Z", end: "2026-04-20T19:25:00Z"}
      health_probe: null
      characterization:
        result_count: 5
      raw:
        siem_response: "(5 rows)"
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

    def test_scope_override_expands_window_hours(self):
        """PREDICT's routing.scope_override.window_hours replaces the default
        1h lookback. Anchor defaults to 'alert' (window ends at @timestamp)."""
        alert = {"@timestamp": "2026-04-20T19:25:00.000Z"}
        start, end = gather_handler._derive_incident_window(
            alert, scope_override={"window_hours": 24, "anchor": "alert"},
        )
        assert end == "2026-04-20T19:25:00Z"
        # 24h before the alert timestamp:
        assert start == "2026-04-19T19:25:00Z"

    def test_scope_override_anchor_now_ignores_alert_timestamp(self):
        """anchor=now moves the window end to the current wall clock —
        useful for since-last-baseline semantics where the alert timestamp
        is not the right anchor."""
        alert = {"@timestamp": "2026-04-20T19:25:00.000Z"}
        start, end = gather_handler._derive_incident_window(
            alert, scope_override={"window_hours": 48, "anchor": "now"},
        )
        # End is now (wall-clock), not the alert timestamp. Just assert the
        # ordering + that the alert timestamp didn't leak through.
        assert start < end
        assert end != "2026-04-20T19:25:00Z"

    def test_no_scope_override_preserves_default_1h(self):
        """None-override path preserves the documented 1h alert-anchored
        window — the test_incident_window_from_atsign_timestamp invariant
        still holds for the no-override case."""
        alert = {"@timestamp": "2026-04-20T19:25:00.000Z"}
        start, end = gather_handler._derive_incident_window(alert, scope_override=None)
        assert end == "2026-04-20T19:25:00Z"
        assert start == "2026-04-20T18:25:00Z"


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
        # `health_probe_verdict` is emitted under `status: probe_broken`;
        # every other fallback trigger is emitted under `status: error`.
        status = "probe_broken" if trigger == "health_probe_verdict" else "error"
        escalate = textwrap.dedent(f"""
        ```yaml
        gather:
          loop: 1
          mode: "single"
          leads:
            - id: "l-001"
              name: "authentication-history"
              status: {status}
              escalate_trigger: {trigger}
              escalate_context: "test-trigger {trigger}"
              health_probe: null
              raw:
                siem_response: ""
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
        gather:
          loop: 1
          mode: "single"
          leads:
            - id: "l-001"
              name: "authentication-history"
              status: error
              escalate_trigger: some_unknown_trigger
              escalate_context: "unknown"
              raw:
                siem_response: ""
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
        assert result.payload["status"] == "error"


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
            "lead_id": "l-002",
            "lead_name": "authentication-history",
            "status": "complete",
            "result": {
                "id": "l-002",
                "name": "authentication-history",
                "status": "ok",
                "query": {"query": "cached-query"},
                "health_probe": None,
                "characterization": {"distinct_users": 5, "total_events": 99},
                "baseline": {
                    "scope": "same-entity-7d",
                    "distinct_users": 5,
                    "total_events": 700,
                },
                "notes": "",
                "raw": {"siem_response": "(99 rows)"},
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
        # The resume re-dispatch receives the envelope emitted after the
        # subagent finishes — loop 2, lead id l-002.
        resume_envelope = textwrap.dedent("""
        ```yaml
        gather:
          loop: 2
          mode: "single"
          leads:
            - id: "l-002"
              name: "authentication-history"
              status: ok
              query: {system: "wazuh-indexer", query: "q"}
              health_probe: null
              characterization: {distinct_users: 1, total_events: 11}
              baseline: {scope: "same-entity-7d", distinct_users: 1, total_events: 700}
              raw:
                siem_response: "(11 rows)"
        ```
        """).strip()
        monkeypatch.setattr(
            gather_handler, "_invoke_gather",
            stub_invoke(captured, ["(truncated)", resume_envelope]),
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

    def test_routes_to_analyze_when_hypotheses_declared(self, tmp_path, monkeypatch):
        ctx = make_ctx(tmp_path, selected_lead="authentication-history")
        monkeypatch.setattr(
            gather_handler, "_invoke_gather",
            stub_invoke([], [_SINGLE_FINDING]),
        )
        result = gather_handler.handle(ctx)
        assert result.next_phase == Phase.ANALYZE

    def test_routes_to_predict_when_no_hypotheses_declared(self, tmp_path, monkeypatch):
        # Shape-E enrichment path: investigation.md has no `hypothesize:`
        # block with declared hypotheses. GATHER should skip ANALYZE and
        # route straight to PREDICT N+1 (there's nothing to grade).
        ctx = make_ctx(
            tmp_path,
            selected_lead="authentication-history",
            existing_investigation="## CONTEXTUALIZE\n\nno hypothesize block yet\n",
        )
        monkeypatch.setattr(
            gather_handler, "_invoke_gather",
            stub_invoke([], [_SINGLE_FINDING]),
        )
        result = gather_handler.handle(ctx)
        assert result.next_phase == Phase.PREDICT

    def test_routes_to_analyze_when_hypothesize_block_empty(self, tmp_path, monkeypatch):
        # Edge case: a `hypothesize:` block exists but its `hypotheses[]` is
        # empty (e.g. shelved-only block). Treat as no-hypotheses — route
        # to PREDICT.
        ctx = make_ctx(
            tmp_path,
            selected_lead="authentication-history",
            existing_investigation=textwrap.dedent("""
                ## CONTEXTUALIZE
                ```yaml
                hypothesize:
                  hypotheses: []
                ```
            """).strip() + "\n",
        )
        monkeypatch.setattr(
            gather_handler, "_invoke_gather",
            stub_invoke([], [_SINGLE_FINDING]),
        )
        result = gather_handler.handle(ctx)
        assert result.next_phase == Phase.PREDICT


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

    def test_composite_secondary_not_list_raises(self, tmp_path):
        ctx = make_ctx(tmp_path)
        ctx.outputs[Phase.PREDICT]["composite_secondary"] = "source-reputation"
        with pytest.raises(OrchestrationError, match="composite_secondary"):
            gather_handler.handle(ctx)

    def test_composite_secondary_with_empty_string_raises(self, tmp_path):
        ctx = make_ctx(tmp_path)
        ctx.outputs[Phase.PREDICT]["composite_secondary"] = ["source-reputation", ""]
        with pytest.raises(OrchestrationError, match="composite_secondary"):
            gather_handler.handle(ctx)


# ---------------------------------------------------------------------------
# Scope-check (prescribed vs executed)
# ---------------------------------------------------------------------------


_COMPOSITE_MULTI_LEAD_OK = textwrap.dedent("""
```yaml
gather:
  loop: 1
  mode: "composite"
  leads:
    - id: "l-001"
      name: "authentication-history"
      reporting_agent: "target-endpoint"
      status: ok
      status_detail: ""
      query: {system: "wazuh-indexer", query: "q1"}
      health_probe: null
      characterization: {events: 10}
      baseline: {scope: "same-entity-7d", events: 700}
      raw:
        siem_response: "(10 rows)"
    - id: "l-001b"
      name: "source-reputation"
      reporting_agent: "target-endpoint"
      status: ok
      status_detail: ""
      query: {system: "wazuh-indexer", query: "q2"}
      health_probe: null
      characterization: {reputation: clean}
      raw:
        siem_response: "(clean)"
  cross_lead_notes: ""
  notes: ""
```
""").strip()


_COMPOSITE_SILENT_DROP = textwrap.dedent("""
```yaml
gather:
  loop: 1
  mode: "composite"
  leads:
    - id: "l-001"
      name: "authentication-history"
      reporting_agent: "target-endpoint"
      status: ok
      status_detail: ""
      query: {system: "wazuh-indexer", query: "q1"}
      health_probe: null
      characterization: {events: 10}
      baseline: {scope: "same-entity-7d", events: 700}
      raw:
        siem_response: "(10 rows)"
  cross_lead_notes: ""
  notes: ""
```
""").strip()


_COMPOSITE_EXPLICIT_DROP = textwrap.dedent("""
```yaml
gather:
  loop: 1
  mode: "composite"
  leads:
    - id: "l-001"
      name: "authentication-history"
      reporting_agent: "target-endpoint"
      status: ok
      status_detail: ""
      query: {system: "wazuh-indexer", query: "q1"}
      health_probe: null
      characterization: {events: 10}
      baseline: {scope: "same-entity-7d", events: 700}
      raw:
        siem_response: "(10 rows)"
    - id: "l-001b"
      name: "source-reputation"
      reporting_agent: "target-endpoint"
      status: dropped_attempt
      status_detail: "budget exhausted after first lead"
      query: {system: "wazuh-indexer", query: ""}
      health_probe: null
      characterization: null
      raw:
        siem_response: ""
  cross_lead_notes: ""
  notes: ""
```
""").strip()


class TestCompositeScopeCheck:
    def test_multi_lead_prescription_with_full_coverage_passes(
        self, tmp_path, monkeypatch,
    ):
        ctx = make_ctx(tmp_path, selected_lead="authentication-history")
        ctx.outputs[Phase.PREDICT]["composite_secondary"] = ["source-reputation"]
        captured_composite: list[str] = []
        monkeypatch.setattr(
            gather_handler, "_invoke_gather_composite",
            stub_invoke(captured_composite, [_COMPOSITE_MULTI_LEAD_OK]),
        )

        result = gather_handler.handle(ctx)

        assert result.next_phase == Phase.ANALYZE
        assert result.payload["prescribed_leads"] == [
            "authentication-history", "source-reputation",
        ]
        assert set(result.payload["executed_leads"]) == {
            "authentication-history", "source-reputation",
        }
        # Composite dispatch was forced even though the primary lead has a
        # template — composite_secondary is non-empty.
        assert len(captured_composite) == 1
        assert "source-reputation" in captured_composite[0]

    def test_silent_drop_of_secondary_lead_raises(self, tmp_path, monkeypatch):
        ctx = make_ctx(tmp_path, selected_lead="authentication-history")
        ctx.outputs[Phase.PREDICT]["composite_secondary"] = ["source-reputation"]
        monkeypatch.setattr(
            gather_handler, "_invoke_gather_composite",
            stub_invoke([], [_COMPOSITE_SILENT_DROP]),
        )

        with pytest.raises(OrchestrationError, match=r"prescribed leads \['source-reputation'\]"):
            gather_handler.handle(ctx)

    def test_explicit_dropped_attempt_status_passes(self, tmp_path, monkeypatch):
        ctx = make_ctx(tmp_path, selected_lead="authentication-history")
        ctx.outputs[Phase.PREDICT]["composite_secondary"] = ["source-reputation"]
        monkeypatch.setattr(
            gather_handler, "_invoke_gather_composite",
            stub_invoke([], [_COMPOSITE_EXPLICIT_DROP]),
        )

        result = gather_handler.handle(ctx)

        # Prescribed scope is covered (entry exists with dropped_attempt status),
        # so scope-check passes. But only the first lead is in executed_leads —
        # dropped_attempt is not a resolved status. ANALYZE will see this gap
        # and can surface via unresolved_prescribed_set.
        assert result.payload["prescribed_leads"] == [
            "authentication-history", "source-reputation",
        ]
        assert result.payload["executed_leads"] == ["authentication-history"]

    def test_single_lead_prescription_records_executed_correctly(
        self, tmp_path, monkeypatch,
    ):
        ctx = make_ctx(tmp_path, selected_lead="authentication-history")
        monkeypatch.setattr(
            gather_handler, "_invoke_gather",
            stub_invoke([], [_SINGLE_FINDING]),
        )

        result = gather_handler.handle(ctx)

        assert result.payload["prescribed_leads"] == ["authentication-history"]
        assert result.payload["executed_leads"] == ["authentication-history"]

    def test_single_lead_escalate_records_empty_executed(
        self, tmp_path, monkeypatch,
    ):
        ctx = make_ctx(tmp_path, selected_lead="authentication-history")
        # Unknown trigger → error payload surfaced as-is, no composite fallback
        escalate = textwrap.dedent("""
        ```yaml
        gather:
          loop: 1
          mode: "single"
          leads:
            - id: "l-001"
              name: "authentication-history"
              status: error
              escalate_trigger: some_unknown_trigger
              escalate_context: "unknown"
              raw:
                siem_response: ""
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

        assert result.payload["prescribed_leads"] == ["authentication-history"]
        # Escalate didn't produce characterization → empty executed_leads.
        assert result.payload["executed_leads"] == []


# ---------------------------------------------------------------------------
# Definition preload + per-lead contract enforcement
# ---------------------------------------------------------------------------


class TestDefinitionPreload:
    """The handler inlines `definition.md` into the dispatch prompt so the
    subagent cannot skip the contract Read. See task
    `gather-composite-skips-lead-def-lookup`.
    """

    def test_single_dispatch_inlines_definition_md(self, tmp_path, monkeypatch):
        ctx = make_ctx(tmp_path, selected_lead="authentication-history")
        captured: list[str] = []
        monkeypatch.setattr(
            gather_handler, "_invoke_gather",
            stub_invoke(captured, [_SINGLE_FINDING]),
        )
        monkeypatch.setattr(
            gather_handler, "_invoke_gather_composite",
            stub_invoke([], []),
        )

        gather_handler.handle(ctx)

        assert len(captured) == 1
        prompt = captured[0]
        assert "definition_md=|" in prompt
        # Frontmatter content from authentication-history's def must be inlined.
        assert "baseline: required" in prompt
        # And a marker phrase from the body, to confirm full content (not
        # just frontmatter).
        assert "What to Characterize" in prompt

    def test_composite_dispatch_inlines_definition_per_lead(
        self, tmp_path, monkeypatch,
    ):
        ctx = make_ctx(tmp_path, selected_lead="authentication-history")
        ctx.outputs[Phase.PREDICT]["composite_secondary"] = ["source-reputation"]
        captured: list[str] = []
        monkeypatch.setattr(
            gather_handler, "_invoke_gather_composite",
            stub_invoke(captured, [_COMPOSITE_MULTI_LEAD_OK]),
        )

        gather_handler.handle(ctx)

        assert len(captured) == 1
        prompt = captured[0]
        # Both leads' definitions must be present in the dispatch prompt.
        assert "definition_md:" in prompt
        # Marker from authentication-history's frontmatter.
        assert "baseline: required" in prompt
        # Marker from source-reputation's frontmatter.
        assert "baseline: not-applicable" in prompt

    def test_ad_hoc_lead_omits_definition_md(self, tmp_path, monkeypatch):
        # `made-up-lead-name` has no on-disk definition → field must be absent.
        ctx = make_ctx(tmp_path, selected_lead="made-up-lead-name")
        captured: list[str] = []
        monkeypatch.setattr(
            gather_handler, "_invoke_gather_composite",
            stub_invoke(captured, [textwrap.dedent("""
            ```yaml
            gather:
              loop: 1
              mode: "ad-hoc"
              leads:
                - id: "l-001"
                  name: "made-up-lead-name"
                  reporting_agent: "target-endpoint"
                  status: ok
                  status_detail: ""
                  query: {system: "wazuh-indexer", query: "q"}
                  health_probe: null
                  characterization: {events: 1}
                  raw:
                    siem_response: "(1 row)"
              cross_lead_notes: ""
              notes: ""
            ```
            """).strip()]),
        )

        gather_handler.handle(ctx)

        assert len(captured) == 1
        # No definition.md on disk → no inlined block, no key in the spec.
        assert "definition_md" not in captured[0]

    def test_predict_lead_hint_attached_to_named_lead(
        self, tmp_path, monkeypatch,
    ):
        ctx = make_ctx(tmp_path, selected_lead="authentication-history")
        ctx.outputs[Phase.PREDICT]["composite_secondary"] = ["source-reputation"]
        ctx.outputs[Phase.PREDICT]["lead_hints"] = {
            "source-reputation": "cross-check the same IP for known-bad reputation",
        }
        captured: list[str] = []
        monkeypatch.setattr(
            gather_handler, "_invoke_gather_composite",
            stub_invoke(captured, [_COMPOSITE_MULTI_LEAD_OK]),
        )

        gather_handler.handle(ctx)

        prompt = captured[0]
        # The hint string is attached only to the named lead (source-reputation).
        # We can't easily parse the YAML inside the prompt, but the hint text
        # must appear once.
        assert prompt.count("cross-check the same IP for known-bad reputation") == 1


class TestContractValidation:
    """The handler post-validates the returned envelope against each
    prescribed lead's on-disk contract. Currently checks: when the
    definition's frontmatter is `baseline: required`, a resolved entry
    must carry a non-null `baseline:` field.
    """

    def test_baseline_required_violation_flips_status(
        self, tmp_path, monkeypatch,
    ):
        # _COMPOSITE_MULTI_LEAD_OK_NO_BASELINE: same shape as the OK fixture
        # but auth-history's `baseline:` is missing. Resolved status (ok) +
        # baseline: required + baseline: null → contract_violation.
        envelope = textwrap.dedent("""
        ```yaml
        gather:
          loop: 1
          mode: "composite"
          leads:
            - id: "l-001"
              name: "authentication-history"
              reporting_agent: "target-endpoint"
              status: ok
              status_detail: ""
              query: {system: "wazuh-indexer", query: "q1"}
              health_probe: null
              characterization: {events: 10}
              raw:
                siem_response: "(10 rows)"
            - id: "l-001b"
              name: "source-reputation"
              reporting_agent: "target-endpoint"
              status: ok
              status_detail: ""
              query: {system: "wazuh-indexer", query: "q2"}
              health_probe: null
              characterization: {reputation: clean}
              raw:
                siem_response: "(clean)"
          cross_lead_notes: ""
          notes: ""
        ```
        """).strip()
        ctx = make_ctx(tmp_path, selected_lead="authentication-history")
        ctx.outputs[Phase.PREDICT]["composite_secondary"] = ["source-reputation"]
        monkeypatch.setattr(
            gather_handler, "_invoke_gather_composite",
            stub_invoke([], [envelope]),
        )

        result = gather_handler.handle(ctx)

        # auth-history (baseline: required, no baseline emitted) → violation.
        # source-reputation (baseline: not-applicable) → unaffected.
        assert "authentication-history" not in result.payload["executed_leads"]
        # The investigation markdown should record the contract_violation status.
        inv = (ctx.run_dir / "investigation.md").read_text()
        assert "contract_violation" in inv

    def test_baseline_required_with_baseline_passes(
        self, tmp_path, monkeypatch,
    ):
        # _COMPOSITE_MULTI_LEAD_OK already has baseline on auth-history → no
        # violation. Already exercised in TestCompositeScopeCheck, but this
        # test asserts the post-validation path explicitly.
        ctx = make_ctx(tmp_path, selected_lead="authentication-history")
        ctx.outputs[Phase.PREDICT]["composite_secondary"] = ["source-reputation"]
        monkeypatch.setattr(
            gather_handler, "_invoke_gather_composite",
            stub_invoke([], [_COMPOSITE_MULTI_LEAD_OK]),
        )

        result = gather_handler.handle(ctx)

        assert set(result.payload["executed_leads"]) == {
            "authentication-history", "source-reputation",
        }

    def test_baseline_exempt_status_skips_check(self, tmp_path, monkeypatch):
        # status: data_missing on a baseline-required lead → exempt from
        # contract check (foreground had no data → shift query has nothing
        # to compare against).
        envelope = textwrap.dedent("""
        ```yaml
        gather:
          loop: 1
          mode: "single"
          leads:
            - id: "l-001"
              name: "authentication-history"
              reporting_agent: "target-endpoint"
              status: data_missing
              status_detail: "no foreground events for entity"
              query: {system: "wazuh-indexer", query: "q"}
              health_probe: null
              characterization: null
              raw:
                siem_response: ""
        ```
        """).strip()
        ctx = make_ctx(tmp_path, selected_lead="authentication-history")
        monkeypatch.setattr(
            gather_handler, "_invoke_gather",
            stub_invoke([], [envelope]),
        )
        monkeypatch.setattr(
            gather_handler, "_invoke_gather_composite",
            stub_invoke([], []),
        )

        result = gather_handler.handle(ctx)

        # data_missing is preserved, not flipped to contract_violation.
        assert result.payload["status"] == "data_missing"
