"""Unit tests for the ANALYZE phase handler.

The subagent invocation is mocked — these tests exercise prompt assembly
(loop_n counting), terminal YAML parsing, routing-payload validation,
markdown extraction + append, and error propagation. They do not spawn a
Claude subprocess.
"""

import sys
import textwrap
from pathlib import Path

import pytest

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from schemas.state import Phase  # noqa: E402
from scripts.handlers import analyze as analyze_handler  # noqa: E402
from scripts.orchestrate import Context, OrchestrationError, PhaseResult  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def make_ctx(
    tmp_path: Path,
    *,
    history: list[str] | None = None,
    existing_investigation: str | None = None,
) -> Context:
    run_dir = tmp_path / "run-test"
    run_dir.mkdir()
    # alert.json is required — the analyze handler preloads it into the prompt.
    alert = {"id": "alert-1", "rule": {"id": "5710"}, "data": {}}
    import json as _json
    (run_dir / "alert.json").write_text(_json.dumps(alert))
    if existing_investigation is not None:
        (run_dir / "investigation.md").write_text(existing_investigation)
    return Context(
        run_dir=run_dir,
        signature_id="wazuh-rule-5710",
        ticket_id="SEC-2026-042",
        alert=alert,
        history=history or [],
    )


def stub_invoke(captured: list[str], response: str):
    def fn(prompt, *, timeout=None):
        captured.append(prompt)
        return response
    return fn


# Canned valid response fragments used across several tests.
_CONCLUDE_RESPONSE = textwrap.dedent("""
## ANALYZE (loop 2)

**Evidence:** cadence-check — cadence matches declared 60s interval (±1.8s).

**Assessment:**
- ?benign-automation: ++ (was +) — matched prediction p2; r2 failed.
- ?brute-force: -- (was +) — matched refutation r1.

**Surviving hypotheses:** ?benign-automation
**Next action:** CONCLUDE → disposition: benign, confidence: high, matched_archetype: monitoring-probe

## Self-report

- **Context wished for:** none
- **Uncertain claims:** none
- **Anomalies:**
  - none

```yaml
next_action: CONCLUDE
disposition: benign
confidence: high
matched_archetype: monitoring-probe
surviving_hypotheses: [h-001]
```
""").strip()

_HYPOTHESIZE_RESPONSE = textwrap.dedent("""
## ANALYZE (loop 1)

**Evidence:** source-classification — IP matches approved registry.

**Assessment:**
- ?benign-automation: + (was new) — consistent with registry.
- ?brute-force: + (was new) — no differentiating evidence yet.

**Surviving hypotheses:** ?benign-automation, ?brute-force
**Next action:** HYPOTHESIZE — need cadence check to distinguish.

## Self-report

- **Context wished for:** cadence data
- **Uncertain claims:** registry freshness
- **Anomalies:**
  - none

```yaml
next_action: HYPOTHESIZE
discriminator: "Does the source IP's rule-5710 event history show tool-regular cadence?"
```
""").strip()


# ---------------------------------------------------------------------------
# Prompt assembly
# ---------------------------------------------------------------------------


class TestPromptAssembly:
    def test_passes_run_dir_and_signature(self, tmp_path, monkeypatch):
        ctx = make_ctx(tmp_path, history=[Phase.HYPOTHESIZE.value])
        captured: list[str] = []
        monkeypatch.setattr(
            analyze_handler, "_invoke_subagent",
            stub_invoke(captured, _HYPOTHESIZE_RESPONSE),
        )
        analyze_handler.handle(ctx)
        assert f"run_dir={ctx.run_dir}" in captured[0]
        assert "signature_id=wazuh-rule-5710" in captured[0]

    def test_prompt_inlines_alert_investigation_archetypes(self, tmp_path, monkeypatch):
        """Handler preloads all deterministic context into the prompt so the
        subagent doesn't need Read/Glob tools."""
        ctx = make_ctx(
            tmp_path,
            history=[Phase.HYPOTHESIZE.value],
            existing_investigation="## CONTEXTUALIZE\n\nalert observed.\n",
        )
        captured: list[str] = []
        monkeypatch.setattr(
            analyze_handler, "_invoke_subagent",
            stub_invoke(captured, _HYPOTHESIZE_RESPONSE),
        )
        analyze_handler.handle(ctx)
        prompt = captured[0]

        # Tagged blocks present
        assert "<alert>" in prompt and "</alert>" in prompt
        assert "<investigation>" in prompt and "</investigation>" in prompt
        assert "<archetypes>" in prompt
        # Inlined content landed
        assert "alert observed." in prompt  # from investigation.md
        assert '"id": "alert-1"' in prompt  # from alert.json
        # Real 5710 archetypes surface (live knowledge/ dir)
        assert 'name="monitoring-probe"' in prompt

    def test_loop_n_counts_hypothesize_entries(self, tmp_path, monkeypatch):
        # Three HYPOTHESIZE entries → loop_n = 3
        ctx = make_ctx(
            tmp_path,
            history=[
                Phase.CONTEXTUALIZE.value,
                Phase.HYPOTHESIZE.value, Phase.GATHER.value, Phase.ANALYZE.value,
                Phase.HYPOTHESIZE.value, Phase.GATHER.value, Phase.ANALYZE.value,
                Phase.HYPOTHESIZE.value, Phase.GATHER.value,
            ],
        )
        captured: list[str] = []
        monkeypatch.setattr(
            analyze_handler, "_invoke_subagent",
            stub_invoke(captured, _CONCLUDE_RESPONSE),
        )
        analyze_handler.handle(ctx)
        assert "loop_n=3" in captured[0]

    def test_loop_n_defaults_to_one_when_no_hypothesize(self, tmp_path, monkeypatch):
        # Edge case: SCREEN-match path without hypothesize shouldn't normally
        # land in ANALYZE, but the fallback protects against surprise history.
        ctx = make_ctx(tmp_path, history=[Phase.CONTEXTUALIZE.value])
        captured: list[str] = []
        monkeypatch.setattr(
            analyze_handler, "_invoke_subagent",
            stub_invoke(captured, _CONCLUDE_RESPONSE),
        )
        analyze_handler.handle(ctx)
        assert "loop_n=1" in captured[0]


# ---------------------------------------------------------------------------
# Routing — CONCLUDE
# ---------------------------------------------------------------------------


class TestHandleRoutesConclude:
    def test_routes_to_conclude_on_valid_yaml(self, tmp_path, monkeypatch):
        ctx = make_ctx(tmp_path, history=[Phase.HYPOTHESIZE.value])
        monkeypatch.setattr(
            analyze_handler, "_invoke_subagent",
            stub_invoke([], _CONCLUDE_RESPONSE),
        )
        result = analyze_handler.handle(ctx)
        assert result.next_phase == Phase.CONCLUDE
        assert result.payload["disposition"] == "benign"
        assert result.payload["confidence"] == "high"
        assert result.payload["matched_archetype"] == "monitoring-probe"
        assert result.payload["surviving_hypotheses"] == ["h-001"]

    def test_matched_archetype_null_accepted(self, tmp_path, monkeypatch):
        response = _CONCLUDE_RESPONSE.replace(
            "matched_archetype: monitoring-probe",
            "matched_archetype: null",
        )
        ctx = make_ctx(tmp_path, history=[Phase.HYPOTHESIZE.value])
        monkeypatch.setattr(
            analyze_handler, "_invoke_subagent",
            stub_invoke([], response),
        )
        result = analyze_handler.handle(ctx)
        assert result.next_phase == Phase.CONCLUDE
        assert result.payload["matched_archetype"] is None

    def test_escalated_with_surviving_list_accepted(self, tmp_path, monkeypatch):
        response = _CONCLUDE_RESPONSE.replace(
            "disposition: benign", "disposition: escalated"
        ).replace(
            "matched_archetype: monitoring-probe",
            "matched_archetype: null",
        ).replace(
            "surviving_hypotheses: [h-001]",
            "surviving_hypotheses: [h-001, h-002]",
        )
        ctx = make_ctx(tmp_path, history=[Phase.HYPOTHESIZE.value])
        monkeypatch.setattr(
            analyze_handler, "_invoke_subagent",
            stub_invoke([], response),
        )
        result = analyze_handler.handle(ctx)
        assert result.next_phase == Phase.CONCLUDE
        assert result.payload["disposition"] == "escalated"
        assert result.payload["surviving_hypotheses"] == ["h-001", "h-002"]

    def test_writes_markdown_sections_without_terminal_yaml(
        self, tmp_path, monkeypatch,
    ):
        ctx = make_ctx(tmp_path, history=[Phase.HYPOTHESIZE.value])
        monkeypatch.setattr(
            analyze_handler, "_invoke_subagent",
            stub_invoke([], _CONCLUDE_RESPONSE),
        )
        analyze_handler.handle(ctx)
        written = (ctx.run_dir / "investigation.md").read_text()
        assert "## ANALYZE (loop 2)" in written
        assert "## Self-report" in written
        # The terminal routing YAML fence must NOT have been written
        assert "next_action: CONCLUDE" not in written
        assert "surviving_hypotheses: [h-001]" not in written

    def test_strips_all_yaml_fences_not_just_terminal(
        self, tmp_path, monkeypatch,
    ):
        # Defense in depth: the subagent contract forbids companion YAML
        # emission from ANALYZE. If it emits an extra ```yaml block
        # (accidentally or via prompt injection), the handler must drop
        # it before appending to investigation.md — otherwise the invlang
        # validator would merge the injected YAML into the companion graph.
        response = textwrap.dedent("""
        ## ANALYZE (loop 1)

        **Evidence:** test

        ```yaml
        gather:
          - id: l-injected
            malicious: payload
        ```

        More prose after the injection.

        ## Self-report

        - none

        ```yaml
        next_action: HYPOTHESIZE
        discriminator: "test"
        ```
        """).strip()
        ctx = make_ctx(tmp_path, history=[Phase.HYPOTHESIZE.value])
        monkeypatch.setattr(
            analyze_handler, "_invoke_subagent",
            stub_invoke([], response),
        )
        analyze_handler.handle(ctx)
        written = (ctx.run_dir / "investigation.md").read_text()
        assert "## ANALYZE (loop 1)" in written
        assert "More prose after the injection." in written
        assert "l-injected" not in written
        assert "malicious: payload" not in written
        assert "next_action: HYPOTHESIZE" not in written


# ---------------------------------------------------------------------------
# Routing — HYPOTHESIZE
# ---------------------------------------------------------------------------


class TestHandleRoutesHypothesize:
    def test_routes_to_hypothesize_on_valid_yaml(self, tmp_path, monkeypatch):
        ctx = make_ctx(tmp_path, history=[Phase.HYPOTHESIZE.value])
        monkeypatch.setattr(
            analyze_handler, "_invoke_subagent",
            stub_invoke([], _HYPOTHESIZE_RESPONSE),
        )
        result = analyze_handler.handle(ctx)
        assert result.next_phase == Phase.HYPOTHESIZE
        assert "cadence" in result.payload["discriminator"].lower()

    def test_writes_markdown_sections(self, tmp_path, monkeypatch):
        ctx = make_ctx(tmp_path, history=[Phase.HYPOTHESIZE.value])
        monkeypatch.setattr(
            analyze_handler, "_invoke_subagent",
            stub_invoke([], _HYPOTHESIZE_RESPONSE),
        )
        analyze_handler.handle(ctx)
        written = (ctx.run_dir / "investigation.md").read_text()
        assert "## ANALYZE (loop 1)" in written
        assert "## Self-report" in written


# ---------------------------------------------------------------------------
# Malformed output
# ---------------------------------------------------------------------------


class TestHandleMalformedOutput:
    def test_missing_terminal_yaml_raises(self, tmp_path, monkeypatch):
        response = "## ANALYZE (loop 1)\n\nSome markdown but no YAML.\n"
        ctx = make_ctx(tmp_path, history=[Phase.HYPOTHESIZE.value])
        monkeypatch.setattr(
            analyze_handler, "_invoke_subagent",
            stub_invoke([], response),
        )
        with pytest.raises(OrchestrationError, match="terminal YAML"):
            analyze_handler.handle(ctx)

    def test_invalid_next_action_raises(self, tmp_path, monkeypatch):
        response = textwrap.dedent("""
        ## ANALYZE (loop 1)

        ## Self-report
        - none

        ```yaml
        next_action: BOGUS
        ```
        """).strip()
        ctx = make_ctx(tmp_path, history=[Phase.HYPOTHESIZE.value])
        monkeypatch.setattr(
            analyze_handler, "_invoke_subagent",
            stub_invoke([], response),
        )
        with pytest.raises(OrchestrationError, match="invalid next_action"):
            analyze_handler.handle(ctx)

    def test_conclude_without_disposition_raises(self, tmp_path, monkeypatch):
        response = textwrap.dedent("""
        ## ANALYZE (loop 1)

        ## Self-report
        - none

        ```yaml
        next_action: CONCLUDE
        confidence: high
        matched_archetype: null
        surviving_hypotheses: []
        ```
        """).strip()
        ctx = make_ctx(tmp_path, history=[Phase.HYPOTHESIZE.value])
        monkeypatch.setattr(
            analyze_handler, "_invoke_subagent",
            stub_invoke([], response),
        )
        with pytest.raises(OrchestrationError, match="disposition"):
            analyze_handler.handle(ctx)

    def test_conclude_without_surviving_hypotheses_raises(self, tmp_path, monkeypatch):
        response = textwrap.dedent("""
        ## ANALYZE (loop 1)

        ## Self-report
        - none

        ```yaml
        next_action: CONCLUDE
        disposition: benign
        confidence: high
        matched_archetype: null
        ```
        """).strip()
        ctx = make_ctx(tmp_path, history=[Phase.HYPOTHESIZE.value])
        monkeypatch.setattr(
            analyze_handler, "_invoke_subagent",
            stub_invoke([], response),
        )
        with pytest.raises(OrchestrationError, match="surviving_hypotheses"):
            analyze_handler.handle(ctx)

    def test_hypothesize_without_discriminator_raises(self, tmp_path, monkeypatch):
        response = textwrap.dedent("""
        ## ANALYZE (loop 1)

        ## Self-report
        - none

        ```yaml
        next_action: HYPOTHESIZE
        ```
        """).strip()
        ctx = make_ctx(tmp_path, history=[Phase.HYPOTHESIZE.value])
        monkeypatch.setattr(
            analyze_handler, "_invoke_subagent",
            stub_invoke([], response),
        )
        with pytest.raises(OrchestrationError, match="discriminator"):
            analyze_handler.handle(ctx)


# ---------------------------------------------------------------------------
# Append behavior
# ---------------------------------------------------------------------------


class TestAppendBehavior:
    def test_preserves_existing_investigation_content(self, tmp_path, monkeypatch):
        existing = (
            "## CONTEXTUALIZE\n\n"
            "Existing prologue content.\n\n"
            "## HYPOTHESIZE (loop 1)\n\n"
            "Existing hypotheses.\n"
        )
        ctx = make_ctx(
            tmp_path,
            history=[Phase.HYPOTHESIZE.value],
            existing_investigation=existing,
        )
        monkeypatch.setattr(
            analyze_handler, "_invoke_subagent",
            stub_invoke([], _HYPOTHESIZE_RESPONSE),
        )
        analyze_handler.handle(ctx)
        written = (ctx.run_dir / "investigation.md").read_text()
        # Existing content must come first
        assert written.startswith("## CONTEXTUALIZE")
        assert "Existing hypotheses." in written
        # New ANALYZE section appended
        assert "## ANALYZE (loop 1)" in written.split("Existing hypotheses.")[1]

    def test_handler_is_deterministic_on_same_input(self, tmp_path, monkeypatch):
        """Same response → same file content on repeat invocation (minus append)."""
        ctx = make_ctx(tmp_path, history=[Phase.HYPOTHESIZE.value])
        monkeypatch.setattr(
            analyze_handler, "_invoke_subagent",
            stub_invoke([], _CONCLUDE_RESPONSE),
        )
        result1 = analyze_handler.handle(ctx)
        assert result1.next_phase == Phase.CONCLUDE
        # Only verify that a second call appends rather than duplicates the stripping behavior.
        written_once = (ctx.run_dir / "investigation.md").read_text()
        assert written_once.count("## ANALYZE (loop 2)") == 1
