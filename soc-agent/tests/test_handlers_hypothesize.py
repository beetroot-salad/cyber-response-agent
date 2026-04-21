"""Unit tests for the HYPOTHESIZE phase handler.

The subagent invocation is mocked — these tests exercise prompt assembly
(loop_n counting, remediation notes on retry), block-type detection,
trailer validation, terminal-routing stripping, validator-error retry flow,
and routing output. They do not spawn a Claude subprocess.
"""

import sys
import textwrap
from pathlib import Path

import pytest

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))
sys.path.insert(0, str(SOC_AGENT_ROOT / "scripts"))

from schemas.state import Phase  # noqa: E402
from scripts.handlers import hypothesize as hypothesize_handler  # noqa: E402
from scripts.orchestrate import Context, OrchestrationError  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def make_ctx(
    tmp_path: Path,
    *,
    history: list[str] | None = None,
    current_phase: Phase | None = Phase.HYPOTHESIZE,
    existing_investigation: str | None = None,
) -> Context:
    run_dir = tmp_path / "run-test"
    run_dir.mkdir()
    if existing_investigation is not None:
        (run_dir / "investigation.md").write_text(existing_investigation)
    ctx = Context(
        run_dir=run_dir,
        signature_id="wazuh-rule-5710",
        ticket_id="SEC-2026-042",
        alert={"id": "alert-1"},
        history=history or [Phase.HYPOTHESIZE.value],
        current_phase=current_phase,
    )
    return ctx


def stub_invoke(captured: list[str], responses: list[str]):
    """Return a stub that records prompts and returns each response in turn."""
    iterator = iter(responses)

    def fn(prompt, *, timeout=None):
        captured.append(prompt)
        try:
            return next(iterator)
        except StopIteration:
            raise AssertionError("stub_invoke exhausted — handler called subagent "
                                 "more times than the test scripted")
    return fn


def stub_validator(results: list[list[str]]):
    """Return a stub for _validate_companion_proposed that yields each error list."""
    iterator = iter(results)

    def fn(ctx, new_section):
        try:
            return next(iterator)
        except StopIteration:
            raise AssertionError("stub_validator exhausted")
    return fn


# Canned subagent responses. Trailer lives in the last ```yaml fence; invlang
# block(s) precede it. Handler strips only the last fence before appending.

_FORK_RESPONSE = textwrap.dedent("""
## HYPOTHESIZE (loop 1)

**Active hypotheses:** ?scheduled-automation-health-check, ?adversary-controlled-monitoring-host
**Selected lead:** authentication-history
**Pitfalls:**
- ?scheduled-automation-health-check: …
- ?adversary-controlled-monitoring-host: …

```yaml
hypothesize:
  hypotheses:
    - id: h-001
      name: "?scheduled-automation-health-check"
      attached_to_vertex: v-001
      proposed_edge:
        relation: initiated_by
        parent_vertex: {type: identity, classification: scheduled-automation-health-check}
      predictions:
        - {id: p1, subject: proposed_parent, claim: "event cadence matches documented probe interval within ±5s"}
      refutation_shape:
        - {id: r1, refutes_predictions: [p1], claim: "event cadence is off-documented-interval"}
      weight: null
```

```yaml
mode: fork
selected_lead: authentication-history
loop_n: 1
```
""").strip()


_NO_FORK_RESPONSE = textwrap.dedent("""
## GATHER (loop 1)

**Selected lead:** source-classification
**Pitfalls:**
- lead-level pitfall …

```yaml
gather:
  - id: l-001
    loop: 1
    name: source-classification
    target: v-001
    query_details: {}
    outcome: {}
    resolutions: []
    predictions:
      - {id: lp1, if: "classifies as internal-monitoring-host", read_as: "sanctioned", advance_to: authentication-history}
```

```yaml
mode: no-fork
selected_lead: source-classification
loop_n: 1
```
""").strip()


_ERROR_RESPONSE = textwrap.dedent("""
```yaml
error: "investigation.md missing prologue — cannot form hypotheses"
```
""").strip()


# ---------------------------------------------------------------------------
# Prompt assembly
# ---------------------------------------------------------------------------


class TestPromptAssembly:
    def test_first_loop_passes_loop_n_1(self, tmp_path, monkeypatch):
        ctx = make_ctx(tmp_path, history=[Phase.HYPOTHESIZE.value])
        captured: list[str] = []
        monkeypatch.setattr(hypothesize_handler, "_invoke_subagent",
                            stub_invoke(captured, [_FORK_RESPONSE]))
        monkeypatch.setattr(hypothesize_handler, "_validate_companion_proposed",
                            stub_validator([[]]))
        hypothesize_handler.handle(ctx)
        assert captured[0].count("loop_n=1") == 1
        assert "run_dir=" in captured[0]
        assert "signature_id=wazuh-rule-5710" in captured[0]
        assert "resume_from_checkpoint" not in captured[0]

    def test_second_loop_passes_loop_n_2(self, tmp_path, monkeypatch):
        # History of one completed loop + current HYPOTHESIZE entry for loop 2.
        history = [
            Phase.CONTEXTUALIZE.value,
            Phase.HYPOTHESIZE.value,
            Phase.GATHER.value,
            Phase.ANALYZE.value,
            Phase.HYPOTHESIZE.value,
        ]
        ctx = make_ctx(tmp_path, history=history)
        response = _FORK_RESPONSE.replace("loop_n: 1", "loop_n: 2").replace(
            "HYPOTHESIZE (loop 1)", "HYPOTHESIZE (loop 2)"
        )
        captured: list[str] = []
        monkeypatch.setattr(hypothesize_handler, "_invoke_subagent",
                            stub_invoke(captured, [response]))
        monkeypatch.setattr(hypothesize_handler, "_validate_companion_proposed",
                            stub_validator([[]]))
        hypothesize_handler.handle(ctx)
        assert "loop_n=2" in captured[0]

    def test_retry_prompt_carries_remediation(self, tmp_path, monkeypatch):
        ctx = make_ctx(tmp_path)
        captured: list[str] = []
        monkeypatch.setattr(hypothesize_handler, "_invoke_subagent",
                            stub_invoke(captured, [_FORK_RESPONSE, _FORK_RESPONSE]))
        monkeypatch.setattr(hypothesize_handler, "_validate_companion_proposed",
                            stub_validator([
                                ["hypothesis h-001 prediction p1: claim contains "
                                 "semicolon-separated clauses"],
                                [],
                            ]))
        hypothesize_handler.handle(ctx)
        assert "resume_from_checkpoint=true" in captured[1]
        assert "remediation_notes=" in captured[1]
        assert "semicolon-separated" in captured[1]
        # First prompt has no remediation, second does.
        assert "resume_from_checkpoint" not in captured[0]


# ---------------------------------------------------------------------------
# Past-investigation priors integration
# ---------------------------------------------------------------------------


_INVESTIGATION_WITH_HYPOTHESIZE = textwrap.dedent("""
## CONTEXTUALIZE

```yaml
prologue:
  vertices:
    - id: v-001
      type: endpoint
      classification: monitoring-host
    - id: v-002
      type: endpoint
      classification: internal-server
  edges:
    - id: e-001
      relation: attempted_auth
      source_vertex: v-001
      target_vertex: v-002
```

## HYPOTHESIZE (loop 1)

```yaml
hypothesize:
  hypotheses:
    - id: h-001
      name: "?monitoring-probe"
      attached_to_vertex: v-002
      proposed_edge: e-001
```
""").strip() + "\n"


def _synthetic_companion():
    """Build one in-memory companion the handler can retrieve priors against."""
    from invlang.corpus import Companion  # imported lazily; test-only path

    body = {
        "prologue": {
            "vertices": [
                {"id": "v-001", "type": "endpoint", "classification": "monitoring-host"},
                {"id": "v-002", "type": "endpoint", "classification": "internal-server"},
            ],
            "edges": [
                {
                    "id": "e-001",
                    "relation": "attempted_auth",
                    "source_vertex": "v-001",
                    "target_vertex": "v-002",
                }
            ],
        },
        "hypothesize": {
            "hypotheses": [
                {
                    "id": "h-001",
                    "name": "?monitoring-probe",
                    "attached_to_vertex": "v-002",
                    "proposed_edge": "e-001",
                }
            ]
        },
        "gather": [
            {
                "id": "l-001",
                "name": "auth-history",
                "tests": [{"id": "t1"}],
                "resolutions": [
                    {"hypothesis": "h-001", "before": None, "after": "++"}
                ],
                "outcome": {},
            }
        ],
        "conclude": {"disposition": "benign"},
    }
    return Companion(case_id="synthetic", source_path=Path("."), body=body)


class TestPriorsIntegration:
    def test_assemble_prompt_includes_priors_section(self, tmp_path, monkeypatch):
        ctx = make_ctx(
            tmp_path,
            existing_investigation=_INVESTIGATION_WITH_HYPOTHESIZE,
        )
        import invlang
        monkeypatch.setattr(invlang, "load_corpus", lambda *a, **k: [_synthetic_companion()])

        prompt = hypothesize_handler._assemble_prompt(ctx)
        assert "## Past-investigation priors" in prompt
        assert "?monitoring-probe (tier 0 — exact)" in prompt
        assert "auth-history" in prompt
        assert "n=1" in prompt

    def test_assemble_prompt_loop1_fallback_uses_playbook_seeds(self, tmp_path, monkeypatch):
        # Only CONTEXTUALIZE written — no prior hypothesize block yet.
        prologue_only = textwrap.dedent("""
            ## CONTEXTUALIZE

            ```yaml
            prologue:
              vertices: []
              edges: []
            ```
        """).strip() + "\n"
        ctx = make_ctx(tmp_path, existing_investigation=prologue_only)
        import invlang
        # Empty corpus → seeds will narrow to "no match" banners.
        monkeypatch.setattr(invlang, "load_corpus", lambda *a, **k: [])

        prompt = hypothesize_handler._assemble_prompt(ctx)
        assert "## Past-investigation priors" in prompt
        # Playbook for rule-5710 has hypothesis seeds. Assert at least one
        # seed-shaped section header appears in the rendered block.
        assert "tier 4" in prompt or "(no frontier extracted)" in prompt

    def test_priors_failure_is_non_fatal(self, tmp_path, monkeypatch):
        ctx = make_ctx(
            tmp_path,
            existing_investigation=_INVESTIGATION_WITH_HYPOTHESIZE,
        )
        import invlang

        def _boom(*a, **k):
            raise RuntimeError("corpus env unset")

        monkeypatch.setattr(invlang, "load_corpus", _boom)

        prompt = hypothesize_handler._assemble_prompt(ctx)
        assert "## Past-investigation priors" in prompt
        assert "(priors unavailable" in prompt
        # Handler still dispatches cleanly when priors fail.
        captured: list[str] = []
        monkeypatch.setattr(hypothesize_handler, "_invoke_subagent",
                            stub_invoke(captured, [_FORK_RESPONSE]))
        monkeypatch.setattr(hypothesize_handler, "_validate_companion_proposed",
                            stub_validator([[]]))
        result = hypothesize_handler.handle(ctx)
        assert result.next_phase == Phase.GATHER
        assert "(priors unavailable" in captured[0]


# ---------------------------------------------------------------------------
# Block-type detection
# ---------------------------------------------------------------------------


class TestDetectBlockType:
    def test_detects_hypothesize_block(self):
        assert hypothesize_handler._detect_block_type(_FORK_RESPONSE) == "hypothesize"

    def test_detects_gather_block(self):
        assert hypothesize_handler._detect_block_type(_NO_FORK_RESPONSE) == "gather"

    def test_detects_error_block(self):
        assert hypothesize_handler._detect_block_type(_ERROR_RESPONSE) == "error"

    def test_returns_unknown_when_no_yaml_key_matches(self):
        raw = "```yaml\nmode: fork\nselected_lead: foo\nloop_n: 1\n```"
        # Only a trailer, no invlang block → unknown.
        assert hypothesize_handler._detect_block_type(raw) == "unknown"

    def test_returns_unknown_on_malformed_yaml(self):
        raw = "```yaml\n: : : :\n```"
        assert hypothesize_handler._detect_block_type(raw) == "unknown"


# ---------------------------------------------------------------------------
# Trailer validation
# ---------------------------------------------------------------------------


class TestValidateTrailer:
    def test_fork_mode_hypothesize_block_ok(self):
        trailer = {"mode": "fork", "selected_lead": "foo", "loop_n": 1}
        hypothesize_handler._validate_trailer(
            trailer, block_type="hypothesize", expected_loop_n=1,
        )

    def test_no_fork_mode_gather_block_ok(self):
        trailer = {"mode": "no-fork", "selected_lead": "foo", "loop_n": 2}
        hypothesize_handler._validate_trailer(
            trailer, block_type="gather", expected_loop_n=2,
        )

    def test_invalid_mode_raises(self):
        with pytest.raises(OrchestrationError, match="invalid trailer mode"):
            hypothesize_handler._validate_trailer(
                {"mode": "other", "selected_lead": "x", "loop_n": 1},
                block_type="hypothesize", expected_loop_n=1,
            )

    def test_mode_mismatches_block_type_raises(self):
        with pytest.raises(OrchestrationError, match="does not match block type"):
            hypothesize_handler._validate_trailer(
                {"mode": "no-fork", "selected_lead": "x", "loop_n": 1},
                block_type="hypothesize", expected_loop_n=1,
            )

    def test_missing_selected_lead_raises(self):
        with pytest.raises(OrchestrationError, match="selected_lead"):
            hypothesize_handler._validate_trailer(
                {"mode": "fork", "selected_lead": "", "loop_n": 1},
                block_type="hypothesize", expected_loop_n=1,
            )

    def test_non_int_loop_n_raises(self):
        with pytest.raises(OrchestrationError, match="loop_n must be int"):
            hypothesize_handler._validate_trailer(
                {"mode": "fork", "selected_lead": "x", "loop_n": "1"},
                block_type="hypothesize", expected_loop_n=1,
            )

    def test_loop_n_mismatch_raises(self):
        with pytest.raises(OrchestrationError, match="does not match"):
            hypothesize_handler._validate_trailer(
                {"mode": "fork", "selected_lead": "x", "loop_n": 5},
                block_type="hypothesize", expected_loop_n=1,
            )


# ---------------------------------------------------------------------------
# Terminal-routing strip
# ---------------------------------------------------------------------------


class TestStripTerminalRouting:
    def test_strips_only_last_fence(self):
        raw = textwrap.dedent("""
            ## HYPOTHESIZE

            ```yaml
            hypothesize:
              hypotheses: []
            ```

            ```yaml
            mode: fork
            selected_lead: x
            loop_n: 1
            ```
            """).strip()
        stripped = hypothesize_handler._strip_terminal_routing(raw)
        assert "hypothesize:" in stripped
        assert "mode: fork" not in stripped
        assert "selected_lead: x" not in stripped

    def test_preserves_preceding_fences(self):
        # Two invlang fences (rare but possible) + trailer — only trailer dropped.
        raw = textwrap.dedent("""
            ```yaml
            prologue:
              vertices: []
            ```

            ```yaml
            hypothesize:
              hypotheses: []
            ```

            ```yaml
            mode: fork
            selected_lead: x
            loop_n: 1
            ```
            """).strip()
        stripped = hypothesize_handler._strip_terminal_routing(raw)
        assert "prologue:" in stripped
        assert "hypothesize:" in stripped
        assert "mode: fork" not in stripped


# ---------------------------------------------------------------------------
# End-to-end happy paths
# ---------------------------------------------------------------------------


class TestHandleHappyPaths:
    def test_fork_mode_routes_to_gather(self, tmp_path, monkeypatch):
        ctx = make_ctx(tmp_path)
        monkeypatch.setattr(hypothesize_handler, "_invoke_subagent",
                            stub_invoke([], [_FORK_RESPONSE]))
        monkeypatch.setattr(hypothesize_handler, "_validate_companion_proposed",
                            stub_validator([[]]))
        result = hypothesize_handler.handle(ctx)
        assert result.next_phase == Phase.GATHER
        assert result.payload["mode"] == "fork"
        assert result.payload["selected_lead"] == "authentication-history"
        assert result.payload["loop_n"] == 1
        assert result.payload["block_type"] == "hypothesize"

    def test_no_fork_mode_routes_to_gather(self, tmp_path, monkeypatch):
        ctx = make_ctx(tmp_path)
        monkeypatch.setattr(hypothesize_handler, "_invoke_subagent",
                            stub_invoke([], [_NO_FORK_RESPONSE]))
        monkeypatch.setattr(hypothesize_handler, "_validate_companion_proposed",
                            stub_validator([[]]))
        result = hypothesize_handler.handle(ctx)
        assert result.next_phase == Phase.GATHER
        assert result.payload["mode"] == "no-fork"
        assert result.payload["block_type"] == "gather"

    def test_appends_sections_without_trailer(self, tmp_path, monkeypatch):
        ctx = make_ctx(tmp_path, existing_investigation="## CONTEXTUALIZE\n\nexisting.\n")
        monkeypatch.setattr(hypothesize_handler, "_invoke_subagent",
                            stub_invoke([], [_FORK_RESPONSE]))
        monkeypatch.setattr(hypothesize_handler, "_validate_companion_proposed",
                            stub_validator([[]]))
        hypothesize_handler.handle(ctx)
        written = (ctx.run_dir / "investigation.md").read_text()
        assert "existing." in written
        assert "## HYPOTHESIZE (loop 1)" in written
        assert "hypothesize:" in written
        # Terminal trailer must not land in investigation.md.
        assert "mode: fork" not in written
        assert "selected_lead: authentication-history\nloop_n: 1" not in written


# ---------------------------------------------------------------------------
# Error-block + malformed-output paths
# ---------------------------------------------------------------------------


class TestHandleErrorPaths:
    def test_error_block_raises(self, tmp_path, monkeypatch):
        ctx = make_ctx(tmp_path)
        monkeypatch.setattr(hypothesize_handler, "_invoke_subagent",
                            stub_invoke([], [_ERROR_RESPONSE]))
        with pytest.raises(OrchestrationError, match="error block"):
            hypothesize_handler.handle(ctx)

    def test_no_invlang_block_raises(self, tmp_path, monkeypatch):
        ctx = make_ctx(tmp_path)
        only_trailer = textwrap.dedent("""
            ```yaml
            mode: fork
            selected_lead: x
            loop_n: 1
            ```
            """).strip()
        monkeypatch.setattr(hypothesize_handler, "_invoke_subagent",
                            stub_invoke([], [only_trailer]))
        with pytest.raises(OrchestrationError, match="no hypothesize:/gather:/error:"):
            hypothesize_handler.handle(ctx)

    def test_trailer_loop_mismatch_raises(self, tmp_path, monkeypatch):
        ctx = make_ctx(tmp_path)
        mismatched = _FORK_RESPONSE.replace("loop_n: 1", "loop_n: 7")
        monkeypatch.setattr(hypothesize_handler, "_invoke_subagent",
                            stub_invoke([], [mismatched]))
        monkeypatch.setattr(hypothesize_handler, "_validate_companion_proposed",
                            stub_validator([[]]))
        with pytest.raises(OrchestrationError, match="does not match"):
            hypothesize_handler.handle(ctx)


# ---------------------------------------------------------------------------
# Validator-error retry flow
# ---------------------------------------------------------------------------


class TestValidationRetry:
    def test_first_fails_second_succeeds(self, tmp_path, monkeypatch):
        ctx = make_ctx(tmp_path)
        captured: list[str] = []
        monkeypatch.setattr(hypothesize_handler, "_invoke_subagent",
                            stub_invoke(captured, [_FORK_RESPONSE, _FORK_RESPONSE]))
        monkeypatch.setattr(hypothesize_handler, "_validate_companion_proposed",
                            stub_validator([
                                ["hypothesis h-001: classification starts with "
                                 "evaluation-packed prefix"],
                                [],
                            ]))
        result = hypothesize_handler.handle(ctx)
        assert result.next_phase == Phase.GATHER
        assert len(captured) == 2

    def test_both_attempts_fail_raises(self, tmp_path, monkeypatch):
        ctx = make_ctx(tmp_path)
        monkeypatch.setattr(hypothesize_handler, "_invoke_subagent",
                            stub_invoke([], [_FORK_RESPONSE, _FORK_RESPONSE]))
        monkeypatch.setattr(hypothesize_handler, "_validate_companion_proposed",
                            stub_validator([
                                ["error one"],
                                ["error two"],
                            ]))
        with pytest.raises(OrchestrationError, match="validation failed on retry"):
            hypothesize_handler.handle(ctx)

    def test_no_retry_if_first_passes(self, tmp_path, monkeypatch):
        ctx = make_ctx(tmp_path)
        captured: list[str] = []
        monkeypatch.setattr(hypothesize_handler, "_invoke_subagent",
                            stub_invoke(captured, [_FORK_RESPONSE]))
        monkeypatch.setattr(hypothesize_handler, "_validate_companion_proposed",
                            stub_validator([[]]))
        hypothesize_handler.handle(ctx)
        assert len(captured) == 1
