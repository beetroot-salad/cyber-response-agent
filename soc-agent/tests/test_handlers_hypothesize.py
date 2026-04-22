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
    # alert.json + meta.json are required — the hypothesize handler preloads
    # the alert and per-run salt into the prompt along with investigation.md
    # + signature knowledge + lead catalog + archetype shapes.
    import json as _json
    alert = {"id": "alert-1", "rule": {"id": "5710"}, "data": {}}
    (run_dir / "alert.json").write_text(_json.dumps(alert))
    (run_dir / "meta.json").write_text(_json.dumps({"salt": "test-salt"}))
    if existing_investigation is not None:
        (run_dir / "investigation.md").write_text(existing_investigation)
    ctx = Context(
        run_dir=run_dir,
        signature_id="wazuh-rule-5710",
        ticket_id="SEC-2026-042",
        alert=alert,
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
## HYPOTHESIZE (loop 1) — no fork yet

**Selected lead:** source-classification — classifies srcip against
ip-ranges.md and approved-monitoring-sources anchor; discriminates
sanctioned-automation vs unregistered-internal vs external-origin.

**Pitfalls:**
- l-001: anchor registry lag — a newly-added approved source may
  not be in the cached copy; re-fetch if the classification misses.

```yaml
mode: no-fork
selected_lead: source-classification
loop_n: 1
```
""").strip()


# A legacy shape: the subagent incorrectly emits a `gather:` block. This
# is the contract violation the handler catches and retries with the
# gather_block_in_hypothesize remediation directive.
_NO_FORK_WITH_GATHER_BLOCK_RESPONSE = textwrap.dedent("""
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

    def test_prompt_inlines_all_deterministic_context(self, tmp_path, monkeypatch):
        """Handler preloads alert + investigation + signature knowledge +
        archetypes + lead catalog so the subagent needs no Read tool."""
        ctx = make_ctx(
            tmp_path,
            history=[Phase.HYPOTHESIZE.value],
            existing_investigation="## CONTEXTUALIZE\n\nsignature summary.\n",
        )
        captured: list[str] = []
        monkeypatch.setattr(hypothesize_handler, "_invoke_subagent",
                            stub_invoke(captured, [_FORK_RESPONSE]))
        monkeypatch.setattr(hypothesize_handler, "_validate_companion_proposed",
                            stub_validator([[]]))
        hypothesize_handler.handle(ctx)
        prompt = captured[0]

        # All five tagged blocks present (alert tag is salted)
        assert "<alert-test-salt>" in prompt and "</alert-test-salt>" in prompt
        # hypothesize handler uses mode="hypothesize" — tag carries a mode attribute
        assert "<investigation mode=\"hypothesize\">" in prompt and "signature summary" in prompt
        assert "<signature-knowledge>" in prompt
        assert "<playbook>" in prompt  # real 5710 playbook body inlined
        assert "<archetypes>" in prompt
        assert 'name="monitoring-probe"' in prompt
        assert "<lead-catalog>" in prompt
        assert 'name="authentication-history"' in prompt  # real lead inlined

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
      proposed_edge:
        relation: attempted_auth
        parent_vertex:
          type: endpoint
          classification: monitoring-host
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
                    "proposed_edge": {
                        "relation": "attempted_auth",
                        "parent_vertex": {
                            "type": "endpoint",
                            "classification": "monitoring-host",
                        },
                    },
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

    def test_assemble_prompt_loop1_empty_corpus_renders_no_match_banner(self, tmp_path, monkeypatch):
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
        # Empty corpus → prologue retrieval returns no matches at any tier.
        monkeypatch.setattr(invlang, "load_corpus", lambda *a, **k: [])

        prompt = hypothesize_handler._assemble_prompt(ctx)
        # Loop-1 now takes the prologue-keyed retrieval path, which renders
        # a single block keyed on the prologue shape (not per-seed). With an
        # empty corpus we expect the "no match" sentinel at tier 3.
        assert "## Past-investigation priors" in prompt
        assert "Loop 1 — keyed on prologue topology" in prompt
        assert "tier 3: no match" in prompt
        assert "Leads: (no corpus matches)" in prompt
        # Sentinel that would fire if the loop-1 detection silently broke
        # and fell through to the loop-2+ per-seed path.
        assert "(no frontier extracted)" not in prompt

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

    def test_detects_gather_block_as_contract_violation(self):
        """A `gather:` block in hypothesize output is now a contract
        violation — detection still returns "gather", and the handler
        catches it upstream to trigger the registry-loaded remediation."""
        assert hypothesize_handler._detect_block_type(
            _NO_FORK_WITH_GATHER_BLOCK_RESPONSE
        ) == "gather"

    def test_detects_no_block_when_only_trailer(self):
        """The valid no-fork shape — narrative + trailer, no invlang block."""
        assert hypothesize_handler._detect_block_type(_NO_FORK_RESPONSE) == "unknown"

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

    def test_no_fork_mode_no_block_ok(self):
        """Valid no-fork shape — trailer with no invlang block (block_type=unknown)."""
        trailer = {"mode": "no-fork", "selected_lead": "foo", "loop_n": 2}
        hypothesize_handler._validate_trailer(
            trailer, block_type="unknown", expected_loop_n=2,
        )

    def test_no_fork_mode_with_gather_block_raises(self):
        """A `gather:` block under no-fork is a contract violation — the
        validator rejects it here (the handler's earlier short-circuit
        catches it before validation in the live path, but the trailer
        check is the backstop)."""
        with pytest.raises(OrchestrationError, match="requires block_type"):
            hypothesize_handler._validate_trailer(
                {"mode": "no-fork", "selected_lead": "x", "loop_n": 1},
                block_type="gather", expected_loop_n=1,
            )

    def test_invalid_mode_raises(self):
        with pytest.raises(OrchestrationError, match="invalid trailer mode"):
            hypothesize_handler._validate_trailer(
                {"mode": "other", "selected_lead": "x", "loop_n": 1},
                block_type="hypothesize", expected_loop_n=1,
            )

    def test_fork_mode_with_no_block_raises(self):
        """fork mode requires a hypothesize: block — trailer-only is a contract
        violation."""
        with pytest.raises(OrchestrationError, match="requires block_type"):
            hypothesize_handler._validate_trailer(
                {"mode": "fork", "selected_lead": "x", "loop_n": 1},
                block_type="unknown", expected_loop_n=1,
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
        """No-fork emits no invlang block — narrative + trailer only.
        Nothing is appended to investigation.md; routing still flows to GATHER."""
        ctx = make_ctx(tmp_path, existing_investigation="## CONTEXTUALIZE\n\nexisting.\n")
        monkeypatch.setattr(hypothesize_handler, "_invoke_subagent",
                            stub_invoke([], [_NO_FORK_RESPONSE]))
        # validator not expected to be called — no sections to append
        monkeypatch.setattr(hypothesize_handler, "_validate_companion_proposed",
                            stub_validator([[]]))
        result = hypothesize_handler.handle(ctx)
        assert result.next_phase == Phase.GATHER
        assert result.payload["mode"] == "no-fork"
        assert result.payload["selected_lead"] == "source-classification"
        assert result.payload["block_type"] == "unknown"

        # investigation.md unchanged — no-fork writes nothing.
        inv = (ctx.run_dir / "investigation.md").read_text()
        assert inv == "## CONTEXTUALIZE\n\nexisting.\n"

    def test_prose_only_stdout_triggers_summary_not_yaml_remediation(self, tmp_path, monkeypatch):
        """Subagent emits narrative prose with no YAML fences at all (typical
        when it wrote a detailed checkpoint and then 'summarized' for the
        caller). Handler detects the missing structured output and retries
        with the `stdout_summary_not_yaml` directive."""
        prose_only = textwrap.dedent("""
            HYPOTHESIZE loop 1 complete. Three mutually exclusive mechanism
            hypotheses formed against v-001. Next lead: container-baseline.
        """).strip()
        captured: list[str] = []
        monkeypatch.setattr(
            hypothesize_handler, "_invoke_subagent",
            stub_invoke(captured, [prose_only, _FORK_RESPONSE]),
        )
        monkeypatch.setattr(hypothesize_handler, "_validate_companion_proposed",
                            stub_validator([[]]))
        ctx = make_ctx(tmp_path)
        result = hypothesize_handler.handle(ctx)

        # Retry fired with the registry directive.
        assert len(captured) == 2
        directive = hypothesize_handler._FAILURE_REMEDIATIONS["stdout_summary_not_yaml"]
        assert directive in captured[1]
        assert directive not in captured[0]
        # Final routing is the fork shape (the retry emitted _FORK_RESPONSE).
        assert result.next_phase == Phase.GATHER
        assert result.payload["mode"] == "fork"
        assert result.payload["block_type"] == "hypothesize"

    def test_gather_block_triggers_structured_remediation_retry(self, tmp_path, monkeypatch):
        """When the subagent emits a `gather:` block, the handler retries with
        the registry-loaded `gather_block_in_hypothesize` directive. On the
        second attempt the subagent emits the correct no-fork shape."""
        captured: list[str] = []
        monkeypatch.setattr(
            hypothesize_handler, "_invoke_subagent",
            stub_invoke(captured, [_NO_FORK_WITH_GATHER_BLOCK_RESPONSE, _NO_FORK_RESPONSE]),
        )
        monkeypatch.setattr(hypothesize_handler, "_validate_companion_proposed",
                            stub_validator([[]]))
        ctx = make_ctx(tmp_path)
        result = hypothesize_handler.handle(ctx)

        # Two attempts — the second is the retry.
        assert len(captured) == 2
        # The retry prompt carries the registry-loaded directive verbatim.
        directive = hypothesize_handler._FAILURE_REMEDIATIONS["gather_block_in_hypothesize"]
        assert directive in captured[1]
        assert "resume_from_checkpoint=true" in captured[1]
        # First-attempt prompt has no remediation directive.
        assert directive not in captured[0]
        # Final routing is the no-fork shape.
        assert result.next_phase == Phase.GATHER
        assert result.payload["mode"] == "no-fork"
        assert result.payload["block_type"] == "unknown"

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
        # mode=fork without an invlang block is a contract mismatch caught
        # by _validate_trailer — "requires block_type 'hypothesize', got
        # 'unknown'".
        with pytest.raises(OrchestrationError, match="requires block_type"):
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

    def test_all_attempts_fail_raises(self, tmp_path, monkeypatch):
        ctx = make_ctx(tmp_path)
        # Retry budget is 2 → 3 total attempts. All three fail → raise.
        monkeypatch.setattr(hypothesize_handler, "_invoke_subagent",
                            stub_invoke([], [_FORK_RESPONSE, _FORK_RESPONSE, _FORK_RESPONSE]))
        monkeypatch.setattr(hypothesize_handler, "_validate_companion_proposed",
                            stub_validator([
                                ["error one"],
                                ["error two"],
                                ["error three"],
                            ]))
        with pytest.raises(OrchestrationError, match="failed after"):
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


# ---------------------------------------------------------------------------
# Checkpoint recovery (stdout-empty → read M_last instead of retrying)
# ---------------------------------------------------------------------------


def _write_checkpoint(run_dir: Path, loop_n: int, payload: dict) -> None:
    import yaml
    ckpt_dir = run_dir / "subagent_checkpoints"
    ckpt_dir.mkdir(exist_ok=True)
    (ckpt_dir / f"hypothesize-loop-{loop_n}.yaml").write_text(
        yaml.safe_dump(payload, sort_keys=False)
    )


class TestCheckpointRecovery:
    """Empty-stdout case: subagent ended on tool_use(Write M_last), `claude
    --print` captured nothing. Handler reads the checkpoint and synthesizes the
    response — no retry."""

    def test_no_fork_checkpoint_synthesized_without_retry(self, tmp_path, monkeypatch):
        ctx = make_ctx(tmp_path)
        _write_checkpoint(ctx.run_dir, 1, {
            "status": "complete",
            "mode": "no-fork",
            "selected_lead": "shell-context",
        })
        captured: list[str] = []
        # Subagent returns empty stdout (the pathology).
        monkeypatch.setattr(hypothesize_handler, "_invoke_subagent",
                            stub_invoke(captured, [""]))
        result = hypothesize_handler.handle(ctx)
        # No retry — recovery short-circuited the rerun.
        assert len(captured) == 1
        assert result.payload["mode"] == "no-fork"
        assert result.payload["selected_lead"] == "shell-context"
        assert result.payload["block_type"] == "unknown"
        # No-fork writes nothing to investigation.md.
        assert not (ctx.run_dir / "investigation.md").exists() or \
               "HYPOTHESIZE" not in (ctx.run_dir / "investigation.md").read_text()

    def test_fork_checkpoint_synthesized_and_appended(self, tmp_path, monkeypatch):
        ctx = make_ctx(tmp_path, existing_investigation="## CONTEXTUALIZE\n\nexisting.\n")
        _write_checkpoint(ctx.run_dir, 1, {
            "status": "complete",
            "mode": "fork",
            "hypotheses": [
                {
                    "id": "h-001",
                    "name": "?scheduled-automation-health-check",
                    "attached_to_vertex": "v-001",
                    "proposed_edge": {
                        "relation": "initiated_by",
                        "parent_vertex": {
                            "type": "identity",
                            "classification": "scheduled-automation-health-check",
                        },
                    },
                    "predictions": [
                        {"id": "p1", "subject": "proposed_parent",
                         "claim": "event cadence matches documented probe interval within ±5s"},
                    ],
                    "refutation_shape": [
                        {"id": "r1", "refutes_predictions": ["p1"],
                         "claim": "event cadence is off-documented-interval"},
                    ],
                    "weight": None,
                },
            ],
            "selected_lead": "authentication-history",
        })
        captured: list[str] = []
        monkeypatch.setattr(hypothesize_handler, "_invoke_subagent",
                            stub_invoke(captured, [""]))
        monkeypatch.setattr(hypothesize_handler, "_validate_companion_proposed",
                            stub_validator([[]]))
        result = hypothesize_handler.handle(ctx)
        assert len(captured) == 1  # no retry
        assert result.payload["mode"] == "fork"
        assert result.payload["selected_lead"] == "authentication-history"
        assert result.payload["block_type"] == "hypothesize"
        written = (ctx.run_dir / "investigation.md").read_text()
        assert "existing." in written
        assert "## HYPOTHESIZE (loop 1)" in written
        assert "?scheduled-automation-health-check" in written

    def test_incomplete_checkpoint_falls_through_to_retry(self, tmp_path, monkeypatch):
        """Checkpoint with status != 'complete' should NOT synthesize — the
        subagent needs to finish the work. Handler falls through to the
        existing stdout_summary_not_yaml retry path."""
        ctx = make_ctx(tmp_path)
        _write_checkpoint(ctx.run_dir, 1, {
            "status": "drafting",  # ← not complete
            "mode": "fork",
        })
        captured: list[str] = []
        monkeypatch.setattr(
            hypothesize_handler, "_invoke_subagent",
            stub_invoke(captured, ["", _FORK_RESPONSE]),
        )
        monkeypatch.setattr(hypothesize_handler, "_validate_companion_proposed",
                            stub_validator([[]]))
        result = hypothesize_handler.handle(ctx)
        # Retry fired — the second call carried the stdout_summary_not_yaml directive.
        assert len(captured) == 2
        directive = hypothesize_handler._FAILURE_REMEDIATIONS["stdout_summary_not_yaml"]
        assert directive in captured[1]
        assert result.payload["mode"] == "fork"

    def test_no_checkpoint_file_falls_through_to_retry(self, tmp_path, monkeypatch):
        """When the subagent emits empty stdout AND wrote no checkpoint at all,
        the retry path is the only recovery."""
        ctx = make_ctx(tmp_path)
        # Deliberately do not write a checkpoint.
        captured: list[str] = []
        monkeypatch.setattr(
            hypothesize_handler, "_invoke_subagent",
            stub_invoke(captured, ["", _FORK_RESPONSE]),
        )
        monkeypatch.setattr(hypothesize_handler, "_validate_companion_proposed",
                            stub_validator([[]]))
        hypothesize_handler.handle(ctx)
        assert len(captured) == 2

    def test_retry_does_not_re_synthesize_from_checkpoint(self, tmp_path, monkeypatch):
        """Both attempts return empty stdout with a stale `status: complete`
        checkpoint on disk. Attempt 1 triggers synthesis; synthesis passes
        validator but routes the handler into its normal retry path (e.g.
        because the first validation errored). Attempt 2 must NOT re-synthesize
        the same checkpoint — it would loop the same failure silently. Instead
        the retry path raises with the stdout_summary_not_yaml directive as
        the unresolved error."""
        ctx = make_ctx(tmp_path)
        _write_checkpoint(ctx.run_dir, 1, {
            "status": "complete",
            "mode": "fork",
            "hypotheses": [{"id": "h-001", "name": "?x"}],
            "selected_lead": "authentication-history",
        })
        captured: list[str] = []
        # All 3 attempts return empty stdout (retry budget = 2 → 3 total).
        monkeypatch.setattr(
            hypothesize_handler, "_invoke_subagent",
            stub_invoke(captured, ["", "", ""]),
        )
        # Validator flags synthesis output on attempt 1, forcing the retry
        # path; attempts 2 + 3 then hit empty-stdout and (with recovery
        # disabled) surface the stdout_summary_not_yaml error.
        monkeypatch.setattr(hypothesize_handler, "_validate_companion_proposed",
                            stub_validator([["invlang rule 27 violation"]]))
        with pytest.raises(OrchestrationError, match="failed after"):
            hypothesize_handler.handle(ctx)
        # Three attempts, no infinite synthesis loop.
        assert len(captured) == 3


# ---------------------------------------------------------------------------
# Archetype-scan-aware prompt trimming
# ---------------------------------------------------------------------------


class TestArchetypeSelection:
    """Vocabulary: archetype-scan emits `candidate | ruled-out` — no
    strong/moderate/weak ranking. The hypothesize prompt ships every candidate
    (plus the adversarial archetype, even if ruled-out)."""

    def test_candidates_plus_adversarial(self):
        investigation = textwrap.dedent("""\
            **Plausible archetypes (candidates for HYPOTHESIZE):**
            - alpha — notes
            - beta — notes
            - gamma — notes
            **Ruled-out archetypes:**
            - epsilon — disqualifier tripped
            **Adversarial archetype:** epsilon — reason
        """)
        picked = hypothesize_handler._select_archetypes_for_prompt(investigation)
        # Every candidate in doc order, then adversarial unioned in even though ruled-out.
        assert picked == ["alpha", "beta", "gamma", "epsilon"]

    def test_adversarial_already_in_candidates_no_duplicate(self):
        investigation = textwrap.dedent("""\
            **Plausible archetypes (candidates for HYPOTHESIZE):**
            - alpha — notes
            - beta — notes
            **Adversarial archetype:** alpha — already candidate
        """)
        picked = hypothesize_handler._select_archetypes_for_prompt(investigation)
        assert picked == ["alpha", "beta"]

    def test_missing_scan_returns_none(self):
        """No archetype-scan block → fall back to loading all archetypes."""
        picked = hypothesize_handler._select_archetypes_for_prompt("nothing here")
        assert picked is None
