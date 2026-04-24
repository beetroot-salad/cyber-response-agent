"""Unit tests for the PREDICT phase handler.

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
from scripts.handlers import predict as predict_handler  # noqa: E402
from scripts.orchestrate import Context, OrchestrationError  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def make_ctx(
    tmp_path: Path,
    *,
    history: list[str] | None = None,
    current_phase: Phase | None = Phase.PREDICT,
    existing_investigation: str | None = None,
) -> Context:
    run_dir = tmp_path / "run-test"
    run_dir.mkdir()
    # alert.json + meta.json are required — the predict handler preloads
    # the alert and per-run salt into the prompt along with investigation.md
    # + signature knowledge + lead catalog.
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
        history=history or [Phase.PREDICT.value],
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
```yaml
predict:
  loop: 1
  shape: M
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
    - id: h-002
      name: "?adversary-controlled-monitoring-host"
      attached_to_vertex: v-001
      proposed_edge:
        relation: initiated_by
        parent_vertex: {type: identity, classification: adversary-controlled-monitoring-host}
      predictions:
        - {id: p1, subject: proposed_parent, claim: "event pattern deviates from documented probe"}
      refutation_shape:
        - {id: r1, refutes_predictions: [p1], claim: "event pattern matches documented probe"}
      weight: null
  routing:
    selected_lead: authentication-history
    composite_secondary: []
```
""").strip()


# Shape E — no hypotheses, branch_plan only. Replaces the old "no new
# hypotheses" / "continue stable fork" shape.
_NO_FORK_RESPONSE = textwrap.dedent("""
```yaml
predict:
  loop: 1
  shape: E
  branch_plan:
    primary_lead: source-classification
    predictions:
      - {id: lp1, if: "classifies as internal-monitoring-host", read_as: "sanctioned", advance_to: authentication-history}
      - {id: lp2, if: "classifies as external-origin", read_as: "bruteforce", advance_to: escalate}
  routing:
    selected_lead: source-classification
    composite_secondary: []
```
""").strip()


# Contract violation: subagent emitted an invlang `hypothesize:` block instead
# of the unified `predict:` envelope. The parser rejects it; the handler
# passes the error verbatim as a remediation note.
_NO_FORK_WITH_GATHER_BLOCK_RESPONSE = textwrap.dedent("""
```yaml
findings:
  - id: l-001
    loop: 1
    name: source-classification
```
""").strip()


# Malformed envelope: the subagent returned invlang `error:` but not wrapped
# in the `predict:` envelope. The parser rejects with a missing-top-level-
# key error which becomes the remediation note.
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
        ctx = make_ctx(tmp_path, history=[Phase.PREDICT.value])
        captured: list[str] = []
        monkeypatch.setattr(predict_handler, "_invoke_subagent",
                            stub_invoke(captured, [_FORK_RESPONSE]))
        monkeypatch.setattr(predict_handler, "_validate_companion_proposed",
                            stub_validator([[]]))
        predict_handler.handle(ctx)
        assert captured[0].count("loop_n=1") == 1
        assert "run_dir=" in captured[0]
        assert "signature_id=wazuh-rule-5710" in captured[0]
        assert "resume_from_checkpoint" not in captured[0]

    def test_prompt_inlines_all_deterministic_context(self, tmp_path, monkeypatch):
        """Handler preloads alert + investigation + signature knowledge +
        lead catalog so the subagent needs no Read tool. Archetype context
        is intentionally absent — PREDICT works at the mechanism layer."""
        ctx = make_ctx(
            tmp_path,
            history=[Phase.PREDICT.value],
            existing_investigation="## CONTEXTUALIZE\n\nsignature summary.\n",
        )
        captured: list[str] = []
        monkeypatch.setattr(predict_handler, "_invoke_subagent",
                            stub_invoke(captured, [_FORK_RESPONSE]))
        monkeypatch.setattr(predict_handler, "_validate_companion_proposed",
                            stub_validator([[]]))
        predict_handler.handle(ctx)
        prompt = captured[0]

        # Tagged blocks present (alert tag is salted)
        assert "<alert-test-salt>" in prompt and "</alert-test-salt>" in prompt
        # predict handler uses mode="predict" — tag carries a mode attribute
        assert "<investigation mode=\"predict\">" in prompt and "signature summary" in prompt
        assert "<signature-knowledge>" in prompt
        assert "<playbook>" in prompt  # real 5710 playbook body inlined
        # Archetype context is NOT in the PREDICT prompt (dropped per the
        # reframe — archetypes are a REPORT-phase concern).
        assert "<archetypes>" not in prompt
        assert "<lead-catalog>" in prompt
        assert 'name="authentication-history"' in prompt  # real lead inlined

    def test_second_loop_passes_loop_n_2(self, tmp_path, monkeypatch):
        # History of one completed loop + current PREDICT entry for loop 2.
        history = [
            Phase.CONTEXTUALIZE.value,
            Phase.PREDICT.value,
            Phase.GATHER.value,
            Phase.ANALYZE.value,
            Phase.PREDICT.value,
        ]
        ctx = make_ctx(tmp_path, history=history)
        response = _FORK_RESPONSE.replace("loop: 1", "loop: 2")
        captured: list[str] = []
        monkeypatch.setattr(predict_handler, "_invoke_subagent",
                            stub_invoke(captured, [response]))
        monkeypatch.setattr(predict_handler, "_validate_companion_proposed",
                            stub_validator([[]]))
        predict_handler.handle(ctx)
        assert "loop_n=2" in captured[0]

    def test_retry_prompt_carries_remediation(self, tmp_path, monkeypatch):
        ctx = make_ctx(tmp_path)
        captured: list[str] = []
        monkeypatch.setattr(predict_handler, "_invoke_subagent",
                            stub_invoke(captured, [_FORK_RESPONSE, _FORK_RESPONSE]))
        monkeypatch.setattr(predict_handler, "_validate_companion_proposed",
                            stub_validator([
                                ["hypothesis h-001 prediction p1: claim contains "
                                 "semicolon-separated clauses"],
                                [],
                            ]))
        predict_handler.handle(ctx)
        assert "resume_from_checkpoint=true" in captured[1]
        assert "remediation_notes=" in captured[1]
        assert "semicolon-separated" in captured[1]
        # First prompt has no remediation, second does.
        assert "resume_from_checkpoint" not in captured[0]


# ---------------------------------------------------------------------------
# Past-investigation priors integration
# ---------------------------------------------------------------------------


_INVESTIGATION_WITH_PREDICT = textwrap.dedent("""
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

## PREDICT (loop 1)

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
        "findings": [
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
            existing_investigation=_INVESTIGATION_WITH_PREDICT,
        )
        import invlang
        monkeypatch.setattr(invlang, "load_corpus", lambda *a, **k: [_synthetic_companion()])

        prompt = predict_handler._assemble_prompt(ctx)
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

        prompt = predict_handler._assemble_prompt(ctx)
        # Loop-1 takes the prologue-keyed retrieval path. With an empty
        # corpus, priors fall through to the sparse-prior fallback —
        # "scaffold from first principles per PREDICT's ASSESS gate."
        assert "## Past-investigation priors" in prompt
        assert "Prologue topology" in prompt
        assert "tier 3: no match" in prompt
        assert "sparse" in prompt
        assert "first principles" in prompt
        # Sentinel: the loop-2+ per-seed frontier path would emit this.
        assert "(no frontier extracted)" not in prompt

    def test_priors_failure_is_non_fatal(self, tmp_path, monkeypatch):
        ctx = make_ctx(
            tmp_path,
            existing_investigation=_INVESTIGATION_WITH_PREDICT,
        )
        import invlang

        def _boom(*a, **k):
            raise RuntimeError("corpus env unset")

        monkeypatch.setattr(invlang, "load_corpus", _boom)

        prompt = predict_handler._assemble_prompt(ctx)
        assert "## Past-investigation priors" in prompt
        assert "(priors unavailable" in prompt
        # Handler still dispatches cleanly when priors fail.
        captured: list[str] = []
        monkeypatch.setattr(predict_handler, "_invoke_subagent",
                            stub_invoke(captured, [_FORK_RESPONSE]))
        monkeypatch.setattr(predict_handler, "_validate_companion_proposed",
                            stub_validator([[]]))
        result = predict_handler.handle(ctx)
        assert result.next_phase == Phase.GATHER
        assert "(priors unavailable" in captured[0]


# ---------------------------------------------------------------------------
# Block-type detection
# ---------------------------------------------------------------------------


# (Legacy test classes TestDetectBlockType, TestValidateTrailer, and
# TestStripTerminalRouting removed — the helpers they covered
# (_detect_block_type, _validate_trailer, _strip_terminal_routing) are part
# of the old two-fence contract superseded by the unified `predict:`
# envelope + parse_predict_output pipeline. Coverage of the new shape lives
# in tests/test_output_parser.py.)


# ---------------------------------------------------------------------------
# End-to-end happy paths
# ---------------------------------------------------------------------------


class TestHandleHappyPaths:
    def test_hypotheses_block_routes_to_gather(self, tmp_path, monkeypatch):
        """≥1 new hypotheses this loop → invlang block present. Payload carries
        selected_lead + handler-computed loop_n. No mode/block_type fields."""
        ctx = make_ctx(tmp_path)
        monkeypatch.setattr(predict_handler, "_invoke_subagent",
                            stub_invoke([], [_FORK_RESPONSE]))
        monkeypatch.setattr(predict_handler, "_validate_companion_proposed",
                            stub_validator([[]]))
        result = predict_handler.handle(ctx)
        assert result.next_phase == Phase.GATHER
        assert result.payload["selected_lead"] == "authentication-history"
        assert result.payload["loop_n"] == 1
        assert result.payload["composite_secondary"] == []
        # Retired fields must not appear in the payload.
        assert "mode" not in result.payload
        assert "block_type" not in result.payload

    def test_zero_new_hypotheses_routes_to_gather(self, tmp_path, monkeypatch):
        """Continue-stable-fork path: narrative-only emission (no invlang
        block). Nothing appended to investigation.md; routing flows to GATHER."""
        ctx = make_ctx(tmp_path, existing_investigation="## CONTEXTUALIZE\n\nexisting.\n")
        monkeypatch.setattr(predict_handler, "_invoke_subagent",
                            stub_invoke([], [_NO_FORK_RESPONSE]))
        # validator not expected to be called — no sections to append
        monkeypatch.setattr(predict_handler, "_validate_companion_proposed",
                            stub_validator([[]]))
        result = predict_handler.handle(ctx)
        assert result.next_phase == Phase.GATHER
        assert result.payload["selected_lead"] == "source-classification"
        assert result.payload["loop_n"] == 1
        assert result.payload["composite_secondary"] == []

        # investigation.md unchanged — zero-hypotheses writes nothing.
        inv = (ctx.run_dir / "investigation.md").read_text()
        assert inv == "## CONTEXTUALIZE\n\nexisting.\n"

    def test_composite_secondary_passes_through_to_payload(self, tmp_path, monkeypatch):
        """PREDICT can prescribe multiple leads via routing.composite_secondary.
        Handler passes through verbatim to GATHER."""
        response_with_secondary = textwrap.dedent("""
            ```yaml
            predict:
              loop: 1
              shape: A
              hypotheses:
                - id: h-001
                  name: "?host-runtime-exec"
                  attached_to_vertex: v-001
                  proposed_edge:
                    relation: spawned
                    parent_vertex: {type: process, classification: host-side-exec-invoker}
                  predictions:
                    - {id: p1, claim: "baseline has prior runc-parent shell"}
                  refutation_shape:
                    - {id: r1, refutes_predictions: [p1], claim: "no baseline"}
                  authorization_contract:
                    - {id: ac1, edge_ref: proposed, anchor_kind: ci-cd-job-record, asks: authorization}
                  weight: null
              routing:
                selected_lead: correlated-falco-events
                composite_secondary: [source-reputation]
            ```
        """).strip()
        ctx = make_ctx(tmp_path)
        monkeypatch.setattr(predict_handler, "_invoke_subagent",
                            stub_invoke([], [response_with_secondary]))
        monkeypatch.setattr(predict_handler, "_validate_companion_proposed",
                            stub_validator([[]]))
        result = predict_handler.handle(ctx)
        assert result.payload["selected_lead"] == "correlated-falco-events"
        assert result.payload["composite_secondary"] == ["source-reputation"]

    def test_empty_stdout_triggers_stdout_empty_remediation(self, tmp_path, monkeypatch):
        """Empty stdout (M_last pathology — subagent ended on tool_use, dropped
        by `claude --print`) with no checkpoint to recover from → retry with
        the `stdout_empty` remediation directive."""
        captured: list[str] = []
        monkeypatch.setattr(
            predict_handler, "_invoke_subagent",
            stub_invoke(captured, ["", _FORK_RESPONSE]),
        )
        monkeypatch.setattr(predict_handler, "_validate_companion_proposed",
                            stub_validator([[]]))
        ctx = make_ctx(tmp_path)
        result = predict_handler.handle(ctx)

        # Retry fired with the stdout_empty directive.
        assert len(captured) == 2
        directive = predict_handler._FAILURE_REMEDIATIONS["stdout_empty"]
        assert directive in captured[1]
        assert directive not in captured[0]
        # Final routing lands on the fork-shape response.
        assert result.next_phase == Phase.GATHER
        assert result.payload["selected_lead"] == "authentication-history"

    def test_non_predict_envelope_triggers_parse_error_retry(self, tmp_path, monkeypatch):
        """When the subagent emits a YAML block without the top-level
        `predict:` key (e.g., an invlang `findings:` block directly), the parser
        rejects with a PredictOutputError. The handler passes the error
        verbatim as a remediation note and retries."""
        captured: list[str] = []
        monkeypatch.setattr(
            predict_handler, "_invoke_subagent",
            stub_invoke(captured, [_NO_FORK_WITH_GATHER_BLOCK_RESPONSE, _NO_FORK_RESPONSE]),
        )
        monkeypatch.setattr(predict_handler, "_validate_companion_proposed",
                            stub_validator([[]]))
        ctx = make_ctx(tmp_path)
        result = predict_handler.handle(ctx)

        # Two attempts — the second is the retry.
        assert len(captured) == 2
        # Parser's error message lands in the retry prompt as a remediation.
        assert "top-level key `predict:`" in captured[1]
        assert "resume_from_checkpoint=true" in captured[1]
        # Final routing — Shape E response successfully parsed.
        assert result.next_phase == Phase.GATHER
        assert result.payload["selected_lead"] == "source-classification"

    def test_appends_sections_without_trailer(self, tmp_path, monkeypatch):
        ctx = make_ctx(tmp_path, existing_investigation="## CONTEXTUALIZE\n\nexisting.\n")
        monkeypatch.setattr(predict_handler, "_invoke_subagent",
                            stub_invoke([], [_FORK_RESPONSE]))
        monkeypatch.setattr(predict_handler, "_validate_companion_proposed",
                            stub_validator([[]]))
        predict_handler.handle(ctx)
        written = (ctx.run_dir / "investigation.md").read_text()
        assert "existing." in written
        assert "## PREDICT (loop 1)" in written
        assert "hypothesize:" in written
        # Terminal trailer must not land in investigation.md.
        assert "selected_lead: authentication-history" not in written

    def test_unresolved_prescribed_set_threaded_as_remediation_note(
        self, tmp_path, monkeypatch,
    ):
        """ANALYZE's unresolved_prescribed_set feeds PREDICT's first-attempt
        remediation_notes — guidance for the subagent to re-prescribe dropped
        leads."""
        ctx = make_ctx(tmp_path)
        ctx.outputs[Phase.ANALYZE] = {
            "route": "continue",
            "unresolved_prescribed_set": ["source-reputation"],
        }
        captured: list[str] = []
        monkeypatch.setattr(predict_handler, "_invoke_subagent",
                            stub_invoke(captured, [_FORK_RESPONSE]))
        monkeypatch.setattr(predict_handler, "_validate_companion_proposed",
                            stub_validator([[]]))
        predict_handler.handle(ctx)
        # First-attempt prompt carries the unresolved-prescribed directive.
        assert "UNRESOLVED PRESCRIBED LEADS" in captured[0]
        assert "source-reputation" in captured[0]


# ---------------------------------------------------------------------------
# Error-block + malformed-output paths
# ---------------------------------------------------------------------------


class TestHandleErrorPaths:
    def test_error_block_triggers_retry_then_raises_after_budget(self, tmp_path, monkeypatch):
        """Under the unified envelope, an `error:` top-level block (without
        the `predict:` wrapper) fails the parser with a missing-top-level-
        key error. That's a retry-directive, not a raise. Three failed
        attempts in a row exhaust the retry budget → OrchestrationError."""
        ctx = make_ctx(tmp_path)
        monkeypatch.setattr(
            predict_handler, "_invoke_subagent",
            stub_invoke([], [_ERROR_RESPONSE, _ERROR_RESPONSE, _ERROR_RESPONSE]),
        )
        with pytest.raises(OrchestrationError, match="failed after"):
            predict_handler.handle(ctx)

    def test_shape_E_branch_plan_only_is_legal(self, tmp_path, monkeypatch):
        """Shape E — no hypotheses, branch_plan with lead-level readings.
        Under the unified envelope this is a first-class shape; handler routes
        to GATHER and passes branch_plan.predictions through the payload."""
        ctx = make_ctx(tmp_path, existing_investigation="## CONTEXTUALIZE\n\nexisting.\n")
        monkeypatch.setattr(predict_handler, "_invoke_subagent",
                            stub_invoke([], [_NO_FORK_RESPONSE]))
        result = predict_handler.handle(ctx)
        assert result.next_phase == Phase.GATHER
        assert result.payload["selected_lead"] == "source-classification"
        # branch_plan.predictions propagated to GATHER via the payload.
        assert "branch_plan_predictions" in result.payload
        assert len(result.payload["branch_plan_predictions"]) == 2

    def test_routing_missing_selected_lead_retries_then_raises(self, tmp_path, monkeypatch):
        """Missing routing.selected_lead is a parser-level rejection. Handler
        retries; three failures exhaust the retry budget → OrchestrationError."""
        ctx = make_ctx(tmp_path)
        bad = textwrap.dedent("""
            ```yaml
            predict:
              loop: 1
              shape: E
              branch_plan:
                primary_lead: x
                predictions: [{id: lp1, if: "a", read_as: "b", advance_to: c}]
              routing:
                composite_secondary: []
            ```
            """).strip()
        monkeypatch.setattr(predict_handler, "_invoke_subagent",
                            stub_invoke([], [bad, bad, bad]))
        with pytest.raises(OrchestrationError, match="selected_lead"):
            predict_handler.handle(ctx)


# ---------------------------------------------------------------------------
# Validator-error retry flow
# ---------------------------------------------------------------------------


class TestValidationRetry:
    def test_first_fails_second_succeeds(self, tmp_path, monkeypatch):
        ctx = make_ctx(tmp_path)
        captured: list[str] = []
        monkeypatch.setattr(predict_handler, "_invoke_subagent",
                            stub_invoke(captured, [_FORK_RESPONSE, _FORK_RESPONSE]))
        monkeypatch.setattr(predict_handler, "_validate_companion_proposed",
                            stub_validator([
                                ["hypothesis h-001: classification starts with "
                                 "evaluation-packed prefix"],
                                [],
                            ]))
        result = predict_handler.handle(ctx)
        assert result.next_phase == Phase.GATHER
        assert len(captured) == 2

    def test_all_attempts_fail_raises(self, tmp_path, monkeypatch):
        ctx = make_ctx(tmp_path)
        # Retry budget is 2 → 3 total attempts. All three fail → raise.
        monkeypatch.setattr(predict_handler, "_invoke_subagent",
                            stub_invoke([], [_FORK_RESPONSE, _FORK_RESPONSE, _FORK_RESPONSE]))
        monkeypatch.setattr(predict_handler, "_validate_companion_proposed",
                            stub_validator([
                                ["error one"],
                                ["error two"],
                                ["error three"],
                            ]))
        with pytest.raises(OrchestrationError, match="failed after"):
            predict_handler.handle(ctx)

    def test_no_retry_if_first_passes(self, tmp_path, monkeypatch):
        ctx = make_ctx(tmp_path)
        captured: list[str] = []
        monkeypatch.setattr(predict_handler, "_invoke_subagent",
                            stub_invoke(captured, [_FORK_RESPONSE]))
        monkeypatch.setattr(predict_handler, "_validate_companion_proposed",
                            stub_validator([[]]))
        predict_handler.handle(ctx)
        assert len(captured) == 1


# ---------------------------------------------------------------------------
# Checkpoint recovery (stdout-empty → read M_last instead of retrying)
# ---------------------------------------------------------------------------


def _write_checkpoint(run_dir: Path, loop_n: int, payload: dict) -> None:
    import yaml
    ckpt_dir = run_dir / "subagent_checkpoints"
    ckpt_dir.mkdir(exist_ok=True)
    (ckpt_dir / f"predict-loop-{loop_n}.yaml").write_text(
        yaml.safe_dump(payload, sort_keys=False)
    )


class TestCheckpointRecovery:
    """Empty-stdout case: subagent ended on tool_use(Write M_last), `claude
    --print` captured nothing. Handler reads the checkpoint and synthesizes the
    response — no retry. Checkpoint shape mirrors the unified envelope:
    {status: complete, predict: {...}}.
    """

    def test_shape_E_checkpoint_synthesized_without_retry(self, tmp_path, monkeypatch):
        """Checkpoint with a Shape E envelope (branch_plan only, no
        hypotheses) → synthesized, no invlang block appended, no retry."""
        ctx = make_ctx(tmp_path)
        _write_checkpoint(ctx.run_dir, 1, {
            "status": "complete",
            "predict": {
                "loop": 1,
                "shape": "E",
                "branch_plan": {
                    "primary_lead": "shell-context",
                    "predictions": [
                        {"id": "lp1", "if": "a", "read_as": "b", "advance_to": "c"},
                    ],
                },
                "routing": {
                    "selected_lead": "shell-context",
                    "composite_secondary": [],
                },
            },
        })
        captured: list[str] = []
        # Subagent returns empty stdout (the pathology).
        monkeypatch.setattr(predict_handler, "_invoke_subagent",
                            stub_invoke(captured, [""]))
        result = predict_handler.handle(ctx)
        # No retry — recovery short-circuited the rerun.
        assert len(captured) == 1
        assert result.payload["selected_lead"] == "shell-context"
        # Shape E writes nothing to investigation.md (branch_plan flows via payload).
        assert not (ctx.run_dir / "investigation.md").exists() or \
               "PREDICT" not in (ctx.run_dir / "investigation.md").read_text()

    def test_hypotheses_checkpoint_synthesized_and_appended(self, tmp_path, monkeypatch):
        """Checkpoint with hypotheses → synthesized as `hypothesize:` block
        appended to investigation.md, no retry."""
        ctx = make_ctx(tmp_path, existing_investigation="## CONTEXTUALIZE\n\nexisting.\n")
        _write_checkpoint(ctx.run_dir, 1, {
            "status": "complete",
            "predict": {
                "loop": 1,
                "shape": "M",
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
                "routing": {
                    "selected_lead": "authentication-history",
                    "composite_secondary": [],
                },
            },
        })
        captured: list[str] = []
        monkeypatch.setattr(predict_handler, "_invoke_subagent",
                            stub_invoke(captured, [""]))
        monkeypatch.setattr(predict_handler, "_validate_companion_proposed",
                            stub_validator([[]]))
        result = predict_handler.handle(ctx)
        assert len(captured) == 1  # no retry
        assert result.payload["selected_lead"] == "authentication-history"
        written = (ctx.run_dir / "investigation.md").read_text()
        assert "existing." in written
        assert "## PREDICT (loop 1)" in written
        assert "?scheduled-automation-health-check" in written

    def test_incomplete_checkpoint_falls_through_to_retry(self, tmp_path, monkeypatch):
        """Checkpoint with status != 'complete' should NOT synthesize — the
        subagent needs to finish the work. Handler falls through to the
        stdout_empty retry path."""
        ctx = make_ctx(tmp_path)
        _write_checkpoint(ctx.run_dir, 1, {
            "status": "drafting",  # ← not complete
            "predict": {
                "loop": 1,
                "shape": "E",
                "branch_plan": {"primary_lead": "x", "predictions": [
                    {"id": "lp1", "if": "a", "read_as": "b", "advance_to": "c"},
                ]},
                "routing": {"selected_lead": "x", "composite_secondary": []},
            },
        })
        captured: list[str] = []
        monkeypatch.setattr(
            predict_handler, "_invoke_subagent",
            stub_invoke(captured, ["", _FORK_RESPONSE]),
        )
        monkeypatch.setattr(predict_handler, "_validate_companion_proposed",
                            stub_validator([[]]))
        result = predict_handler.handle(ctx)
        # Retry fired — the second call carried the stdout_empty directive.
        assert len(captured) == 2
        directive = predict_handler._FAILURE_REMEDIATIONS["stdout_empty"]
        assert directive in captured[1]
        assert result.payload["selected_lead"] == "authentication-history"

    def test_no_checkpoint_file_falls_through_to_retry(self, tmp_path, monkeypatch):
        """When the subagent emits empty stdout AND wrote no checkpoint at all,
        the retry path is the only recovery."""
        ctx = make_ctx(tmp_path)
        # Deliberately do not write a checkpoint.
        captured: list[str] = []
        monkeypatch.setattr(
            predict_handler, "_invoke_subagent",
            stub_invoke(captured, ["", _FORK_RESPONSE]),
        )
        monkeypatch.setattr(predict_handler, "_validate_companion_proposed",
                            stub_validator([[]]))
        predict_handler.handle(ctx)
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
            "predict": {
                "loop": 1,
                "shape": "M",
                "hypotheses": [
                    {
                        "id": "h-001",
                        "name": "?x",
                        "attached_to_vertex": "v-001",
                        "proposed_edge": {
                            "relation": "spawned",
                            "parent_vertex": {"type": "process", "classification": "x"},
                        },
                        "predictions": [{"id": "p1", "claim": "..."}],
                        "refutation_shape": [
                            {"id": "r1", "refutes_predictions": ["p1"], "claim": "..."},
                        ],
                        "weight": None,
                    },
                    {
                        "id": "h-002",
                        "name": "?y",
                        "attached_to_vertex": "v-001",
                        "proposed_edge": {
                            "relation": "spawned",
                            "parent_vertex": {"type": "process", "classification": "y"},
                        },
                        "predictions": [{"id": "p1", "claim": "..."}],
                        "refutation_shape": [
                            {"id": "r1", "refutes_predictions": ["p1"], "claim": "..."},
                        ],
                        "weight": None,
                    },
                ],
                "routing": {
                    "selected_lead": "authentication-history",
                    "composite_secondary": [],
                },
            },
        })
        captured: list[str] = []
        # All 3 attempts return empty stdout (retry budget = 2 → 3 total).
        monkeypatch.setattr(
            predict_handler, "_invoke_subagent",
            stub_invoke(captured, ["", "", ""]),
        )
        # Validator flags synthesis output on attempt 1, forcing the retry
        # path; attempts 2 + 3 then hit empty-stdout and (with recovery
        # disabled) surface the stdout_empty error.
        monkeypatch.setattr(predict_handler, "_validate_companion_proposed",
                            stub_validator([["invlang rule 27 violation"]]))
        with pytest.raises(OrchestrationError, match="failed after"):
            predict_handler.handle(ctx)
        # Three attempts, no infinite synthesis loop.
        assert len(captured) == 3


# Archetype selection was removed — PREDICT no longer consumes archetype
# context. Archetype labeling now happens at REPORT time via the
# `archetype-match` subagent (see tests/test_handlers_report.py
# ::test_archetype_match_is_invoked_on_analyze_routed_path). CONTEXTUALIZE
# no longer emits an archetype block, so the `_select_archetypes_for_prompt`
# helper and the old parsers (`parse_archetype_candidates` /
# `parse_adversarial_archetype`) are gone.
