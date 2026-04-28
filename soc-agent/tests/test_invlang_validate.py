"""Orchestration + shared-fixture entry point for invlang validator tests.

This module hosts the shared YAML fixtures re-exported by the per-concern
test modules (test_invlang_structural.py, test_invlang_predictions.py,
test_invlang_authorization.py, test_invlang_impact.py,
test_invlang_hypothesis.py, test_invlang_warnings.py) along with end-to-end
and subprocess-level coverage:

- `TestValidateCompanion`   — orchestrator smoke tests
- `TestCheckAppendOnly`     — block-level append-only guard
- `TestCheckRouteCompliance`— warning channel for prediction routing
- `TestCollectWarnings`     — warning aggregator
- `TestHookIntegration`     — subprocess PreToolUse simulation
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from hooks.scripts.invlang_validate import (
    YAML_BLOCK_RE,
    _check_append_only,
    _check_route_compliance,
    _merge_blocks,
    collect_warnings,
    validate_companion,
)

HOOK_SCRIPT = SOC_AGENT_ROOT / "hooks" / "scripts" / "invlang_validate.py"


# ---------------------------------------------------------------------------
# Shared YAML fixtures — re-exported to sibling test_invlang_* modules
# ---------------------------------------------------------------------------

VALID_PROLOGUE_YAML = """\
prologue:
  vertices:
    - id: v-001
      type: endpoint
      classification: external-unknown
      identifier: "203.0.113.47"
    - id: v-002
      type: endpoint
      classification: internal-server
      identifier: "web-server-01"
  edges:
    - id: e-001
      relation: attempted_auth
      source_vertex: v-001
      target_vertex: v-002
      authority:
        kind: siem-event
        source: wazuh-indexer
"""

VALID_PREDICT_YAML = """\
hypothesize:
  hypotheses:
    - id: h-001
      name: "?opportunistic-scanner"
      attached_to_vertex: v-001
      proposed_edge:
        relation: initiated_by
        parent_vertex:
          type: identity
          classification: automated-scanner
      predictions:
        - id: p1
          subject: proposed_parent
          claim: "source IP appears in threat-intel scanner list"
      refutation_shape:
        - id: r1
          refutes_predictions: [p1]
          shape: "source IP authenticated previously in last 90d"
      weight: null
"""

VALID_LEAD_YAML = """\
findings:
  - id: l-001
    loop: 1
    name: source-classification
    target: v-001
    query_details:
      system: wazuh-indexer
      template: source-ip-lookup
      query: "src_ip:203.0.113.47"
      time_window: "30d"
      substitutions: {}
    outcome:
      attribute_updates:
        - target: v-001
          updates:
            classification: external-unknown
      observations:
        vertices: []
        edges:
          - id: e-002
            relation: classified_as
            source_vertex: v-001
            target_vertex: v-002
            authority:
              kind: siem-event
              source: wazuh-indexer
    resolutions:
      - hypothesis: h-001
        before: null
        after: "--"
        severity_of_test: strong
        matched_prediction_ids: []
        matched_refutation_ids: [r1]
        reasoning: "source IP authenticated from web-server-01 six hours prior — refutation r1 matched"
        supporting_edges: [e-001]
"""

VALID_CONCLUDE_YAML = """\
conclude:
  termination:
    category: adversarial-refuted
    rationale: "All adversarial hypotheses refuted with -- evidence"
  disposition: benign
  impact_verdict: none
  impact_severity: null
  confidence: high
  matched_archetype: external-bruteforce
  surviving_hypotheses: []
  summary: "SSH brute force from external scanner; no successful auth"
"""

FULL_COMPANION_MD = f"""## CONTEXTUALIZE

**Alert:** TEST-001

```yaml
{VALID_PROLOGUE_YAML}
```

## PREDICT (loop 1)

**Active hypotheses:** ?opportunistic-scanner

```yaml
{VALID_PREDICT_YAML}
```

## GATHER (loop 1)

**Raw observation:** source IP not in threat-intel lists

## ANALYZE (loop 1)

**Assessment:** h-001 moves to +

```yaml
{VALID_LEAD_YAML}
```

## REPORT

**Verdict:** resolved

```yaml
{VALID_CONCLUDE_YAML}
```
"""


def _parse_yaml_block(text: str) -> dict:
    """Parse the first ```yaml block in `text`. Used by sibling test modules."""
    import yaml
    for match in YAML_BLOCK_RE.finditer(text):
        doc = yaml.safe_load(match.group(1))
        if isinstance(doc, dict):
            return doc
    return {}


def _companion_with_contract(
    contract_edge_ref: str = "proposed",
    contract_id: str = "ac1",
    resolutions: list[dict] | None = None,
    disposition: str = "benign",
    hypothesis_weight: str = "+",
    extra_edges: list[dict] | None = None,
    anchor_consultations: list[dict] | None = None,
) -> dict:
    """Build a merged companion carrying one hypothesis with one authorization_contract.

    Post-v2.11 shape:
      - `authorization_resolutions[]` lives INLINE on the observed edge
        (`gather[0].outcome.observations.edges[0].authorization_resolutions[]`).
      - The lead also carries a minimal `anchor_consultations[]` entry
        (telemetry-baseline baseline) to exercise the provenance checks.
      - The parent_vertex.type is `endpoint` (non-acting-entity) so the
        rule-#32 integrity-peer discipline does not apply by default.

    Defaults shape a live-weight benign resolution with one `authorized`
    verdict on the edge. Override parameters to flip individual dimensions
    for negative cases.
    """
    edges = [
        {
            "id": "e-001",
            "relation": "attempted_auth",
            "source_vertex": "v-001",
            "target_vertex": "v-002",
            "authority": {"kind": "siem-event", "source": "wazuh"},
        }
    ]
    if extra_edges:
        edges.extend(extra_edges)
    default_resolutions = [
        {
            "verdict": "authorized",
            "anchor_kind": "approved-monitoring-sources",
            "anchor_id": "ams-registry-2026-01",
            "grounding_kind": "org-authority",
            "authority_for_question": "full",
            "anchor_query": "source triple lookup",
            "as_of": "2026-04-18T00:00:00Z",
            "resolved_by_lead": "l-001",
            "fulfills_contract": f"h-001.{contract_id}",
        }
    ]
    observed_edge = {
        "id": "e-002",
        "relation": "classified_as",
        "source_vertex": "v-001",
        "target_vertex": "v-002",
        "authority": {"kind": "authoritative-source", "source": "registry"},
        "authorization_resolutions": (
            resolutions if resolutions is not None else default_resolutions
        ),
    }
    default_consultations = [
        {
            "anchor_id": "approved-monitoring-sources",
            "anchor_kind": "approved-monitoring-sources",
            "grounding_kind": "org-authority",
            "result": "confirmed",
            "as_of": "2026-04-18T00:00:00Z",
            "authority_for_question": "full",
        }
    ]
    return {
        "prologue": {
            "vertices": [
                {"id": "v-001", "type": "endpoint", "classification": "external"},
                {"id": "v-002", "type": "endpoint", "classification": "internal"},
            ],
            "edges": edges,
        },
        "hypothesize": {
            "hypotheses": [
                {
                    "id": "h-001",
                    "name": "?source-authorization-unknown",
                    "attached_to_vertex": "v-001",
                    "proposed_edge": {
                        "relation": "attempted_auth",
                        "parent_vertex": {"type": "endpoint", "classification": "unknown"},
                    },
                    "predictions": [{"id": "p1", "claim": "source resolves to an approved entry"}],
                    "authorization_contract": [
                        {
                            "id": contract_id,
                            "edge_ref": contract_edge_ref,
                            "anchor_kind": "approved-monitoring-sources",
                            "predicate": "authorized iff srcip in approved-monitoring-sources",
                            "on_unauthorized": "escalate",
                            "on_indeterminate": "escalate",
                        }
                    ],
                }
            ]
        },
        "findings": [
            {
                "id": "l-001",
                "loop": 1,
                "name": "authorization-lookup",
                "target": "v-001",
                "query_details": {},
                "outcome": {
                    "observations": {"vertices": [], "edges": [observed_edge]},
                    "anchor_consultations": (
                        anchor_consultations
                        if anchor_consultations is not None
                        else default_consultations
                    ),
                },
                "resolutions": [
                    {
                        "hypothesis": "h-001",
                        "after": hypothesis_weight,
                        "severity_of_test": "severe",
                        "matched_prediction_ids": ["p1"],
                        "matched_refutation_ids": [],
                        "reasoning": "anchor lookup resolved",
                        "supporting_edges": ["e-002"],
                    }
                ],
            }
        ],
        "conclude": {
            "termination": {"category": "trust-root", "rationale": "contract resolved"},
            "disposition": disposition,
            "confidence": "high",
        },
    }


# ---------------------------------------------------------------------------
# Unit tests: _check_route_compliance (warning channel)
# ---------------------------------------------------------------------------


def _merged_with_leads(leads):
    return {"findings": leads}


def _lead(name, predictions=None):
    return {
        "id": f"l-{name}", "loop": 1, "name": name, "target": "v-001",
        "query_details": {}, "outcome": {},
        "predictions": predictions,
        "resolutions": [],
    }


class TestCheckRouteCompliance:
    def test_no_predictions_is_silent(self):
        merged = _merged_with_leads([_lead("a"), _lead("b")])
        assert _check_route_compliance(merged) == []

    def test_next_lead_matches_advance_to(self):
        preds = [{"id": "lp1", "if": "x", "read_as": "y", "advance_to": "next-step"}]
        merged = _merged_with_leads([_lead("first", preds), _lead("next-step")])
        assert _check_route_compliance(merged) == []

    def test_next_lead_mismatch_emits_warning(self):
        preds = [{"id": "lp1", "if": "x", "read_as": "y", "advance_to": "expected"}]
        merged = _merged_with_leads([_lead("first", preds), _lead("actual-other")])
        warnings = _check_route_compliance(merged)
        assert warnings
        assert "actual-other" in warnings[0]
        assert "expected" in warnings[0]

    def test_terminal_lead_with_conclude_is_silent(self):
        preds = [{"id": "lp1", "if": "x", "read_as": "y", "advance_to": "REPORT"}]
        merged = _merged_with_leads([_lead("first", preds)])
        assert _check_route_compliance(merged) == []

    def test_terminal_lead_without_conclude_warns(self):
        preds = [{"id": "lp1", "if": "x", "read_as": "y", "advance_to": "next-step"}]
        merged = _merged_with_leads([_lead("first", preds)])
        warnings = _check_route_compliance(merged)
        assert warnings
        assert "terminal" in warnings[0].lower()

    def test_hypothesize_advance_does_not_require_next_lead(self):
        preds = [{"id": "lp1", "if": "x", "read_as": "y", "advance_to": "PREDICT"}]
        merged = _merged_with_leads([_lead("first", preds), _lead("some-other")])
        warnings = _check_route_compliance(merged)
        assert warnings


class TestCollectWarnings:
    def test_companion_with_route_warning(self):
        text = (
            "```yaml\n"
            "findings:\n"
            "  - id: l-001\n"
            "    loop: 1\n"
            "    name: first\n"
            "    target: v-001\n"
            "    query_details: {}\n"
            "    outcome: {}\n"
            "    predictions:\n"
            "      - id: lp1\n"
            "        if: x\n"
            "        read_as: y\n"
            "        advance_to: expected-next\n"
            "    resolutions: []\n"
            "  - id: l-002\n"
            "    loop: 1\n"
            "    name: actual-next\n"
            "    target: v-001\n"
            "    query_details: {}\n"
            "    outcome: {}\n"
            "    resolutions: []\n"
            "```\n"
        )
        warnings = collect_warnings(text)
        assert warnings
        assert "actual-next" in warnings[0]


# ---------------------------------------------------------------------------
# Unit tests: _check_append_only
# ---------------------------------------------------------------------------


class TestCheckAppendOnly:
    def test_adding_block_passes(self):
        current = "## CONTEXTUALIZE\n\nsome prose\n"
        proposed = current + "\n```yaml\nprologue:\n  vertices: []\n  edges: []\n```\n"
        assert _check_append_only(proposed, current) == []

    def test_same_count_passes(self):
        block = "\n```yaml\nprologue:\n  vertices: []\n  edges: []\n```\n"
        assert _check_append_only(block, block) == []

    def test_removing_block_fails(self):
        block = "\n```yaml\nprologue:\n  vertices: []\n  edges: []\n```\n"
        current = block + block
        proposed = block  # one block removed
        errors = _check_append_only(proposed, current)
        assert errors
        assert "append-only" in errors[0]


# ---------------------------------------------------------------------------
# Unit tests: validate_companion (end-to-end)
# ---------------------------------------------------------------------------


class TestValidateCompanion:
    def test_no_yaml_blocks_passes(self):
        text = "## CONTEXTUALIZE\n\nsome prose only\n"
        assert validate_companion(text, None) == []

    def test_valid_full_companion_passes(self):
        errs = validate_companion(FULL_COMPANION_MD, None)
        assert errs == [], errs

    def test_yaml_parse_error_caught(self):
        text = "## CONTEXTUALIZE\n\n```yaml\n: invalid: yaml: [\n```\n"
        errors = validate_companion(text, None)
        assert any("parse error" in e.lower() for e in errors)

    def test_trap_shape_rejected_at_validate_time(self):
        """Mirrors the documented production trap (run #44 / 20260428-060839):
        ?operator-runtime-exec graded `+`, no adversarial peer, conclude
        routes disposition=true_positive. Validator rule #36 must reject.
        """
        text = (
            "## CONTEXTUALIZE\n\n"
            "```yaml\n"
            "prologue:\n"
            "  vertices:\n"
            "    - id: v-001\n"
            "      type: process\n"
            "      classification: container-runtime\n"
            "      identifier: \"runc\"\n"
            "  edges:\n"
            "    - id: e-001\n"
            "      relation: spawned\n"
            "      source_vertex: v-001\n"
            "      target_vertex: v-001\n"
            "      authority: {kind: runtime-audit, source: Falco}\n"
            "```\n\n"
            "## PREDICT (loop 1)\n\n"
            "```yaml\n"
            "hypothesize:\n"
            "  hypotheses:\n"
            "    - id: h-001\n"
            "      name: \"?operator-runtime-exec\"\n"
            "      attached_to_vertex: v-001\n"
            "      proposed_edge:\n"
            "        relation: exec_into\n"
            "        parent_vertex:\n"
            "          type: process\n"
            "          classification: host-side-runtime-exec-primitive\n"
            "      predictions:\n"
            "        - id: p1\n"
            "          subject: proposed_parent\n"
            "          claim: \"a change-management ticket exists for this exec\"\n"
            "      weight: null\n"
            "```\n\n"
            "## REPORT\n\n"
            "```yaml\n"
            "findings:\n"
            "  - id: l-001\n"
            "    loop: 1\n"
            "    name: change-management\n"
            "    target: v-001\n"
            "    query_details: {}\n"
            "    outcome: {}\n"
            "    resolutions:\n"
            "      - hypothesis: h-001\n"
            "        before: null\n"
            "        after: \"+\"\n"
            "        severity_of_test: weak\n"
            "        matched_prediction_ids: [p1]\n"
            "        reasoning: ticket query returned no records\n"
            "        supporting_edges: [e-001]\n"
            "conclude:\n"
            "  termination:\n"
            "    category: trust-root\n"
            "  disposition: true_positive\n"
            "  confidence: medium\n"
            "  surviving_hypotheses: [h-001]\n"
            "  matched_archetype: null\n"
            "  deferred_predictions: []\n"
            "```\n"
        )
        errors = validate_companion(text, None)
        # Rule #36 fires.
        tp_errors = [e for e in errors if "true_positive" in e]
        assert tp_errors, f"expected a rule-#36 error, got: {errors}"
        assert "h-001" in tp_errors[0] or "non-adversarial" in tp_errors[0]

    def test_trap_shape_passes_when_adversarial_pp_added(self):
        """Same shape as the trap, plus an adversarial peer at ++ — should
        validate clean. Confirms rule #36 does not block legitimate true-
        positive routings.
        """
        text = (
            "## CONTEXTUALIZE\n\n"
            "```yaml\n"
            "prologue:\n"
            "  vertices:\n"
            "    - id: v-001\n"
            "      type: process\n"
            "      classification: container-runtime\n"
            "      identifier: \"runc\"\n"
            "  edges:\n"
            "    - id: e-001\n"
            "      relation: spawned\n"
            "      source_vertex: v-001\n"
            "      target_vertex: v-001\n"
            "      authority: {kind: runtime-audit, source: Falco}\n"
            "```\n\n"
            "## PREDICT (loop 1)\n\n"
            "```yaml\n"
            "hypothesize:\n"
            "  hypotheses:\n"
            "    - id: h-001\n"
            "      name: \"?operator-runtime-exec\"\n"
            "      attached_to_vertex: v-001\n"
            "      proposed_edge:\n"
            "        relation: exec_into\n"
            "        parent_vertex:\n"
            "          type: process\n"
            "          classification: host-side-runtime-exec-primitive\n"
            "      predictions:\n"
            "        - id: p1\n"
            "          subject: proposed_parent\n"
            "          claim: \"a change-management ticket exists\"\n"
            "      weight: null\n"
            "    - id: h-002\n"
            "      name: \"?adversary-controlled-runtime-exec\"\n"
            "      attached_to_vertex: v-001\n"
            "      proposed_edge:\n"
            "        relation: exec_into\n"
            "        parent_vertex:\n"
            "          type: process\n"
            "          classification: adversary-controlled-runtime-exec\n"
            "      predictions:\n"
            "        - id: p1\n"
            "          subject: proposed_parent\n"
            "          claim: \"audit shows no operator session for this exec\"\n"
            "      weight: null\n"
            "```\n\n"
            "## REPORT\n\n"
            "```yaml\n"
            "findings:\n"
            "  - id: l-001\n"
            "    loop: 1\n"
            "    name: audit-correlation\n"
            "    target: v-001\n"
            "    query_details: {}\n"
            "    outcome: {}\n"
            "    resolutions:\n"
            "      - hypothesis: h-002\n"
            "        before: null\n"
            "        after: \"++\"\n"
            "        severity_of_test: severe\n"
            "        matched_prediction_ids: [p1]\n"
            "        reasoning: audit confirmed no operator session correlated with the exec\n"
            "        supporting_edges: [e-001]\n"
            "conclude:\n"
            "  termination:\n"
            "    category: adversarial-refuted\n"
            "  disposition: true_positive\n"
            "  confidence: high\n"
            "  surviving_hypotheses: [h-001, h-002]\n"
            "  matched_archetype: null\n"
            "  deferred_predictions:\n"
            "    - {prediction_ref: \"h-001.p1\", rationale: \"ticket anchor unreachable; superseded by h-002 ++\"}\n"
            "```\n"
        )
        errors = validate_companion(text, None)
        # No rule-#36 error.
        tp_errors = [e for e in errors if "true_positive" in e and "adversarial" in e.lower()]
        assert not tp_errors, f"unexpected rule-#36 error: {tp_errors}"


# ---------------------------------------------------------------------------
# Integration tests (subprocess) — PreToolUse event simulation
# ---------------------------------------------------------------------------


def _run_hook(
    content: str,
    tool_name: str = "Write",
    tmp_path: Path | None = None,
    existing_content: str | None = None,
) -> subprocess.CompletedProcess:
    """Simulate a PreToolUse event for investigation.md."""
    if tmp_path is None:
        tmp_path = Path(tempfile.mkdtemp())

    runs_dir = tmp_path / "runs"
    run_dir = runs_dir / "test-run"
    run_dir.mkdir(parents=True, exist_ok=True)
    inv_path = run_dir / "investigation.md"

    if existing_content is not None:
        inv_path.write_text(existing_content)

    if tool_name == "Write":
        tool_input: dict = {"file_path": str(inv_path), "content": content}
    else:  # Edit
        old = existing_content or ""
        tool_input = {
            "file_path": str(inv_path),
            "old_string": old,
            "new_string": content,
        }

    event = json.dumps({"tool_name": tool_name, "tool_input": tool_input})
    import os
    return subprocess.run(
        [sys.executable, str(HOOK_SCRIPT)],
        input=event,
        capture_output=True,
        text=True,
        env={**os.environ, "SOC_AGENT_RUNS_DIR": str(runs_dir)},
    )


class TestHookIntegration:
    def test_no_yaml_blocks_passes(self, tmp_path):
        result = _run_hook("## CONTEXTUALIZE\n\nsome prose\n", tmp_path=tmp_path)
        assert result.returncode == 0

    def test_valid_prologue_passes(self, tmp_path):
        content = f"## CONTEXTUALIZE\n\n```yaml\n{VALID_PROLOGUE_YAML}```\n"
        result = _run_hook(content, tmp_path=tmp_path)
        assert result.returncode == 0, result.stderr

    def test_valid_full_companion_passes(self, tmp_path):
        result = _run_hook(FULL_COMPANION_MD, tmp_path=tmp_path)
        assert result.returncode == 0, result.stderr

    def test_missing_lead_field_fails(self, tmp_path):
        bad_lead = """\
findings:
  - id: l-001
    loop: 1
    name: test
    target: v-001
    query_details:
      system: wazuh
      template: t
      query: q
      time_window: 1h
      substitutions: {}
    outcome:
      observations:
        vertices: []
        edges: []
    # resolutions missing
"""
        content = f"## ANALYZE\n\n```yaml\n{bad_lead}```\n"
        result = _run_hook(content, tmp_path=tmp_path)
        assert result.returncode == 2
        assert "resolutions" in result.stderr

    def test_pp_missing_supporting_edges_fails(self, tmp_path):
        prologue_content = f"## CONTEXTUALIZE\n\n```yaml\n{VALID_PROLOGUE_YAML}```\n"
        lead_no_edges = """\
findings:
  - id: l-001
    loop: 1
    name: test
    target: v-001
    query_details:
      system: wazuh
      template: t
      query: q
      time_window: 1h
      substitutions: {}
    outcome:
      observations:
        vertices: []
        edges: []
    resolutions:
      - hypothesis: h-001
        before: null
        after: "++"
        severity_of_test: severe
        matched_prediction_ids: [p1]
        matched_refutation_ids: []
        reasoning: "strong evidence"
        supporting_edges: []
"""
        content = prologue_content + f"\n```yaml\n{lead_no_edges}```\n"
        result = _run_hook(content, tmp_path=tmp_path)
        assert result.returncode == 2
        assert "supporting_edges" in result.stderr

    def test_mm_missing_refutation_ids_fails(self, tmp_path):
        bad_resolution = """\
findings:
  - id: l-001
    loop: 1
    name: test
    target: v-001
    query_details:
      system: wazuh
      template: t
      query: q
      time_window: 1h
      substitutions: {}
    outcome:
      observations:
        vertices: []
        edges:
          - id: e-003
            relation: attempted_auth
            source_vertex: v-001
            target_vertex: v-002
            authority:
              kind: siem-event
              source: wazuh
    resolutions:
      - hypothesis: h-001
        before: null
        after: "--"
        severity_of_test: severe
        matched_prediction_ids: []
        matched_refutation_ids: []
        reasoning: "contradicts prediction"
        supporting_edges: [e-003]
"""
        prologue = f"```yaml\n{VALID_PROLOGUE_YAML}```\n"
        content = f"## CONTEXTUALIZE\n\n{prologue}\n## ANALYZE\n\n```yaml\n{bad_resolution}```\n"
        result = _run_hook(content, tmp_path=tmp_path)
        assert result.returncode == 2
        assert "matched_refutation_ids" in result.stderr

    def test_screen_result_on_non_screen_lead_fails(self, tmp_path):
        bad_screen = """\
findings:
  - id: l-001
    loop: 1
    name: test
    target: v-001
    query_details:
      system: wazuh
      template: t
      query: q
      time_window: 1h
      substitutions: {}
    outcome:
      screen_result: no_match
      observations:
        vertices: []
        edges: []
    resolutions: []
"""
        content = f"## ANALYZE\n\n```yaml\n{bad_screen}```\n"
        result = _run_hook(content, tmp_path=tmp_path)
        assert result.returncode == 2
        assert "screen_result" in result.stderr

    def test_append_only_removing_block_fails(self, tmp_path):
        existing = f"## CONTEXTUALIZE\n\n```yaml\n{VALID_PROLOGUE_YAML}```\n"
        proposed = "## CONTEXTUALIZE\n\nsome prose only\n"
        result = _run_hook(
            content=proposed,
            tool_name="Write",
            tmp_path=tmp_path,
            existing_content=existing,
        )
        assert result.returncode == 2
        assert "append-only" in result.stderr

    def test_yaml_parse_error_fails(self, tmp_path):
        content = "## CONTEXTUALIZE\n\n```yaml\n: invalid: [\n```\n"
        result = _run_hook(content, tmp_path=tmp_path)
        assert result.returncode == 2
        assert "parse error" in result.stderr.lower()

    def test_dangling_id_reference_fails(self, tmp_path):
        bad_ref = """\
findings:
  - id: l-001
    loop: 1
    name: test
    target: v-999
    query_details:
      system: wazuh
      template: t
      query: q
      time_window: 1h
      substitutions: {}
    outcome:
      observations:
        vertices: []
        edges: []
    resolutions: []
"""
        content = f"## ANALYZE\n\n```yaml\n{bad_ref}```\n"
        result = _run_hook(content, tmp_path=tmp_path)
        assert result.returncode == 2
        assert "v-999" in result.stderr
