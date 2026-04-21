"""Orchestration + shared-fixture entry point for invlang validator tests.

This module hosts the shared YAML fixtures re-exported by the per-concern
test modules (test_invlang_structural.py, test_invlang_predictions.py,
test_invlang_legitimacy.py, test_invlang_hypothesis.py, test_invlang_warnings.py)
along with end-to-end and subprocess-level coverage:

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

VALID_HYPOTHESIZE_YAML = """\
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
gather:
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

## HYPOTHESIZE (loop 1)

**Active hypotheses:** ?opportunistic-scanner

```yaml
{VALID_HYPOTHESIZE_YAML}
```

## GATHER (loop 1)

**Raw observation:** source IP not in threat-intel lists

## ANALYZE (loop 1)

**Assessment:** h-001 moves to +

```yaml
{VALID_LEAD_YAML}
```

## CONCLUDE

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
    contract_id: str = "lc1",
    resolutions: list[dict] | None = None,
    disposition: str = "benign",
    hypothesis_weight: str = "+",
    extra_edges: list[dict] | None = None,
    trust_anchor_result: dict | None = None,
) -> dict:
    """Build a merged companion carrying one hypothesis with one legitimacy_contract.

    Post-migration shape: `legitimacy_resolutions[]` lives in
    `gather[0].outcome.legitimacy_resolutions[]` as a sibling of
    `attribute_updates`. The lead also carries a `trust_anchor_result`
    with `asks: authorization` and `verdict: authorized` — resolutions
    must be backed by an explicit authority consultation.

    Defaults shape a live-weight benign resolution with one `authorized`
    verdict targeting edge e-002. Override parameters to flip individual
    dimensions for negative cases.
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
    observed_edge = {
        "id": "e-002",
        "relation": "classified_as",
        "source_vertex": "v-001",
        "target_vertex": "v-002",
        "authority": {"kind": "authoritative-source", "source": "registry"},
    }
    default_resolutions = [
        {
            "id": "lr1",
            "target": "e-002",
            "fulfills_contract": f"h-001.{contract_id}",
            "verdict": "authorized",
        }
    ]
    default_tar = {
        "anchor_id": "approved-monitoring-sources",
        "anchor_name": "approved-monitoring-sources",
        "kind": "org-authority",
        "asks": "authorization",
        "verdict": "authorized",
        "result": "confirmed",
        "as_of": "2026-04-18T00:00:00Z",
        "authority_for_question": "full",
    }
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
                        "parent_vertex": {"type": "identity", "classification": "unknown"},
                    },
                    "predictions": [{"id": "p1", "claim": "source resolves to an approved entry"}],
                    "legitimacy_contract": [
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
        "gather": [
            {
                "id": "l-001",
                "loop": 1,
                "name": "trust-anchor-lookup",
                "target": "v-001",
                "query_details": {},
                "outcome": {
                    "observations": {"vertices": [], "edges": [observed_edge]},
                    "trust_anchor_result": (
                        trust_anchor_result
                        if trust_anchor_result is not None
                        else default_tar
                    ),
                    "legitimacy_resolutions": (
                        resolutions if resolutions is not None else default_resolutions
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
    return {"gather": leads}


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
        preds = [{"id": "lp1", "if": "x", "read_as": "y", "advance_to": "CONCLUDE"}]
        merged = _merged_with_leads([_lead("first", preds)])
        assert _check_route_compliance(merged) == []

    def test_terminal_lead_without_conclude_warns(self):
        preds = [{"id": "lp1", "if": "x", "read_as": "y", "advance_to": "next-step"}]
        merged = _merged_with_leads([_lead("first", preds)])
        warnings = _check_route_compliance(merged)
        assert warnings
        assert "terminal" in warnings[0].lower()

    def test_hypothesize_advance_does_not_require_next_lead(self):
        # advance_to HYPOTHESIZE is valid even on a terminal lead — the
        # companion may continue in a follow-up HYPOTHESIZE block elsewhere.
        # Here we check the non-terminal case: if next lead isn't HYPOTHESIZE-
        # flavored (which it won't be — phases aren't leads), that's still a
        # mismatch, and the warning is correct.
        preds = [{"id": "lp1", "if": "x", "read_as": "y", "advance_to": "HYPOTHESIZE"}]
        merged = _merged_with_leads([_lead("first", preds), _lead("some-other")])
        warnings = _check_route_compliance(merged)
        assert warnings


class TestCollectWarnings:
    def test_companion_with_route_warning(self):
        text = (
            "```yaml\n"
            "gather:\n"
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
        assert validate_companion(FULL_COMPANION_MD, None) == []

    def test_yaml_parse_error_caught(self):
        text = "## CONTEXTUALIZE\n\n```yaml\n: invalid: yaml: [\n```\n"
        errors = validate_companion(text, None)
        assert any("parse error" in e.lower() for e in errors)


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
gather:
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
gather:
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
gather:
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

    def test_trust_anchor_incomplete_fails(self, tmp_path):
        incomplete_tar = """\
gather:
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
      trust_anchor_result:
        anchor_id: approved-sources
        kind: org-authority
        # missing: result, as_of, authority_for_question
      observations:
        vertices: []
        edges: []
    resolutions: []
"""
        content = f"## ANALYZE\n\n```yaml\n{incomplete_tar}```\n"
        result = _run_hook(content, tmp_path=tmp_path)
        assert result.returncode == 2
        assert "trust_anchor_result" in result.stderr

    def test_screen_result_on_non_screen_lead_fails(self, tmp_path):
        bad_screen = """\
gather:
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
        # Proposed content replaces the prologue block with nothing
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
        # Lead targets v-999 which is not declared
        bad_ref = """\
gather:
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
