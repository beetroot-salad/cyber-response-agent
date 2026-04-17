"""Tests for the invlang PreToolUse validation hook.

Tests invlang_validate.py: unit tests for check functions, and subprocess
integration tests simulating PreToolUse events on stdin.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from hooks.scripts.invlang_validate import (
    validate_companion,
    _check_lead_required_fields,
    _check_id_formats,
    _check_id_references,
    _check_edge_authority,
    _check_refutation_ids,
    _check_trust_anchor_completeness,
    _check_screen_result_scope,
    _check_append_only,
    _merge_blocks,
    YAML_BLOCK_RE,
)

HOOK_SCRIPT = SOC_AGENT_ROOT / "hooks" / "scripts" / "invlang_validate.py"

# ---------------------------------------------------------------------------
# Shared fixtures
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
          claim: "source IP appears in threat-intel scanner list"
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
        - vertex: v-001
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
        after: "+"
        severity_of_test: weak
        matched_prediction_ids: []
        matched_refutation_ids: []
        reasoning: "No prior authenticated sessions — consistent with scanner"
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


# ---------------------------------------------------------------------------
# Unit tests: _check_lead_required_fields
# ---------------------------------------------------------------------------


class TestCheckLeadRequiredFields:
    def test_valid_lead(self):
        merged = _merge_blocks([_parse_yaml_block(f"```yaml\n{VALID_LEAD_YAML}\n```")])
        assert _check_lead_required_fields(merged) == []

    def test_missing_resolutions(self):
        lead_no_resolutions = """\
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
"""
        merged = {"gather": [{
            "id": "l-001", "loop": 1, "name": "test", "target": "v-001",
            "query_details": {}, "outcome": {},
            # resolutions missing
        }]}
        errors = _check_lead_required_fields(merged)
        assert any("resolutions" in e for e in errors)

    def test_missing_multiple_fields(self):
        merged = {"gather": [{"id": "l-001"}]}
        errors = _check_lead_required_fields(merged)
        assert errors
        assert any("l-001" in e for e in errors)


def _parse_yaml_block(text: str) -> dict:
    import yaml
    for match in YAML_BLOCK_RE.finditer(text):
        doc = yaml.safe_load(match.group(1))
        if isinstance(doc, dict):
            return doc
    return {}


# ---------------------------------------------------------------------------
# Unit tests: _check_id_formats
# ---------------------------------------------------------------------------


class TestCheckIdFormats:
    def test_valid_ids(self):
        merged = _merge_blocks([_parse_yaml_block(f"```yaml\n{VALID_PROLOGUE_YAML}\n```")])
        assert _check_id_formats(merged) == []

    def test_invalid_vertex_id(self):
        merged = {"prologue": {"vertices": [{"id": "vertex001", "type": "endpoint", "classification": "x", "identifier": "y"}], "edges": []}}
        errors = _check_id_formats(merged)
        assert any("vertex001" in e for e in errors)

    def test_uppercase_id(self):
        merged = {"prologue": {"vertices": [{"id": "V-001", "type": "endpoint", "classification": "x", "identifier": "y"}], "edges": []}}
        errors = _check_id_formats(merged)
        assert errors

    def test_hypothesis_id_valid(self):
        merged = {"hypothesize": {"hypotheses": [{"id": "h-001", "name": "?test"}]}}
        assert _check_id_formats(merged) == []


# ---------------------------------------------------------------------------
# Unit tests: _check_id_references
# ---------------------------------------------------------------------------


class TestCheckIdReferences:
    def test_all_refs_resolve(self):
        import yaml
        prologue = yaml.safe_load(VALID_PROLOGUE_YAML)
        hyp = yaml.safe_load(VALID_HYPOTHESIZE_YAML)
        lead_raw = yaml.safe_load(VALID_LEAD_YAML)
        merged = _merge_blocks([prologue, hyp, lead_raw])
        errors = _check_id_references(merged)
        assert errors == [], errors

    def test_dangling_target_ref(self):
        merged = {"gather": [{
            "id": "l-001", "loop": 1, "name": "test",
            "target": "v-999",  # doesn't exist
            "query_details": {}, "outcome": {}, "resolutions": [],
        }]}
        errors = _check_id_references(merged)
        assert any("v-999" in e for e in errors)

    def test_dangling_resolution_hypothesis(self):
        merged = {
            "prologue": {"vertices": [{"id": "v-001"}], "edges": [{"id": "e-001", "authority": {"kind": "siem-event"}}]},
            "gather": [{
                "id": "l-001", "loop": 1, "name": "test", "target": "v-001",
                "query_details": {}, "outcome": {},
                "resolutions": [{"hypothesis": "h-999", "after": "+", "supporting_edges": ["e-001"]}],
            }],
        }
        errors = _check_id_references(merged)
        assert any("h-999" in e for e in errors)


# ---------------------------------------------------------------------------
# Unit tests: _check_edge_authority
# ---------------------------------------------------------------------------


class TestCheckEdgeAuthority:
    def _make_merged(self, after: str, authority_kind: str) -> dict:
        return {
            "prologue": {
                "vertices": [],
                "edges": [{"id": "e-001", "relation": "attempted_auth",
                            "source_vertex": "v-001", "target_vertex": "v-002",
                            "authority": {"kind": authority_kind, "source": "wazuh"}}]
            },
            "gather": [{
                "id": "l-001", "loop": 1, "name": "test", "target": "v-001",
                "query_details": {}, "outcome": {"observations": {"vertices": [], "edges": []}},
                "resolutions": [{
                    "hypothesis": "h-001", "before": None, "after": after,
                    "severity_of_test": "severe",
                    "matched_prediction_ids": ["p1"],
                    "matched_refutation_ids": [],
                    "reasoning": "test",
                    "supporting_edges": ["e-001"],
                }],
            }],
        }

    def test_pp_with_siem_event_passes(self):
        assert _check_edge_authority(self._make_merged("++", "siem-event")) == []

    def test_mm_with_runtime_audit_passes(self):
        assert _check_edge_authority(self._make_merged("--", "runtime-audit")) == []

    def test_pp_with_client_asserted_fails(self):
        errors = _check_edge_authority(self._make_merged("++", "client-asserted"))
        assert errors

    def test_pp_empty_supporting_edges_fails(self):
        merged = {
            "prologue": {"vertices": [], "edges": []},
            "gather": [{
                "id": "l-001", "loop": 1, "name": "test", "target": "v-001",
                "query_details": {}, "outcome": {"observations": {"vertices": [], "edges": []}},
                "resolutions": [{"hypothesis": "h-001", "after": "++", "supporting_edges": []}],
            }],
        }
        errors = _check_edge_authority(merged)
        assert errors

    def test_plus_does_not_require_strong_authority(self):
        assert _check_edge_authority(self._make_merged("+", "client-asserted")) == []


# ---------------------------------------------------------------------------
# Unit tests: _check_refutation_ids
# ---------------------------------------------------------------------------


class TestCheckRefutationIds:
    def test_mm_with_ids_passes(self):
        merged = {"gather": [{
            "id": "l-001", "loop": 1, "name": "t", "target": "v-001",
            "query_details": {}, "outcome": {},
            "resolutions": [{"hypothesis": "h-001", "after": "--",
                              "matched_refutation_ids": ["r1"], "supporting_edges": []}],
        }]}
        assert _check_refutation_ids(merged) == []

    def test_mm_empty_ids_fails(self):
        merged = {"gather": [{
            "id": "l-001", "loop": 1, "name": "t", "target": "v-001",
            "query_details": {}, "outcome": {},
            "resolutions": [{"hypothesis": "h-001", "after": "--",
                              "matched_refutation_ids": [], "supporting_edges": []}],
        }]}
        errors = _check_refutation_ids(merged)
        assert errors
        assert "l-001" in errors[0]

    def test_mm_missing_key_fails(self):
        merged = {"gather": [{
            "id": "l-001", "loop": 1, "name": "t", "target": "v-001",
            "query_details": {}, "outcome": {},
            "resolutions": [{"hypothesis": "h-001", "after": "--", "supporting_edges": []}],
        }]}
        assert _check_refutation_ids(merged)


# ---------------------------------------------------------------------------
# Unit tests: _check_trust_anchor_completeness
# ---------------------------------------------------------------------------


class TestCheckTrustAnchorCompleteness:
    def test_complete_passes(self):
        merged = {"gather": [{
            "id": "l-001", "loop": 1, "name": "t", "target": "v-001",
            "query_details": {}, "outcome": {
                "trust_anchor_result": {
                    "anchor_id": "approved-monitoring-sources",
                    "kind": "org-authority",
                    "result": "confirmed",
                    "as_of": "2026-04-17T09:00:00Z",
                    "authority_for_question": "full",
                },
                "observations": {"vertices": [], "edges": []},
            },
            "resolutions": [],
        }]}
        assert _check_trust_anchor_completeness(merged) == []

    def test_missing_two_fields_fails(self):
        merged = {"gather": [{
            "id": "l-001", "loop": 1, "name": "t", "target": "v-001",
            "query_details": {}, "outcome": {
                "trust_anchor_result": {
                    "anchor_id": "approved-monitoring-sources",
                    "kind": "org-authority",
                    # missing: result, as_of, authority_for_question
                },
            },
            "resolutions": [],
        }]}
        errors = _check_trust_anchor_completeness(merged)
        assert errors
        assert "l-001" in errors[0]


# ---------------------------------------------------------------------------
# Unit tests: _check_screen_result_scope
# ---------------------------------------------------------------------------


class TestCheckScreenResultScope:
    def test_screen_result_on_screen_lead_passes(self):
        merged = {"gather": [{
            "id": "l-001", "loop": 0, "name": "t", "target": "v-001",
            "mode": "screen",
            "query_details": {}, "outcome": {"screen_result": "no_match"},
            "resolutions": [],
        }]}
        assert _check_screen_result_scope(merged) == []

    def test_screen_result_on_non_screen_lead_fails(self):
        merged = {"gather": [{
            "id": "l-001", "loop": 1, "name": "t", "target": "v-001",
            # mode: screen absent
            "query_details": {}, "outcome": {"screen_result": "no_match"},
            "resolutions": [],
        }]}
        errors = _check_screen_result_scope(merged)
        assert errors
        assert "l-001" in errors[0]


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
# Integration tests (subprocess)
# ---------------------------------------------------------------------------


def _run_hook(
    content: str,
    tool_name: str = "Write",
    tmp_path: Path | None = None,
    existing_content: str | None = None,
) -> subprocess.CompletedProcess:
    """Simulate a PreToolUse event for investigation.md."""
    # Use a tmp path that looks like a real run dir
    if tmp_path is None:
        import tempfile
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
    return subprocess.run(
        [sys.executable, str(HOOK_SCRIPT)],
        input=event,
        capture_output=True,
        text=True,
        env={**__import__("os").environ, "SOC_AGENT_RUNS_DIR": str(runs_dir)},
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
