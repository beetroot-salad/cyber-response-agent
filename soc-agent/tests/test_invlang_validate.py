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

# ---------------------------------------------------------------------------
# Dense ```invlang fixtures — strict-cutover form (post-#170)
# ---------------------------------------------------------------------------
# Mirror the YAML fixtures above semantically so end-to-end / hook tests
# exercise the same validator paths after the validator stopped accepting
# ```yaml fences. The YAML strings are still consumed by sibling test
# modules via `_parse_yaml_block` (dict source, not a markdown surface).

VALID_PROLOGUE_INVLANG = """\
:V prologue.vertices [id|type|class|ident|attrs]
v-001|endpoint|external-unknown|203.0.113.47|
v-002|endpoint|internal-server|web-server-01|

:E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs]
e-001|attempted_auth|v-001|v-002||siem-event:wazuh-indexer|
"""

VALID_PREDICT_INVLANG = """\
:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|parent_attrs|preds|attr_preds|refuts|authz|integrity_waived|weight|status]
h-001|?opportunistic-scanner|v-001|initiated_by|identity|automated-scanner||p1:proposed_parent:"source IP appears in threat-intel scanner list"||r1[p1]:"source IP authenticated previously in last 90d"|||null|
"""

VALID_LEAD_INVLANG = """\
:L findings [id|name|loop|target|mode|system|template|query|window|status]
l-001|source-classification|1|v-001|graded|wazuh-indexer|source-ip-lookup|src_ip:203.0.113.47|30d|

:E l-001.observations.edges [id|rel|src|tgt|when|auth_kind:source|attrs]
e-002|classified_as|v-001|v-002||siem-event:wazuh-indexer|

:R attr_updates [resolved_by|target|key|value]
l-001|v-001|classification|external-unknown

:T resolutions
h-001  null → --    [l-001 r1 strong ⟂ e-001 :: source IP authenticated from web-server-01 six hours prior — refutation r1 matched]
"""

VALID_CONCLUDE_INVLANG = """\
:T conclude
termination.category   adversarial-refuted
termination.rationale  "All adversarial hypotheses refuted with -- evidence"
disposition            benign
impact_verdict         none
impact_severity        null
confidence             high
matched_archetype      external-bruteforce
summary                "SSH brute force from external scanner; no successful auth"

:T conclude.surviving [hyp_id|final_weight]
none
"""

FULL_COMPANION_MD = f"""## CONTEXTUALIZE

**Alert:** TEST-001

```invlang
{VALID_PROLOGUE_INVLANG}```

## PREDICT (loop 1)

**Active hypotheses:** ?opportunistic-scanner

```invlang
{VALID_PREDICT_INVLANG}```

## GATHER (loop 1)

**Raw observation:** source IP not in threat-intel lists

## ANALYZE (loop 1)

**Assessment:** h-001 moves to +

```invlang
{VALID_LEAD_INVLANG}```

## REPORT

**Verdict:** resolved

```invlang
{VALID_CONCLUDE_INVLANG}```
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
            "```invlang\n"
            ":L findings [id|name|loop|target|mode]\n"
            "l-001|first|1|v-001|graded\n"
            "l-002|actual-next|1|v-001|graded\n"
            "\n"
            ":L l-001.lead_preds [id|if|read_as|advance_to]\n"
            "lp1|x|y|expected-next\n"
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
        proposed = current + "\n```invlang\n:V prologue.vertices [id|type|class|ident|attrs]\nv-001|endpoint|external|1.2.3.4|\n```\n"
        assert _check_append_only(proposed, current) == []

    def test_same_count_passes(self):
        block = "\n```invlang\n:V prologue.vertices [id|type|class|ident|attrs]\nv-001|endpoint|external|1.2.3.4|\n```\n"
        assert _check_append_only(block, block) == []

    def test_removing_block_fails(self):
        block = "\n```invlang\n:V prologue.vertices [id|type|class|ident|attrs]\nv-001|endpoint|external|1.2.3.4|\n```\n"
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

    def test_yaml_fence_rejected_post_cutover(self):
        """Strict cutover (#170): any ```yaml fence in investigation.md is
        rejected with a clear error so the writer immediately knows to
        switch to ```invlang. Replaces the prior `test_yaml_parse_error_caught`
        — yaml content is no longer parsed at all.
        """
        text = "## CONTEXTUALIZE\n\n```yaml\nprologue:\n  vertices: []\n```\n"
        errors = validate_companion(text, None)
        assert any("```yaml" in e and "no longer accepted" in e for e in errors), errors

    def test_invlang_fence_parse_error_caught(self):
        text = "## CONTEXTUALIZE\n\n```invlang\n:Q bogus tag\n```\n"
        errors = validate_companion(text, None)
        assert any("malformed" in e.lower() or "unknown" in e.lower() for e in errors), errors

    def test_trap_shape_rejected_at_validate_time(self):
        """Mirrors the documented production trap (run #44 / 20260428-060839):
        ?operator-runtime-exec graded `+`, no adversarial peer, conclude
        routes disposition=true_positive. Validator rule #36 must reject.
        """
        text = (
            "## CONTEXTUALIZE\n\n"
            "```invlang\n"
            ":V prologue.vertices [id|type|class|ident|attrs]\n"
            "v-001|process|container-runtime|runc|\n"
            "\n"
            ":E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs]\n"
            "e-001|spawned|v-001|v-001||runtime-audit:Falco|\n"
            "```\n\n"
            "## PREDICT (loop 1)\n\n"
            "```invlang\n"
            ":H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|parent_attrs|preds|attr_preds|refuts|authz|integrity_waived|weight|status]\n"
            "h-001|?operator-runtime-exec|v-001|exec_into|process|host-side-runtime-exec-primitive||p1:proposed_parent:\"a change-management ticket exists for this exec\"|||||null|\n"
            "```\n\n"
            "## REPORT\n\n"
            "```invlang\n"
            ":L findings [id|name|loop|target|mode|status]\n"
            "l-001|change-management|1|v-001|graded|active\n"
            "\n"
            ":T resolutions\n"
            "h-001  null → +    [l-001 p1 weak ⟂ e-001 :: ticket query returned no records]\n"
            "\n"
            ":T conclude\n"
            "termination.category   trust-root\n"
            "disposition            true_positive\n"
            "confidence             medium\n"
            "\n"
            ":T conclude.surviving [hyp_id|final_weight]\n"
            "h-001|+\n"
            "```\n"
        )
        errors = validate_companion(text, None)
        # Rule #36 fires — survivor at `+`, no `++` anywhere.
        tp_errors = [e for e in errors if "true_positive" in e]
        assert tp_errors, f"expected a rule-#36 error, got: {errors}"
        assert "h-001" in tp_errors[0] or "++" in tp_errors[0]

    def test_trap_shape_passes_when_adversarial_pp_added(self):
        """Same shape as the trap, plus an adversarial peer at ++ — should
        validate clean. Confirms rule #36 does not block legitimate true-
        positive routings.
        """
        text = (
            "## CONTEXTUALIZE\n\n"
            "```invlang\n"
            ":V prologue.vertices [id|type|class|ident|attrs]\n"
            "v-001|process|container-runtime|runc|\n"
            "\n"
            ":E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs]\n"
            "e-001|spawned|v-001|v-001||runtime-audit:Falco|\n"
            "```\n\n"
            "## PREDICT (loop 1)\n\n"
            "```invlang\n"
            ":H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|parent_attrs|preds|attr_preds|refuts|authz|integrity_waived|weight|status]\n"
            "h-001|?operator-runtime-exec|v-001|exec_into|process|host-side-runtime-exec-primitive||p1:proposed_parent:\"a change-management ticket exists\"|||||null|\n"
            "h-002|?adversary-controlled-runtime-exec|v-001|exec_into|process|adversary-controlled-runtime-exec||p1:proposed_parent:\"audit shows no operator session for this exec\"|||||null|\n"
            "```\n\n"
            "## REPORT\n\n"
            "```invlang\n"
            ":L findings [id|name|loop|target|mode|status]\n"
            "l-001|audit-correlation|1|v-001|graded|active\n"
            "\n"
            ":T resolutions\n"
            "h-002  null → ++    [l-001 p1 severe ⟂ e-001 :: audit confirmed no operator session correlated with the exec]\n"
            "\n"
            ":T conclude\n"
            "termination.category   adversarial-refuted\n"
            "disposition            true_positive\n"
            "confidence             high\n"
            "\n"
            ":T conclude.surviving [hyp_id|final_weight]\n"
            "h-001|null\n"
            "h-002|++\n"
            "\n"
            ":T conclude.deferred_preds [prediction_ref|rationale]\n"
            "h-001.p1|ticket anchor unreachable; superseded by h-002 ++\n"
            "```\n"
        )
        errors = validate_companion(text, None)
        # No rule-#36 error — h-002 graded ++ satisfies the weight check.
        tp_errors = [
            e for e in errors
            if "true_positive" in e and "++" in e and "no surviving" in e
        ]
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
        content = f"## CONTEXTUALIZE\n\n```invlang\n{VALID_PROLOGUE_INVLANG}```\n"
        result = _run_hook(content, tmp_path=tmp_path)
        assert result.returncode == 0, result.stderr

    def test_valid_full_companion_passes(self, tmp_path):
        result = _run_hook(FULL_COMPANION_MD, tmp_path=tmp_path)
        assert result.returncode == 0, result.stderr

    def test_pp_missing_supporting_edges_fails(self, tmp_path):
        # Resolution graded `++` but the supp-edges slot uses the
        # `no-authority` marker — rule #14 (strong-resolution authority)
        # rejects.
        prologue_content = f"## CONTEXTUALIZE\n\n```invlang\n{VALID_PROLOGUE_INVLANG}```\n"
        predict_content = f"## PREDICT (loop 1)\n\n```invlang\n{VALID_PREDICT_INVLANG}```\n"
        analyze_content = (
            "## ANALYZE (loop 1)\n\n"
            "```invlang\n"
            ":L findings [id|name|loop|target|mode|status]\n"
            "l-001|test|1|v-001|graded|active\n"
            "\n"
            ":T resolutions\n"
            "h-001  null → ++    [l-001 p1 severe ⟂ no-authority :: strong evidence]\n"
            "```\n"
        )
        content = prologue_content + "\n" + predict_content + "\n" + analyze_content
        result = _run_hook(content, tmp_path=tmp_path)
        assert result.returncode == 2
        assert "supporting_edges" in result.stderr

    def test_mm_missing_refutation_ids_fails(self, tmp_path):
        # Resolution graded `--` with no matched_refutation_ids — rule
        # requiring `--` to cite at least one refutation fires.
        prologue = f"## CONTEXTUALIZE\n\n```invlang\n{VALID_PROLOGUE_INVLANG}```\n"
        predict = f"## PREDICT (loop 1)\n\n```invlang\n{VALID_PREDICT_INVLANG}```\n"
        analyze_content = (
            "## ANALYZE (loop 1)\n\n"
            "```invlang\n"
            ":L findings [id|name|loop|target|mode|status]\n"
            "l-001|test|1|v-001|graded|active\n"
            "\n"
            ":T resolutions\n"
            "h-001  null → --    [l-001 severe ⟂ e-001 :: contradicts prediction]\n"
            "```\n"
        )
        content = prologue + "\n" + predict + "\n" + analyze_content
        result = _run_hook(content, tmp_path=tmp_path)
        assert result.returncode == 2
        assert "refutation" in result.stderr.lower() or "matched_refutation_ids" in result.stderr

    def test_append_only_removing_block_fails(self, tmp_path):
        existing = f"## CONTEXTUALIZE\n\n```invlang\n{VALID_PROLOGUE_INVLANG}```\n"
        proposed = "## CONTEXTUALIZE\n\nsome prose only\n"
        result = _run_hook(
            content=proposed,
            tool_name="Write",
            tmp_path=tmp_path,
            existing_content=existing,
        )
        assert result.returncode == 2
        assert "append-only" in result.stderr

    def test_yaml_fence_rejected_by_hook(self, tmp_path):
        """Strict-cutover (#170): a ```yaml fence on the proposed write is
        rejected with the cutover-specific error string. Replaces the prior
        `test_yaml_parse_error_fails` — the validator no longer parses
        yaml content at all.
        """
        content = "## CONTEXTUALIZE\n\n```yaml\nprologue: {}\n```\n"
        result = _run_hook(content, tmp_path=tmp_path)
        assert result.returncode == 2
        assert "```yaml" in result.stderr
        assert "no longer accepted" in result.stderr

    def test_dangling_id_reference_fails(self, tmp_path):
        # Lead targets a non-existent vertex (v-999) — rule rejecting
        # dangling id references fires.
        prologue = f"## CONTEXTUALIZE\n\n```invlang\n{VALID_PROLOGUE_INVLANG}```\n"
        predict = f"## PREDICT (loop 1)\n\n```invlang\n{VALID_PREDICT_INVLANG}```\n"
        analyze_content = (
            "## ANALYZE (loop 1)\n\n"
            "```invlang\n"
            ":L findings [id|name|loop|target|mode|status]\n"
            "l-001|test|1|v-999|graded|active\n"
            "```\n"
        )
        content = prologue + "\n" + predict + "\n" + analyze_content
        result = _run_hook(content, tmp_path=tmp_path)
        assert result.returncode == 2
        assert "v-999" in result.stderr
