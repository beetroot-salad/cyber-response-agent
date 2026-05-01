"""Unit tests for the prior-recall block built by the ANALYZE handler."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(ROOT))

from invlang.corpus import Companion
from handlers import _prior_recall as pr


# ---------------------------------------------------------------------------
# Companion fixture builders (mirror the patterns in test_invlang_queries.py)
# ---------------------------------------------------------------------------


def _prologue(classification: str = "high-trust") -> dict[str, Any]:
    return {
        "vertices": [{"id": "v-1", "type": "endpoint", "classification": classification}],
        "edges": [],
    }


def _make_lead(name: str, *, hyp_id: str, after: str) -> dict[str, Any]:
    return {
        "id": "l-001",
        "name": name,
        "loop": 1,
        "query_details": {"system": "wazuh"},
        "outcome": {"observations": {"vertices": [], "edges": []}},
        "resolutions": [{"hypothesis": hyp_id, "before": None, "after": after, "reasoning": "x"}],
    }


def _make_companion(
    case_id: str,
    *,
    classification: str = "high-trust",
    lead_name: str = "ssh-login-history",
    disposition: str = "benign",
    after: str = "++",
    created_at: str = "2026-04-01T00:00:00+00:00",
) -> Companion:
    h = {"id": "h-001", "name": "?monitoring-probe", "status": "active"}
    body = {
        "prologue": _prologue(classification),
        "hypothesize": {"hypotheses": [h]},
        "findings": [_make_lead(lead_name, hyp_id="h-001", after=after)],
        "conclude": {
            "termination": {"category": "trust-root", "rationale": "x"},
            "disposition": disposition,
            "confidence": "high",
            "matched_archetype": None,
        },
    }
    c = Companion(case_id=case_id, source_path=Path("."), body=body)
    c.created_at = created_at
    return c


# ---------------------------------------------------------------------------
# Investigation.md → live hypotheses + open contracts
# ---------------------------------------------------------------------------


_INV_MD_WITH_CONTRACTS = """\
## CONTEXTUALIZE

```yaml
prologue:
  vertices:
    - id: v-1
      type: endpoint
      classification: internal-endpoint
  edges: []
```

## PREDICT (loop 1)

```yaml
hypothesize:
  hypotheses:
    - id: h-001
      name: "?monitoring-probe"
      weight: null
      authorization_contract:
        - predicate: "actor is registered in approved-monitoring-sources"
    - id: h-002
      name: "?adversary-credential-stuffing"
      weight: "--"
      authorization_contract:
        - predicate: "should not appear here (refuted)"
```
"""


def test_open_contracts_excludes_refuted_hypotheses():
    body = pr._merge_yaml_blocks(_INV_MD_WITH_CONTRACTS)
    contracts = pr._open_contracts(body)
    names = [c[0] for c in contracts]
    assert "?monitoring-probe" in names
    assert "?adversary-credential-stuffing" not in names


def test_vertex_where_specs_from_prologue():
    body = pr._merge_yaml_blocks(_INV_MD_WITH_CONTRACTS)
    specs = pr._vertex_where_specs(body)
    assert specs == ["endpoint:classification=internal-endpoint"]


# ---------------------------------------------------------------------------
# Digest renderers
# ---------------------------------------------------------------------------


def test_digest_lead_modal_and_surprises():
    payload = {
        "count": 5,
        "summary": {
            "disposition_mix": {"benign": 4, "true_positive": 1},
            "assessment_mix": {"++": 3, "+": 2},
            "modal_hypothesis_outcome": [],
            "surprises": 2,
        },
    }
    line = pr._digest_lead(payload)
    assert "n=5" in line
    assert "modal=benign 4/5" in line
    assert "surprises=2" in line


def test_digest_lead_empty():
    assert pr._digest_lead({"count": 0, "summary": {}}) == ""
    assert pr._digest_lead(None) == ""


def test_digest_authz_distribution():
    payload = {
        "count": 7,
        "distribution": [
            {"verdict": "authorized", "count": 5},
            {"verdict": "unauthorized", "count": 1},
            {"verdict": "indeterminate", "count": 1},
        ],
        "surprises": 0,
    }
    line = pr._digest_authz(payload)
    assert line.startswith("n=7,")
    assert "authorized=5" in line
    assert "unauthorized=1" in line


# ---------------------------------------------------------------------------
# Vertex-where narrowing policy: stay unscoped when n < threshold
# ---------------------------------------------------------------------------


def test_unscoped_used_when_corpus_too_small_to_narrow(monkeypatch):
    # 3 cases, far below VERTEX_WHERE_MIN_NARROW_HITS — narrowing would
    # zero out, so the unscoped result must win.
    corpus = [
        _make_companion("c1", classification="high-trust"),
        _make_companion("c2", classification="untrusted"),
        _make_companion("c3", classification="untrusted"),
    ]
    out = pr._recall_lead(corpus, "ssh-login-history", ["endpoint:classification=high-trust"])
    assert out["count"] == 3  # unscoped — narrow would have given 1


def test_narrowed_used_when_unscoped_dense(monkeypatch):
    # Build 12 cases (>= VERTEX_WHERE_MIN_NARROW_HITS); 4 of them
    # have 'high-trust' classification.
    corpus = []
    for i in range(8):
        corpus.append(_make_companion(f"u{i}", classification="untrusted"))
    for i in range(4):
        corpus.append(_make_companion(f"h{i}", classification="high-trust"))
    out = pr._recall_lead(corpus, "ssh-login-history", ["endpoint:classification=high-trust"])
    assert out["count"] == 4  # narrowed view


# ---------------------------------------------------------------------------
# Public entry point — full block render + empty-corpus collapse
# ---------------------------------------------------------------------------


def test_build_block_empty_when_no_inputs():
    out = pr.build_prior_recall_block([], "", "abc123")
    assert out == ""


def test_build_block_renders_lead_lines(monkeypatch):
    corpus = [_make_companion("c1"), _make_companion("c2", after="--", disposition="true_positive")]
    monkeypatch.setattr(pr, "load_corpus", lambda: corpus)
    leads = [{"name": "ssh-login-history", "id": "l-001"}]
    out = pr.build_prior_recall_block(leads, _INV_MD_WITH_CONTRACTS, "saltXYZ")
    assert out.startswith("<prior-recall-saltXYZ>")
    assert out.endswith("</prior-recall-saltXYZ>")
    assert "lead ssh-login-history:" in out
    assert "Advisory only" in out


def test_build_block_collapses_when_corpus_empty(monkeypatch):
    monkeypatch.setattr(pr, "load_corpus", lambda: [])
    leads = [{"name": "ssh-login-history", "id": "l-001"}]
    out = pr.build_prior_recall_block(leads, _INV_MD_WITH_CONTRACTS, "salt")
    assert out == ""


def test_build_block_silent_on_corpus_load_error(monkeypatch):
    def boom():
        raise RuntimeError("corpus exploded")
    monkeypatch.setattr(pr, "load_corpus", boom)
    leads = [{"name": "ssh-login-history", "id": "l-001"}]
    out = pr.build_prior_recall_block(leads, _INV_MD_WITH_CONTRACTS, "salt")
    assert out == ""
