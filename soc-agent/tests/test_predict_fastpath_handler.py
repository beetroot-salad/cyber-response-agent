"""Handler-level tests for the PREDICT loop-1 fast-path.

Exercises `predict.handle()`'s fast-path branch. The cache lookup itself is
covered by `test_predict_fastpath_gate.py`; these tests verify the
integration: signature opt-in, marker block authoring, JSONL log shape,
loop-N skip, subagent never invoked on hit.
"""

from __future__ import annotations

import json
import sys
import textwrap
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))
sys.path.insert(0, str(SOC_AGENT_ROOT / "scripts"))

from invlang.corpus import Companion  # noqa: E402
from schemas.state import Phase  # noqa: E402
from scripts.handlers import predict as predict_handler  # noqa: E402
from scripts.orchestrate import Context  # noqa: E402


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


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


_PROLOGUE_MARKDOWN = """## CONTEXTUALIZE

Test header.

```yaml
prologue:
  vertices:
    - {id: v-src, type: endpoint, classification: internal-monitoring-host, identifier: 172.22.0.5}
    - {id: v-user, type: identity, classification: monitoring-pattern, identifier: nagios}
    - {id: v-target, type: endpoint, classification: internal-server, identifier: host-001}
  edges:
    - {id: e-001, relation: attempted_auth, source_vertex: v-src, target_vertex: v-target}
```
"""


def _make_ctx(
    tmp_path: Path,
    *,
    signature_id: str = "wazuh-rule-5710",
    history: list[str] | None = None,
    investigation_md: str | None = None,
) -> Context:
    run_dir = tmp_path / "run-test"
    run_dir.mkdir()
    alert = {"id": "alert-1", "rule": {"id": "5710"}, "data": {}}
    (run_dir / "alert.json").write_text(json.dumps(alert))
    (run_dir / "meta.json").write_text(json.dumps({"salt": "test-salt"}))
    if investigation_md is not None:
        (run_dir / "investigation.md").write_text(investigation_md)
    return Context(
        run_dir=run_dir,
        signature_id=signature_id,
        ticket_id="SEC-2026-042",
        alert=alert,
        history=history or [Phase.PREDICT.value],
        current_phase=Phase.PREDICT,
    )


def _companion(case_id: str, primary_lead: str, *, age_days: int = 30) -> Companion:
    iso = (datetime.now(timezone.utc) - timedelta(days=age_days)).isoformat()
    body = {
        "prologue": {
            "vertices": [
                {"id": "v-src", "type": "endpoint",
                 "classification": "internal-monitoring-host", "identifier": "172.22.0.5"},
                {"id": "v-user", "type": "identity",
                 "classification": "monitoring-pattern", "identifier": "nagios"},
                {"id": "v-target", "type": "endpoint",
                 "classification": "internal-server", "identifier": "host-001"},
            ],
            "edges": [
                {"id": "e-001", "relation": "attempted_auth",
                 "source_vertex": "v-src", "target_vertex": "v-target"}
            ],
        },
        "hypothesize": {"hypotheses": []},
        "findings": [{"id": "l-1", "loop": 1, "name": primary_lead, "outcome": {}}],
        "conclude": {"disposition": "benign"},
    }
    return Companion(
        case_id=case_id,
        source_path=Path(f"/runs/case-{case_id}-rule5710/investigation.md"),
        body=body,
        created_at=iso,
    )


def _stub_subagent(captured: list[str], responses: list[str]):
    iterator = iter(responses)
    def fn(prompt, *, timeout=None):
        captured.append(prompt)
        return next(iterator)
    return fn


# ---------------------------------------------------------------------------
# Cache hit → subagent skipped
# ---------------------------------------------------------------------------


def test_cache_hit_skips_subagent_writes_marker_and_log(tmp_path, monkeypatch):
    ctx = _make_ctx(tmp_path, investigation_md=_PROLOGUE_MARKDOWN)
    corpus = [
        _companion(f"c{i}", "source-classification") for i in range(3)
    ]
    # Patch the corpus loader the handler reaches for inside _try_fast_path.
    monkeypatch.setattr("invlang.corpus.load_corpus", lambda *a, **kw: corpus)

    captured: list[str] = []
    monkeypatch.setattr(
        predict_handler, "_invoke_subagent",
        _stub_subagent(captured, []),  # exhaust assertion if called
    )

    result = predict_handler.handle(ctx)

    # Subagent never invoked
    assert captured == []
    # Routes to GATHER with the cached lead
    assert result.next_phase == Phase.GATHER
    assert result.payload["selected_lead"] == "source-classification"
    assert result.payload["loop_n"] == 1
    assert result.payload["composite_secondary"] == []
    assert "fast_path" in result.payload
    assert result.payload["fast_path"]["selected_lead"] == "source-classification"
    # Marker block landed in investigation.md
    inv = (ctx.run_dir / "investigation.md").read_text()
    assert "## PREDICT (loop 1) — fast-path" in inv
    assert "source-classification" in inv
    # JSONL log line written
    log = (ctx.run_dir / "predict_priors.jsonl").read_text().strip().splitlines()
    assert len(log) == 1
    rec = json.loads(log[0])
    assert rec["fastpath_taken"] is True
    assert rec["selected_lead"] == "source-classification"
    assert rec["status"] == "ok"


# ---------------------------------------------------------------------------
# Cache miss → subagent invoked, no marker
# ---------------------------------------------------------------------------


def test_cache_miss_falls_through_to_subagent(tmp_path, monkeypatch):
    ctx = _make_ctx(tmp_path, investigation_md=_PROLOGUE_MARKDOWN)
    # Empty corpus → cache miss.
    monkeypatch.setattr("invlang.corpus.load_corpus", lambda *a, **kw: [])
    captured: list[str] = []
    monkeypatch.setattr(
        predict_handler, "_invoke_subagent",
        _stub_subagent(captured, [_FORK_RESPONSE]),
    )
    monkeypatch.setattr(
        predict_handler, "_validate_companion_proposed", lambda ctx, sec: [],
    )

    result = predict_handler.handle(ctx)

    # Subagent WAS invoked
    assert len(captured) == 1
    # Routing reflects the subagent's pick, not a fast-path lead
    assert result.payload["selected_lead"] == "authentication-history"
    assert "fast_path" not in result.payload
    # No marker section
    inv = (ctx.run_dir / "investigation.md").read_text()
    assert "fast-path" not in inv
    # JSONL still written, with fastpath_taken=false
    log = (ctx.run_dir / "predict_priors.jsonl").read_text().strip().splitlines()
    assert len(log) == 1
    rec = json.loads(log[0])
    assert rec["fastpath_eligible"] is True
    assert rec["fastpath_taken"] is False


# ---------------------------------------------------------------------------
# Loop 2+ → fast-path skipped regardless
# ---------------------------------------------------------------------------


def test_loop_2_skips_fast_path(tmp_path, monkeypatch):
    history = [
        Phase.CONTEXTUALIZE.value,
        Phase.PREDICT.value,
        Phase.GATHER.value,
        Phase.ANALYZE.value,
        Phase.PREDICT.value,
    ]
    ctx = _make_ctx(tmp_path, history=history, investigation_md=_PROLOGUE_MARKDOWN)
    corpus = [
        _companion(f"c{i}", "source-classification") for i in range(5)
    ]
    monkeypatch.setattr("invlang.corpus.load_corpus", lambda *a, **kw: corpus)
    captured: list[str] = []
    response = _FORK_RESPONSE.replace("loop: 1", "loop: 2")
    monkeypatch.setattr(
        predict_handler, "_invoke_subagent",
        _stub_subagent(captured, [response]),
    )
    monkeypatch.setattr(
        predict_handler, "_validate_companion_proposed", lambda ctx, sec: [],
    )

    predict_handler.handle(ctx)

    # Subagent invoked at loop 2 even though corpus would yield a hit
    assert len(captured) == 1
    # No fast-path log line written at loop 2
    assert not (ctx.run_dir / "predict_priors.jsonl").exists()


# ---------------------------------------------------------------------------
# Signature without discriminating_classifications never fast-paths
# ---------------------------------------------------------------------------


def test_signature_without_opt_in_skips_lookup(tmp_path, monkeypatch):
    ctx = _make_ctx(
        tmp_path,
        signature_id="wazuh-rule-100001",  # has no discriminating_classifications
        investigation_md=_PROLOGUE_MARKDOWN,
    )
    # Corpus that would cache-hit if the signature opted in
    corpus = [
        _companion(f"c{i}", "source-classification") for i in range(5)
    ]
    monkeypatch.setattr("invlang.corpus.load_corpus", lambda *a, **kw: corpus)
    captured: list[str] = []
    monkeypatch.setattr(
        predict_handler, "_invoke_subagent",
        _stub_subagent(captured, [_FORK_RESPONSE]),
    )
    monkeypatch.setattr(
        predict_handler, "_validate_companion_proposed", lambda ctx, sec: [],
    )

    predict_handler.handle(ctx)

    # Subagent invoked
    assert len(captured) == 1
    # JSONL line written but eligible=false, taken=false
    log = (ctx.run_dir / "predict_priors.jsonl").read_text().strip().splitlines()
    rec = json.loads(log[0])
    assert rec["fastpath_eligible"] is False
    assert rec["fastpath_taken"] is False
    assert rec["telemetry"]["signature_opted_in"] is False


# ---------------------------------------------------------------------------
# Lookup exception → degraded log + subagent fallthrough
# ---------------------------------------------------------------------------


def test_lookup_exception_degrades_to_subagent(tmp_path, monkeypatch):
    ctx = _make_ctx(tmp_path, investigation_md=_PROLOGUE_MARKDOWN)

    def boom(*a, **kw):
        raise RuntimeError("corpus exploded")
    monkeypatch.setattr("invlang.corpus.load_corpus", boom)
    captured: list[str] = []
    monkeypatch.setattr(
        predict_handler, "_invoke_subagent",
        _stub_subagent(captured, [_FORK_RESPONSE]),
    )
    monkeypatch.setattr(
        predict_handler, "_validate_companion_proposed", lambda ctx, sec: [],
    )

    predict_handler.handle(ctx)

    assert len(captured) == 1  # subagent fell through
    log = (ctx.run_dir / "predict_priors.jsonl").read_text().strip().splitlines()
    rec = json.loads(log[0])
    assert rec["status"] == "degraded"
    assert rec["exc_type"] == "RuntimeError"
