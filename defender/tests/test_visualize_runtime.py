"""Regression tests for the runtime.html data layer + page composition.

The PydanticAI migration renamed the run-dir writers (``Write``/``Edit`` →
``write_file``/``edit_file``, arg ``file_path`` → ``path``) and dispatches the
gather subagent through a ``gather`` tool rather than ``Task``/``Agent``. The
visualizer's phase tagger + cost/transcript machinery was still coded for the
old ``claude -p`` shapes, so every event collapsed into the first phase and the
gather panel was always empty. These tests pin the fixed behavior:

  - ``write_file``/``edit_file`` writes that introduce ``## PHASE`` headers
    advance the phase cursor, so per-phase cost is spread across phases;
  - the transcript is built from ``llm_requests.jsonl`` (full content + retries)
    with correct per-entry kind + phase;
  - per-phase cost reconciles with the headline total (main + folded gather);
  - run-health surfaces gate retries + dead-end leads;
  - § Leads & queries renders from the two-table join.
"""
from __future__ import annotations

import json
from pathlib import Path

from defender.scripts.visualize import visualize_data as d
from defender.scripts.visualize.visualize_primitives import load_jsonl
from defender.scripts.visualize.visualize_run import render_runtime_page

# A four-phase run. Each assistant turn writes investigation.md, introducing one
# new "## PHASE" header with substantive body (so the tagger advances), and the
# PLAN turn also dispatches a gather. The model ids match between tool_trace and
# llm_requests so the phase map lines up (as it does in production).
_USAGE = {"input_tokens": 100, "output_tokens": 800, "cache_read_input_tokens": 5000, "cache_creation_input_tokens": 200}

_TURNS = [
    ("main#0", "ORIENT", "## ORIENT\n\nOriented on the alert: ssh auth anomaly.\n", None),
    ("main#1", "PLAN", "## ORIENT\n\nOriented.\n\n## PLAN\n\nPlanning to gather ssh auth + identity.\n", "l-001"),
    ("main#2", "GATHER", "## PLAN\n\nPlanned.\n\n## GATHER\n\nGathered measurements from elastic.\n", None),
    ("main#3", "REPORT", "## GATHER\n\nGathered.\n\n## REPORT\n\nDisposition: malicious — confirmed pivot.\n", None),
]

# The on-disk investigation.md is the *cumulative* document (all four headers);
# split_investigation_phases reads this to derive the phase order.
_FULL_INVESTIGATION = (
    "## ORIENT\n\nOriented on the alert: ssh auth anomaly.\n\n"
    "## PLAN\n\nPlanning to gather ssh auth + identity.\n\n"
    "## GATHER\n\nGathered measurements from elastic.\n\n"
    "## REPORT\n\nDisposition: malicious — confirmed pivot.\n"
)


def _build_run(tmp: Path) -> Path:
    run = tmp / "run"
    (run / "gather_raw" / "l-001").mkdir(parents=True)

    (run / "investigation.md").write_text(_FULL_INVESTIGATION)
    (run / "report.md").write_text(
        "---\ncase_id: t\ndisposition: malicious\nconfidence: high\n---\nConfirmed root-ssh pivot from 10.0.0.5.\n"
    )
    (run / "alert.json").write_text(json.dumps({"rule": "ssh-auth"}))

    trace: list[dict] = []
    messages: list[dict] = []
    seq = 0

    def write_call(i: int, content: str) -> dict:
        return {"type": "tool_use", "name": "write_file", "id": f"w{i}", "input": {"path": "investigation.md", "content": content}}

    for i, (mid, _phase, content, lead) in enumerate(_TURNS):
        blocks = [write_call(i, content)]
        if lead:
            blocks.append({
                "type": "tool_use", "name": "gather", "id": f"g{i}",
                "input": {"lead_id": lead, "system": "elastic", "goal": "confirm pivot", "what_to_summarize": ["auth"]},
            })
        trace.append({
            "type": "assistant", "timestamp": f"2026-06-26T14:0{i}:00+00:00",
            "message": {"id": mid, "model": "claude-sonnet-4-6", "usage": _USAGE, "content": blocks},
        })
        trace.append({
            "type": "user", "timestamp": f"2026-06-26T14:0{i}:30+00:00",
            "message": {"content": [{"type": "tool_result", "tool_name": "write_file"}]},
        })
        # llm_requests: response (same id) + a request carrying the tool returns.
        parts = [{"part_kind": "tool-call", "tool_name": b["name"], "tool_call_id": b["id"], "args": b["input"]} for b in blocks]
        messages.append({
            "agent_id": "main", "seq": seq, "id": mid, "kind": "response",
            "model": "claude-sonnet-4-6", "usage": _USAGE, "duration_ms": 2000.0,
            "message": {"kind": "response", "parts": parts},
        })
        seq += 1
        returns = [{"part_kind": "tool-return", "tool_name": b["name"], "tool_call_id": b["id"], "content": f"ok {b['name']}"} for b in blocks]
        messages.append({"agent_id": "main", "seq": seq, "id": f"r{seq}", "kind": "request", "message": {"kind": "request", "parts": returns}})
        seq += 1

    # one gate retry (health + transcript) and one gather instance (Haiku cost)
    messages.append({"agent_id": "main", "seq": seq, "id": f"r{seq}", "kind": "request",
                     "message": {"kind": "request", "parts": [{"part_kind": "retry-prompt", "tool_name": "bash", "content": "Denied: raw adapter from main loop."}]}})
    messages.append({"agent_id": "gather:l-001", "seq": 0, "id": "gather:l-001#0", "kind": "response",
                     "model": "claude-haiku-4-5", "usage": {"input_tokens": 50, "output_tokens": 300, "cache_read_input_tokens": 1000, "cache_creation_input_tokens": 0},
                     "duration_ms": 1500.0, "message": {"kind": "response", "parts": [{"part_kind": "text", "content": "summary"}]}})

    trace.append({"type": "result", "duration_ms": 90000, "duration_api_ms": 80000,
                  "total_cost_usd": 0.5, "num_turns": 4, "usage": _USAGE})

    (run / "tool_trace.jsonl").write_text("".join(json.dumps(e) + "\n" for e in trace))
    (run / "llm_requests.jsonl").write_text("".join(json.dumps(m) + "\n" for m in messages))

    # two tables: l-001 ran two queries; l-002 has a sidecar but no query row
    # (a dead-end lead — the planning/tooling gap run_health surfaces).
    queries = [
        {"lead_id": "l-001", "seq": 0, "system": "elastic", "verb": "search", "query_id": "elastic.ssh-auth",
         "params": {"user": "root"}, "exit_code": 0, "payload_status": "ok", "payload_path": "gather_raw/l-001/0.json"},
        {"lead_id": "l-001", "seq": 1, "system": "elastic", "verb": "search", "query_id": "elastic.ssh-pivot",
         "params": {"src": "10.0.0.5"}, "exit_code": 0, "payload_status": "ok", "payload_path": "gather_raw/l-001/1.json"},
    ]
    (run / "executed_queries.jsonl").write_text("".join(json.dumps(q) + "\n" for q in queries))
    (run / "gather_raw" / "l-001.lead.json").write_text(json.dumps({"goal": "confirm pivot", "what_to_summarize": ["auth"]}))
    (run / "gather_raw" / "l-002.lead.json").write_text(json.dumps({"goal": "check identity", "what_to_summarize": ["status"]}))
    (run / "gather_raw" / "l-001" / "0.json").write_text(json.dumps({"hits": 1}))
    return run


def _phase_order(run: Path) -> list[str]:
    phases = d.normalize_phase_names(d.split_investigation_phases(run))
    return [p["name"] for p in phases if p["name"] != "preamble"]


def test_tagger_advances_on_write_file(tmp_path):
    """write_file/edit_file writes introducing ## headers advance the cursor —
    so cost lands in multiple phases, not all in phase[0] (the migration bug)."""
    run = _build_run(tmp_path)
    events = load_jsonl(run / "tool_trace.jsonl")
    order = _phase_order(run)
    tags = d.tag_events_by_phase(events, order)

    distinct = {t for t in tags if t is not None}
    assert len(distinct) >= 3, f"tagger collapsed phases: {distinct}"

    attr = d.phase_attribution(events, order)
    nonzero = [ph for ph in order if attr[ph]["cost"] > 0]
    assert len(nonzero) >= 3, f"cost not spread across phases: {nonzero}"


def test_gather_dispatch_phase_and_cost(tmp_path):
    """The gather call is tagged to the PLAN turn that issued it, and its Haiku
    cost folds into that phase (the trace alone can't see gather messages)."""
    run = _build_run(tmp_path)
    events = load_jsonl(run / "tool_trace.jsonl")
    order = _phase_order(run)
    tags = d.tag_events_by_phase(events, order)

    gphase = d.gather_dispatch_phase(events, tags)
    assert gphase["l-001"].startswith("PLAN")

    attr = d.phase_attribution(events, order)
    main_total = sum(b["cost"] for b in attr.values())
    by_phase, gather_total = d.gather_cost_by_phase(run, events, tags, order, main_total, 0.5)
    assert gather_total > 0
    assert by_phase[gphase["l-001"]] > 0


def test_transcript_from_messages(tmp_path):
    """The transcript is built from llm_requests.jsonl with full content +
    retries, one entry per assistant turn / tool-return / retry, phase-tagged."""
    run = _build_run(tmp_path)
    events = load_jsonl(run / "tool_trace.jsonl")
    order = _phase_order(run)
    tags = d.tag_events_by_phase(events, order)
    messages = d.load_messages(run)
    entries = d.build_transcript(messages, d.msg_phase_map(events, tags), order)

    kinds = {e["kind"] for e in entries}
    assert {"assistant", "tool_result", "retry"} <= kinds

    # tool-results carry real content (not the empty trace projection)
    results = [e for e in entries if e["kind"] == "tool_result"]
    assert results
    assert all(e["content"] for e in results)

    # the gather call is an assistant entry tagged to a PLAN phase
    plan_calls = [e for e in entries if e["kind"] == "assistant" and "gather" in (e.get("tools") or [])]
    assert plan_calls
    assert plan_calls[0]["phase"].startswith("PLAN")


def test_run_health(tmp_path):
    run = _build_run(tmp_path)
    events = load_jsonl(run / "tool_trace.jsonl")
    order = _phase_order(run)
    health = d.run_health(run, events, d.load_messages(run), order)

    assert health["completed"] is True
    assert health["retries"] == 1
    assert health["dead_ends"] == 1  # l-002 has a sidecar but ran no query
    assert health["level"] == "warn"
    assert any("retr" in det for det in health["details"])


def test_render_runtime_page_reconciles_and_renders(tmp_path, monkeypatch):
    """The page renders the fold + transcript + leads table, and the headline
    cost equals the sum of the per-phase cost-bar segments."""
    import re

    run = _build_run(tmp_path)
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(tmp_path / "state"))
    html = render_runtime_page(run)

    for marker in ("card-analysis", "card-metrics", "sec-transcript", "sec-leads", "tx-chip", "disp-badge"):
        assert marker in html, f"missing {marker}"

    # leads & queries table has the ran lead and the dead-end lead
    assert "elastic.ssh-auth" in html
    assert "dead-end lead" in html

    # headline cost == sum of the cost-bar $ segments
    headline = float(re.search(r'me-cost">\$([0-9.]+)', html).group(1))
    segs = [float(x) for x in re.findall(r'cb-pct">\$([0-9.]+)', html)]
    assert abs(headline - sum(segs)) < 0.002, f"{headline} != {sum(segs)}"
