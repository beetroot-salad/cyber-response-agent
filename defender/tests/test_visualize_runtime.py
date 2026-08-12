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

from defender._io import read_jsonl_rows
from defender._run_paths import RunPaths
from defender.scripts.visualize import visualize_data as d
from defender.scripts.visualize.visualize_run import render_runtime_page

_USAGE = {"input_tokens": 100, "output_tokens": 800, "cache_read_input_tokens": 5000, "cache_creation_input_tokens": 200}

_TURNS = [
    ("main#0", "ORIENT", "## ORIENT\n\nOriented on the alert: ssh auth anomaly.\n", None),
    ("main#1", "PLAN", "## ORIENT\n\nOriented.\n\n## PLAN\n\nPlanning to gather ssh auth + identity.\n", "l-001"),
    ("main#2", "GATHER", "## PLAN\n\nPlanned.\n\n## GATHER\n\nGathered measurements from elastic.\n", None),
    ("main#3", "REPORT", "## GATHER\n\nGathered.\n\n## REPORT\n\nDisposition: malicious — confirmed pivot.\n", None),
]

_FULL_INVESTIGATION = (
    "## ORIENT\n\nOriented on the alert: ssh auth anomaly.\n\n"
    "## PLAN\n\nPlanning to gather ssh auth + identity.\n\n"
    "## GATHER\n\nGathered measurements from elastic.\n\n"
    "## REPORT\n\nDisposition: malicious — confirmed pivot.\n"
)


def _seed_session_store(run: Path, messages: list[dict]) -> None:
    """`render_runtime_page`/`render_judge_page` now open the run's own session store
    (R4/#705) — this fixture predates the store, so give it a real one seeded from the
    same `messages` it already writes to the wire log, rather than fabricating a
    run dir the new render path cannot resolve."""
    from pydantic_ai.messages import ModelMessagesTypeAdapter

    from defender.runtime import session_store as ss

    # A per-test-unique case_id: `store_path_for` resolves off `runs_base.parent`, which
    # for this fixture (`runs_base = run.parent = tmp_path`) is the shared parent every
    # test in this file's pytest run gets its own `tmp_path` under — so a fixed case_id
    # collides across tests into one shared store file and one shared `main` session
    # lineage. #754's `_main_session_analysis` refuses that ambiguity outright instead of
    # silently picking one, which is what surfaces this fixture's own pre-existing
    # cross-test collision.
    store = ss.open_store(
        case_id=f"visualize-runtime-fixture-{run.parent.name}", runs_base=run.parent)
    ss.write_case_pointer(run, case_id=store.case_id, store_path=store.path)
    sessions: dict[str, str] = {}
    for rec in messages:
        agent_id = rec.get("agent_id", "main")
        # `dict.setdefault(k, expr)` evaluates `expr` eagerly, so `store.new_session(...)`
        # as the default arg minted one orphan `main` session PER MESSAGE — nine rows,
        # only the first ever used for an append — and the old rowid-ordered picker
        # masked it by always grabbing that same first row. #754's root-of-lineage
        # picker refuses the ambiguity outright, which is what surfaces it.
        if agent_id not in sessions:
            sessions[agent_id] = store.new_session(agent_id=agent_id)
        session_id = sessions[agent_id]
        message = ModelMessagesTypeAdapter.validate_python([rec["message"]])[0]
        store.append(session_id, [message], agent_id=agent_id)
    store.close()


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

    messages.append({"agent_id": "main", "seq": seq, "id": f"r{seq}", "kind": "request",
                     "message": {"kind": "request", "parts": [{"part_kind": "retry-prompt", "tool_name": "bash", "content": "Denied: raw adapter from main loop."}]}})
    messages.append({"agent_id": "gather:l-001", "seq": 0, "id": "gather:l-001#0", "kind": "response",
                     "model": "claude-haiku-4-5", "usage": {"input_tokens": 50, "output_tokens": 300, "cache_read_input_tokens": 1000, "cache_creation_input_tokens": 0},
                     "duration_ms": 1500.0, "message": {"kind": "response", "parts": [{"part_kind": "text", "content": "summary"}]}})

    trace.append({"type": "result", "duration_ms": 90000, "duration_api_ms": 80000,
                  "total_cost_usd": 0.5, "num_turns": 4, "usage": _USAGE})

    (run / "tool_trace.jsonl").write_text("".join(json.dumps(e) + "\n" for e in trace))
    wire = RunPaths(run).wire_log
    wire.parent.mkdir(parents=True, exist_ok=True)
    wire.write_text("".join(json.dumps(m) + "\n" for m in messages))
    _seed_session_store(run, messages)

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
    events = read_jsonl_rows(run / "tool_trace.jsonl")
    order = _phase_order(run)
    tags = d.tag_events_by_phase(events, order)

    distinct = {t for t in tags if t is not None}
    assert len(distinct) >= 3, f"tagger collapsed phases: {distinct}"

    attr = d.phase_attribution(events, order)
    nonzero = [ph for ph in order if attr[ph]["cost"] > 0]
    assert len(nonzero) >= 3, f"cost not spread across phases: {nonzero}"


def test_gather_dispatch_phase_and_cost(tmp_path):
    """The gather call is *dispatched* from the PLAN turn that issued it, but its
    subagent cost lands in the GATHER phase of that loop — the agent calls gather
    before writing the ``## GATHER`` header, so raw tagging would bury the cost in
    PLAN and leave the GATHER bar empty."""
    run = _build_run(tmp_path)
    events = read_jsonl_rows(run / "tool_trace.jsonl")
    order = _phase_order(run)
    tags = d.tag_events_by_phase(events, order)

    gphase = d.gather_dispatch_phase(events, tags)
    assert gphase["l-001"].startswith("PLAN")

    attr = d.phase_attribution(events, order)
    main_total = sum(b["cost"] for b in attr.values())
    by_phase, gather_total = d.gather_cost_by_phase(run, events, tags, order, main_total, 0.5)
    assert gather_total > 0
    gather_phase = next(p for p in order if p.startswith("GATHER"))
    assert by_phase[gather_phase] > 0
    assert by_phase[gphase["l-001"]] == 0


def test_gather_wall_and_model_reattribution(tmp_path):
    """Gather wall moves from its PLAN dispatch window into the GATHER bar, and
    gather cost is reported under the model the gather agent actually ran on."""
    run = _build_run(tmp_path)
    events = read_jsonl_rows(run / "tool_trace.jsonl")
    order = _phase_order(run)
    tags = d.tag_events_by_phase(events, order)

    to_gather, from_dispatch = d.gather_wall_by_phase(run, events, tags, order)
    gather_phase = next(p for p in order if p.startswith("GATHER"))
    plan_phase = next(p for p in order if p.startswith("PLAN"))
    assert to_gather[gather_phase] > 0
    assert from_dispatch[plan_phase] > 0
    assert to_gather[plan_phase] == 0

    by_model = d.gather_cost_by_model(run)
    assert list(by_model) == ["haiku-4-5"]
    assert by_model["haiku-4-5"] > 0


def test_gather_cost_not_dropped_without_gather_phase(tmp_path):
    """A gather whose dispatch turn was never tagged (no matching trace event)
    and a run with no ``## GATHER`` header still has its cost placed in a bar —
    so gather_total stays equal to the full gather cost the per-model breakdown
    reports, and the headline never under-counts what by_model shows."""
    order = ["ORIENT loop 1", "PLAN loop 1", "REPORT loop 1"]
    messages = [
        {"kind": "response", "agent_id": "gather:l-001", "model": "claude-haiku-4-5", "usage": _USAGE},
    ]
    by_phase, gather_total = d.gather_cost_by_phase(
        tmp_path, [], [], order, 0.0, 0.0, messages
    )
    full = sum(d.gather_cost_by_model(tmp_path, messages).values())
    assert full > 0
    assert gather_total == full
    assert by_phase[order[0]] == gather_total

def test_transcript_from_messages(tmp_path):
    """The transcript is built from llm_requests.jsonl with full content +
    retries, one entry per assistant turn / tool-return / retry, phase-tagged."""
    run = _build_run(tmp_path)
    events = read_jsonl_rows(run / "tool_trace.jsonl")
    order = _phase_order(run)
    tags = d.tag_events_by_phase(events, order)
    messages = d.load_messages(run)
    entries = d.build_transcript(messages, d.msg_phase_map(events, tags), order)

    kinds = {e["kind"] for e in entries}
    assert {"assistant", "tool_result", "retry"} <= kinds

    results = [e for e in entries if e["kind"] == "tool_result"]
    assert results
    assert all(e["content"] for e in results)

    plan_calls = [e for e in entries if e["kind"] == "assistant" and "gather" in (e.get("tools") or [])]
    assert plan_calls
    assert plan_calls[0]["phase"].startswith("PLAN")


def test_run_health(tmp_path):
    run = _build_run(tmp_path)
    events = read_jsonl_rows(run / "tool_trace.jsonl")
    order = _phase_order(run)
    health = d.run_health(run, events, d.load_messages(run), order)

    assert health["completed"] is True
    assert health["retries"] == 1
    assert health["dead_ends"] == 1
    assert health["level"] == "warn"
    assert any("retr" in det for det in health["details"])


def test_render_runtime_page_reconciles_and_renders(tmp_path, monkeypatch):
    """The page renders the fold + transcript + leads table, and the headline
    cost equals the sum of the per-phase cost-bar segments."""
    import re

    run = _build_run(tmp_path)
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(tmp_path / "state"))
    html = render_runtime_page(run)

    for marker in (
        "card-analysis", "an-cols", "top-stats", "sec-metrics", "tu-row",
        "sec-transcript", "tx-group", "tx-group-head", "sec-leads", "tx-chip", "disp-badge",
    ):
        assert marker in html, f"missing {marker}"

    assert "elastic.ssh-auth" in html
    assert "dead-end lead" in html

    headline = float(re.search(r'ts-cost">\$([0-9.]+)', html).group(1))
    segs = [float(x) for x in re.findall(r'cb-pct">\$([0-9.]+)', html)]
    assert abs(headline - sum(segs)) < 0.002, f"{headline} != {sum(segs)}"
    # Asked of the rendered SPAN, not of the class name: the stylesheet is inlined into every
    # page, so `"ts-review" in html` is true whether or not anything was rendered with it.
    assert re.search(r'ts-review">', html) is None, (
        "this fixture's gate made no model call, and a $0.0000 review term would read as "
        "'the gate was free' rather than 'the gate did not run'"
    )


def _append_review_calls(run: Path, n_per_lens: int = 1) -> float:
    """Give the fixture run a review gate that actually cost something, and return the total.

    Written as wire records under `review:{lens}` because that is where the gate's calls land
    since #787 — one shared `RequestLogger`, one `agent_id` namespace."""
    from defender.scripts.pricing import usage_cost

    rows = []
    for lens in ("support", "ablation", "composer"):
        for seq in range(n_per_lens):
            rows.append({
                "agent_id": f"review:{lens}", "seq": seq, "id": f"review:{lens}#{seq}",
                "kind": "response", "model": "kimi-k3", "usage": _USAGE, "duration_ms": 900.0,
                "message": {"kind": "response", "parts": [{"part_kind": "text", "content": "read"}]},
            })
    with RunPaths(run).wire_log.open("a", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")
    return len(rows) * usage_cost("kimi-k3", _USAGE)


def test_the_review_gate_s_spend_is_inside_the_headline_and_named_there(tmp_path, monkeypatch):
    """#787. The gate's calls are calls the run made, so they are IN the total — and named,
    because an operator who cannot separate them cannot answer what the gate cost.

    The headline therefore stops equalling the per-phase bar sum, and that is the intended
    relationship rather than drift: the gate is not a phase (the investigator is never "in"
    it), so its money has no phase segment to live in. Pinned as the exact difference."""
    import re

    run = _build_run(tmp_path)
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(tmp_path / "state"))
    review_total = _append_review_calls(run)
    assert review_total > 0.002, "fixture too cheap to discriminate against the tolerance"

    html = render_runtime_page(run)

    headline = float(re.search(r'ts-cost">\$([0-9.]+)', html).group(1))
    segs = [float(x) for x in re.findall(r'cb-pct">\$([0-9.]+)', html)]
    assert abs(headline - (sum(segs) + review_total)) < 0.002, (
        f"headline {headline} is not the phase bars {sum(segs)} plus the review {review_total}"
    )

    named = re.search(r'ts-review">\(incl review \$([0-9.]+)\)', html)
    assert named is not None, "the review's share is folded into the total unnamed"
    assert abs(float(named.group(1)) - review_total) < 0.0001

    assert "kimi-k3" in html, (
        "the by-model breakdown and the models byline must show the model the review "
        "actually billed, not fold its spend into the investigator's row"
    )


def test_load_messages_still_finds_a_pre_observe_run_s_wire_log(tmp_path):
    """A run dir written before the wire log moved under `observe/` still renders.

    The move is a read-GATE fact — `<run>/observe/` is outside every reader agent's
    single-segment run-dir read shape — and the visualizer is host code that sits outside the
    gate entirely, so nothing is reopened by reading the old location when the new one is
    absent. Without the fallback the page silently shows its "older run" empty state for runs
    that DO have a transcript, which reads as a broken run rather than a moved file.

    The precedence is the other half: when both exist, the current location wins."""
    legacy = tmp_path / "legacy"
    legacy.mkdir()
    (legacy / d.LLM_REQUESTS).write_text(json.dumps({"id": "old#0", "kind": "response"}) + "\n")
    assert [r["id"] for r in d.load_messages(legacy)] == ["old#0"]

    both = tmp_path / "both"
    wire = RunPaths(both).wire_log
    wire.parent.mkdir(parents=True)
    (both / d.LLM_REQUESTS).write_text(json.dumps({"id": "old#0", "kind": "response"}) + "\n")
    wire.write_text(json.dumps({"id": "new#0", "kind": "response"}) + "\n")
    assert [r["id"] for r in d.load_messages(both)] == ["new#0"]
