"""runtime.html data layer and page composition: the phase tagger follows write_file/edit_file, per-phase cost and wall reconcile with the headline (gather folded in, repeated phase names are one bucket), the transcript is built from the wire log in the right id space, and run health surfaces retries and dead-end leads."""
from __future__ import annotations

from defender.tests.support.shared.contracts._spec1077 import fixture_run as _run_handle_1165

import json
from pathlib import Path

from defender._io import read_jsonl_rows
from defender.run_repository import RunPaths
from defender.scripts.visualize import visualize_data as d
from defender.scripts.visualize.visualize_run import render_runtime_page
from defender.run_repository import SessionPaths

_USAGE = {"input_tokens": 100, "output_tokens": 800, "cache_read_input_tokens": 5000, "cache_creation_input_tokens": 200}

_SESSION = "9f2c1ab84e7d4f0e9c3b5a6d7e8f0a1b"

_TURNS = [
    (1, "main#1", "ORIENT", "## ORIENT\n\nOriented on the alert: ssh auth anomaly.\n", None),
    (3, "main#5", "PLAN", "## ORIENT\n\nOriented.\n\n## PLAN\n\nPlanning to gather ssh auth + identity.\n", "l-001"),
    (5, "main#11", "GATHER", "## PLAN\n\nPlanned.\n\n## GATHER\n\nGathered measurements from elastic.\n", None),
    (7, "main#19", "REPORT", "## GATHER\n\nGathered.\n\n## REPORT\n\nDisposition: malicious — confirmed pivot.\n", None),
]

_FULL_INVESTIGATION = (
    "## ORIENT\n\nOriented on the alert: ssh auth anomaly.\n\n"
    "## PLAN\n\nPlanning to gather ssh auth + identity.\n\n"
    "## GATHER\n\nGathered measurements from elastic.\n\n"
    "## REPORT\n\nDisposition: malicious — confirmed pivot.\n"
)


def _seed_session_store(run: Path, messages: list[dict]) -> None:
    """`render_runtime_page` now opens the run's own session store
    (R4/#705) — this fixture predates the store, so give it a real one seeded from the
    same `messages` it already writes to the wire log, rather than fabricating a
    run dir the new render path cannot resolve."""
    from pydantic_ai.messages import ModelMessagesTypeAdapter

    from defender.runtime import session_store as ss

    store = ss.open_store(
        case_id=f"visualize-runtime-fixture-{run.parent.name}", sessions=SessionPaths(run.parent))
    ss.write_case_pointer(_run_handle_1165(run), case_id=store.case_id, store_path=store.path)
    sessions: dict[str, str] = {}
    for rec in messages:
        agent_id = rec.get("agent_id", "main")
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

    for i, (coord_seq, wire_id, _phase, content, lead) in enumerate(_TURNS):
        coord = f"{_SESSION}/main#{coord_seq}"
        blocks = [write_call(i, content)]
        if lead:
            blocks.append({
                "type": "tool_use", "name": "gather", "id": f"g{i}",
                "input": {"lead_id": lead, "system": "elastic", "goal": "confirm pivot", "what_to_summarize": ["auth"]},
            })
        trace.append({
            "type": "assistant", "timestamp": f"2026-06-26T14:0{i}:00+00:00",
            "message": {"id": coord, "model": "claude-sonnet-4-6",
                        "usage": _USAGE, "content": blocks},
        })
        trace.append({
            "type": "user", "timestamp": f"2026-06-26T14:0{i}:30+00:00",
            "message": {"content": [{"type": "tool_result", "tool_name": "write_file"}]},
        })
        parts = [{"part_kind": "tool-call", "tool_name": b["name"], "tool_call_id": b["id"], "args": b["input"]} for b in blocks]
        messages.append({
            "agent_id": "main", "seq": seq, "id": wire_id, "kind": "response",
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
    entries = d.build_transcript(
        messages, d.transcript_phase_map(events, tags, messages), order)

    kinds = {e["kind"] for e in entries}
    assert {"assistant", "tool_result", "retry"} <= kinds

    results = [e for e in entries if e["kind"] == "tool_result"]
    assert results
    assert all(e["content"] for e in results)

    plan_calls = [e for e in entries if e["kind"] == "assistant" and "gather" in (e.get("tools") or [])]
    assert plan_calls
    assert plan_calls[0]["phase"].startswith("PLAN")

    phases = {e["phase"] for e in entries}
    assert len(phases) > 1, (
        f"every entry carries one phase ({phases}) — the wire-id/coord join is dead and "
        f"cur_phase never left its phase_order[0] seed")
    assert phases == set(order), f"expected every tagged phase to reach the transcript, got {phases}"


def test_the_trace_and_the_wire_log_name_a_turn_in_two_id_spaces(tmp_path):
    run = _build_run(tmp_path)
    events = read_jsonl_rows(run / "tool_trace.jsonl")
    messages = d.load_messages(run)

    trace_ids = [e["message"]["id"] for e in events if e.get("type") == "assistant"]
    wire_ids = [r["id"] for r in messages
                if r.get("kind") == "response" and r.get("agent_id", "main") == "main"]
    assert trace_ids
    assert wire_ids
    assert not set(trace_ids) & set(wire_ids), (
        "the fixture collapsed the two id spaces into one — production keeps them apart "
        "and the join under test only exists because they differ")
    assert all("/" in tid for tid in trace_ids), "a store coord carries its session prefix"
    assert all("/" not in wid for wid in wire_ids), "a wire id carries no session prefix"

    order = _phase_order(run)
    tags = d.tag_events_by_phase(events, order)
    coord_map = d.msg_phase_map(events, tags)
    wire_map = d.transcript_phase_map(events, tags, messages)

    assert set(coord_map) == set(trace_ids), (
        "the cost attribution's map must be keyed by coord — `_attribute_main_agent` "
        "reads trace events and joins in that space")
    assert set(wire_map) == set(wire_ids), (
        "the transcript's map must be keyed by wire id — `build_transcript` has nothing else")
    # Same turns, same phases, two spellings — the translation must not lose a phase.
    assert sorted(coord_map.values()) == sorted(wire_map.values())
    assert [wire_map[w] for w in wire_ids] == [coord_map[t] for t in trace_ids]


def test_the_phase_join_survives_a_fold_that_left_the_trace_holding_only_the_tail(tmp_path):
    run = _build_run(tmp_path)
    events = read_jsonl_rows(run / "tool_trace.jsonl")
    messages = d.load_messages(run)
    order = _phase_order(run)
    tags = d.tag_events_by_phase(events, order)

    # Drop the first two assistant turns (and their tags) from the trace, the way a fold
    # through loop 1 drops them off the store's path. The wire log is untouched.
    keep = [i for i, ev in enumerate(events) if ev.get("type") == "assistant"][2:]
    folded_events = [events[i] for i in keep]
    folded_tags = [tags[i] for i in keep]

    wire_map = d.transcript_phase_map(folded_events, folded_tags, messages)
    entries = d.build_transcript(messages, wire_map, order)
    phases = [e["phase"] for e in entries if e["kind"] == "assistant"]

    assert phases[0].startswith("ORIENT"), (
        f"the folded-away turns must fall back to phase_order[0], got {phases[0]!r} — "
        f"the join slid the surviving phases onto the wrong turns")
    assert phases[-1].startswith("REPORT"), (
        f"the surviving turns must keep their own phases, got {phases!r}")


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
    from defender._pricing import usage_cost

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
    because an operator who cannot separate them cannot answer what the gate cost."""
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


def _duplicate_the_gather_phase(run: Path) -> None:
    """Two `## GATHER` headers with no `PLAN` between them — the shape the review gate's
    "another GATHER turn" return path invites. `normalize_phase_names` only bumps the loop
    counter on a PLAN, so both normalize to `GATHER (loop 1)`: one dict bucket, two entries
    in the render list."""
    p = run / "investigation.md"
    text = p.read_text(encoding="utf-8")
    second = "## GATHER\n\nGathered again after the gate sent the turn back.\n\n"
    p.write_text(text.replace("## REPORT", second + "## REPORT"), encoding="utf-8")


def test_a_bucket_that_appears_twice_is_tiled_once(tmp_path):
    """#956, the half the render list hides: a repeat that is NOT adjacent."""
    phases = [{"name": n} for n in ["ORIENT", "PLAN", "GATHER", "ANALYZE", "GATHER", "REPORT"]]
    order = [p["name"] for p in d.normalize_phase_names(phases)]
    assert order.count("GATHER (loop 1)") == 2, f"fixture names no repeat: {order}"

    tags = ["ORIENT", "PLAN (loop 1)", "GATHER (loop 1)", "ANALYZE (loop 1)",
            "ANALYZE (loop 1)", "REPORT"]
    events = [
        {"type": "user", "timestamp": f"2026-06-26T14:0{i}:00+00:00"}
        for i in range(len(tags))
    ]
    wall = d.phase_wall_times(events, tags, order)

    assert wall["ANALYZE (loop 1)"]["duration_sec"] > 0, (
        "the later appearance of the GATHER bucket ended ANALYZE before it began"
    )
    assert sum(v["duration_sec"] for v in wall.values()) == 300.0, (
        f"the tiles no longer cover the run: {[(k, v['duration_sec']) for k, v in wall.items()]}"
    )


def _bar_figures(html: str) -> dict[str, dict[str, str]]:
    """`{bar: {phase: rendered value}}`, read off the segment tooltips — the only place the
    per-phase cost and wall land in the page as numbers a reader can check."""
    import re

    out: dict[str, dict[str, str]] = {}
    bars = re.findall(
        r'me-bar-label">(cost|wall)</span><div class="cost-bar">(.*?)</div></div></div>', html)
    assert [name for name, _ in bars] == ["cost", "wall"], f"bars not rendered: {bars}"
    for name, inner in bars:
        widths = [float(w) for w in re.findall(r'class="cb-seg" style="width:([0-9.]+)%', inner)]
        assert abs(sum(widths) - 100.0) < 0.1, (
            f"the {name} bar's segments overflow it: {sum(widths)}% from {widths}"
        )
        figures: dict[str, str] = {}
        for title in re.findall(r'title="([^"]+)"', inner):
            phase, value, _pct = (part.strip() for part in title.split("·"))
            assert phase not in figures, f"{phase} drew two {name} segments from one bucket"
            figures[phase] = value
        out[name] = figures
    return out


def test_a_repeated_phase_name_is_one_bucket_not_two(tmp_path, monkeypatch):
    import re

    plain = _build_run(tmp_path / "plain")
    doubled = _build_run(tmp_path / "doubled")
    _duplicate_the_gather_phase(doubled)
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(tmp_path / "state"))

    assert _phase_order(doubled).count("GATHER (loop 1)") == 2, (
        f"fixture no longer duplicates a name: {_phase_order(doubled)}"
    )
    assert "GATHER (loop 1)" in _phase_order(plain)

    doubled_html = render_runtime_page(doubled)
    assert _bar_figures(doubled_html) == _bar_figures(render_runtime_page(plain)), (
        "the repeated header moved a per-phase number"
    )

    headline = float(re.search(r'ts-cost">\$([0-9.]+)', doubled_html).group(1))
    segs = [float(x) for x in re.findall(r'cb-pct">\$([0-9.]+)', doubled_html)]
    assert abs(headline - sum(segs)) < 0.002, (
        f"the repeated name was counted twice: headline {headline} != bars {sum(segs)}"
    )

    per_block = [float(x) for x in re.findall(r'ps-cost">\$([0-9.]+)', doubled_html)]
    assert abs(headline - sum(per_block)) < 0.002, (
        f"the repeated header re-printed its bucket's stats: headline {headline} != "
        f"per-phase blocks {sum(per_block)}"
    )


def test_a_repeated_planning_name_is_one_loop(tmp_path):
    written = [{"name": n} for n in ["PLAN (loop 2)", "GATHER", "PLAN (loop 2)", "REPORT"]]
    order = [p["name"] for p in d.normalize_phase_names(written)]
    assert order.count("PLAN (loop 2)") == 2, f"fixture names no repeat: {order}"

    run = _build_run(tmp_path)
    health = d.run_health(
        run, read_jsonl_rows(run / "tool_trace.jsonl"), d.load_messages(run), order)
    assert health["loops"] == 1, (
        f"the repeated planning header was counted as its own loop: {health['loops']}"
    )
