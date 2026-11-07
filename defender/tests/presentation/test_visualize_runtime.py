"""runtime.html data layer and page composition: the phase tagger follows write_file/edit_file, per-phase cost and wall reconcile with the headline (gather folded in, repeated phase names are one bucket), the transcript is built from the wire log in the right id space, and run health surfaces retries and dead-end leads."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import fixture_runs_base

from defender.tests.support.shared.contracts._spec1077 import fixture_run as _run_handle_1165

import json
import uuid
from pathlib import Path

import pytest

from defender._io import read_jsonl_rows
from defender.records import RunPaths
from defender.presentation import visualize_data as d
from defender.configuration._pricing import usage_cost
from defender.presentation.visualize_run import render_page
from defender.records import SessionPaths
from defender.tests.support.jobs._jobs1342 import SPEND_LEDGER, insert_spend
from defender.tests.support.shared._fixture_uuid import fixture_uuid

_USAGE = {"input_tokens": 100, "output_tokens": 800, "cache_read_input_tokens": 5000, "cache_creation_input_tokens": 200}

_SESSION = "9f2c1ab84e7d4f0e9c3b5a6d7e8f0a1b"

_HAIKU_USAGE = {"input_tokens": 50, "output_tokens": 300, "cache_read_input_tokens": 1000, "cache_creation_input_tokens": 0}
_BIG = {"input_tokens": 400_000, "output_tokens": 50_000, "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0}

#: The run's spend ledger as the host wrote it (#1377 r6 S5): a row for every response the request log shows (four MAIN
#: turns, one lead's) and one response the request log never held. Rows of another run in the same database are planted too.
_LEDGER = [("claude-sonnet-4-6", _USAGE)] * 4 + [("claude-haiku-4-5", _HAIKU_USAGE), ("claude-sonnet-4-6", _BIG)]
_OTHER_RUNS_LEDGER = [("claude-sonnet-4-6", _BIG)] * 3
_REVIEW_LEDGER = [("kimi-k3", _USAGE)] * 3


def _priced(rows: list) -> float:
    return sum(usage_cost(model, usage) for model, usage in rows)

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
    """A real session store seeded from the same `messages` the fixture writes to the wire log, and holding the run's spend
    ledger (`_LEDGER`, beside another run's rows): the page reads its headline from the run's own store (#1377 r6 S5)."""
    from pydantic_ai.messages import ModelMessagesTypeAdapter

    from defender.records import session_store as ss

    # One database per call: pytest's 30-character tmp names repeat across parametrized cases, and a shared file would pool ledger rows.
    with ss.open_store(case_id=f"visualize-runtime-fixture-{uuid.uuid4().hex}",
                       sessions=SessionPaths(fixture_runs_base(run.parent))) as store:
        ss.write_case_pointer(_run_handle_1165(run), case_id=store.case_id, store_path=store.path)
        sessions: dict[str, str] = {}
        for rec in messages:
            agent_id = rec.get("agent_id", "main")
            if agent_id not in sessions:
                sessions[agent_id] = store.new_session(agent_id=agent_id)
            session_id = sessions[agent_id]
            message = ModelMessagesTypeAdapter.validate_python([rec["message"]])[0]
            store.append(session_id, [message], agent_id=agent_id)
        store_path = store.path
    insert_spend(store_path, run.name, _LEDGER)
    insert_spend(store_path, fixture_uuid("another run"), _OTHER_RUNS_LEDGER)


def _build_run(tmp: Path) -> Path:
    # A run id is a canonical UUID, so the folder is `fixture_uuid(<label>)`.
    run = tmp / fixture_uuid("run")
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
                  "total_cost_usd": 0.5, "total_cost_is_lower_limit": False, "num_turns": 4, "usage": _USAGE})

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
    so cost lands in multiple phases, not all in phase[0]."""
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

    by_phase, gather_total = d.gather_cost_by_phase(run, events, tags, order)
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
    by_phase, gather_total = d.gather_cost_by_phase(tmp_path, [], [], order, messages=messages)
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
    assert len(phases) > 1, f"every entry carries one phase ({phases}): the wire-id/coord join is dead"
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
    assert not set(trace_ids) & set(wire_ids), "the fixture collapsed the two id spaces into one"
    assert all("/" in tid for tid in trace_ids), "a store coord carries its session prefix"
    assert all("/" not in wid for wid in wire_ids), "a wire id carries no session prefix"

    order = _phase_order(run)
    tags = d.tag_events_by_phase(events, order)
    coord_map = d.msg_phase_map(events, tags)
    wire_map = d.transcript_phase_map(events, tags, messages)

    assert set(coord_map) == set(trace_ids), "the cost attribution's map is not keyed by coord"
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
        f"the folded-away turns must fall back to phase_order[0], got {phases[0]!r}")
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


def _page(run: Path, *, spend_write_failed: bool = False) -> str:
    """The run's page through the post-run step's own entry: it holds the `Run` (the host's handle on the run's store).
    `spend_write_failed` is the host's own fact that a spend write failed, handed in as an argument and read from no file
    in the run dir, as `update_ticket` is (r6 S5: the "at least" mark)."""
    return render_page(_run_handle_1165(run), spend_write_failed=spend_write_failed)


def _headline(html: str) -> str:
    import re

    found = re.search(r'ts-cost">(.*?)</', html, flags=re.S)
    assert found is not None, "no headline cost"
    return found.group(1).strip()


def _dollars(headline: str) -> float:
    import re

    found = re.fullmatch(r"(?:at least )?\$([0-9.]+)", headline)
    assert found is not None, f"the headline reads {headline!r}, not a dollar figure"
    return float(found.group(1))


def _unattributed(bars: dict[str, float]) -> list[float]:
    return [v for n, v in bars.items() if "unattributed" in n.lower()]


def _phases(bars: dict[str, float]) -> float:
    return sum(v for n, v in bars.items() if n.lower() != "review" and "unattributed" not in n.lower())


def _append_review_calls(run: Path) -> float:
    """Give the fixture run a review gate that actually cost something: its calls as request-log records under
    `review:{lens}` and as ledger rows. Returns the gate's priced spend."""
    rows = [{
        "agent_id": f"review:{lens}", "seq": 0, "id": f"review:{lens}#0",
        "kind": "response", "model": "kimi-k3", "usage": _USAGE, "duration_ms": 900.0,
        "message": {"kind": "response", "parts": [{"part_kind": "text", "content": "read"}]},
    } for lens in ("support", "ablation", "composer")]
    with RunPaths(run).wire_log.open("a", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")
    from defender.records import session_store as ss

    insert_spend(ss.resolve_store_path(_run_handle_1165(run)), run.name, _REVIEW_LEDGER)
    return _priced(_REVIEW_LEDGER)


def _cost_segments(html: str) -> dict[str, float]:
    """Every cost-bar segment (cb-seg title "<name> · $v · p%") by name, whether or not it is wide enough to print its value."""
    import re

    return {name: float(v) for name, v in re.findall(r'class="cb-seg"[^>]*title="([^"]*?) · \$([0-9.]+) · ', html)}


def _result_line(run: Path, **fields: object) -> None:
    """Rewrite the run file's result line the way a box could between the host's write and teardown: `fields` replace the
    host's, a `None` value drops that key (`_DOUBLED` repeats the line instead)."""
    path = run / "tool_trace.jsonl"
    events = [json.loads(line) for line in path.read_text().splitlines()]
    for key, value in fields.items():
        if value is None:
            events[-1].pop(key, None)
        else:
            events[-1][key] = value
    path.write_text("".join(json.dumps(e) + "\n" for e in events))


def _without_styles(html: str) -> str:
    """The page minus its inlined stylesheet, which names every class whether or not anything was rendered with it."""
    import re

    return re.sub(r"<style.*?</style>", "", html, flags=re.S)


def test_render_runtime_page_reconciles_and_renders(tmp_path, monkeypatch):
    """CONFLICT-UPDATED (r6 S5; was: the headline is the run file's total): the page renders the fold, transcript and leads,
    and the headline is the ledger's priced sum, which the cost-bar segments add up to."""
    import re

    run = _build_run(tmp_path)
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(tmp_path / "state"))
    html = _page(run)

    for marker in (
        "card-analysis", "an-cols", "top-stats", "sec-metrics", "tu-row",
        "sec-transcript", "tx-group", "tx-group-head", "sec-leads", "tx-chip", "disp-badge",
    ):
        assert marker in html, f"missing {marker}"

    assert "elastic.ssh-auth" in html
    assert "dead-end lead" in html

    headline = _dollars(_headline(html))
    segs = _cost_segments(html)
    assert abs(headline - 0.5) > 0.5, "premise: the result line's 0.5 is far from the ledger"
    assert headline == pytest.approx(_priced(_LEDGER), abs=2e-4), f"the headline {headline} is not the ledger's priced sum"
    assert abs(headline - sum(segs.values())) < 0.003, f"{headline} != {sum(segs.values())}"
    assert _unattributed(segs), "the part of the headline no request-log bar explains is not shown"
    # Asked of the rendered SPAN, not of the class name: the stylesheet is inlined into every
    # page, so `"ts-review" in html` is true whether or not anything was rendered with it.
    assert re.search(r'ts-review">', html) is None, (
        "a review term is shown for a gate that made no model call"
    )


def test_the_review_gate_s_spend_is_inside_the_headline_and_named_there(tmp_path, monkeypatch):
    """UPDATED (r6 S5): the gate's ledger rows are in the headline once and its request-log calls are their own "review" segment; phases, review and unattributed (headline less both) add up to the headline."""
    run = _build_run(tmp_path)
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(tmp_path / "state"))
    review_total = _append_review_calls(run)
    assert review_total > 0.002, "fixture too cheap to discriminate against the tolerance"

    html = _page(run)

    headline = _dollars(_headline(html))
    assert headline == pytest.approx(_priced(_LEDGER) + review_total, abs=2e-4), (
        f"headline {headline}: the review was counted twice or dropped")

    bars = _cost_segments(html)
    review = [v for n, v in bars.items() if n.lower() == "review"]
    assert len(review) == 1, f"expected one review segment, bars were {bars}"
    assert review[0] == pytest.approx(review_total, abs=0.002), f"review segment {review[0]} is not the gate's spend {review_total}"
    unattributed = _unattributed(bars)
    assert len(unattributed) == 1, f"expected one unattributed segment, bars were {bars}"
    assert unattributed[0] == pytest.approx(headline - _phases(bars) - review[0], abs=0.003), (
        f"unattributed {unattributed[0]} is not the headline {headline} less phases {_phases(bars)} and review {review[0]}")
    assert sum(bars.values()) == pytest.approx(headline, abs=0.003), f"segments {bars} do not add up to the headline {headline}"

    assert "kimi-k3" in html, "the page does not name the model the review billed"


@pytest.mark.parametrize("spend_write_failed", [False, True], ids=["exact", "at least"])
@pytest.mark.parametrize("result_line_mark", [False, True, None], ids=["line-false", "line-true", "line-none"])
def test_s5_the_headline_says_at_least_exactly_when_the_host_knows_a_spend_write_failed(
        tmp_path, monkeypatch, spend_write_failed, result_line_mark):
    """UPDATED (r6 S5; was: the run file's mark): "at least" leads the ledger sum exactly when the host's own fact says a spend write failed, whatever the result line's mark says."""
    run = _build_run(tmp_path)
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(tmp_path / "state"))
    _result_line(run, total_cost_is_lower_limit=result_line_mark)

    headline = _headline(_page(run, spend_write_failed=spend_write_failed))

    assert headline.startswith("at least ") is spend_write_failed, f"the headline reads {headline!r}"
    assert _dollars(headline) == pytest.approx(_priced(_LEDGER), abs=2e-4)


@pytest.mark.parametrize("spend_write_failed", [False, True], ids=["no write failed", "a write failed"])
def test_a3_an_unreadable_ledger_reads_unknown_in_the_headline_not_zero_and_not_at_least(tmp_path, monkeypatch, spend_write_failed):
    """UPDATED (r6 S5; was: a null total on the result line): a session database without its ledger table reads "unknown", never `$0.0000` or "at least" (the mark stands only beside a number, S4), with no unattributed segment, and the page still renders."""
    import sqlite3

    from defender.records import session_store as ss

    run = _build_run(tmp_path)
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(tmp_path / "state"))
    control = _page(run)
    assert _dollars(_headline(control)) > 0, "positive control: a readable ledger gives a figure"
    conn = sqlite3.connect(ss.resolve_store_path(_run_handle_1165(run)), timeout=10)
    try:
        conn.execute(f"DROP TABLE {SPEND_LEDGER}")
        conn.commit()
    finally:
        conn.close()

    html = _page(run, spend_write_failed=spend_write_failed)

    assert _headline(html) == "unknown"
    assert not _unattributed(_cost_segments(html)), "an unattributed segment beside an unknown headline"
    assert _cost_segments(html), "the request-log bars are gone with the ledger"


def test_s5_a_run_with_no_ledger_rows_reads_zero_and_the_other_runs_rows_are_not_its_spend(tmp_path, monkeypatch):
    """A readable ledger with no row for this run id (another run's rows sit beside it) reads exactly `$0.0000`: not unknown, not "at least", no negative unattributed segment. (r6 S5)"""
    import sqlite3

    from defender.records import session_store as ss

    run = _build_run(tmp_path)
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(tmp_path / "state"))
    conn = sqlite3.connect(ss.resolve_store_path(_run_handle_1165(run)), timeout=10)
    try:
        conn.execute(f"DELETE FROM {SPEND_LEDGER} WHERE run_id = ?", (run.name,))
        assert conn.execute(f"SELECT count(*) FROM {SPEND_LEDGER}").fetchone()[0] == len(_OTHER_RUNS_LEDGER), "premise"  # noqa: S608
        conn.commit()
    finally:
        conn.close()

    html = _page(run)

    assert _headline(html) == "$0.0000"
    assert "unattributed" not in _without_styles(html), "an unattributed segment was shown with nothing unattributed"
    assert _cost_segments(html), "the request-log bars were dropped with the ledger rows"


def test_s5_a_ledger_sum_below_what_the_bars_explain_stays_the_headline_and_no_unattributed_segment_goes_negative(tmp_path, monkeypatch):
    """UPDATED (r6 S5): the unattributed segment is the headline minus the bars, floored at 0: a ledger sum under the request-log bars is still the headline."""
    import re
    import sqlite3

    from defender.records import session_store as ss

    run = _build_run(tmp_path)
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(tmp_path / "state"))
    conn = sqlite3.connect(ss.resolve_store_path(_run_handle_1165(run)), timeout=10)
    try:
        conn.execute(f"DELETE FROM {SPEND_LEDGER} WHERE run_id = ?", (run.name,))
        conn.commit()
    finally:
        conn.close()
    small = [("claude-haiku-4-5", _HAIKU_USAGE)]
    insert_spend(ss.resolve_store_path(_run_handle_1165(run)), run.name, small)

    html = _page(run)

    bars = _cost_segments(html)
    assert _phases(bars) > _priced(small) + 0.01, "premise: the request-log bars explain more than the ledger holds"
    assert _dollars(_headline(html)) == pytest.approx(_priced(small), abs=2e-4)
    assert "unattributed" not in _without_styles(html), "an unattributed segment was shown with nothing unattributed"
    assert all(float(x) >= 0 for x in re.findall(r'cb-pct">\$(-?[0-9.]+)', html))


_NUMBERS = {"nan": float("nan"), "inf": float("inf"), "-inf": float("-inf"), "negative": -3.5, "huge": 1e15,
            "string": "12.5", "bool": True, "list": [1, 2], "in-range": 0.37, "zero": 0}
#: (total on the line or the keyword for its absence, mark): every shape a box can leave the result line in.
_FORGERIES = {f"{name}-{mark_name}": (value, mark)
              for name, value in _NUMBERS.items() for mark_name, mark in (("mark-true", True), ("mark-string", "yes"))}
_FORGERIES |= {"no-total": ("no total", False), "no-mark": (0.37, "no mark"), "missing-line": ("no line", False),
               "doubled-line": ("two lines", True),
               "json-null-total-and-usage": ("json null", False)}  # what the host writes when the ledger was unreadable


@pytest.mark.parametrize(("total", "mark"), _FORGERIES.values(), ids=_FORGERIES.keys())
def test_s5_nothing_the_result_line_says_changes_the_headline_the_bars_or_whether_the_page_renders(
        tmp_path, monkeypatch, total, mark):
    """r6 S5 (accepted trade-off 2): whatever a box leaves in the run file's total, mark, usage or line count, the page renders the ledger's headline, exact, with segments that add up to it."""
    run = _build_run(tmp_path)
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(tmp_path / "state"))
    control = _page(run)
    path = run / "tool_trace.jsonl"
    lines = path.read_text().splitlines()
    if total == "no line":
        path.write_text("".join(line + "\n" for line in lines[:-1]))
    elif total == "json null":
        events = [json.loads(line) for line in lines]
        events[-1].update(total_cost_usd=None, usage=None, total_cost_is_lower_limit=mark)  # literal JSON nulls, not absent keys
        path.write_text("".join(json.dumps(e) + "\n" for e in events))
        assert '"total_cost_usd": null' in path.read_text().splitlines()[-1], "premise: the key is present, null"
    elif total == "two lines":
        forged = {**json.loads(lines[-1]), "total_cost_usd": 77.0, "total_cost_is_lower_limit": mark}
        path.write_text("".join(line + "\n" for line in [*lines, json.dumps(forged)]))
    else:
        _result_line(run, total_cost_usd=None if total == "no total" else total, usage=total,
                     total_cost_is_lower_limit=None if mark == "no mark" else mark)

    html = _page(run)

    assert _headline(html) == _headline(control), f"the result line moved the headline: {_headline(html)!r}"
    assert _dollars(_headline(html)) == pytest.approx(_priced(_LEDGER), abs=2e-4)
    assert _cost_segments(html) == _cost_segments(control)
    assert sum(_cost_segments(html).values()) == pytest.approx(_dollars(_headline(html)), abs=0.003)


def test_s5_without_gather_responses_in_the_request_log_the_total_over_main_is_not_called_gather(tmp_path):
    """No lead response in the log means no gather cost on any phase; the run file's total minus MAIN's is not gather spend. (S5)"""
    run = _build_run(tmp_path)
    events = read_jsonl_rows(run / "tool_trace.jsonl")
    order = _phase_order(run)
    tags = d.tag_events_by_phase(events, order)
    assert events[-1]["total_cost_usd"] == 0.5, "premise: a total far over what MAIN's responses cost"

    main_only = [m for m in d.load_messages(run) if not str(m.get("agent_id", "")).startswith("gather")]
    assert len(main_only) < len(d.load_messages(run)), "premise: the log did hold a lead response to leave out"

    by_phase, gather_total = d.gather_cost_by_phase(run, events, tags, order, messages=main_only)

    assert gather_total == 0, by_phase
    assert not any(by_phase.values()), by_phase


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
    """A repeated bucket that is NOT adjacent is still tiled once (#956)."""
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
    """UPDATED (r6 S5): a repeated phase header moves no per-phase number, and the bars plus unattributed add up to the ledger's headline."""
    import re

    plain = _build_run(tmp_path / "plain")
    doubled = _build_run(tmp_path / "doubled")
    _duplicate_the_gather_phase(doubled)
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(tmp_path / "state"))

    assert _phase_order(doubled).count("GATHER (loop 1)") == 2, (
        f"fixture no longer duplicates a name: {_phase_order(doubled)}"
    )
    assert "GATHER (loop 1)" in _phase_order(plain)

    doubled_html = _page(doubled)
    assert _bar_figures(doubled_html) == _bar_figures(_page(plain)), (
        "the repeated header moved a per-phase number"
    )

    headline = float(re.search(r'ts-cost">\$([0-9.]+)', doubled_html).group(1))
    bars = _cost_segments(doubled_html)
    assert abs(headline - _priced(_LEDGER)) < 0.002, f"the headline {headline} is not the ledger's priced sum (r6 S5)"
    assert any("unattributed" in n.lower() for n in bars), f"no unattributed segment in {bars}"
    assert abs(headline - sum(bars.values())) < 0.002, (
        f"the bars plus unattributed do not add up to the headline: {headline} != {sum(bars.values())}"
    )

    # The headline is the ledger's sum alone; the per-phase blocks explain only the request-log bars.
    request_log_bars = sum(v for n, v in bars.items() if "unattributed" not in n.lower())
    per_block = [float(x) for x in re.findall(r'ps-cost">\$([0-9.]+)', doubled_html)]
    assert abs(request_log_bars - sum(per_block)) < 0.002, (
        f"the repeated header re-printed its bucket's stats: request-log bars {request_log_bars} != "
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
