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
from defender.tests.support.jobs._jobs1342 import REFUSED, SPEND_LEDGER, UNSEEN, insert_spend, seal_at
from defender.tests.support.shared._fixture_uuid import fixture_uuid

_USAGE = {"input_tokens": 100, "output_tokens": 800, "cache_read_input_tokens": 5000, "cache_creation_input_tokens": 200}

_SESSION = "9f2c1ab84e7d4f0e9c3b5a6d7e8f0a1b"

_HAIKU_USAGE = {"input_tokens": 50, "output_tokens": 300, "cache_read_input_tokens": 1000, "cache_creation_input_tokens": 0}
_BIG = {"input_tokens": 400_000, "output_tokens": 50_000, "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0}

#: The run's spend ledger as the host wrote it (#1377 r6 S5), by requesting agent (r7): a row for every response the request
#: log shows (four MAIN turns, one lead's) and one MAIN response the request log never held. Rows of another run in the same
#: database are planted too.
_MAIN_LEDGER = [("claude-sonnet-4-6", _USAGE)] * 4 + [("claude-sonnet-4-6", _BIG)]
#: The lead's and the lenses' ledger rows differ from what the request log shows for them, so a bar or figure built from the log fails.
_LEDGER_ONLY_GATHER_USAGE = {"input_tokens": 90, "output_tokens": 700, "cache_read_input_tokens": 3000, "cache_creation_input_tokens": 100}
_GATHER_LEDGER = [("claude-haiku-4-5", _LEDGER_ONLY_GATHER_USAGE)]
_LEDGER = _MAIN_LEDGER + _GATHER_LEDGER
_OTHER_RUNS_LEDGER = [("claude-sonnet-4-6", _BIG)] * 3
_REVIEW_LENSES = ("support", "ablation", "composer")
_LEDGER_ONLY_REVIEW_USAGE = {"input_tokens": 300, "output_tokens": 1500, "cache_read_input_tokens": 9000, "cache_creation_input_tokens": 0}
_REVIEW_LEDGER = [("kimi-k3", _LEDGER_ONLY_REVIEW_USAGE)] * len(_REVIEW_LENSES)


def _priced(rows: list) -> float:
    return sum(usage_cost(model, usage) for model, usage in rows)


assert _priced(_GATHER_LEDGER) != pytest.approx(_priced([("claude-haiku-4-5", _HAIKU_USAGE)]), abs=1e-6), "premise: the lead's ledger differs from its request log"
assert _priced(_REVIEW_LEDGER) != pytest.approx(_priced([("kimi-k3", _USAGE)] * 3), abs=1e-6), "premise: the lenses' ledger differs from their request log"

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
    insert_spend(store_path, run.name, _MAIN_LEDGER, agent_id="main")
    insert_spend(store_path, run.name, _GATHER_LEDGER, agent_id="gather:l-001")
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


def _run_ledger(run: Path):
    """The run's ledger through the one read: the only thing the page prices through (#1377 r7.2 P1)."""
    from defender.records import session_store as ss

    with ss.open_store_for_read(ss.resolve_store_path(_run_handle_1165(run))) as store:
        return ss.read_ledger(store, run.name)


def _at_sonnet(usage: dict) -> float:
    """The test's own oracle for MAIN's `price`: the fixture's MAIN requested Sonnet (the ledger says so)."""
    return usage_cost("claude-sonnet-4-6", usage)


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

    attr = d.phase_attribution(events, order, price=_at_sonnet)
    nonzero = [ph for ph in order if attr[ph]["cost"] > 0]
    assert len(nonzero) >= 3, f"cost not spread across phases: {nonzero}"


def test_phase_attribution_without_a_ledger_carries_no_dollars(tmp_path):
    """r7.2 P1: `price=None` (no readable ledger) leaves every phase's cost None, never priced at the trace's model;
    the counts the cost never touched still hold."""
    run = _build_run(tmp_path)
    events = read_jsonl_rows(run / "tool_trace.jsonl")
    order = _phase_order(run)

    attr = d.phase_attribution(events, order, price=None)
    priced = d.phase_attribution(events, order, price=_at_sonnet)

    assert {ph: a["cost"] for ph, a in attr.items()} == dict.fromkeys(order)
    assert {ph: (a["turns"], a["in"], a["out"]) for ph, a in attr.items()} == {
        ph: (a["turns"], a["in"], a["out"]) for ph, a in priced.items()}


def test_gather_dispatch_phase_and_cost(tmp_path):
    run = _build_run(tmp_path)
    events = read_jsonl_rows(run / "tool_trace.jsonl")
    order = _phase_order(run)
    tags = d.tag_events_by_phase(events, order)

    gphase = d.gather_dispatch_phase(events, tags)
    assert gphase["l-001"].startswith("PLAN")

    by_phase, gather_total = d.gather_cost_by_phase(
        run, events, tags, order, messages=d.load_messages(run), ledger=_run_ledger(run))
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

    by_model = d.gather_cost_by_model(run, d.load_messages(run), _run_ledger(run))
    assert list(by_model) == ["claude-haiku-4-5"]
    assert by_model["claude-haiku-4-5"] > 0


def _planted_ledger(tmp_path: Path, requested: dict[str, str]):
    """A ledger read with one row per agent at the model it requested, for tests that hand the helpers their own messages."""
    from defender.records import session_store as ss

    run_id = fixture_uuid("planted ledger")
    with ss.open_store(case_id=f"planted-{uuid.uuid4().hex}", sessions=SessionPaths(fixture_runs_base(tmp_path / "runs"))) as store:
        for agent_id, model in requested.items():
            insert_spend(store.path, run_id, [(model, _USAGE)], agent_id=agent_id)
        return ss.read_ledger(store, run_id)


def test_without_a_ledger_gather_cost_has_no_dollars(tmp_path):
    """r7.2 P1: no readable ledger means no gather dollars by phase or by model, not the log's reported name priced."""
    run = _build_run(tmp_path)
    events = read_jsonl_rows(run / "tool_trace.jsonl")
    order = _phase_order(run)
    tags = d.tag_events_by_phase(events, order)
    messages = d.load_messages(run)

    by_phase, gather_total = d.gather_cost_by_phase(run, events, tags, order, messages=messages, ledger=None)

    assert not any(by_phase.values()), by_phase
    assert not gather_total, gather_total
    assert d.gather_cost_by_model(run, messages, None) == {}


def test_gather_cost_not_dropped_without_gather_phase(tmp_path):
    order = ["ORIENT loop 1", "PLAN loop 1", "REPORT loop 1"]
    messages = [
        {"kind": "response", "agent_id": "gather:l-001", "model": "claude-haiku-4-5", "usage": _USAGE},
    ]
    ledger = _planted_ledger(tmp_path, {"gather:l-001": "claude-haiku-4-5"})
    by_phase, gather_total = d.gather_cost_by_phase(tmp_path, [], [], order, messages=messages, ledger=ledger)
    full = sum(d.gather_cost_by_model(tmp_path, messages, ledger).values())
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


_SEALED: set[Path] = set()


@pytest.fixture(autouse=True)
def _no_seals_carried_between_tests():
    """A run folder's path can repeat across tests (truncated tmp names): each test starts with no run sealed."""
    _SEALED.clear()


def _page(run: Path, *, sealed: bool = True) -> str:
    """The run's page through the post-run step's own entry: it holds the `Run` (the host's handle on the run's store), and
    nothing else is handed in. r7.3 T1: the ledger is sealed first (once per run, as a run that ended without a failed write
    leaves it); `sealed=False` is a run whose seal never landed (a failed write, a kill)."""
    if sealed and run not in _SEALED:
        _SEALED.add(run)
        pointer = _run_handle_1165(run).observability.session_pointer.read_result().text
        seal_at(fixture_runs_base(run.parent), json.loads(pointer)["case_id"], run.name)
    return render_page(_run_handle_1165(run))


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


def _append_review_calls(run: Path) -> float:
    """Give the fixture run a review gate that actually cost something: its calls as request-log records under
    `review:{lens}` and as ledger rows. Returns the gate's priced spend."""
    rows = [{
        "agent_id": f"review:{lens}", "seq": 0, "id": f"review:{lens}#0",
        "kind": "response", "model": "kimi-k3", "usage": _USAGE, "duration_ms": 900.0,
        "message": {"kind": "response", "parts": [{"part_kind": "text", "content": "read"}]},
    } for lens in _REVIEW_LENSES]
    with RunPaths(run).wire_log.open("a", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")
    from defender.records import session_store as ss

    for lens, row in zip(_REVIEW_LENSES, _REVIEW_LEDGER, strict=True):
        insert_spend(ss.resolve_store_path(_run_handle_1165(run)), run.name, [row], agent_id=f"review:{lens}")
    return _priced(_REVIEW_LEDGER)


def _cost_segments(html: str) -> dict[str, float]:
    """Every cost-bar segment (cb-seg title "<name> · $v · p%") by name, whether or not it is wide enough to print its value."""
    import re

    return {name: float(v) for name, v in re.findall(r'class="cb-seg"[^>]*title="([^"]*?) · \$([0-9.]+) · ', html)}


def _by_kind(html: str) -> dict[str, float]:
    """The cost bar's segments by lower-cased name (r7 S6: one per requesting agent kind)."""
    return {name.lower(): v for name, v in _cost_segments(html).items()}


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
    """CONFLICT-UPDATED (r7 S6; was r6: request-log bars plus "unattributed"): the page renders the fold, transcript and leads;
    the headline is the ledger's priced sum, and the cost bar is the ledger by agent kind, which adds up to it."""
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
    kinds = _by_kind(html)
    assert kinds["main"] == pytest.approx(_priced(_MAIN_LEDGER), abs=2e-4), f"main is not MAIN's ledger rows: {kinds}"
    assert kinds["gather"] == pytest.approx(_priced(_GATHER_LEDGER), abs=2e-4), f"gather is not the lead's ledger rows: {kinds}"
    assert not _unattributed(segs), f"an unattributed segment in a bar built from the ledger: {segs}"
    assert set(kinds) == {"main", "gather"}, f"a run with no correlation lead and no review has only the kinds that spent: {kinds}"
    # Asked of the rendered SPAN, not of the class name: the stylesheet is inlined into every
    # page, so `"ts-review" in html` is true whether or not anything was rendered with it.
    assert re.search(r'ts-review">', html) is None, (
        "a review term is shown for a gate that made no model call"
    )


def test_the_review_gate_s_spend_is_inside_the_headline_and_named_there(tmp_path, monkeypatch):
    """CONFLICT-UPDATED (r7 S6; was r6: review from the request log, phases and unattributed): the gate's ledger rows are in
    the headline once and are the "review" segment; the segments by kind add up to the headline, nothing unattributed."""
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
    assert not _unattributed(bars), f"an unattributed segment beside the ledger's kinds: {bars}"
    assert _by_kind(html)["main"] == pytest.approx(_priced(_MAIN_LEDGER), abs=2e-4)
    assert sum(bars.values()) == pytest.approx(headline, abs=0.003), f"segments {bars} do not add up to the headline {headline}"

    assert "kimi-k3" in html, "the page does not name the model the review billed"


_CORRELATION_LEDGER = [("claude-haiku-4-5", _BIG)]


def _append_correlation_rows(run: Path) -> float:
    """The correlation lead's ledger row (its reserved lead id, `l-00c`); the request log never held it. Returns its spend."""
    from defender.records import session_store as ss

    insert_spend(ss.resolve_store_path(_run_handle_1165(run)), run.name, _CORRELATION_LEDGER, agent_id="gather:l-00c")
    return _priced(_CORRELATION_LEDGER)


def test_s6_r7_the_cost_bar_has_one_segment_per_agent_kind_from_the_ledger_adding_up_to_the_headline(tmp_path, monkeypatch):
    """MAIN, a lead, the correlation lead and three review lenses in the ledger: the bar is exactly main, gather, correlation
    and review, each its agents' ledger sum, adding up to the headline; nothing unattributed, no phase segment. (r7 S6)"""
    run = _build_run(tmp_path)
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(tmp_path / "state"))
    review_total = _append_review_calls(run)
    correlation_total = _append_correlation_rows(run)

    html = _page(run)

    headline = _dollars(_headline(html))
    assert headline == pytest.approx(_priced(_LEDGER) + review_total + correlation_total, abs=2e-4)
    kinds = _by_kind(html)
    assert set(kinds) == {"main", "gather", "correlation", "review"}, f"the bar is not by agent kind: {kinds}"
    expected = {"main": _priced(_MAIN_LEDGER), "gather": _priced(_GATHER_LEDGER), "correlation": correlation_total,
                "review": review_total}
    for kind, spent in expected.items():
        assert kinds[kind] == pytest.approx(spent, abs=2e-4), f"{kind}: {kinds[kind]} is not its agents' ledger sum {spent}"
    assert sum(kinds.values()) == pytest.approx(headline, abs=2e-4)


def test_s6_r7_a_phase_named_review_does_not_touch_the_review_segment(tmp_path, monkeypatch):
    """The investigation doc carries a `## review` phase: the bar's one "review" segment is still the gate's ledger rows, and
    the bar still adds up to the headline. (r7 S6; #1441 review finding 4)"""
    run = _build_run(tmp_path)
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(tmp_path / "state"))
    doc = run / "investigation.md"
    doc.write_text(doc.read_text(encoding="utf-8") + "\n## review\n\nNotes the model titled review.\n", encoding="utf-8")
    assert any(n.lower().startswith("review") for n in _phase_order(run)), f"premise: a phase named review {_phase_order(run)}"
    review_total = _append_review_calls(run)

    html = _page(run)

    review = [v for n, v in _cost_segments(html).items() if n.lower() == "review"]
    assert review == [pytest.approx(review_total, abs=2e-4)], f"the review segment is not the gate's ledger rows: {_cost_segments(html)}"
    assert sum(_cost_segments(html).values()) == pytest.approx(_dollars(_headline(html)), abs=2e-4)


def test_s6_r7_a_run_whose_doc_has_no_phases_still_shows_main(tmp_path, monkeypatch):
    """An investigation doc with no `## ` header: the page renders, and the bar's main segment is MAIN's ledger rows. (r7 S6)"""
    run = _build_run(tmp_path)
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(tmp_path / "state"))
    (run / "investigation.md").write_text("Oriented on the alert; no phases were written.\n", encoding="utf-8")
    assert _phase_order(run) == [], f"premise: no phases {_phase_order(run)}"

    html = _page(run)

    assert _by_kind(html).get("main") == pytest.approx(_priced(_MAIN_LEDGER), abs=2e-4), _cost_segments(html)
    assert sum(_cost_segments(html).values()) == pytest.approx(_dollars(_headline(html)), abs=2e-4)


@pytest.mark.parametrize("sealed", [True, False], ids=["sealed", "unsealed"])
@pytest.mark.parametrize("result_line_mark", [False, True, None], ids=["line-false", "line-true", "line-none"])
def test_s5_the_headline_says_at_least_exactly_when_the_ledger_is_not_sealed(tmp_path, monkeypatch, sealed, result_line_mark):
    """UPDATED (r7.3 T1; was: the host's argument): "at least" leads the ledger sum exactly when the run's ledger was never sealed
    (a failed write, a kill), whatever the result line's mark says, and the page is handed nothing else. (r7.3 T1; r6 S5)"""
    run = _build_run(tmp_path)
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(tmp_path / "state"))
    _result_line(run, total_cost_is_lower_limit=result_line_mark)

    headline = _headline(_page(run, sealed=sealed))

    assert headline.startswith("at least ") is (not sealed), f"the headline reads {headline!r}"
    assert _dollars(headline) == pytest.approx(_priced(_LEDGER), abs=2e-4)


@pytest.mark.parametrize(("kind", "at_least"), [("refused", False), ("unseen", True), ("unpriced", True)])
def test_s5_r7_the_ledger_alone_makes_the_headline_at_least_when_a_row_is_unseen_or_unpriced_not_when_refused(
        tmp_path, monkeypatch, kind, at_least):
    """One extra row beside the priced ones, no failed spend write: unseen or unpriced reads "at least" the same sum; a refused
    ($0, complete) row leaves it exact; the `line-false-exact` arm above is the control. (r7 S2a, S2b, S5)"""
    from defender.records import session_store as ss

    run = _build_run(tmp_path)
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(tmp_path / "state"))
    path = ss.resolve_store_path(_run_handle_1165(run))
    if kind == "unpriced":
        insert_spend(path, run.name, [("claude-opus-9-0", _USAGE)], agent_id="gather:l-002")
    else:
        insert_spend(path, run.name, [("claude-haiku-4-5", {})], agent_id="gather:l-002",
                     outcome=UNSEEN if kind == "unseen" else REFUSED)

    headline = _headline(_page(run))

    assert headline.startswith("at least ") is at_least, f"the headline reads {headline!r}"
    assert _dollars(headline) == pytest.approx(_priced(_LEDGER), abs=2e-4)


def test_r1_r7_4_a_database_with_no_ledger_table_reads_unknown_with_no_dollars_even_when_the_run_file_has_a_total(tmp_path, monkeypatch):
    """CONFLICT-UPDATED (was r7.3 Q1): a database whose ledger table is gone is an unreadable ledger (r7.4 R1, r7.2 P1): the
    headline is exactly "unknown", no bar, no informational dollars, and the run file's total (1.2345) appears nowhere."""
    import sqlite3

    from defender.records import session_store as ss

    run = _build_run(tmp_path)
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(tmp_path / "state"))
    _append_review_calls(run)
    _a_gate_that_ran(run)
    control = _page(run)
    assert _dollars(_headline(control)) > _priced(_LEDGER) - 2e-4, "positive control: the ledger's figure, the review's spend beside it"
    _result_line(run, total_cost_usd=1.2345, total_cost_is_lower_limit=False)
    conn = sqlite3.connect(ss.resolve_store_path(_run_handle_1165(run)), timeout=10)
    try:
        conn.execute(f"DROP TABLE {SPEND_LEDGER}")
        conn.commit()
    finally:
        conn.close()

    html = _page(run)

    assert _headline(html) == "unknown"
    assert _cost_segments(html) == {}, "a bar beside a total no ledger backs"
    priced = {name: texts for name, texts in _informational_text(html).items() if any("$" in t for t in texts)}
    assert not priced, f"an informational figure carries dollars beside a run with no ledger: {priced}"
    assert "1.2345" not in html, "the run file's total reached the page"


@pytest.mark.parametrize("agent_id", ["gather", "planner"])
def test_a3_r7_a_ledger_holding_a_row_of_an_unknown_agent_id_reads_unknown_with_no_bar(tmp_path, monkeypatch, agent_id):
    """One row beside the run's others whose agent id is not main, `gather:*` or `review:*`: the headline reads "unknown" and the page has no bar, as for any unreadable ledger. (r7.1 F, S4)"""
    from defender.records import session_store as ss

    run = _build_run(tmp_path)
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(tmp_path / "state"))
    assert _dollars(_headline(_page(run))) > 0, "positive control: the known ids read"
    insert_spend(ss.resolve_store_path(_run_handle_1165(run)), run.name, [("claude-sonnet-4-6", _USAGE)], agent_id=agent_id)

    html = _page(run)

    assert _headline(html) == "unknown"
    assert _cost_segments(html) == {}


def test_s5_a_run_with_no_ledger_rows_reads_zero_and_the_other_runs_rows_are_not_its_spend(tmp_path, monkeypatch):
    """A readable ledger with no row for this run id (another run's rows sit beside it) reads exactly `$0.0000`: not unknown, not "at least", and no cost-bar segment. CONFLICT-UPDATED (r7.1 S6; was r6: request-log bars stayed). (r6 S5)"""
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
    assert _cost_segments(html) == {}, "a segment was shown for a run that spent nothing (r7.1 S6: no kind spent, no segment)"


def test_s6_r7_the_cost_bar_is_the_ledger_not_the_request_log(tmp_path, monkeypatch):
    """CONFLICT-UPDATED (r7 S6; was r6: "a ledger sum below the request-log bars, unattributed floored at 0"): with a ledger
    holding far less than the request log shows, the bar is that ledger's one MAIN row, equal to the headline, nothing unattributed."""
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

    logged = sum(usage_cost(m["model"], m["usage"]) for m in d.load_messages(run) if m.get("kind") == "response")
    assert logged > _priced(small) + 0.01, "premise: the request log shows more than the ledger holds"

    html = _page(run)

    assert _dollars(_headline(html)) == pytest.approx(_priced(small), abs=2e-4)
    assert _by_kind(html)["main"] == pytest.approx(_priced(small), abs=2e-4), _cost_segments(html)
    assert sum(_cost_segments(html).values()) == pytest.approx(_priced(small), abs=2e-4), "the bar was built from the request log"
    assert "unattributed" not in _without_styles(html), "an unattributed segment was shown with nothing unattributed"


def test_s6_r7_a_kind_whose_rows_are_all_refused_unseen_or_unpriced_has_no_segment(tmp_path, monkeypatch):
    """The correlation lead's only row refused, a review lens's only row unseen, a second lead's only row unpriced: the bar
    is still main and gather, and the headline's "at least" carries the unseen and unpriced rows. (r7.1 S6)"""
    from defender.records import session_store as ss

    run = _build_run(tmp_path)
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(tmp_path / "state"))
    path = ss.resolve_store_path(_run_handle_1165(run))
    insert_spend(path, run.name, [("claude-haiku-4-5", {})], agent_id="gather:l-00c", outcome=REFUSED)
    insert_spend(path, run.name, [("kimi-k3", {})], agent_id="review:support", outcome=UNSEEN)

    html = _page(run)

    assert set(_by_kind(html)) == {"main", "gather"}, _cost_segments(html)
    assert _headline(html).startswith("at least ")

    insert_spend(path, run.name, [("claude-opus-9-0", _USAGE)], agent_id="gather:l-002")
    kinds = _by_kind(_page(run))
    assert kinds["gather"] == pytest.approx(_priced(_GATHER_LEDGER), abs=2e-4), "an unpriced row added to its kind"


@pytest.mark.parametrize(("agent_id", "kind"), [("review:support", "review"), ("gather:l-00c", "correlation")])
def test_s6_r7_a_kind_with_only_an_unpriced_row_on_its_own_page_has_no_segment(tmp_path, monkeypatch, agent_id, kind):
    """The review gate's (or the correlation lead's) only row requests a model with no pricing row: no segment for the kind, "at least" on the headline; the same row at a priced model is the control. (r7.1 S6, S2b)"""
    from defender.records import session_store as ss

    run = _build_run(tmp_path)
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(tmp_path / "state"))
    path = ss.resolve_store_path(_run_handle_1165(run))
    insert_spend(path, run.name, [("claude-haiku-4-5", _USAGE)], agent_id=agent_id)
    assert kind in _by_kind(_page(run)), "control: the same row priced has its segment"
    other = tmp_path / "unpriced"
    other.mkdir()
    run2 = _build_run(other)
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(other / "state"))
    insert_spend(ss.resolve_store_path(_run_handle_1165(run2)), run2.name, [("claude-opus-9-0", _USAGE)], agent_id=agent_id)

    html = _page(run2)

    assert set(_by_kind(html)) == {"main", "gather"}, _cost_segments(html)
    assert _headline(html).startswith("at least ")
    assert _dollars(_headline(html)) == pytest.approx(_priced(_LEDGER), abs=2e-4)


def test_s6_r7_h_the_bar_s_figures_carry_the_headline_s_four_decimals(tmp_path, monkeypatch):
    """Every cost-bar segment's title and every printed label is written `$d.dddd`, as the headline is. (r7.1 H)"""
    import re

    from defender.tests.support.presentation import _cost_page_1377 as C

    run = _build_run(tmp_path)
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(tmp_path / "state"))
    _append_review_calls(run)

    html = _page(run)

    titles = C.segment_titles(html)
    labels = re.findall(r'cb-pct">(\$[0-9.]+)', html)
    assert len(titles) >= 3, "premise: segments"
    assert labels, "premise: a printed label"
    assert all(re.fullmatch(r"\$\d+\.\d{4}", figure) for figure in titles + labels), (titles, labels)
    assert re.fullmatch(r"\$\d+\.\d{4}", _headline(html))


_REPORTED_ELSEWHERE = {"claude-sonnet-4-6": "claude-sonnet-4-6-rerouted", "claude-haiku-4-5": "claude-haiku-4-5-0905",
                       "kimi-k3": "kimi-k3-0905"}


def _informational(html: str) -> dict[str, object]:
    """The page's figures that are not the headline or the bar: phase lines, the by-model strip, the review gate's lens figures."""
    import re

    models = re.search(r'me-models">(.*?)</div>', html, flags=re.S)
    return {"phase lines": re.findall(r'ps-cost">(\$[0-9.]+)', html),
            "by model": sorted(re.findall(r"\$([0-9.]+)", models.group(1))) if models else [],
            "review lenses": re.findall(r'rv-cost-lenses">(.*?)</span>', html),
            "review total": re.findall(r'rv-cost">(.*?)</span>', html)}


def test_c_r7_1_the_phase_lines_the_by_model_strip_and_the_review_lenses_are_priced_at_the_requested_model(tmp_path, monkeypatch):
    """The request log reports spellings with no pricing row for MAIN, the lead and the review: every informational figure
    reads as the control's, priced at what each agent requested. (r7.1 C, S1)"""
    import re

    run = _build_run(tmp_path)
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(tmp_path / "state"))
    _append_review_calls(run)
    (run / RunPaths(run).review_record(1).name).write_text(json.dumps({  # a gate that ran, so the page prints its lens figures
        "verdict": "stands", "reviewed_disposition": "malicious", "reviewed": True, "detail": "", "failure_kind": None}), encoding="utf-8")
    control = _informational(_page(run))
    assert all(control.values()), f"premise: the control shows every informational figure: {control}"
    assert all(usage_cost(name, _USAGE) == 0.0 for name in _REPORTED_ELSEWHERE.values()), "premise: the spellings have no price"
    for path in (RunPaths(run).wire_log, run / "tool_trace.jsonl"):
        text = path.read_text(encoding="utf-8")
        for requested, reported in _REPORTED_ELSEWHERE.items():
            text = text.replace(requested, reported)
        path.write_text(text, encoding="utf-8")

    after = _page(run)
    assert _informational(after) == control, "an informational figure was priced at the name the request log reports"
    strip = re.search(r'me-models">(.*?)</div>', after, flags=re.S).group(1)
    assert all(name in strip for name in _REPORTED_ELSEWHERE), f"the by-model strip does not name the requested models: {strip}"
    assert not any(name in strip for name in _REPORTED_ELSEWHERE.values()), f"the by-model strip names a reported spelling: {strip}"


def _informational_text(html: str) -> dict[str, list[str]]:
    """The text of every informational element, whatever it holds: phase lines, the by-model strip, the review gate's figures."""
    import re

    return {"phase lines": re.findall(r'ps-cost">(.*?)</span>', html, flags=re.S),
            "incl gather": re.findall(r'ps-gather">(.*?)</span>', html, flags=re.S),
            "by model": re.findall(r'me-models">(.*?)</div>', html, flags=re.S),
            "review lenses": re.findall(r'rv-cost-lenses">(.*?)</span>', html, flags=re.S),
            "review total": re.findall(r'rv-cost">(.*?)</span>', html, flags=re.S)}


def _a_gate_that_ran(run: Path) -> None:
    (run / RunPaths(run).review_record(1).name).write_text(json.dumps({  # so the page prints the gate's lens figures
        "verdict": "stands", "reviewed_disposition": "malicious", "reviewed": True, "detail": "", "failure_kind": None}), encoding="utf-8")


def test_p1_r7_2_the_page_renders_only_from_a_cost_it_is_handed():
    """`render_runtime_page` takes `cost` with no default: no rendering path exists that prices the run without the one
    ledger read. (r7.2 P1: "its rendering path that takes no cost is removed")"""
    import inspect

    from defender.presentation import visualize_run

    parameter = inspect.signature(visualize_run.render_runtime_page).parameters.get("cost")
    assert parameter is not None, "render_runtime_page takes no `cost`"
    assert parameter.default is inspect.Parameter.empty, f"`cost` has a default: {parameter.default!r}"


def test_p1_r7_2_an_unreadable_ledger_leaves_the_phase_lines_the_by_model_strip_and_the_review_figures_without_dollars(tmp_path, monkeypatch):
    """A ledger that exists but cannot be read (a row of an agent id outside the four kinds): besides the headline ("unknown")
    and the bar (none), no informational figure carries a dollar amount: the page prices nothing outside the one ledger read. A
    readable ledger is the control, showing dollars in every one of them. (r7.2 P1; r7.3 Q1: a dropped table is another case)"""
    from defender.records import session_store as ss

    run = _build_run(tmp_path)
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(tmp_path / "state"))
    _append_review_calls(run)
    _a_gate_that_ran(run)
    control = _informational_text(_page(run))
    for name, texts in control.items():
        assert texts, f"premise: the control shows {name}"
        assert all("$" in t for t in texts), f"premise: the control's {name} carry dollars: {texts}"
    insert_spend(ss.resolve_store_path(_run_handle_1165(run)), run.name, [("claude-sonnet-4-6", _USAGE)], agent_id="planner")

    html = _page(run)

    assert _headline(html) == "unknown"
    assert _cost_segments(html) == {}
    priced = {name: texts for name, texts in _informational_text(html).items() if any("$" in t for t in texts)}
    assert not priced, f"an informational figure carries dollars beside an unknown ledger: {priced}"


#: One reported name per class of spelling a provider can answer with, beside the exact one: none at all, one with no pricing
#: row, the requested row's name with a suffix (rerouted), and another priced model's name.
_REQUESTED = {"main": "claude-sonnet-4-6", "gather:l-001": "claude-haiku-4-5", "gather:l-00c": "claude-haiku-4-5",
              "review:support": "kimi-k3", "review:ablation": "kimi-k3", "review:composer": "kimi-k3"}
_LOG_ONLY = "gather:l-002"  # answers in the request log, has no ledger row
_RESPONSES_PER_AGENT = 4


def _reported_spellings(requested: str) -> list[str]:
    other = "claude-haiku-4-5" if requested != "claude-haiku-4-5" else "claude-sonnet-4-6"
    return ["", "no-such-model-9", f"{requested}-rerouted", other]


def _rate_cost(model: str, counts: dict[str, int]) -> float:
    """The test's own oracle: the pricing table's rate row for `model` times the four counts (rates per million tokens)."""
    from defender.configuration._pricing import PRICING

    rate = PRICING[model]
    return (counts["input_tokens"] * rate["in"] + counts["output_tokens"] * rate["out"]
            + counts["cache_creation_input_tokens"] * rate["cache_w"]
            + counts["cache_read_input_tokens"] * rate["cache_r"]) / 1_000_000


def _generated_request_log(run: Path, seed: int) -> dict[str, list[dict[str, int]]]:
    """Rewrite the run's request log (the wire log and the run file's assistant events) so each agent answers
    `_RESPONSES_PER_AGENT` times with generated nonzero counts of all four kinds, each response under a different class of
    reported spelling (rotated by `seed`), and plant the ledger rows that tell the page which model each agent requested.
    Returns the counts by agent."""
    import random

    from defender.records import session_store as ss

    rng = random.Random(seed)

    def counts() -> dict[str, int]:
        return {"input_tokens": rng.randint(1, 600_000), "output_tokens": rng.randint(1, 60_000),
                "cache_read_input_tokens": rng.randint(1, 900_000), "cache_creation_input_tokens": rng.randint(1, 90_000)}

    by_agent = {agent: [counts() for _ in range(_RESPONSES_PER_AGENT)] for agent in (*_REQUESTED, _LOG_ONLY)}

    def spelling(agent: str, i: int) -> str:
        names = _reported_spellings(_REQUESTED.get(agent, "claude-haiku-4-5"))
        return names[(i + seed) % len(names)]

    wire = RunPaths(run).wire_log
    kept, seen = [], {}
    for row in read_jsonl_rows(wire):
        if row.get("kind") == "response":
            agent = row.get("agent_id", "main")
            i = seen[agent] = seen.get(agent, -1) + 1
            row["model"], row["usage"] = spelling(agent, i), by_agent[agent][i]
            kept.append(row)
        else:
            kept.append(row)
    seen_main = seen["main"] + 1
    assert seen_main == 4, f"premise: the fixture's four MAIN responses ({seen_main})"
    extra = [(agent, i) for agent, rows in by_agent.items() for i in range(len(rows))
             if not (agent == "main" or (agent == "gather:l-001" and i == 0))]
    for agent, i in extra:
        kept.append({"agent_id": agent, "seq": i, "id": f"{agent}#{i}", "kind": "response", "model": spelling(agent, i),
                     "usage": by_agent[agent][i], "duration_ms": 900.0,
                     "message": {"kind": "response", "parts": [{"part_kind": "text", "content": "read"}]}})
    wire.write_text("".join(json.dumps(r) + "\n" for r in kept), encoding="utf-8")

    trace = run / "tool_trace.jsonl"
    events = [json.loads(line) for line in trace.read_text(encoding="utf-8").splitlines()]
    assistants = [e for e in events if e.get("type") == "assistant"]
    assert len(assistants) == 4, "premise: the fixture's four MAIN events"
    for i, event in enumerate(assistants):
        event["message"]["model"], event["message"]["usage"] = spelling("main", i), by_agent["main"][i]
    trace.write_text("".join(json.dumps(e) + "\n" for e in events), encoding="utf-8")

    path = ss.resolve_store_path(_run_handle_1165(run))
    for agent in ("gather:l-00c", *(f"review:{lens}" for lens in _REVIEW_LENSES)):
        insert_spend(path, run.name, [(_REQUESTED[agent], by_agent[agent][0])], agent_id=agent)
    return by_agent


@pytest.mark.parametrize("seed", [0, 1, 2, 3], ids=lambda n: f"seed-{n}")
def test_f6_r7_2_every_informational_figure_is_the_pricing_tables_rates_times_the_counts_at_the_requested_model(tmp_path, monkeypatch, seed):
    """A generated request log: four responses per agent (MAIN, two leads, the correlation lead, three review lenses), all four
    counts nonzero, reported under every class of spelling (none, no pricing row, the requested name rerouted, another priced
    model); one lead answers in the log with no ledger row. The oracle prices each response from the pricing table's rates times
    its counts at the model its agent requested ($0 for the agent with no row), never through the product's pricing helpers; the
    phase lines' sum, each model's dollars in the by-model strip (keyed by requested name) and each review lens must equal it.
    (r7.1 C, r7.2 P1, S1)"""
    import re

    run = _build_run(tmp_path)
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(tmp_path / "state"))
    _a_gate_that_ran(run)
    by_agent = _generated_request_log(run, seed)
    assert all(all(v > 0 for v in c.values()) for rows in by_agent.values() for c in rows), "premise: nonzero counts"

    def oracle(agent: str) -> float:
        return sum(_rate_cost(_REQUESTED[agent], c) for c in by_agent[agent]) if agent in _REQUESTED else 0.0

    phase_sum = sum(oracle(a) for a in _REQUESTED if not a.startswith("review:"))
    by_model: dict[str, float] = {}
    for agent in _REQUESTED:
        by_model[_REQUESTED[agent]] = by_model.get(_REQUESTED[agent], 0.0) + oracle(agent)
    lenses = {lens: oracle(f"review:{lens}") for lens in _REVIEW_LENSES}
    assert phase_sum > 0.05, "premise: figures large enough to discriminate"
    assert all(v > 0.01 for v in lenses.values()), "premise: lens figures large enough to discriminate"

    html = _page(run)

    phase_lines = [float(v) for v in re.findall(r'ps-cost">\$([0-9.]+)', html)]
    assert phase_lines, "premise: the page prints phase lines"
    assert sum(phase_lines) == pytest.approx(phase_sum, abs=1e-3), f"phase lines {phase_lines}: want the oracle's {phase_sum}"
    strip = re.search(r'me-models">(.*?)</div>', html, flags=re.S).group(1)
    shown = {name.removeprefix("claude-"): float(v) for name, v in re.findall(r"([^\s·]+) \$([0-9.]+)", strip)}
    assert shown == pytest.approx({k.removeprefix("claude-"): v for k, v in by_model.items()}, abs=2e-4), (
        f"the by-model strip {strip!r}: want {by_model} keyed by the requested names")
    per_lens = re.search(r'rv-cost-lenses">(.*?)</span>', html, flags=re.S).group(1)
    assert dict((lens, float(v)) for lens, v in re.findall(r"(\w+) \$([0-9.]+)", per_lens)) == pytest.approx(lenses, abs=2e-4), (
        f"the review lenses {per_lens!r}: want {lenses}")


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

    by_phase, gather_total = d.gather_cost_by_phase(run, events, tags, order, messages=main_only, ledger=_run_ledger(run))

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
    """CONFLICT-UPDATED (r7 S6; was r6: the bars plus unattributed, and per-phase blocks equal to the request-log bars): a
    repeated phase header moves no per-phase number and no bar segment; the bar adds up to the ledger's headline."""
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
    assert not _unattributed(bars), f"an unattributed segment in {bars}"
    assert abs(headline - sum(bars.values())) < 0.002, (
        f"the bar does not add up to the headline: {headline} != {sum(bars.values())}"
    )

    # Per-phase cost is informational (r7 S6): the repeated header re-prints no bucket's figure.
    def per_block(html: str) -> float:
        return sum(float(x) for x in re.findall(r'ps-cost">\$([0-9.]+)', html))

    assert per_block(doubled_html) == pytest.approx(per_block(_page(plain)), abs=2e-4), (
        "the repeated header re-printed its bucket's stats")


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
