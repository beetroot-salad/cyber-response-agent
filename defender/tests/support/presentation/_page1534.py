"""The run page's test fixture (#1534: moved out of `tests/presentation/test_visualize_runtime.py`): a run folder with a real
session store, its spend ledger and its closing record, and the page rendered through the post-run step's own entry."""
from __future__ import annotations

import json
import uuid
from pathlib import Path

from defender.presentation.visualize_run import render_page
from defender.records import RunPaths, SessionPaths
from defender.tests.support.jobs._jobs1342 import SPEND_LEDGER, insert_spend, seal_at  # noqa: F401
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.shared._locations_1210 import fixture_runs_base
from defender.tests.support.shared.contracts._spec1077 import fixture_run as _run_handle_1165

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

def _seed_session_store(run: Path, messages: list[dict], closing: dict | None = None, *, record: bool = True,
                        case_id: str | None = None) -> None:
    """A real session store seeded from the same `messages` the fixture writes to the wire log, and holding the run's spend
    ledger (`_LEDGER`, beside another run's rows): the page reads its headline from the run's own store (#1377 r6 S5)."""
    from pydantic_ai.messages import ModelMessagesTypeAdapter

    from defender.records import session_store as ss

    # One database per call: pytest's 30-character tmp names repeat across parametrized cases, and a shared file would pool ledger rows.
    with ss.open_store(case_id=case_id or f"visualize-runtime-fixture-{uuid.uuid4().hex}",
                       sessions=SessionPaths(fixture_runs_base(run.parent))) as store:
        ss.write_case_pointer(_run_handle_1165(run), case_id=store.case_id, store_path=store.path)
        if record:  # the run's closing record, in the store its pointer names (#1534; no `report.md`)
            from defender.tests.storage.verdict_1534 import _spec1534 as V

            V.plant(store, V.a_record(run.name, **(closing or {})))
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


def _build_run(tmp: Path, closing: dict | None = None, *, record: bool = True, case_id: str | None = None) -> Path:
    """A run folder whose store holds its closing record: `a_record`'s defaults (a `malicious` close that stood, with
    `MARKUP_SUMMARY`) overridden by `closing`; `record=False` leaves the table with no row (a run that never closed)."""
    # A run id is a canonical UUID, so the folder is `fixture_uuid(<label>)`.
    run = tmp / fixture_uuid("run")
    (run / "gather_raw" / "l-001").mkdir(parents=True)

    (run / "investigation.md").write_text(_FULL_INVESTIGATION)
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
    _seed_session_store(run, messages, closing, record=record, case_id=case_id)

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

_SEALED: set[Path] = set()

def _page(run: Path, *, sealed: bool = True) -> str:
    """The run's page through the post-run step's own entry: it holds the `Run` (the host's handle on the run's store), and
    nothing else is handed in. r7.3 T1: the ledger is sealed first (once per run, as a run that ended without a failed write
    leaves it); `sealed=False` is a run whose seal never landed (a failed write, a kill)."""
    if sealed and run not in _SEALED:
        _SEALED.add(run)
        pointer = _run_handle_1165(run).observability.session_pointer.read_result().text
        seal_at(fixture_runs_base(run.parent), json.loads(pointer)["case_id"], run.name)
    return render_page(_run_handle_1165(run))


#: The keyword the run page's render takes the lookup result by (#1534: required, never defaulted). Proposed: the interface
#: names none, so every caller spells it here.
CLOSING_ARG = "closing"


def render_runtime(run_dir: Path, *, cost: object, closing: object, **kw: object) -> str:
    """`render_runtime_page` handed an explicit lookup result (a `Record`, `NeverClosed` or `CouldNotLook`)."""
    from defender.presentation.visualize_run import render_runtime_page

    return render_runtime_page(run_dir, cost=cost, **{CLOSING_ARG: closing}, **kw)


def render_unclosed(run_dir: Path, *, cost: object) -> str:
    """The page of a run whose closing record these tests do not look at: handed `NeverClosed()`."""
    from defender.records import closing as C

    return render_runtime(run_dir, cost=cost, closing=C.NeverClosed())
