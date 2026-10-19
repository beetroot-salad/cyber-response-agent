"""#872 — attributability, the run record, and the readers of the part this change moves
(`d15b`, `d27`, `d28`, `d29`, `d30`, `d38`, `d39`, `d41`, `d63`, `d65`, `d66`)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

toons = pytest.importorskip("toons")  # noqa: E402

from defender._io import read_jsonl_rows  # noqa: E402
from defender.run_repository import RunPaths  # noqa: E402
from defender.tests._session_store_705 import sql, store_factory  # noqa: E402
from defender.tests.e2e._replay_harness import (  # noqa: E402
    GOLDEN_AB3,
    ReplayFn,
    Turn,
    VerbRecorder,
    drive,
    materialize,
)
from defender.tests.e2e._toon872 import (  # noqa: E402
    gate_metadata_key,
    RUN_ID,
    PartRecorder,
    corpus,
    foreign_toolset,
    framed_content,
    toon_rows,
    wire_text,
)
from defender.tests.e2e.test_query_tool_611 import DONE, elastic_ok, q  # noqa: E402

pytestmark = pytest.mark.e2e


def _payload() -> dict:
    return toon_rows(corpus()["fx-33"])


def _substituting_run(tmp_path: Path, *, turns: int = 2, stores: list | None = None,
                      gather: bool = False, summaries: list | None = None):
    """One driven run in which a foreign result IS substituted — the shared setup for every
    demand in this module, and the positive control each of the negatives needs. `summaries`
    receives what `drive()` returned, whose `run_state` is the run's own state (#1235)."""
    run_dir = materialize(tmp_path, GOLDEN_AB3, run_id=RUN_ID)
    calls = [Turn(tool_calls=[("fetch_rows", {})]) for _ in range(turns)]
    if gather:
        calls.insert(0, Turn(tool_calls=[("gather", {
            "lead_id": "l-001", "system": "elastic", "goal": "measure this lead",
            "what_to_summarize": ["auth events"],
        })]))
    main = PartRecorder([*calls, Turn(text="Complete.")])
    rec = VerbRecorder()
    seams: dict = {"toolset": foreign_toolset(_payload())}
    if gather:
        seams["gather"] = ReplayFn([q("elastic", "query", {"native_query": "FROM logs"}), DONE])
        seams["verbs"] = elastic_ok(rec)
    if stores is not None:
        seams["store_factory"] = store_factory(tmp_path / "store", sink=stores)
    summary = drive(run_dir, run_id=RUN_ID, main=main, **seams)
    if summaries is not None:
        summaries.append(summary)
    return run_dir, main


def test_both_encodings_are_recoverable_from_the_wire_log_joined_by_agent_seq_and_tool_call_id(
    tmp_path: Path,
) -> None:
    """After a run in which a substitution occurred, BOTH encodings and their join key are
    recoverable from the wire log."""
    value = _payload()
    run_dir, _ = _substituting_run(tmp_path)
    records = read_jsonl_rows(RunPaths(run_dir).wire_log) if hasattr(
        RunPaths(run_dir), "wire_log") else read_jsonl_rows(
        run_dir / "wire_logs" / "llm_requests.jsonl")
    assert records, "the wire log is empty — nothing was recorded to recover from"

    found = []
    for rec in records:
        for key in ("agent_id", "seq"):
            assert key in rec or rec.get("kind") == "response", (
                f"a wire-log record carries no {key}, so the join key f5 = B rests on is incomplete"
            )
        for part in _tool_return_parts(rec):
            meta = part.get("metadata") or {}
            if gate_metadata_key() in meta:
                found.append((rec.get("agent_id"), rec.get("seq"), part.get("tool_call_id"),
                              part.get("content"), meta[gate_metadata_key()]))

    assert found, "no substituted call is recoverable from the wire log"
    agent_id, seq, tool_call_id, view, original = found[-1]
    incomplete = "the join key (agent_id, seq, tool_call_id) is not complete on the record"
    assert agent_id is not None, incomplete
    assert seq is not None, incomplete
    assert tool_call_id is not None, incomplete
    assert original == value, "the original JSON is not recoverable from the wire log"
    assert framed_content(view) == toons.dumps(value), (
        "the view is not recoverable from the wire log after decoding the log's own escaping"
    )


def _every_view(main, view: str) -> bool:
    """Every `fetch_rows` return in the final dispatched history carries the substituted view."""
    texts = main.dispatched.texts("fetch_rows")
    assert texts, "no foreign return reached the model at all"
    return all(framed_content(t) == view for t in texts)


def _tool_return_parts(rec: dict) -> list[dict]:
    """Every tool-return part in one wire-log record."""
    out: list[dict] = []
    recorded = rec.get("message") or rec.get("request_messages") or rec.get("messages") or []
    messages = [recorded] if isinstance(recorded, dict) else recorded
    for message in messages:
        for part in (message or {}).get("parts", []) or []:
            if (part or {}).get("part_kind") in ("tool-return", "tool_return"):
                out.append(part)
    return out


def test_a_run_records_what_the_gate_examined_substituted_and_saved(tmp_path: Path) -> None:
    run_dir, _ = _substituting_run(tmp_path)
    records = read_jsonl_rows(run_dir / "wire_logs" / "llm_requests.jsonl")
    counters = [rec["toon_gate"] for rec in records if isinstance(rec.get("toon_gate"), dict)]
    assert counters, "no run-level record of the gate's own action exists"

    final = counters[-1]
    for field in ("examined", "refused", "substituted", "bytes_saved"):
        assert field in final, f"the gate's record has no {field!r} category"
    idle_record = "the gate's record shows nothing examined or substituted in a run that substituted"
    assert final["examined"] >= 1, idle_record
    assert final["substituted"] >= 1, idle_record
    assert final["bytes_saved"] > 0
    assert final["refused"] == 0


def test_a_substituted_return_survives_the_history_the_run_rebuilds_before_sending(
    tmp_path: Path,
) -> None:
    """A substituted return is still the substituted view in the messages the model is
    DISPATCHED on a later turn — after the send history has been rebuilt from the store."""
    value = _payload()
    _, main = _substituting_run(tmp_path, turns=3)
    assert len(main.requests) >= 3, "the run did not survive to a rebuilt request"

    views = main.dispatched.texts("fetch_rows")
    assert len(views) >= 2, (
        "the final dispatched history carries fewer foreign returns than the run made, so the "
        "rebuild dropped one and this assertion would be about the survivors only"
    )
    for i, view in enumerate(views):
        assert framed_content(view) == toons.dumps(value), (
            f"substituted return {i + 1} did not survive the send-history rebuild"
        )


def test_a_substituted_calls_metadata_survives_persist_and_hydrate_through_the_store(
    tmp_path: Path,
) -> None:
    """A substituted call's `metadata` is written into the session store's `message_payload`
    and read back out of it."""
    value = _payload()
    view = toons.dumps(value)
    stores: list = []
    _substituting_run(tmp_path, turns=2, stores=stores)
    assert stores, "no session store was opened, so nothing was persisted to read back"

    payloads = [row[0] for row in sql(stores[-1], "SELECT payload FROM message_payload")]
    assert payloads, "the store holds no message payloads"
    carriers = [p for p in payloads if _is_json(p) and _carries_view(json.loads(p), view)]
    assert carriers, (
        "no persisted message payload carries the substituted TOON view at all, so nothing "
        "here distinguishes this run from one in which the gate never fired"
    )
    assert any(
        _carries_original(json.loads(p), value) for p in carriers
    ), "the view reached the store but the original JSON did not survive beside it"


def _is_json(text: object) -> bool:
    try:
        json.loads(text)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return False
    return True


def _strings(obj: object):
    """Every string anywhere in a decoded payload — the store's own nesting is not this
    suite's to pin, so the walk is shape-blind rather than keyed on a path."""
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _strings(v)


def _carries_view(payload: object, view: str) -> bool:
    """The substituted TOON view is present as text — the half an un-gated run cannot have."""
    return any(view in s for s in _strings(payload))


def _carries_original(payload: object, value: dict) -> bool:
    """The original JSON is present beside it, under whatever nesting the store uses."""
    needle = json.dumps(value, sort_keys=True)
    return needle in json.dumps(payload, sort_keys=True)


def test_no_toon_text_is_written_to_any_run_dir_sink_or_reducer_input(tmp_path: Path) -> None:
    """No TOON text is written into ANY run-dir sink: not the gather capture, not the queries
    table, not the run dir at large, and not the reducer's input."""
    value = _payload()
    view = toons.dumps(value)
    run_dir, main = _substituting_run(tmp_path, turns=2, gather=True)
    assert _every_view(main, view), (
        "nothing substituted in this run, so every absence below is vacuous"
    )

    wire_log = (run_dir / "wire_logs").resolve()
    offenders = []
    for path in run_dir.rglob("*"):
        if not path.is_file() or wire_log in path.parents:
            continue
        if path.suffix == ".toon":
            offenders.append(str(path))
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if view in text:
            offenders.append(str(path))
    assert not offenders, f"TOON text reached run-dir sinks: {offenders}"


def test_a_queries_row_written_before_the_wrapper_sees_the_return_is_unchanged_by_the_gates_decision(
    tmp_path: Path,
) -> None:
    """A queries row written before the wrapper sees the return is byte-identical whether the
    gate substitutes in that run or not."""
    gated_dir, main = _substituting_run(tmp_path / "gated", turns=2, gather=True)
    assert _every_view(main, toons.dumps(_payload())), (
        "the gated run did not substitute, so the two runs are the same run"
    )

    idle_dir = materialize(tmp_path / "idle", GOLDEN_AB3, run_id=RUN_ID)
    rec = VerbRecorder()
    idle_main = PartRecorder([
        Turn(tool_calls=[("gather", {
            "lead_id": "l-001", "system": "elastic", "goal": "measure this lead",
            "what_to_summarize": ["auth events"],
        })]),
        Turn(text="Complete."),
    ])
    drive(
        idle_dir, run_id=RUN_ID, main=idle_main,
        gather=ReplayFn([q("elastic", "query", {"native_query": "FROM logs"}), DONE]),
        verbs=elastic_ok(rec))

    gated_rows = read_jsonl_rows(RunPaths(gated_dir).executed_queries)
    idle_rows = read_jsonl_rows(RunPaths(idle_dir).executed_queries)
    assert gated_rows, "the gated run wrote no queries row"
    assert idle_rows, "the idle run wrote no queries row"
    lanes = {r.get("lead_id") for r in gated_rows}
    assert "l-001" in lanes, (
        f"the dispatched lead put no row in the table ({sorted(lanes)}), so the differential "
        "below is at the table's altitude and not per-writer"
    )
    assert gated_rows == idle_rows, (
        "an executed-queries row differs between a run where the gate substituted and one "
        "where it did not"
    )


def test_the_rendered_runtime_page_shows_the_original_json_of_a_substituted_call(
    tmp_path: Path,
) -> None:
    """The offline reader's rendered page shows the ORIGINAL JSON of a substituted call, beside
    the view — it does not merely survive the new field."""
    import defender.scripts.visualize.visualize_data  # noqa: F401 — enter the cycle at the
    # other end first: importing `visualize_messages` (and therefore `visualize_run`, which
    # imports it) as the module head raises ImportError on this pre-existing cycle.
    from defender.scripts.visualize.visualize_run import render_runtime_page

    value = _payload()
    run_dir, main = _substituting_run(tmp_path / "sub", turns=2, gather=True)
    assert _every_view(main, toons.dumps(value))

    page = render_runtime_page(run_dir)
    needle = json.dumps(value["values"][0], separators=(",", ":"))
    assert needle in page or json.dumps(value["values"][0]) in page, (
        "the rendered page shows the TOON view and not the original JSON the gate replaced"
    )

    plain_dir = materialize(tmp_path / "plain", GOLDEN_AB3, run_id=RUN_ID)
    rec = VerbRecorder()
    drive(plain_dir, run_id=RUN_ID,
          main=PartRecorder([Turn(tool_calls=[("gather", {
              "lead_id": "l-001", "system": "elastic", "goal": "measure this lead",
              "what_to_summarize": ["auth events"],
          })]), Turn(text="Complete.")]),
          gather=ReplayFn([q("elastic", "query", {"native_query": "FROM logs"}), DONE]),
          verbs=elastic_ok(rec))
    plain_page = render_runtime_page(plain_dir)
    assert plain_page, "the reader produced nothing for a run with no substitution"
    assert wire_text(value) not in plain_page
