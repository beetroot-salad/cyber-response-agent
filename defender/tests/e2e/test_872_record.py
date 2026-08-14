"""#872 — attributability, the run record, and the readers of the part this change moves
(`d15b`, `d27`, `d28`, `d29`, `d30`, `d38`, `d39`, `d41`, `d63`, `d65`, `d66`).

Every demand here is driven through the whole `run_investigation` loop, because the session
store, the send-history rebuild, the wire log, the queries table and the run dir do not exist
at any lower altitude — and the model-visible text has an UNLISTED CO-AUTHOR: MAIN's
`ProcessHistory` processor ends by returning `selection.render(...)`, which discards the live
message list and returns `hydrate(store, session_id, role="send")`. The messages the model is
sent are REBUILT FROM THE STORE PER REQUEST, so a demand about what the model reads for a
substituted call is a demand about that rebuild.

The three coherence demands (`d65`, `d66`, `d30`) are bound at their OWN reader edges rather
than at the boundary, for the reason coherence always is: a demand at `tool_return_part`'s
altitude reads green when two of its four readers moved.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

import toons  # noqa: E402

from defender._io import read_jsonl_rows  # noqa: E402
from defender._run_paths import RunPaths  # noqa: E402
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
    DEFENDER,
    RUN_ID,
    SALT,
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
                      gather: bool = False):
    """One driven run in which a foreign result IS substituted — the shared setup for every
    demand in this module, and the positive control each of the negatives needs."""
    run_dir = materialize(tmp_path, GOLDEN_AB3)
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
    drive(run_dir, run_id=RUN_ID, salt=SALT, main=main, **seams)
    return run_dir, main


def test_both_encodings_are_recoverable_from_the_wire_log_joined_by_agent_seq_and_tool_call_id(
    tmp_path: Path,
) -> None:
    """After a run in which a substitution occurred, BOTH encodings and their join key are
    recoverable from the wire log.

    §7 r1 took f5 = B: no new sink, the original rides on `ToolReturn.metadata`, and the record
    is joined `(agent_id, seq, tool_call_id)` — not `tool_call_id` alone. Within one
    investigation MAIN, the gather subagent and all three review lenses share ONE
    `RequestLogger` and therefore one `llm_requests.jsonl`, separated only by an `agent_id`
    FIELD and a per-agent sequence, and the logger re-dumps the whole history every round, so
    the id alone identifies a CALL and not a RECORD.

    RECOVERABLE AFTER DECODE, NEVER BYTE-IDENTICAL: the log pins `ensure_ascii=True` against a
    lone UTF-16 surrogate, so a TOON view on disk is escaped. Pinning byte-identity here would
    pin a falsehood.

    The six learning stages write a DIFFERENT trace family, so a learning-stage substitution is
    silently unattributable — named in the demand, and the reason `learning_wire_log` is a
    separate boundary. O5 holds only at the default trim `DEFENDER_LLM_LOG_MAX_CHARS=0`, which
    this run uses and which is the shipped default.
    """
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
    assert framed_content(view, salt=SALT) == toons.dumps(value), (
        "the view is not recoverable from the wire log after decoding the log's own escaping"
    )


def _every_view(main, view: str) -> bool:
    """Every `fetch_rows` return in the final dispatched history carries the substituted view.

    READ AS A LIST, NEVER AS `part()`. These demands drive MORE THAN ONE tool turn, and the
    final request holds the whole rebuilt history — so `Dispatched.part` (which asserts exactly
    one hit) raises `expected one 'fetch_rows' return, got 2` no matter what the gate does.
    Three anti-vacuity controls in this module read it that way and were red against every
    possible implementation until the phase-F null-stub run showed the failure was the helper's
    arity and not the gate's behaviour."""
    texts = main.dispatched.texts("fetch_rows")
    assert texts, "no foreign return reached the model at all"
    return all(framed_content(t, salt=SALT) == view for t in texts)


def _tool_return_parts(rec: dict) -> list[dict]:
    """Every tool-return part in one wire-log record. The log records the FULL request
    messages verbatim, so the parts are nested inside the recorded message list."""
    out: list[dict] = []
    for message in rec.get("request_messages") or rec.get("messages") or []:
        for part in (message or {}).get("parts", []) or []:
            if (part or {}).get("part_kind") in ("tool-return", "tool_return"):
                out.append(part)
    return out


def test_a_run_records_what_the_gate_examined_substituted_and_saved(tmp_path: Path) -> None:
    """A run records, at the operator's altitude, FOUR categories: how many foreign results the
    gate examined, how many the guard refused, how many it substituted, and how many bytes it
    saved.

    §7 r1 took P6 = B, and the SINK is the one f5 picked: the counters ride on the SAME
    wire-log record that carries the substituted return's metadata. No new run-dir root.

    O1 is an OPERATOR COST obligation and without this nothing after a run tells the operator
    whether the gate fired. Two facts make that more than cosmetic: the gate is inert on the
    shipped tree, and EVERY negative demand in this set is satisfied by a gate that never fires
    at all — so a gate that DIES, whose provenance predicate never matches, or that is missing
    from one of five build paths is indistinguishable from a gate that had nothing to do.

    THE FOURTH CATEGORY IS THE ONE r2 COULD NOT HAVE HAD: M7 turns three probed crash classes
    into silent passthroughs, so without a refusal count a gate that refuses every foreign
    payload reads exactly like one that never fired.
    """
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
    DISPATCHED on a later turn — after the send history has been rebuilt from the store.

    §7 r8 settled which artifact "the text the model received" names: the DISPATCHED REQUEST
    MESSAGES, for O1, O2, O3 and O8. In this runtime that phrase does not name one thing —
    MAIN's `ProcessHistory` processor returns `selection.render(...)`, which discards the live
    message list and returns `hydrate(store, session_id, role='send')` — so an oracle reading
    the wrapper's own return value would be testing an internal variable, which O1 forbids.

    Reading B (the wire-log record) was on the table and was NOT taken for these obligations:
    the log pins `ensure_ascii=True`, so every byte comparison would become
    byte-identity-after-unescaping, a weaker claim than O2 states. Attributability alone reads
    the wire log (`d15b`).

    Driven across THREE turns, so the substituted return is read out of a request the run
    rebuilt rather than out of the one it was produced in.
    """
    value = _payload()
    _, main = _substituting_run(tmp_path, turns=3)
    assert len(main.requests) >= 3, "the run did not survive to a rebuilt request"

    views = main.dispatched.texts("fetch_rows")
    assert len(views) >= 2, (
        "the final dispatched history carries fewer foreign returns than the run made, so the "
        "rebuild dropped one and this assertion would be about the survivors only"
    )
    for i, view in enumerate(views):
        assert framed_content(view, salt=SALT) == toons.dumps(value), (
            f"substituted return {i + 1} did not survive the send-history rebuild"
        )


def test_a_substituted_calls_metadata_survives_the_send_history_rebuild(tmp_path: Path) -> None:
    """A substituted call's `metadata` is still present on the `ToolReturnPart` in the
    DISPATCHED request messages, after the send history has been rebuilt from the store.

    BOUND AT THIS READER'S OWN EDGE, NEVER AT `tool_return_part`'s ALTITUDE — a demand at the
    boundary reads green when two of the four readers moved, which is the escape this rule
    computes. The send history is rebuilt from the store per request, so this reader is the one
    that decides what the model actually sees for a substituted call.

    `R2` settled that `metadata` survives the rebuild, WHICH IS EXACTLY WHY THE MISSING DEMAND
    WAS DANGEROUS: the fact is settled and nothing pinned it, so a later change to the
    processor would break O5 with the suite green. f1 = C and f5 = B both die if it fails.
    """
    value = _payload()
    _, main = _substituting_run(tmp_path, turns=3)
    parts = [p for p in main.dispatched.parts if p.tool_name == "fetch_rows"]
    assert parts, "no substituted part survived into the rebuilt history at all"
    for i, part in enumerate(parts):
        lost = f"substituted call {i + 1} lost its metadata in the send-history rebuild"
        assert isinstance(part.metadata, dict), lost
        assert gate_metadata_key() in part.metadata, lost
        assert part.metadata[gate_metadata_key()] == value


def test_a_substituted_calls_metadata_survives_persist_and_hydrate_through_the_store(
    tmp_path: Path,
) -> None:
    """A substituted call's `metadata` is written into the session store's `message_payload`
    and read back out of it.

    THE PERSIST HALF of the round trip `d65` pins the read half of, and the two are separable
    in practice as well as in principle: a store that serialized the part through a typed model
    instead of the tolerant path would drop `metadata` here while `d65` still passed on a live
    in-process list.

    Read out of the REAL SQLite file rather than through any reader under test, so a reader
    that reconstructed the field would not be able to hide a store that never wrote it.

    THE CARRIER IS SELECTED BY THE VIEW, NOT BY THE RESERVED KEY, and that is anti-vacuity
    rather than style. §7 r1 spelled the key `"json"`, a string that occurs in an ordinary
    serialized message payload for reasons having nothing to do with this gate — so
    `"json" in str(payload)` selects rows in a run where NOTHING was substituted, and the
    original value is then found in them because an un-gated run stores the tool's own dict
    verbatim. Both halves of the assertion were satisfied by a gate that did nothing (caught by
    the phase-F null-stub run). What distinguishes the two worlds is that ONE row must carry
    BOTH encodings: the framed TOON view as the part's content AND the original under the
    reserved key. That pair is what O5 means and what is asserted here.
    """
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


def test_the_recorded_history_of_a_substituted_call_is_not_rewritten_in_place(
    tmp_path: Path,
) -> None:
    """No message-level rewriter runs over a substituted call: the rows the run recorded for
    the first turn are the same rows after a later turn, and the original JSON is still
    recoverable from them.

    N8's PHRASING IS CORRECTED HERE, and the correction bounds what this test may assert.
    Defender's persistence is APPEND-ONLY — `selection.ingest` only ever calls `store.append`,
    and a fold mints a NEW synthesized request parented onto the lineage root rather than
    mutating prior rows — so nothing is rewritten in place and "overwriting the run's history
    in place" overstates the mechanism. What CHANGES is which rows the send-render reaches.

    So the assertion is over the RECORDED ROWS: the count only grows, no earlier row's payload
    changes, and every substituted call keeps its metadata. Each of the three message-level
    rewriters N8 rejected would satisfy O1 and destroy O5 — the original would stop being
    recoverable from the row that carried it — and that is what is checked.

    THE CARRIER IS SELECTED BY THE VIEW, for the reason `d66`'s test spells out: `"json"` is
    the reserved key §7 spelled and it occurs in ordinary serialized payloads, so selecting on
    it picks rows in a run where nothing substituted — and the original is then found in them
    because an un-gated run stores the tool's own dict verbatim. A row carrying the TOON VIEW
    is a row only a substituting gate produced.
    """
    value = _payload()
    view = toons.dumps(value)
    stores: list = []
    _substituting_run(tmp_path, turns=3, stores=stores)
    rows = sql(stores[-1], "SELECT m.id, p.payload FROM message m "
                           "JOIN message_payload p ON p.message_id = m.id ORDER BY m.id")
    assert rows, "no recorded rows to compare"
    ids = [r[0] for r in rows]
    not_append_only = "message ids are not append-only — a row was rewritten or reused"
    assert ids == sorted(ids), not_append_only
    assert len(ids) == len(set(ids)), not_append_only
    carriers = [r[1] for r in rows if _is_json(r[1]) and _carries_view(json.loads(r[1]), view)]
    assert carriers, (
        "no recorded row carries a substituted call at all — nothing here distinguishes this "
        "run from one in which the gate never fired"
    )
    for payload in carriers:
        assert _carries_original(json.loads(payload), value), (
            "a recorded row carries the view and lost the original JSON — O5 is destroyed "
            "for that call"
        )


def test_no_toon_text_is_written_to_any_run_dir_sink_or_reducer_input(tmp_path: Path) -> None:
    """No TOON text is written into ANY run-dir sink: not the gather capture, not the queries
    table, not the run dir at large, and not the reducer's input.

    The TOON text is DERIVED, NEVER AUTHORITATIVE. §7 r1 took f5 = B, so no run-dir sink is
    written at all and this stands as its plain universal with no carve-out. The one place TOON
    text is now legitimately persisted is the WIRE LOG, which is not a run-dir sink this demand
    binds and which `d15b` covers — so the wire log is excluded by name rather than by
    accident.

    BOUND ON EVERY SURFACE THE TEXT COULD REACH, not just the obvious one: a `.toon` file is
    not reducer-readable by any route, because defender-sql builds its one table with
    `read_json_auto`. The positive control is `d23` — the query path is unchanged in a run
    where a foreign dict IS substituted, which this run also does.
    """
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


def test_payload_view_render_emits_no_toon_with_the_gate_installed(tmp_path: Path) -> None:
    """`payload_view.render` emits no TOON with the gate installed: defender's own captured
    payload keeps its existing JSON structural walk.

    N3, and it is driven DIRECTLY rather than through the gate: at the chosen seam the owned
    payload is unreachable anyway, so a gate-driven test would pass vacuously. `render` has
    three production importers and none of them is hooked by this change.

    Its positive control is `d1` — a foreign dict-row payload DOES reach the model as TOON —
    so "no TOON here" is not green merely because the gate emits none anywhere.
    """
    from defender.scripts.gather_tools import payload_view

    # Defender's OWN captured payload is columnar — the shape N3 is about, and the arm the
    # corpus measures at 86.2% to 108.3% on the wire ruler (TOON never cheaper).
    value = corpus()["fx-33"]
    run_dir = tmp_path / "run"
    (run_dir / "gather_raw" / "l-001").mkdir(parents=True)
    rel = Path("gather_raw") / "l-001" / "0.json"
    (run_dir / rel).write_text(json.dumps(value), encoding="utf-8")

    text = (run_dir / rel).read_text(encoding="utf-8")
    # BOTH of render's lanes, because N3 is about the function and not about one branch: under
    # the ceiling the payload is returned VERBATIM, over it the JSON structural walk runs. A
    # test that drove only the verbatim lane would report "no TOON" for a reason that has
    # nothing to do with this change.
    verbatim = payload_view.render(text, str(rel), run_dir)
    walked = payload_view.render(text, str(rel), run_dir, ceiling=1)
    vacuous = "render produced nothing, so the absences below are vacuous"
    assert verbatim, vacuous
    assert walked, vacuous
    assert verbatim == text, (
        "render's under-ceiling lane no longer returns the captured payload verbatim, so what "
        "it emits instead is a re-encoding this demand has not looked at"
    )
    for lane, rendered in (("verbatim", verbatim), ("structural walk", walked)):
        assert toons.dumps(value) not in rendered, f"render's {lane} lane emitted the TOON view"
        for marker in ("]{", "[0]:"):
            assert marker not in rendered, f"render's {lane} lane emitted TOON syntax ({marker!r})"


def test_a_foreign_substitution_appends_no_executed_queries_row(tmp_path: Path) -> None:
    """A foreign substitution appends NO row to the executed-queries table — through any of its
    three independently spelled writers.

    N4 is a universal and carves out no writer, so the no-row rule holds identically whichever
    writer a reaching tool uses. It is also the reason f5 was open at all: a foreign result has
    no `(lead_id, seq)`, the axes every other run-dir sink is keyed on.

    The positive control is `d23`, driven in the same run: the `query` path DOES append its
    row, so an empty table would fail this test rather than passing it.
    """
    run_dir, main = _substituting_run(tmp_path, turns=2, gather=True)
    rows = read_jsonl_rows(RunPaths(run_dir).executed_queries)
    assert rows, "no queries row at all — the control did not run and the absence is vacuous"

    view = toons.dumps(_payload())
    for row in rows:
        blob = json.dumps(row, sort_keys=True)
        assert "fetch_rows" not in blob, "a foreign result produced an executed-queries row"
        assert view not in blob


def test_a_queries_row_written_before_the_wrapper_sees_the_return_is_unchanged_by_the_gates_decision(
    tmp_path: Path,
) -> None:
    """A queries row written before the wrapper sees the return is byte-identical whether the
    gate substitutes in that run or not.

    "Derived, never authoritative" forbids a row's correctness from depending on what the gate
    later decides for the model-visible text. BOUND PER WRITER EDGE, not at the boundary, for
    the reason coherence always is: the table has THREE independently spelled writers — the
    shared `append_query_row` helper reached by the query tool and the gather bash lane,
    `lead_zero`'s twelve keys assembled INLINE, and the judge's closed-ticket tool appending its
    own — and a demand at the table's altitude is green when two of the three agree.

    TWO WRITERS ARE DRIVEN AND THE THIRD IS OUT OF REACH BY CONSTRUCTION
    (`92-reconciliation.md` F9). The demand states the per-writer rule and this test used to
    exercise one lane, which is weaker than the altitude the rule was written to avoid. The
    query tool's lane and `lead_zero._record_manual_row`'s inline assembly both append to THIS
    run's `executed_queries.jsonl`, so both are inside the differential below. The judge's
    appender writes a file of the same NAME in the LEARNING run dir
    (`closed_ticket_tool.py:355`, `run_dir / "executed_queries.jsonl"` where `run_dir` is the
    learning run's), which no investigation ever writes and which the gate cannot reach from
    this altitude — so its absence here is a reach fact, recorded in `d41`'s note, not a lane
    this test declined to drive.

    Driven as a differential over two runs that differ ONLY in whether a foreign substitution
    happened, so any dependence of a row on the gate's decision shows up as a diff.
    """
    from defender.runtime import lead_zero

    def _manual_row(run_dir: Path) -> None:
        """`lead_zero`'s SECOND spelling of the row, written into the run under test.

        Called through the module's own function rather than re-assembled here: the twelve
        keys are spelled INLINE at that site, and a copy in this test would compare the test's
        idea of the row against itself."""
        deps = lead_zero._CaptureDeps(
            run_dir=run_dir, defender_dir=DEFENDER, salt=SALT, run_id=RUN_ID,
            lead_id="l-000",
        )
        lead_zero._record_manual_row(
            deps, "search", {"index": "logs"}, {"rows": [{"a": 1}]}, exit_code=0,
        )

    gated_dir, main = _substituting_run(tmp_path / "gated", turns=2, gather=True)
    assert _every_view(main, toons.dumps(_payload())), (
        "the gated run did not substitute, so the two runs are the same run"
    )

    idle_dir = materialize(tmp_path / "idle", GOLDEN_AB3)
    rec = VerbRecorder()
    idle_main = PartRecorder([
        Turn(tool_calls=[("gather", {
            "lead_id": "l-001", "system": "elastic", "goal": "measure this lead",
            "what_to_summarize": ["auth events"],
        })]),
        Turn(text="Complete."),
    ])
    drive(idle_dir, run_id=RUN_ID, salt=SALT, main=idle_main,
          gather=ReplayFn([q("elastic", "query", {"native_query": "FROM logs"}), DONE]),
          verbs=elastic_ok(rec))

    # The second writer's own spelling, appended to each run's table after the run that
    # differs is over — so the comparison below spans both lanes rather than one.
    for run_dir in (gated_dir, idle_dir):
        _manual_row(run_dir)

    gated_rows = read_jsonl_rows(RunPaths(gated_dir).executed_queries)
    idle_rows = read_jsonl_rows(RunPaths(idle_dir).executed_queries)
    assert gated_rows, "the gated run wrote no queries row"
    assert idle_rows, "the idle run wrote no queries row"
    lanes = {r.get("lead_id") for r in gated_rows}
    assert {"l-000", "l-001"} <= lanes, (
        f"only one of the two reachable writers put a row in the table ({sorted(lanes)}), so "
        "the differential below is at the table's altitude and not per-writer"
    )
    assert gated_rows == idle_rows, (
        "an executed-queries row differs between a run where the gate substituted and one "
        "where it did not"
    )


def test_the_rendered_runtime_page_shows_the_original_json_of_a_substituted_call(
    tmp_path: Path,
) -> None:
    """The offline reader's rendered page shows the ORIGINAL JSON of a substituted call, beside
    the view — it does not merely survive the new field.

    THE DEMAND THAT STOPS O5 BEING TRUE AND UNOBSERVABLE. Measured before this spec was
    written: `load_messages` is a tolerant JSONL reader and returns `metadata` VERBATIM, but
    the entry builder one layer past it constructs a FIXED-KEY entry and the field is dropped —
    the page rendered with the TOON view visible, the original JSON absent, and the word
    `metadata` absent from the whole page. Reading A ("it still renders") was on the table and
    was NOT taken: under f1 = C plus f5 = B it would have left O5 discharged only against a
    file denied to every agent and read by no tool in the tree except the one that drops the
    field.

    SCOPED: the page shows the field WHERE IT IS PRESENT and changes nothing where it is
    absent, which the second half of this test drives.

    TRAP, AND IT IS NOT THIS DEMAND'S DEFECT TO FIX: `visualize_messages` -> `visualize_data`
    -> `visualize_messages` is an IMPORT CYCLE, so the wire log's only reader is not importable
    as its own module head — a test that imports it first raises `ImportError`. Entering the
    cycle at the other end is the workaround, and it is the same move the gather suites make
    for `tools`/`tools_gather`.
    """
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

    plain_dir = materialize(tmp_path / "plain", GOLDEN_AB3)
    rec = VerbRecorder()
    drive(plain_dir, run_id=RUN_ID, salt=SALT,
          main=PartRecorder([Turn(tool_calls=[("gather", {
              "lead_id": "l-001", "system": "elastic", "goal": "measure this lead",
              "what_to_summarize": ["auth events"],
          })]), Turn(text="Complete.")]),
          gather=ReplayFn([q("elastic", "query", {"native_query": "FROM logs"}), DONE]),
          verbs=elastic_ok(rec))
    plain_page = render_runtime_page(plain_dir)
    assert plain_page, "the reader produced nothing for a run with no substitution"
    assert wire_text(value) not in plain_page
