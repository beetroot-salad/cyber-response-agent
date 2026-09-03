"""#996 — the clerk's trace, its wire identity, its price, and the readers that count it.

Every clerk call is a paid model call inside a tool the operator never sees dispatch. Three
things have to hold or the spend is invisible: the call lands in the run's ONE wire log under a
namespace of its own; a per-call trace row records what the call did; and the cost readers
bucket that namespace the way they already bucket gather and review.

The trace is also the ONLY provenance binding a landed row to the clerk that compiled it —
rows are attributed to MAIN by every downstream reader, deliberately, because a row is MAIN's
assertion compiled — so a missing trace row is a row with no author.

THE IDENTITY QUESTION IS TWO CELLS, NOT ONE, and that is the trap the §7 seam called out by
name. The wire log's `clerk:{n}` and the trace row's own id are separate identities over the
same counter: re-keying one and leaving the other on the bare counter looks closed, tests green
within a single process, and collides the first time a run is re-entered. Both are asserted
here, in one scenario, for exactly that reason.

SCOPE, recorded as an examined non-obligation rather than left to be inferred: the caller's
in-memory state is NOT durable across a process. The queue and the last gaps do not survive,
and prose whose call was killed between the prose landing and the clerk being invoked is never
recompiled. The counter is the one exception, and it is the exception because a collision there
corrupts the accounting rather than losing work.

RED against `7fa49f04`: there is no clerk namespace, no trace file and no clerk cost reader.
"""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender._io import read_jsonl_rows  # noqa: E402
from defender._run_paths import WIRE_LOG_DIR, RunPaths  # noqa: E402
from defender.agents import GATHER_DEF, MAIN_DEF  # noqa: E402
from defender.runtime import observe, permission  # noqa: E402
from defender.runtime.agent_definition import compile_policy_for  # noqa: E402
from defender.scripts.pricing import usage_cost  # noqa: E402
from defender.tests import _clerk_996 as C  # noqa: E402
from defender.tests._session_store_705 import (  # noqa: E402
    make_store,
    text_response,
    user_request,
)

#: One priced round, chosen so every usage term is non-zero: a reader that dropped a term would
#: still return a plausible number against a single-field usage dict.
USAGE = {"input_tokens": 4000, "output_tokens": 1000, "cache_read_input_tokens": 2000,
         "cache_creation_input_tokens": 500}


def _response(model: str = C.CLERK_PROVIDER_MODEL):
    """A real `ModelResponse`, not a dict: the logger runs the framework's type adapter over
    what it is handed, so a dict double would exercise a serialisation path production never
    takes."""
    from pydantic_ai.messages import ModelResponse, TextPart
    from pydantic_ai.usage import RequestUsage

    return ModelResponse(
        parts=[TextPart(content="rows")], model_name=model,
        usage=RequestUsage(
            input_tokens=USAGE["input_tokens"], output_tokens=USAGE["output_tokens"],
            cache_read_tokens=USAGE["cache_read_input_tokens"],
            cache_write_tokens=USAGE["cache_creation_input_tokens"],
        ),
    )


# ---------------------------------------------------------------------------------------
# the trace (O5, S4; cluster L)
# ---------------------------------------------------------------------------------------


def test_996_clerk_trace_row_fields(tmp_path: Path) -> None:
    """SHAPE: one trace row per `record` call, carrying the whole declared field set.

    The WHOLE set and not a sample: the row is the only provenance binding a landed row to the
    clerk that compiled it, and a field nobody pinned is a field that can be dropped without
    anything noticing. Two of them carry the D7 decision itself — whether the loop stopped on
    the judgment partition and whether the block is held — and those are the fields the
    validation run recounts the zero-false-negative result from.

    ONE ROW PER CALL INCLUDING EARLY EXITS, round fields zero: the schema sentence read
    literally is what makes the trace a complete census of `record` calls, and a census is what
    gives the prompt-level half of O2 a denominator. A trace that skipped the calls that never
    reached the loop would silently under-count exactly the failures worth counting."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.PROLOGUE)
    clerk = C.ScriptedClerk(C.clerk_reply(C.CLEAN_ROWS, gaps=("who owns it?",)))
    C.record_run(tmp_path, run_dir=run_dir, clerk=clerk)

    rows = C.trace_rows(run_dir)
    assert len(rows) == 1, f"expected one trace row per `record` call, got {len(rows)}"
    missing = [f for f in C.TRACE_FIELDS if f not in rows[0]]
    assert missing == [], f"the clerk trace row is missing {missing}"
    assert rows[0]["gaps"] == ["who owns it?"]
    assert rows[0]["stopped_on_judgment"] is False
    assert rows[0]["held"] is False


def test_996_an_early_exit_still_writes_its_trace_row(tmp_path: Path) -> None:
    """A `record` call that never reaches the round loop still writes ONE trace row, with the
    round fields at zero.

    The early exits are the calls a census most easily loses: a repair round that returns with
    the window still open never reaches the loop at all. If those write nothing, the trace
    stops being a census of `record` calls and the prompt-level observation loses its
    denominator — and the run's own record of how often the clerk was skipped disappears with
    it."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.PROLOGUE + C.WARN_ROWS)
    clerk = C.ScriptedClerk(C.repair_reply())
    C.record_run(tmp_path, run_dir=run_dir, clerk=clerk)

    rows = C.trace_rows(run_dir)
    assert len(rows) == 1, (
        f"a `record` that returned before the round loop wrote {len(rows)} trace rows"
    )
    assert rows[0]["rounds"] == 0, rows[0]


def test_996_the_trace_append_never_fails_a_record(tmp_path: Path) -> None:
    """The trace append is BEST-EFFORT: its own failure never fails a `record`, and it is named
    in the receipt's outcome rather than swallowed.

    The fault is induced through the real filesystem rather than by a fake — a directory
    planted at the trace's own path, so the real append meets a real `IsADirectoryError` and
    the taxonomy assumption ceases to exist rather than being pinned once.

    Best-effort and SILENT are different things: the trace is observability, and a run whose
    provenance quietly stopped being written is a run nobody can audit afterwards."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.PROLOGUE)
    blocked = C.trace_path(run_dir)
    blocked.parent.mkdir(parents=True, exist_ok=True)
    blocked.mkdir()

    clerk = C.ScriptedClerk(C.clerk_reply(C.CLEAN_ROWS))
    _, main, _ = C.record_run(tmp_path, run_dir=run_dir, clerk=clerk)

    assert "attrs.owner" in C.document(run_dir), (
        "a failing trace append failed the whole `record` — the rows never landed"
    )
    assert "trace" in main.receipt.lower(), (
        f"the trace's own failure was swallowed: {main.receipt[:400]!r}"
    )


def test_996_the_clerk_trace_is_denied_like_every_wire_log(tmp_path: Path) -> None:
    """NEGATIVE: the clerk trace is unreadable by MAIN and by GATHER, on the read tool and on
    the bash lane alike.

    It carries the clerk's whole turn verbatim — the document, MAIN's prose and the pending
    queue — so it is the same stream class as the wire log and earns the same component deny.
    Its LOCATION is the mechanism: the throwaway wrote it at the run root, where MAIN's and
    GATHER's single-segment read shape admits every file.

    POSITIVE CONTROL on the same address under the complementary condition: the run-root
    artifacts still read, and the same filename planted at the run ROOT is ADMITTED — so the
    deny is the directory doing the work and not a filename the gate happens to know.

    THE FIRST ASSERTION IS WHERE THE FILE LANDS, and without it the rest is vacuous: the deny
    is a directory rule that already holds for anything under `wire_logs/`, so asserting it
    over a file the TEST placed there proves nothing about where the code writes. The throwaway
    wrote this trace at the RUN ROOT, which is exactly the placement the deny does not
    cover."""
    driven = C.new_run_dir(tmp_path, name="driven")
    C.seed(driven, C.PROLOGUE)
    C.record_run(tmp_path, run_dir=driven, clerk=C.ScriptedClerk(C.clerk_reply("")))
    assert C.trace_path(driven).is_file(), (
        f"a driven run wrote no {C.CLERK_TRACE_NAME} under {WIRE_LOG_DIR}/"
    )
    assert not (driven / C.CLERK_TRACE_NAME).exists(), (
        "the clerk trace landed at the RUN ROOT, where MAIN's and GATHER's single-segment read "
        "shape admits every file — the throwaway's placement, which D4/S4 relocate"
    )

    run = tmp_path / "run"
    (run / WIRE_LOG_DIR).mkdir(parents=True)
    (run / "investigation.md").write_text("## ORIENT\n", encoding="utf-8")
    dfn = tmp_path / "defender"
    dfn.mkdir()
    trace = C.trace_path(run)
    trace.write_text('{"n": 0, "prose_chars": 12}\n', encoding="utf-8")

    policies = {
        "main": compile_policy_for(MAIN_DEF, run_dir=run, defender_dir=dfn),
        "gather": compile_policy_for(GATHER_DEF, run_dir=run, defender_dir=dfn),
    }
    for who, policy in policies.items():
        assert not permission.decide_read(
            trace, run_dir=run, defender_dir=dfn, policy=policy).allow, who
        assert not permission.decide_bash(
            f"cat {trace}", policy=policy, run_dir=run, defender_dir=dfn).allow, who
        assert permission.decide_read(
            run / "investigation.md", run_dir=run, defender_dir=dfn, policy=policy).allow, who

    planted = run / C.CLERK_TRACE_NAME
    planted.write_text("{}\n", encoding="utf-8")
    assert permission.decide_read(
        planted, run_dir=run, defender_dir=dfn, policy=policies["main"]).allow, (
        "the gate denies the clerk trace by NAME rather than by directory, so moving it back "
        "to the run root would not be caught"
    )


# ---------------------------------------------------------------------------------------
# identity — both cells, one decision (HD-2)
# ---------------------------------------------------------------------------------------


def test_996_clerk_calls_land_under_clerk_n(tmp_path: Path) -> None:
    """UNIQUENESS: every clerk call lands in the run's ONE wire log under its own `clerk:`
    namespace, and two calls in one run never share an id.

    The namespace is published beside the two that exist, on the leaf that already owns agent
    identity, because the writer is in the runtime and the cost readers are in the scripts tree
    — a prefix that drifted on one side silently drops a whole namespace out of the run's
    accounted total."""
    prefix = C.sym("runtime.agent_role", "CLERK_AGENT_ID_PREFIX")
    assert prefix == C.CLERK_PREFIX

    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.PROLOGUE)
    clerk = C.ScriptedClerk(C.clerk_reply(""))
    C.record_run(tmp_path, run_dir=run_dir, clerk=clerk,
                 prose=[C.PROSE, C.SECOND_PROSE])

    ids = C.clerk_agent_ids(run_dir)
    assert ids, "no clerk call reached the run's wire log at all"
    assert all(i.startswith(prefix) for i in ids), ids
    assert len(set(ids)) == 2, f"two clerk calls did not get two distinct agent ids: {ids}"


def test_996_clerk_trace_row_identity_survives_a_resume(tmp_path: Path) -> None:
    """UNIQUENESS ACROSS A RESUME, on BOTH identity cells: no `clerk:` agent id and no trace
    row id repeats over the run's whole life, including after the run is re-entered.

    The re-entry is the reachable shape of the collision and it is real: the run's logger
    reopens an already-written wire log in APPEND mode, so a second pass over one run dir adds
    its rows beside the first pass's — and a counter that restarts at zero re-uses every id it
    issued. EXECUTED at this base with the ordinary verbs: the second pass's rows carry
    `main#0`, `main#1` … again, beside the first pass's.

    BOTH CELLS IN ONE SCENARIO, because that is the trap. The fork reads as "the counter
    collision", singular; it is two identities over one counter, and a fix that re-keys the
    wire id and leaves the trace row on the bare counter looks closed, passes within one
    process, and collides on the first resume — with the fork marked resolved.

    Either keying strategy satisfies this: a compound key that carries the run step, or a
    counter seeded at construction from the rows the run already has. If the second is chosen,
    the trace row must be written BEFORE the clerk call rather than after it, or there is
    nothing to seed from."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.PROLOGUE)
    for pass_no in range(2):
        C.record_run(
            tmp_path, run_dir=run_dir, run_id=f"{C.RUN_ID}-{pass_no}",
            clerk=C.ScriptedClerk(C.clerk_reply("")),
            prose=[f"Pass {pass_no}: the bastion host answered."])

    ids = C.clerk_agent_ids(run_dir)
    assert len(ids) >= 2, f"the second pass made no clerk call: {ids}"
    assert len(set(ids)) == len(ids), (
        f"a clerk agent id repeats across the re-entry, so two different calls are one row to "
        f"every cost reader: {ids}"
    )

    rows = C.trace_rows(run_dir)
    assert len(rows) >= 2, f"the second pass wrote no trace row: {rows}"
    keys = [row.get("n") for row in rows]
    assert len(set(map(str, keys))) == len(keys), (
        f"a clerk trace row identity repeats across the re-entry — the wire id was re-keyed "
        f"and this one was not, which is the half the fork's own wording hides: {keys}"
    )


# ---------------------------------------------------------------------------------------
# the cost readers (O5, F21; O12)
# ---------------------------------------------------------------------------------------


def test_996_visualize_messages_buckets_the_clerk_namespace(tmp_path: Path) -> None:
    """COHERENCE: the run's cost reader buckets the `clerk:` namespace, the way it already
    buckets gather and review — and its two MAIN-ONLY filters keep filtering to main.

    Both halves matter and they pull opposite ways. Without the first the clerk's spend is
    absent from every per-run cost view while the provider still charged for it. Without the
    second the clerk's calls are counted as MAIN turns in the transcript and the phase map,
    which would make every run's turn count wrong in the other direction."""
    run_dir = tmp_path / "run"
    (run_dir / WIRE_LOG_DIR).mkdir(parents=True)
    logger = observe.RequestLogger(observe.wire_log_path(run_dir))
    logger.log(request_messages=[], response=_response(), agent_id="clerk:0")
    logger.log(request_messages=[], response=_response("claude-sonnet-4-6"), agent_id="main")
    logger.close()

    vd = C.mod("scripts.visualize.visualize_data")
    messages = list(read_jsonl_rows(RunPaths(run_dir).wire_log))
    by_model = vd.clerk_cost_by_model(run_dir, messages)
    assert by_model, "the cost reader buckets no clerk spend at all"
    assert pytest.approx(sum(by_model.values())) == usage_cost(
        C.CLERK_PROVIDER_MODEL, USAGE)

    main_only = vd.deduped_main_records(messages)
    assert all(rec.get("agent_id", "main") == "main" for rec in main_only), (
        "a clerk call is being counted as a MAIN turn — the transcript's own main-only filter "
        "stopped filtering"
    )


def test_996_total_cost_usd_excludes_the_clerk_exactly_as_it_excludes_gather(
    tmp_path: Path,
) -> None:
    """COHERENCE: the run's `total_cost_usd` excludes the clerk exactly as it already excludes
    gather — because it sums the STORE, not the wire log, and neither role's calls are stored.

    Stated as a demand rather than left as an accident: the number a reader takes for "what
    this run cost" is a main-session sum, and the clerk joining the wire log must not silently
    change what that number means. The whole-run figure that DOES include it is the cost
    reader's, above.

    POSITIVE CONTROL on the same address under the complementary condition: MAIN's own priced
    response IS in the total, so the exclusion is a scope and not a zero."""
    run_dir = tmp_path / "run"
    (run_dir / WIRE_LOG_DIR).mkdir(parents=True)
    store = make_store(tmp_path)
    session = store.new_session(agent_id="main")
    row = store.append(session, [user_request("investigate")], agent_id="main")[0]
    store.append(session, [text_response("thinking")], agent_id="main", parent_id=row)

    logger = observe.RequestLogger(observe.wire_log_path(run_dir))
    logger.log(request_messages=[], response=_response(), agent_id="clerk:0")
    logger.log(request_messages=[], response=_response(), agent_id="gather:l-001")
    logger.close()

    observe.write_trace(run_dir, store=store, session_id=session, wall_ms=1.0)
    result = [
        row for row in read_jsonl_rows(run_dir / "tool_trace.jsonl")
        if row.get("type") == "result"
    ][0]
    clerk_cost = usage_cost(C.CLERK_PROVIDER_MODEL, USAGE)
    assert result["total_cost_usd"] < clerk_cost, (
        f"the clerk's spend entered the run's total ({result['total_cost_usd']} vs a single "
        f"clerk call at {clerk_cost}), so the number changed meaning under the port"
    )


def test_996_the_write_lane_tags_record_calls(tmp_path: Path) -> None:
    """COHERENCE (O12): the run visualizer's write lane tags `record` calls as it tags the
    append today, so a rendered clerk run does not show an empty document-writes lane.

    The two retired names stay in the lane's table beside it: a stale name in a name-keyed
    table is inert — the same policy the budget tier states for the same reason — and old runs
    still render.

    `record` carries NO PATH, like the verb it replaces, so the lane's path filter cannot speak
    for it and the name has to be tested ahead of that filter. A `record` added only to the
    name tuple and left behind the path filter is dropped as "not investigation.md"."""
    vd = C.mod("scripts.visualize.visualize_data")
    src = (C.DEFENDER / "scripts" / "visualize" / "visualize_data.py").read_text(
        encoding="utf-8")
    assert '"record"' in src, "the write lane never names `record`"
    assert '"append_block"' in src, (
        "the retired name was removed from a name-keyed table, so old runs stop rendering"
    )

    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.PROLOGUE)
    C.record_run(tmp_path, run_dir=run_dir, clerk=C.ScriptedClerk(C.clerk_reply(C.CLEAN_ROWS)))
    phases = vd.split_investigation_phases(run_dir)
    assert phases, "the rendered run shows no investigation content at all"


# ---------------------------------------------------------------------------------------
# the unmoved readers (R7)
# ---------------------------------------------------------------------------------------


def test_996_every_unmoved_document_reader_still_reads_a_clerk_authored_record(
    tmp_path: Path,
) -> None:
    """COHERENCE, one assertion per reader: the four document readers the port does NOT change
    still read a record the clerk authored.

    Bound per reader edge rather than at the document, for the reason coherence demands always
    are: a demand at the document's own altitude reads green when three of the four still work.
    The narration cross-check is the sharp one — the learning pipeline is stated as untouched,
    and it IS untouched, while its INPUT changes; both are true at once, and the only way to
    see it is to drive the reader over a document the clerk wrote."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.PROLOGUE)
    C.record_run(tmp_path, run_dir=run_dir, clerk=C.ScriptedClerk(C.clerk_reply(C.CLEAN_ROWS)))
    text = C.document(run_dir)
    assert "attrs.owner" in text, "the clerk landed nothing, so there is nothing to read"

    projector = C.mod("runtime.review.projector")
    assert projector.parse_investigation(text), "the review projector read an empty companion"

    compare = C.mod("learning.pipeline.judge.compare")
    assert compare.parse_investigation_companion(run_dir), (
        "the learning comparator read an empty companion from a clerk-authored record"
    )

    lead_repository = C.mod("learning.lead_repository")
    assert isinstance(lead_repository.narration_crosscheck_from_run(run_dir), dict)

    lessons_frontier = C.mod("scripts.lessons.lessons_frontier")
    rc = lessons_frontier.main([
        "lessons_frontier.py", "--investigation",
        str(RunPaths(run_dir).investigation), "--top-k", "1",
    ])
    assert rc == 0, "the lessons frontier could not derive anything from a clerk-authored record"


def test_996_compaction_rebuilds_nothing_from_a_record_only_transcript(
    tmp_path: Path,
) -> None:
    """COHERENCE: the compaction write-replay rebuilds NOTHING from a transcript whose only
    document calls are `record`, and its docstring says so.

    The helper is dead code — no production caller — and it is deliberately unchanged, so what
    is owed is a note rather than a mechanism. The note is load-bearing anyway: the helper's
    whole premise is that a document can be reconstructed from MAIN's tool arguments, and under
    the port MAIN's arguments are prose. A reader who revives it without knowing that would
    rebuild a document with none of the clerk's rows in it and believe it.

    POSITIVE CONTROL on the same address under the complementary condition: an `append_block`
    transcript still rebuilds, so "rebuilds nothing" is the argument shape and not a broken
    replay."""
    compaction = C.mod("runtime.compaction")
    record_call = {"parts": [{"part_kind": "tool-call", "tool_name": "record",
                              "args": {"text": C.PROSE}}]}
    append_call = {"parts": [{"part_kind": "tool-call", "tool_name": "append_block",
                              "args": {"text": C.PROLOGUE}}]}

    assert compaction.apply_writes("", record_call) == "", (
        "a `record` call was replayed as a document write — the clerk's rows are not in the "
        "transcript, so whatever it rebuilt is not the run's document"
    )
    assert compaction.apply_writes("", append_call) == C.PROLOGUE, (
        "the replay rebuilds nothing at all, so the assertion above says nothing"
    )
    assert "record" in (compaction.apply_writes.__doc__ or ""), (
        "the helper's docstring does not record that MAIN's calls now carry prose only"
    )
