"""#1017 end to end — one row schema, one read surface, and a judge that dumps no row.

THE ROOT. The queries row's shape was spelled by hand in more than one place — the writer
(`record_query.append_query_row`), the second writer (`lead_zero._record_manual_row`), the read
surface (`lead_repository.QueryRow`) and the judge's own raw grouping of the table (a private
reader the judge kept beside the surface, since deleted) — so a column added at the writer
reached a reader only when someone remembered each list. `system_key` (#871) reached none of
them, and it is half the rejection guard's identity: an auditor who reconstructs a run's dead
ends THE WAY THE REPO TELLS THEM TO (through the surface) sees three sentinel rows keyed alike
and concludes the guard should have tripped where the live run ran on.

WHAT IS DRIVEN, and why live rather than over hand-built rows: every claim below is about what a
REAL writer leaves on disk, what the REAL surface reads back off it, or what the REAL judge render
puts in a prompt. Everything between the replay models and the assertions is production code; the
fakes are the harness's own (`FakeVerbs`).

The registry-cannot-list arms this file once carried (#1017 D4) are gone with the apparatus they
drove: #1031 fixes the roster at registry construction, so "the registry cannot list" is a
construction-time fault and never a per-call one (`tests/test_1031_roster_snapshot.py`).
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender._io import append_jsonl, read_jsonl_rows  # noqa: E402
from defender._run_paths import RunPaths  # noqa: E402
from defender.learning.lead_repository import joined, load_queries  # noqa: E402
from defender.runtime import lead_zero  # noqa: E402
from defender.runtime.circuit_breaker import AGENT_FIXABLE_ERROR_CLASS  # noqa: E402
from defender.scripts.gather_tools import record_query  # noqa: E402
from defender.scripts.gather_tools.record_query import (  # noqa: E402
    ABOVE_GUARD_QUERY_ID,
    QUERY_ROW_COLUMNS,
)
from defender.tests import _judge_921 as J  # noqa: E402
from defender.tests.e2e._replay_harness import (  # noqa: E402
    DEFENDER,
    GOLDEN_AB3,
    VerbRecorder,
    materialize,
)
from defender.tests.e2e.test_855_model_named_systems import PARAMS, _bad_args  # noqa: E402
from defender.tests.e2e.test_pitfalls_input_823 import LEAD, _reduce, _run  # noqa: E402
from defender.tests.e2e.test_query_tool_611 import DONE, ROW_KEYS, elastic_ok, q  # noqa: E402
# The companion guard's replay oracle, imported rather than re-written: O2 is the claim that a
# replay built from the SURFACE reaches the live verdict, and a second copy of the oracle here
# could only ever agree with itself.
from defender.tests.e2e.test_repeat_breaker_807 import _replay_rejections  # noqa: E402
# The unit suite's fixtures for the same schema — the row literal, the markers no real value
# hashes to, and the two run-dir builders — imported rather than re-spelled: a fifteenth
# column is then added to ONE fixture row, not to one per suite.
from defender.tests.test_1017_row_schema import (  # noqa: E402
    KEY_MARKER,
    SHA_MARKER,
    _lead_file,
    _row,
    _table,
)

pytestmark = pytest.mark.e2e

HEX64 = re.compile(r"[0-9a-f]{64}")


def _corrected(rec: VerbRecorder) -> int:
    """How many calls reached a backend — the corrected `q("elastic", "query", …)` turn every
    scenario ends on, which proves the lead ran on past its rejections."""
    return len(rec.calls)


# ---------------------------------------------------------------------------------------
# O6 / D1 — one constructor, every writer
# ---------------------------------------------------------------------------------------


def test_every_writer_of_the_table_leaves_rows_keyed_exactly_as_declared(tmp_path):
    """O6/D1 — a live run reaching all three `append_query_row` callers (an executed query, a
    failed reducer shim on the bash lane, an above-guard rejection) plus lead-0's own row, and
    `lead_zero._record_manual_row` driven directly: EVERY row's key tuple — order included —
    equals `record_query.QUERY_ROW_COLUMNS`. Order too, because one constructor leaves one byte
    order and two hand-spelled literals that agree on the SET can still differ on it.

    Observed failing by: the declaration missing, or a writer whose row keys (or their order)
    differ from it — `_record_manual_row`'s inline dict is the writer this exists for."""
    run_dir = materialize(tmp_path / "live", GOLDEN_AB3)
    r = _run(tmp_path / "live", run_dir=run_dir, run_id="d1017-writers", turns=[
        q("elastic", "query", PARAMS), _reduce(run_dir),
        _bad_args("ghostone", verb="ghostverb"), DONE,
    ])
    kinds = {row["query_id"] for row in r.own_rows}
    assert kinds == {"elastic.query", record_query.BASH_SHIM_QUERY_ID, ABOVE_GUARD_QUERY_ID}, \
        f"the three writer paths did not all leave a row: {kinds}"
    assert any(row["lead_id"] in lead_zero.RESERVED_LEAD_IDS for row in r.rows), \
        "lead-0 left no row, so the universal below does not reach its writer"
    for row in r.rows:
        assert tuple(row) == QUERY_ROW_COLUMNS, \
            f"{row['lead_id']}/{row['query_id']}: keys {tuple(row)} != the declared columns"

    manual = materialize(tmp_path / "manual", GOLDEN_AB3)
    lead_zero._record_manual_row(
        lead_zero._CaptureDeps(
            run_dir=manual, defender_dir=DEFENDER, run_id="d1017-second-writer",
            lead_id="l-000",
        ),
        "search", {"index": "logs"}, {"rows": [{"a": 1}]}, exit_code=0,
    )
    rows = record_query.lead_rows(manual, "l-000")
    assert len(rows) == 1, "the second writer left no row"
    assert tuple(rows[0]) == QUERY_ROW_COLUMNS, \
        "the second writer's row is keyed (or ordered) differently from the declaration"


def test_the_suites_frozen_key_set_is_the_writers_declaration():
    """O6/D1 — `test_query_tool_611.ROW_KEYS`, the set eight suites assert `set(row) ==`
    against, equals `set(QUERY_ROW_COLUMNS)`, so the two spellings of the contract cannot
    drift: a fifteenth column declared at the writer fails here until the suite's set follows.

    Observed failing by: the two disagreeing."""
    assert set(QUERY_ROW_COLUMNS) == ROW_KEYS


# ---------------------------------------------------------------------------------------
# O1 / D2 — the surface reads what the writer wrote
# ---------------------------------------------------------------------------------------


def test_the_surface_reads_system_key_and_payload_sha256_off_a_real_table(tmp_path):
    """O1/D2 — over a table a real run wrote, with coarsened rejections (a 64-hex `system_key`)
    and declared rows (`""`) side by side, `load_queries` returns rows whose `system_key` and
    `payload_sha256` equal the raw line's, row by row. The positive controls are on the same
    table: the ghost rows' digests ARE non-empty 64-hex and the declared rows' keys ARE `""`,
    so the equality is over two distinct values and not over a column that is always empty.

    Observed failing by: a row with a non-empty `system_key` on disk whose `QueryRow` reads it
    as anything else."""
    rec = VerbRecorder()
    r = _run(tmp_path, run_id="d1017-surface", verbs=elastic_ok(rec), turns=[
        _bad_args("ghostone", verb="ghostverb"), _bad_args("elastic", verb="ghostverb"),
        q("elastic", "query", PARAMS), DONE,
    ])
    raw = r.rows
    typed = load_queries(r.run_dir)
    assert [t.lead_id for t in typed] == [row["lead_id"] for row in raw], \
        "the surface returns a different row set from the table"
    for row, t in zip(raw, typed, strict=True):
        assert t.seq == row["seq"]
        assert t.system_key == row["system_key"], \
            f"seq {row['seq']}: the surface reads system_key {t.system_key!r}, the table holds " \
            f"{row['system_key']!r}"
        assert t.payload_sha256 == row["payload_sha256"], \
            f"seq {row['seq']}: the surface's payload_sha256 differs from the table's"

    own = [t for t in typed if t.lead_id == LEAD]
    assert [t.exit_code for t in own] == [64, 64, 0]
    assert HEX64.fullmatch(own[0].system_key), \
        "the ghost's row carries no digest, so the equality above is over an always-empty column"
    assert own[0].system_key == record_query.system_fingerprint("ghostone", "")
    assert [t.system_key for t in own[1:]] == ["", ""], \
        "a declared system's row was fingerprinted — the complementary condition is missing"
    assert all(HEX64.fullmatch(t.payload_sha256) for t in own), \
        "a row's payload_sha256 is not the 64-hex the writer derives"


# ---------------------------------------------------------------------------------------
# O2 / D2 — a replay through the surface reaches the live verdict
# ---------------------------------------------------------------------------------------


def test_records_off_the_surface_are_byte_for_byte_what_the_guard_reads_live(tmp_path):
    """O2/D2 — `[r.record() for r in load_queries(run_dir) if r.lead_id == LEAD]` is EXACTLY
    `record_query.lead_rows(run_dir, LEAD)`: same dicts, same order. `lead_rows` is the guard's
    own live reader (N2), so this is the whole of what lets an offline replay hand the guard's
    predicates what the run handed them.

    Observed failing by: `record()` missing, or any key/value/order difference."""
    rec = VerbRecorder()
    r = _run(tmp_path, run_id="d1017-records", verbs=elastic_ok(rec), turns=[
        _bad_args("ghostone", verb="ghostverb"), q("ghosttwo", "ghostverb", PARAMS),
        q("elastic", "query", PARAMS), DONE,
    ])
    live = record_query.lead_rows(r.run_dir, LEAD)
    assert len(live) == 3, "the three calls did not all leave rows"
    assert [t.record() for t in load_queries(r.run_dir) if t.lead_id == LEAD] == live


def test_the_replay_through_the_surface_agrees_with_the_live_run(tmp_path):
    """O2 end to end — `test_855`'s replay parity, driven through the SURFACE instead of over
    raw dicts: the companion guard's oracle over `[r.record() for r in load_queries(...)]`
    reaches the live verdict on BOTH tables — the distinct-ghost lead that ran on (no trip)
    and the same-ghost lead the guard ended at seq 2. Both, on purpose: an oracle fed rows that
    lost `system_key` agrees on the same-ghost table (three `""` keys still match) and trips
    the distinct-ghost table where the run ran on, and one fed rows that INVENTED keys does the
    reverse.

    Observed failing by: the two verdicts differing on either table."""
    rec = VerbRecorder()
    distinct = _run(tmp_path / "distinct", run_id="d1017-replay-on", verbs=elastic_ok(rec),
                    turns=[
                        _bad_args("ghostone"), _bad_args("ghosttwo"), _bad_args("ghostthree"),
                        q("elastic", "query", PARAMS), DONE,
                    ])
    same = _run(tmp_path / "same", run_id="d1017-replay-trip", turns=[
        _bad_args("ghostone"), _bad_args("ghostone"), _bad_args("ghostone"), DONE,
    ])
    assert _corrected(rec) == 1, "the distinct-ghost lead did not run on — wrong table"
    assert [row["exit_code"] for row in same.own_rows] == [64, 64, 64]
    assert "turned back at seq" in same.own_rows[-1]["payload_digest"], \
        "the same-ghost lead did not end on the guard — wrong table"

    assert _replay_rejections([t.record() for t in load_queries(distinct.run_dir)]) == [], \
        "a replay through the surface refuses a lead the live run let run on"
    assert _replay_rejections([t.record() for t in load_queries(same.run_dir)]) \
        == [(LEAD, 2, "repeat")], \
        "a replay through the surface misses the trip the live run took"
    # And the same answer the raw-dict oracle gives, on both — O2 is parity with the run, and
    # parity with the reader the run's guard uses is how that is measured.
    for r in (distinct, same):
        assert _replay_rejections([t.record() for t in load_queries(r.run_dir)]) \
            == _replay_rejections(r.rows)


def test_a_pre_871_table_replays_the_same_through_the_surface_as_over_raw_rows(tmp_path):
    """O2 — a table recorded before `system_key` existed (no such key on any row) replays
    through the surface exactly as over the raw dicts: three rejections of one coarsened ghost
    trip at seq 2 both ways. The surface's `""` coercion is what makes the typed view agree
    with the guard; `record()` handing the guard the key-less dict is what makes the replay
    agree with the run.

    Observed failing by: a surface that reads absent as `None` and hands a re-projection to
    the oracle (no row matches, no trip), or one that invents `""` into the record."""
    rows = [
        {
            "lead_id": LEAD, "seq": seq, "system": "", "verb": "query",
            "query_id": ABOVE_GUARD_QUERY_ID, "params": {"native_query": "FROM logs"},
            "raw_command": "'' query 'native_query=FROM logs'",
            "payload_path": f"gather_raw/{LEAD}/{seq}.json", "exit_code": 64,
            "error_class": AGENT_FIXABLE_ERROR_CLASS, "payload_status": "error",
            "payload_digest": "exit=64; unresolvable: an undeclared system",
        }
        for seq in range(3)
    ]
    append_jsonl(RunPaths(tmp_path).executed_queries, rows)
    raw = read_jsonl_rows(RunPaths(tmp_path).executed_queries)
    assert all("system_key" not in row for row in raw), "the fixture grew the column"

    surface = [t.record() for t in load_queries(tmp_path)]
    assert all("system_key" not in rec for rec in surface), \
        "the surface invented the column into a record the run never wrote"
    assert _replay_rejections(raw) == [(LEAD, 2, "repeat")], "the raw oracle no longer trips"
    assert _replay_rejections(surface) == _replay_rejections(raw)


# ---------------------------------------------------------------------------------------
# O3 / D3 — the judge reads the surface and dumps no row
# ---------------------------------------------------------------------------------------

@pytest.fixture
def judge_roots(tmp_path, monkeypatch):
    """The three roots #921's suite points inside `tmp_path` — the runs base, the episodes
    root and the learning state dir — so a render here reads nothing of the checkout's."""
    monkeypatch.setenv(J.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(J.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    monkeypatch.setenv(J.STATE_DIR_ENV, str(tmp_path / "learning-state"))


def _world_row(seq: int, **overrides) -> dict:
    """The unit suite's full row (`_row`, lead `l-001`) with a DISTINCTIVE value in every
    column the judge cannot act on, so each can be searched for in the rendered leads
    section. One row literal for the schema, in the unit module; this is a re-marking of it."""
    marked = {
        "params": {"native_query": f"PARAMS_MARKER_{seq}"},
        "raw_command": f"RAWCMD_MARKER_{seq}",
        "payload_digest": f"DIGEST_MARKER_{seq}",
    }
    return _row(seq, **{**marked, **overrides})


def _judge_world(tmp_path: Path, rows: list[dict], *, goal: str = "GOAL_MARKER"):
    """An accepted #947 episode whose graded world `b` carries `rows` as its archived
    `executed_queries.jsonl` and `goal` on lead `l-001`'s `.lead.json` — the two files
    `lead_repository.joined` reads off a run-dir-shaped tree (C10), written through the unit
    suite's own builders (`_table`, `_lead_file`), since the world dir IS run-dir shaped.
    Returns `(episode_dir, runs_base, world_dir)`."""
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []})
    base, _src = J.runs_base(tmp_path)
    world = ep / "worlds" / "b"
    _lead_file(world, goal)
    _table(world, rows)
    return ep, base, world


def _leads_view(ep: Path, base: Path):
    """The per-lead chain and the rendered leads section — the address every O3 claim is
    made at, off the REAL `render` with the runs base seam pointed at this test's own."""
    judge_input = J.mod("learning.judge.render").render(ep, "b", runs_base=base)
    return judge_input.leads, judge_input.as_prompt_sections()["leads"]


def test_the_judges_leads_view_carries_no_column_it_cannot_act_on(tmp_path, judge_roots):
    """O3/D3 — a world whose rows carry `system_key`, `payload_sha256`, `payload_path`,
    `raw_command`, `exit_code` and `error_class` with distinctive values: NONE of those values,
    and none of those key names (nor `document_rows`), reaches `as_prompt_sections()["leads"]`.
    The positive controls are on the SAME string: the lead's goal, its first query's params and
    every query's payload digest DO appear — VIEW 1's semantic content (N5) is intact, so the
    negatives are not satisfied by an empty section.

    The chain itself keeps `goal/params/payload/summary/resolutions` and drops `document_rows`.

    Observed failing by: any marker or key name in the leads section — today the whole row is
    stringified under `- document_rows:`."""
    rows = [
        _world_row(0, system_key=KEY_MARKER),
        _world_row(1, exit_code=7, error_class="ERRCLASS_MARKER", payload_status="error"),
    ]
    ep, base, _world = _judge_world(tmp_path, rows)
    leads, text = _leads_view(ep, base)

    chain = leads["l-001"]
    assert set(chain) == {"goal", "params", "payload", "summary", "resolutions"}, \
        f"the per-lead chain carries {sorted(set(chain) - {'goal', 'params', 'payload', 'summary', 'resolutions'})}"
    assert chain["goal"] == "GOAL_MARKER"
    assert chain["params"] == {"native_query": "PARAMS_MARKER_0"}
    assert chain["payload"] == ["DIGEST_MARKER_0", "DIGEST_MARKER_1"]

    # Positive control first: the section says what it is for.
    for kept in ("GOAL_MARKER", "PARAMS_MARKER_0", "DIGEST_MARKER_0", "DIGEST_MARKER_1"):
        assert kept in text, f"the leads view lost {kept!r} — VIEW 1's own content"
    for dropped in (
        KEY_MARKER, SHA_MARKER, "RAWCMD_MARKER_0", "RAWCMD_MARKER_1", "ERRCLASS_MARKER",
        "gather_raw/l-001/0.json", "gather_raw/l-001/1.json",
        "document_rows", "system_key", "payload_sha256", "payload_path", "raw_command",
        "error_class", "exit_code",
    ):
        assert dropped not in text, f"{dropped!r} reached the judge's prompt"


def test_the_judge_still_refuses_a_link_at_the_tables_name(tmp_path, judge_roots):
    """D3 — the lstat gate is the SURFACE's (`load_queries_report`), refusing the table's rows
    and nothing else: a world whose `executed_queries.jsonl` is a SYMLINK to a real table
    elsewhere renders a lead with no params and no payload — AND WITH ITS GOAL, which comes
    off the lead file the same surface read behind its own gate — while the SAME table as a
    regular file (the positive control, same rows, same lead) renders all three. A world with
    NO table at all (the shape `archive.py` records for "the run produced none") keeps its
    goal the same way. `read_jsonl_rows` FOLLOWS a link, so a surface that dropped the check
    would put another tree's rows into VIEW 1 as this world's own conduct; a judge that gated
    the whole join on the table, as it first did, told the judge `goal: None` for every lead
    of such a world.

    Observed failing by: the linked world's chain carrying the target's params or digests, or
    either refused world's chain losing its goal."""
    target_rows = [_world_row(0, params={"native_query": "LINKED_PARAMS"},
                              payload_digest="LINKED_DIGEST")]
    elsewhere = tmp_path / "elsewhere" / "executed_queries.jsonl"
    append_jsonl(elsewhere, target_rows)

    ep, base, world = _judge_world(tmp_path / "linked", [])
    table = world / "executed_queries.jsonl"
    table.unlink()
    os.symlink(elsewhere, table)
    assert table.is_symlink(), "the fixture did not plant a link"
    assert read_jsonl_rows(table) == target_rows, \
        "the link does not resolve to the planted table, so the refusal below is vacuous"
    leads, text = _leads_view(ep, base)
    assert leads["l-001"]["params"] is None, "the judge followed a link at the table's name"
    assert leads["l-001"]["payload"] == []
    assert leads["l-001"]["goal"] == "GOAL_MARKER", \
        "refusing the table cost the lead its goal, which the lead file carries"
    assert "LINKED_PARAMS" not in text
    assert "LINKED_DIGEST" not in text
    assert "GOAL_MARKER" in text

    ep0, base0, world0 = _judge_world(tmp_path / "tableless", [])
    (world0 / "executed_queries.jsonl").unlink()
    leads0, text0 = _leads_view(ep0, base0)
    assert leads0["l-001"] == {**leads0["l-001"], "goal": "GOAL_MARKER", "params": None,
                               "payload": []}, \
        f"a world without a table lost its lead's goal: {leads0['l-001']!r}"
    assert "GOAL_MARKER" in text0

    ep2, base2, _world2 = _judge_world(tmp_path / "regular", target_rows)
    leads2, text2 = _leads_view(ep2, base2)
    assert leads2["l-001"]["params"] == {"native_query": "LINKED_PARAMS"}
    assert leads2["l-001"]["payload"] == ["LINKED_DIGEST"]
    assert "LINKED_PARAMS" in text2
    assert "LINKED_DIGEST" in text2


def test_where_the_surface_and_the_old_raw_grouping_disagree_the_surface_wins(tmp_path, judge_roots):
    """D3/N8 — the judge keeps no private reading of a row. Rows for one lead written in a
    FILE order that is not seq order: `params` is the seq-0 row's (the surface's order), not
    the first-in-file row's (the old grouping's); `payload` lists digests in seq order; a
    non-dict `params` reads as `{}` (the surface's coercion) rather than the raw value; and a
    `∅.` sentinel row's digest is not among the payloads (the split both readers agree on —
    kept as the control that the sentinel partition survived the move).

    Observed failing by: `params` being the first-in-file row's, or the raw non-dict value."""
    rows = [
        _world_row(1, params={"native_query": "SECOND_IN_SEQ"}, payload_digest="DIGEST_SEQ1"),
        _world_row(2, query_id=ABOVE_GUARD_QUERY_ID, exit_code=64,
                   error_class=AGENT_FIXABLE_ERROR_CLASS, payload_status="error",
                   payload_digest="SENTINEL_DIGEST"),
        _world_row(0, params={"native_query": "FIRST_IN_SEQ"}, payload_digest="DIGEST_SEQ0"),
    ]
    ep, base, _world = _judge_world(tmp_path / "order", rows)
    leads, text = _leads_view(ep, base)
    assert leads["l-001"]["params"] == {"native_query": "FIRST_IN_SEQ"}, \
        "the judge shows the first row IN THE FILE, not the lead's first query"
    assert leads["l-001"]["payload"] == ["DIGEST_SEQ0", "DIGEST_SEQ1"]
    assert "SENTINEL_DIGEST" not in text, "a refusal record reached VIEW 1 as a payload"
    assert "DIGEST_SEQ0" in text
    assert "DIGEST_SEQ1" in text

    ep2, base2, _w = _judge_world(tmp_path / "params", [
        _world_row(0, params="PARAMS_NOT_A_DICT", payload_digest="DIGEST_NONDICT"),
    ])
    leads2, text2 = _leads_view(ep2, base2)
    assert leads2["l-001"]["params"] == {}, \
        "the judge shows a raw non-dict params the surface coerces away"
    assert "PARAMS_NOT_A_DICT" not in text2
    assert "DIGEST_NONDICT" in text2, "the row was dropped rather than read the surface's way"


def test_the_judges_chain_is_the_surfaces_own_reading_on_a_row_that_stresses_every_coercion(
    tmp_path, judge_roots,
):
    """D3/N8/O1 — the chain is compared against `lead_repository.joined` ITSELF, not against
    literals, over rows whose every coerced column is non-canonical at once: a string `seq`,
    an integer `payload_digest`, a non-dict `params`, and a lead file with no `goal` key (the
    surface reads that as `""`; a private `.lead.json` read returned `None`). A private
    grouping that re-implemented the two coercions the literal test enumerated (adversary H5)
    drifts from the surface on at least one of these; the only reader that agrees on all of
    them is the surface.

    Observed failing by: any link of the chain differing from the surface's reading."""
    stressed = _world_row(1, params="not-a-dict", payload_digest=5)
    stressed["seq"] = "1"
    rows = [
        stressed,
        _world_row(0, params={"native_query": "SEQ_ZERO"}, payload_digest="DIGEST_0"),
    ]
    ep, base, world = _judge_world(tmp_path, rows)
    (world / "gather_raw" / "l-001.lead.json").write_text(
        json.dumps({"what_to_summarize": ["auth events"]}), encoding="utf-8")
    leads, text = _leads_view(ep, base)
    surface = {lead.lead_id: lead for lead in joined(world)}["l-001"]
    assert len(surface.queries) == 2, "the surface dropped a stressed row — the claim is vacuous"

    chain = leads["l-001"]
    assert chain["goal"] == surface.goal
    assert chain["goal"] == "", "the surface reads an absent goal as \"\"; the judge did not"
    assert chain["params"] == surface.queries[0].params == {"native_query": "SEQ_ZERO"}
    assert chain["payload"] == [q.payload_digest for q in surface.queries] == ["DIGEST_0", "5"]
    assert "not-a-dict" not in text
    assert "SEQ_ZERO" in text

