"""#1017 e2e: every writer of the queries table leaves rows keyed as declared, the read surface returns what the writer wrote, and the judge's leads view reads through the surface (and refuses a link at the table's name)."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

import json
import os
import re
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender._io import append_jsonl, read_jsonl_rows  # noqa: E402
from defender.learning.lead_repository import joined, load_queries  # noqa: E402
from defender.knowledge import _query_rules  # noqa: E402
from defender.runtime import record_query  # noqa: E402
from defender.runtime.record_query import QUERY_ROW_COLUMNS
from defender.knowledge._query_rules import ABOVE_GUARD_QUERY_ID
from defender.tests.support.learning.judge import _judge_921 as J
from defender.tests.e2e._replay_harness import (  # noqa: E402
    GOLDEN_AB3,
    VerbRecorder,
    materialize,
)
from defender.tests.e2e.test_855_model_named_systems import PARAMS, _bad_args  # noqa: E402
from defender.tests.e2e.test_pitfalls_input_823 import LEAD, _reduce, _run  # noqa: E402
from defender.tests.e2e.test_query_tool_611 import DONE, elastic_ok, q  # noqa: E402
from defender.tests.learning.core.test_1017_row_schema import (  # noqa: E402
    KEY_MARKER,
    SHA_MARKER,
    _lead_file,
    _row,
    _table,
)
from defender.tests.support.learning.core import _state1135

pytestmark = pytest.mark.e2e

HEX64 = re.compile(r"[0-9a-f]{64}")


def test_every_writer_of_the_table_leaves_rows_keyed_exactly_as_declared(tmp_path):
    """O6/D1 — a live run reaching all three `append_query_row` callers (an executed query, a failed reducer shim..."""
    run_dir = materialize(tmp_path / "live", GOLDEN_AB3)
    r = _run(tmp_path / "live", run_dir=run_dir, run_id="d1017-writers", turns=[
        q("elastic", "query", PARAMS), _reduce(run_dir),
        _bad_args("ghostone", verb="ghostverb"), DONE,
    ])
    kinds = {row["query_id"] for row in r.own_rows}
    assert kinds == {"elastic.query", _query_rules.BASH_SHIM_QUERY_ID, ABOVE_GUARD_QUERY_ID}, \
        f"the three writer paths did not all leave a row: {kinds}"
    for row in r.rows:
        assert tuple(row) == QUERY_ROW_COLUMNS, \
            f"{row['lead_id']}/{row['query_id']}: keys {tuple(row)} != the declared columns"


def test_the_surface_reads_system_key_and_payload_sha256_off_a_real_table(tmp_path):
    """O1/D2 — over a table a real run wrote, with coarsened rejections (a 64-hex `system_key`) and declared rows..."""
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


def test_records_off_the_surface_are_byte_for_byte_what_the_guard_reads_live(tmp_path):
    """O2/D2 — `[r.record() for r in load_queries(run_dir) if r.lead_id == LEAD]` is EXACTLY what the guard read..."""
    rec = VerbRecorder()
    r = _run(tmp_path, run_id="d1017-records", verbs=elastic_ok(rec), turns=[
        _bad_args("ghostone", verb="ghostverb"), q("ghosttwo", "ghostverb", PARAMS),
        q("elastic", "query", PARAMS), DONE,
    ])
    live = r.state.lead_rows(LEAD)
    on_file = [row for row in r.rows if row.get("lead_id") == LEAD]
    assert len(live) == 3, "the three calls did not all leave rows on the run's state"
    assert json.dumps(live) == json.dumps(on_file), \
        "the run's state and the file disagree — the guard read rows the file does not hold"
    records = [t.record() for t in load_queries(r.run_dir) if t.lead_id == LEAD]
    assert json.dumps(records) == json.dumps(live), \
        "the surface's records are not what the guard read live"


@pytest.fixture
def judge_roots(tmp_path, monkeypatch):
    """The three roots #921's suite points inside `tmp_path` — the runs base, the episodes root and the learning..."""
    monkeypatch.setenv(J.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(J.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    _state1135.set_state_dir(monkeypatch, tmp_path / "learning-state")


def _world_row(seq: int, **overrides) -> dict:
    """The unit suite's full row (`_row`, lead `l-001`) with a DISTINCTIVE value in every column the judge cannot..."""
    marked = {
        "params": {"native_query": f"PARAMS_MARKER_{seq}"},
        "raw_command": f"RAWCMD_MARKER_{seq}",
        "payload_digest": f"DIGEST_MARKER_{seq}",
    }
    return _row(seq, **{**marked, **overrides})


def _judge_world(tmp_path: Path, rows: list[dict], *, goal: str = "GOAL_MARKER"):
    """An accepted #947 episode whose graded world `b` carries `rows` as its archived `executed_queries.jsonl`..."""
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.oracle_row("b")], "c": []})
    base, _src = location_path(J.runs_base)(tmp_path)
    world = ep / "worlds" / J.world_id(ep, "b")
    _lead_file(world, goal)
    token = J.world_id(ep, "b")
    _table(world, rows)
    J.write_call_join(world, [J.call_join_entry(r["lead_id"], int(r["seq"]), f"{token}/{i + 1}")
                              for i, r in enumerate(rows)])
    return ep, base, world


def _leads_view(ep: Path, base: Path):
    """The per-lead chain and the rendered leads view — the address every O3 claim is made at, off the REAL..."""
    from defender.learning.judge import layout, run
    from defender.tests.learning.judge.contrast_contracts import _spec1234 as S34

    ctx = S34.render_context(ep, "b")
    manifest = J.read_manifest_at(ep)
    prompt, _placed = run._build_prompt(ctx, manifest)
    title = f"world b — {layout.FOCUS_VIEW_TITLES['leads']}"
    start = prompt.index(title)
    end = prompt.find("world b — ", start + len(title))
    return ctx.focus.leads, prompt[start:end if end != -1 else len(prompt)]


def test_the_judges_leads_view_carries_no_column_it_cannot_act_on(tmp_path, judge_roots):
    """O3/D3 — a world whose rows carry `system_key`, `payload_sha256`, `payload_path`, `raw_command`,..."""
    rows = [
        _world_row(0, system_key=KEY_MARKER),
        _world_row(1, exit_code=7, error_class="ERRCLASS_MARKER", payload_status="error"),
    ]
    ep, base, _world = _judge_world(tmp_path, rows)
    leads, text = _leads_view(ep, base)

    chain = leads["l-001"]
    chain_keys = {"goal", "params", "payload", "summary", "resolutions", "refused"}
    assert set(chain) == chain_keys, \
        f"the per-lead chain carries {sorted(set(chain) ^ chain_keys)} beyond/short of the pin"
    assert chain["refused"] == [], "a lead with no refusal carries a refused entry"
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
    """D3 — the lstat gate is the SURFACE's (`load_queries_report`), refusing the table's rows and nothing else:"""
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
    judge = J.scripted_judge()
    J.grade(ep, judge=judge)
    row_b = J.world_rows(J.judge_record(ep))["b"]
    assert row_b.get("malformed") is True, f"the judge read a link at the table's name: {row_b}"
    assert "executed_queries.jsonl" in str(row_b.get("ungradable_reason")), row_b
    assert judge.prompts, "control: the pass asked the judge about the other worlds"
    for prompt in judge.prompts:
        assert "LINKED_PARAMS" not in prompt, "the judge followed a link at the table's name"
        assert "LINKED_DIGEST" not in prompt

    ep0, base0, world0 = _judge_world(tmp_path / "tableless", [])
    (world0 / "executed_queries.jsonl").unlink()
    # #1234 A3 (spec AM15 `missing-query-table`): a missing query table is a missing required
    # input — the world is ungradable, naming the table, and never reaches the judge.
    judge0 = J.scripted_judge()
    J.grade(ep0, judge=judge0)
    row0 = J.world_rows(J.judge_record(ep0))["b"]
    assert row0.get("ungradable") is True, f"a world without a table was graded: {row0}"
    assert "executed_queries.jsonl" in str(row0.get("ungradable_reason")), row0
    assert not [a for a in judge0.agent_ids if a.startswith(f"judge:{J.world_id(ep0, 'b')}:")], judge0.agent_ids

    ep2, base2, _world2 = _judge_world(tmp_path / "regular", target_rows)
    leads2, text2 = _leads_view(ep2, base2)
    assert leads2["l-001"]["params"] == {"native_query": "LINKED_PARAMS"}
    assert leads2["l-001"]["payload"] == ["LINKED_DIGEST"]
    assert "LINKED_PARAMS" in text2
    assert "LINKED_DIGEST" in text2


def test_the_judges_chain_is_the_surfaces_own_reading_on_a_row_that_stresses_every_coercion(
    tmp_path, judge_roots,
):
    """D3/N8/O1 — the chain is compared against `lead_repository.joined` ITSELF, not against literals, over rows..."""
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
