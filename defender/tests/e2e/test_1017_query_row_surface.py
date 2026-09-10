"""#1017 end to end — one row schema, one read surface, a judge that dumps no row, and a
registry that cannot list recorded as the infra fault it is.

THE ROOT. The queries row's shape was spelled by hand in more than one place — the writer
(`record_query.append_query_row`), the second writer (`lead_zero._record_manual_row`), the read
surface (`lead_repository.QueryRow`) and the judge's raw dump (`render._queries_by_lead`) — so a
column added at the writer reached a reader only when someone remembered each list. `system_key`
(#871) reached none of them, and it is half the rejection guard's identity: an auditor who
reconstructs a run's dead ends THE WAY THE REPO TELLS THEM TO (through the surface) sees three
sentinel rows keyed alike and concludes the guard should have tripped where the live run ran on.

THE CODE DOES NOT EXIST YET. The names #1017's design fixes — `record_query.QUERY_ROW_COLUMNS`,
`QueryRow.system_key` / `.payload_sha256` / `.record()`, `query_tool.RegistryUnavailable`,
`query_tool.REGISTRY_BREAKER_KEY` — are imported INSIDE the tests that need them, so a missing
target is one failure per test rather than one collection error hiding the other assertions.

WHAT IS DRIVEN, and why live rather than over hand-built rows: every claim below is about what a
REAL writer leaves on disk, what the REAL surface reads back off it, what the REAL judge render
puts in a prompt, or what the REAL `QueryCapture` records when its registry raises. Everything
between the replay models and the assertions is production code; the fakes are the harness's own
(`FakeVerbs`, subclassed once here to make `systems()` raise the one fault the repo has already
observed against the real registry — `PermissionError(13, "Permission denied")`, the fault
`tests/test_869_parity.py::_RaisingRegistry` injects).

D4 IN ONE PARAGRAPH. `_system_of_record` used to swallow a registry that could not list and answer
`""`, so a DECLARED system's above-guard rejection was recorded with `system=""` and
`system_key=sha256("elastic")` — a fingerprint of a real name, which `system_fingerprint`'s own
contract forbids, keyed on a string the guard would then count as a ghost; the only trace was a
stderr line no reader consults. Now the registry raises `RegistryUnavailable`, both above-guard
placements catch it and take the adapter-load branch's path: breaker check, then an `infra`
row (exit `DEFAULT_FAULT_EXIT`) carrying the model's RAW string as `system` and `system_key=""`,
keyed on the host constant `REGISTRY_BREAKER_KEY` — never on the model's string, which for an
empty or unreadable system the breaker skips (C17). The model still receives its ORIGINAL
rejection. No guard is consulted, so no fingerprint is minted on this path at all (O4).
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender._io import append_jsonl, read_jsonl_rows, read_text_utf8  # noqa: E402
from defender._run_paths import RunPaths  # noqa: E402
from defender.learning.lead_repository import load_queries  # noqa: E402
from defender.learning.leads.lead_extraction import collect_general_failures  # noqa: E402
from defender.runtime import lead_zero  # noqa: E402
from defender.runtime.circuit_breaker import (  # noqa: E402
    AGENT_FIXABLE_ERROR_CLASS,
    INFRA_ERROR_CLASS,
    PER_SYSTEM_FAIL_LIMIT,
    RUN_FAIL_KILL_LIMIT,
)
from defender.runtime.query_tool import DEFAULT_FAULT_EXIT, QueryCapture  # noqa: E402
from defender.runtime.verb_grant import DENY_ALL  # noqa: E402
from defender.runtime.verbs import ModuleVerbRegistry  # noqa: E402
from defender.scripts.adapters.faults import TransportFault  # noqa: E402
from defender.scripts.gather_tools import record_query  # noqa: E402
from defender.scripts.gather_tools.record_query import ABOVE_GUARD_QUERY_ID  # noqa: E402
from defender.tests import _judge_921 as J  # noqa: E402
from defender.tests._declared869 import write  # noqa: E402
from defender.tests.e2e._replay_harness import (  # noqa: E402
    DEFENDER,
    GOLDEN_AB3,
    FakeVerbs,
    VerbRecorder,
    materialize,
)
from defender.tests.e2e.test_855_model_named_systems import (  # noqa: E402
    PARAMS,
    PHANTOM,
    ZERO_WIDTH,
    _bad_args,
    _detail,
)
from defender.tests.e2e.test_pitfalls_input_823 import LEAD, _Res, _reduce, _run  # noqa: E402
from defender.tests.e2e.test_query_tool_611 import DONE, ROW_KEYS, elastic_ok, q, raising  # noqa: E402
# The companion guard's replay oracle, imported rather than re-written: O2 is the claim that a
# replay built from the SURFACE reaches the live verdict, and a second copy of the oracle here
# could only ever agree with itself.
from defender.tests.e2e.test_repeat_breaker_807 import _replay_rejections  # noqa: E402
from defender.tests.test_869_parity import _RaisingRegistry  # noqa: E402

pytestmark = pytest.mark.e2e

#: The fault the registry raises here — the SAME one `_RaisingRegistry` raises, and the one
#: #869's C16/G8 executed against the real `ModuleVerbRegistry` (a filesystem error while
#: globbing / resolving the adapters dir; C15 records that nothing else can raise there).
REGISTRY_FAULT = PermissionError(13, "Permission denied")

HEX64 = re.compile(r"[0-9a-f]{64}")


class _RegistryCannotList(FakeVerbs):
    """A verb registry whose LISTING is broken and whose verbs are not: the drop-in for
    `ModuleVerbRegistry` on a box whose adapters dir cannot be globbed. Built from a healthy
    fake's own table so that every grant, every verb signature and every recorded call is the
    same as the healthy run's — the ONLY difference between the two arms of each test below is
    `systems()`. It classifies nothing and decides nothing: the row, the breaker key and the
    model's answer are all production code's."""

    def __init__(self, healthy: FakeVerbs):
        super().__init__({s: healthy.verbs(s) for s in healthy.systems()})

    def systems(self) -> tuple[str, ...]:
        raise REGISTRY_FAULT


def _breaker(r: _Res) -> dict:
    p = r.run_dir / "circuit_breaker.json"
    return json.loads(read_text_utf8(p)) if p.is_file() else {}


def _above_guard_rows(rows: list[dict]) -> list[dict]:
    """Every row an above-guard writer left — BOTH classes, since D4 is precisely about the
    `infra` half `record_query.in_rejection_domain` excludes."""
    return [row for row in rows if row.get("query_id") == ABOVE_GUARD_QUERY_ID]


def _registry_rows(rows: list[dict]) -> list[dict]:
    """The rows the registry-cannot-list path wrote: above-guard AND `infra`."""
    return [row for row in _above_guard_rows(rows) if row.get("error_class") == INFRA_ERROR_CLASS]


def _assert_nothing_printed(err: str) -> None:
    """D4: the ROW is the trace, and nothing about the registry fault reaches stderr. Asserted
    on the FAULT'S OWN TEXT — the exception class and its message, which any print of the
    fault must carry however it is worded or prefixed — rather than on the old line's
    `[query_tool]` / "could not list" spelling, which a reworded print would not contain."""
    for named in ("PermissionError", "Permission denied", "[query_tool]"):
        assert named not in err, \
            f"the registry fault is still reported on stderr instead of the row: {err!r}"


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
    from defender.scripts.gather_tools.record_query import QUERY_ROW_COLUMNS

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
    from defender.scripts.gather_tools.record_query import QUERY_ROW_COLUMNS

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

KEY_MARKER = "c0ffee" * 10 + "abcd"
SHA_MARKER = "5ha256" * 10 + "feed"


@pytest.fixture
def judge_roots(tmp_path, monkeypatch):
    """The three roots #921's suite points inside `tmp_path` — the runs base, the episodes
    root and the learning state dir — so a render here reads nothing of the checkout's."""
    monkeypatch.setenv(J.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(J.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    monkeypatch.setenv(J.STATE_DIR_ENV, str(tmp_path / "learning-state"))


def _world_row(seq: int, **overrides) -> dict:
    """One archived-world queries row carrying a DISTINCTIVE value in every column the judge
    cannot act on, so each can be searched for in the rendered leads section."""
    row = {
        "lead_id": "l-001", "seq": seq, "system": "elastic", "verb": "query",
        "query_id": "elastic.ad-hoc", "params": {"native_query": f"PARAMS_MARKER_{seq}"},
        "raw_command": f"RAWCMD_MARKER_{seq}", "payload_path": f"gather_raw/l-001/{seq}.json",
        "exit_code": 0, "error_class": None, "payload_status": "ok",
        "payload_digest": f"DIGEST_MARKER_{seq}", "payload_sha256": SHA_MARKER,
        "system_key": "",
    }
    row.update(overrides)
    return row


def _judge_world(tmp_path: Path, rows: list[dict], *, goal: str = "GOAL_MARKER"):
    """An accepted #947 episode whose graded world `b` carries `rows` as its archived
    `executed_queries.jsonl` and `goal` on lead `l-001`'s `.lead.json` — the two files
    `lead_repository.joined` reads off a run-dir-shaped tree (C10). Returns
    `(episode_dir, runs_base, world_dir)`."""
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []})
    base, _src = J.runs_base(tmp_path)
    world = ep / "worlds" / "b"
    (world / "gather_raw" / "l-001.lead.json").write_text(
        json.dumps({"goal": goal, "what_to_summarize": ["auth events"]}), encoding="utf-8")
    append_jsonl(world / "executed_queries.jsonl", rows)
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
    """D3 — the lstat gate STAYS ahead of `joined()`: a world whose `executed_queries.jsonl`
    is a SYMLINK to a real table elsewhere renders a lead with no params and no payload, while
    the SAME table as a regular file (the positive control, same rows, same lead) renders
    both. `read_jsonl_rows_report` — what `joined()` reads through — FOLLOWS a link, so a render
    that dropped the `artifact_file` check would put another tree's rows into VIEW 1 as this
    world's own conduct.

    Observed failing by: the linked world's chain carrying the target's params or digests."""
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
    assert "LINKED_PARAMS" not in text
    assert "LINKED_DIGEST" not in text

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
    from defender.learning.lead_repository import joined

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


# ---------------------------------------------------------------------------------------
# O4 / O5 / D4 — a registry that cannot list is an infra fault, on the row
# ---------------------------------------------------------------------------------------


def _assert_registry_row(row: dict, *, system: str, verb: str = "ghostverb",
                         params: dict = PARAMS) -> None:
    """The D4 row contract, at either placement: an `infra` above-guard row carrying the
    model's RAW string as `system`, the call's own `verb` and `params` (O5: the fact is stated
    ON THE ROW OF THE CALL IT AFFECTED — at the schema placement those are extracted from the
    raw arguments, and an implementation that extracted them after the coarsening would write
    `verb=""`, `params={}`, a row that names no call), `system_key=""`, and the registry's
    failure in its digest detail — the row IS the trace, and it must say what failed."""
    assert row["query_id"] == ABOVE_GUARD_QUERY_ID
    assert row["verb"] == verb, f"the infra row does not carry the call's verb: {row['verb']!r}"
    assert row["params"] == params, \
        f"the infra row does not carry the call's params: {row['params']!r}"
    assert row["exit_code"] == DEFAULT_FAULT_EXIT, \
        f"the registry fault was recorded as exit {row['exit_code']}, not the infra exit"
    assert row["error_class"] == INFRA_ERROR_CLASS
    assert row["system"] == system, \
        f"the infra row carries {row['system']!r} where the model's own {system!r} belongs"
    assert row["system_key"] == "", "a fingerprint was minted on the registry-cannot-list path"
    for named in ("PermissionError", "Permission denied"):
        assert named in _detail(row), \
            f"the row's detail does not name the registry failure: {_detail(row)!r}"


def test_at_the_schema_placement_a_broken_registry_records_an_infra_row_and_keeps_the_rejection(tmp_path, capsys):
    """O4/O5/D4, schema placement — a schema-rejected call against a DECLARED system while the
    registry cannot list: the above-guard row is `infra` (exit 2), carries `system="elastic"`
    raw and `system_key=""`, names the registry failure in its detail, and the model still
    received its ORIGINAL schema rejection (the retry carried pydantic's text, the corrected
    call executed, nothing named `RegistryUnavailable` reached the model). Nothing is printed
    to stderr by the query tool — the row is the trace.

    The positive control is the SAME turn against the healthy registry: exit 64,
    `agent-fixable`, `system="elastic"`, `system_key=""` — so the two arms differ in exactly
    the fact under test.

    Observed failing by (today): `system=""` with `system_key=sha256("elastic")` — a real
    name fingerprinted — and a stderr line."""
    from defender.runtime.query_tool import RegistryUnavailable

    turns = [_bad_args("elastic", verb="ghostverb"), q("elastic", "query", PARAMS), DONE]

    rec = VerbRecorder()
    capsys.readouterr()
    broken = _run(tmp_path / "broken", run_id="d1017-schema-broken",
                  verbs=_RegistryCannotList(elastic_ok(rec)), turns=turns)
    err = capsys.readouterr().err
    rows = broken.own_rows
    assert [row["exit_code"] for row in rows] == [DEFAULT_FAULT_EXIT, 0], \
        "the rejection and the corrected call did not both leave their rows"
    _assert_registry_row(rows[0], system="elastic")
    assert record_query.system_fingerprint("elastic", "") not in {row["system_key"] for row in broken.rows}, \
        "a declared name's fingerprint is on the table"
    assert _corrected(rec) == 1, "the corrected call never reached the backend"
    assert broken.gather.calls == len(turns), "the lead ended early"
    assert any("Extra inputs are not permitted" in seen for seen in broken.gather.seen), \
        "the model did not receive its original schema rejection"
    assert not any(RegistryUnavailable.__name__ in seen for seen in broken.gather.seen), \
        "the host's registry fault replaced the model's own rejection"
    _assert_nothing_printed(err)

    healthy = _run(tmp_path / "healthy", run_id="d1017-schema-healthy",
                   verbs=elastic_ok(VerbRecorder()), turns=turns)
    control = healthy.own_rows[0]
    assert control["exit_code"] == 64
    assert control["error_class"] == AGENT_FIXABLE_ERROR_CLASS
    assert control["system"] == "elastic"
    assert control["system_key"] == ""
    assert "Extra inputs are not permitted" in _detail(control)


def test_at_the_schema_placement_a_ghost_is_recorded_raw_and_unfingerprinted_when_the_registry_cannot_answer(tmp_path):
    """O4/D4, the ghost arm — an UNDECLARED name at the schema placement while the registry
    cannot list: the infra row carries the model's raw `"ghostone"` as `system` (the adapter-load
    branch's own rule, and safe because `infra` rows compose no corpus path — see the S1 census
    below) and `system_key=""`: no fingerprint on this path, for a ghost either. Against the
    healthy registry the same turn coarsens to `system=""` with a 64-hex `system_key` — the
    complementary condition, same turn, same writer.

    Observed failing by: a `system_key` on the infra row, or a coarsened `system`."""
    turns = [_bad_args("ghostone", verb="ghostverb"), q("elastic", "query", PARAMS), DONE]
    rec = VerbRecorder()
    broken = _run(tmp_path / "broken", run_id="d1017-schema-ghost",
                  verbs=_RegistryCannotList(elastic_ok(rec)), turns=turns)
    rows = broken.own_rows
    assert [row["exit_code"] for row in rows] == [DEFAULT_FAULT_EXIT, 0]
    _assert_registry_row(rows[0], system="ghostone")
    assert _corrected(rec) == 1

    healthy = _run(tmp_path / "healthy", run_id="d1017-schema-ghost-healthy",
                   verbs=elastic_ok(VerbRecorder()), turns=turns)
    control = healthy.own_rows[0]
    assert control["exit_code"] == 64
    assert control["system"] == ""
    assert control["system_key"] == record_query.system_fingerprint("ghostone", "")
    assert HEX64.fullmatch(control["system_key"])


def test_at_the_grant_placement_a_broken_registry_records_an_infra_row_and_keeps_the_refusal(tmp_path, capsys):
    """D4, grant placement — a schema-VALID call naming a declared system with an undeclared
    verb reaches `_grant_check`'s unresolvable branch; with the registry unable to list, the
    row is `infra`, `system="elastic"` raw, `system_key=""`, and the model received the GRANT
    REFUSAL (`unresolvable: elastic.ghostverb`) as its retry — the corrected call then ran. The
    ghost arm on the same placement records `"ghostone"` raw and unfingerprinted. The two
    shapes are driven as two RUNS rather than two turns of one lead: lead-0's own item-1 call
    (`elastic.alerts`, unresolvable against this table) already reaches this branch, so a
    second registry rejection on the same run is the breaker's down-answer (N7) — which the
    loop test below pins in its own right. The positive controls are the same two turns
    against the healthy registry: exit 64, and a fingerprint for the ghost only.

    Observed failing by (today): both rows coarsened to `""`, the declared one fingerprinted."""
    from defender.runtime.query_tool import RegistryUnavailable

    capsys.readouterr()
    for name, system in (("declared", "elastic"), ("ghost", "ghostone")):
        turns = [q(system, "ghostverb", PARAMS), q("elastic", "query", PARAMS), DONE]
        rec = VerbRecorder()
        broken = _run(tmp_path / name, run_id=f"d1017-grant-{name}",
                      verbs=_RegistryCannotList(elastic_ok(rec)), turns=turns)
        rows = broken.own_rows
        assert [row["exit_code"] for row in rows] == [DEFAULT_FAULT_EXIT, 0], \
            f"{name}: the grant-path rejection and the corrected call did not both leave rows"
        _assert_registry_row(rows[0], system=system)
        assert _corrected(rec) == 1, f"{name}: the corrected call never reached the backend"
        assert broken.gather.calls == len(turns), f"{name}: the lead ended early"
        assert any(f"unresolvable: {system}.ghostverb" in seen for seen in broken.gather.seen), \
            f"{name}: the model did not receive the grant refusal for its call"
        assert not any(RegistryUnavailable.__name__ in seen for seen in broken.gather.seen), \
            f"{name}: the host's registry fault replaced the model's own refusal"
    _assert_nothing_printed(capsys.readouterr().err)

    healthy = _run(tmp_path / "healthy", run_id="d1017-grant-healthy",
                   verbs=elastic_ok(VerbRecorder()), turns=[
                       q("elastic", "ghostverb", PARAMS), q("ghostone", "ghostverb", PARAMS),
                       q("elastic", "query", PARAMS), DONE,
                   ])
    declared, ghost, ran = healthy.own_rows
    assert [row["exit_code"] for row in (declared, ghost, ran)] == [64, 64, 0]
    assert declared["system"] == "elastic"
    assert declared["system_key"] == ""
    assert ghost["system"] == ""
    assert ghost["system_key"] == record_query.system_fingerprint("ghostone", "")


def test_a_loop_against_a_broken_registry_is_bounded_by_the_breaker_on_the_host_key(tmp_path):
    """D4/N7/C17 — a lead spending five DIFFERENT above-guard rejections (a declared name, two
    readable ghosts, two invisible strings, across both placements) against a registry that
    cannot list is bounded by the circuit breaker keyed on `REGISTRY_BREAKER_KEY`, not on the
    model's strings: exactly `PER_SYSTEM_FAIL_LIMIT` registry rows exist in the WHOLE table, the
    breaker document's `systems` holds the host key and no model string, and every rejection
    after the trip wrote no row (N7) while the lead ran to its end and the corrected call
    executed. Under a breaker keyed per name, five distinct strings are five untripped keys —
    five rows, five counted failures, and `RUN_FAIL_KILL_LIMIT` reached on a fault that is ONE
    fault (C17).

    No guard is consulted on this path: no above-guard row of the lead is `agent-fixable`, and
    no `system_key` is minted. The positive control is the same five turns against the healthy
    registry: five exit-64 rows, no breaker document.

    Observed failing by: more than two registry rows, a model string among the breaker's
    systems, an agent-fixable row, or a dead lead."""
    from defender.runtime.query_tool import REGISTRY_BREAKER_KEY

    turns = [
        _bad_args("elastic", verb="ghostverb"), q("ghostone", "ghostverb", PARAMS),
        _bad_args(ZERO_WIDTH, verb="ghostverb"), q("ghosttwo", "ghostverb", PARAMS),
        _bad_args("\ufeff", verb="ghostverb"),
        q("elastic", "query", PARAMS), DONE,
    ]
    rec = VerbRecorder()
    broken = _run(tmp_path / "broken", run_id="d1017-breaker",
                  verbs=_RegistryCannotList(elastic_ok(rec)), turns=turns)
    assert broken.gather.calls == len(turns), "the lead ended early"
    assert broken.main.calls == 2, "MAIN never resumed — the run died inside the lead"
    assert _corrected(rec) == 1, "the corrected call never reached the backend"

    own_above = _above_guard_rows(broken.own_rows)
    assert own_above, "no above-guard row at all — the claims below are vacuous"
    assert {row["error_class"] for row in own_above} == {INFRA_ERROR_CLASS}, \
        "a rejection under a broken registry reached a guard (agent-fixable) — O5's failure"
    assert {row["system_key"] for row in broken.rows} == {""}, \
        "a fingerprint was minted while the registry could not answer"
    for row in own_above:
        assert row["exit_code"] == DEFAULT_FAULT_EXIT
    assert len(_registry_rows(broken.rows)) == PER_SYSTEM_FAIL_LIMIT, \
        "the registry rows are not bounded at the breaker's per-key limit — either a row was " \
        "written after the trip (N7) or the loop is keyed per model string (C17)"

    breaker = _breaker(broken)
    assert set(breaker["systems"]) == {REGISTRY_BREAKER_KEY}, \
        f"the breaker is keyed on {sorted(breaker['systems'])}, not on the host's registry key"
    assert breaker["systems"][REGISTRY_BREAKER_KEY]["failures"] == PER_SYSTEM_FAIL_LIMIT
    assert "tripped_at" in breaker["systems"][REGISTRY_BREAKER_KEY], "the registry key never tripped"
    assert breaker["total_failures"] == PER_SYSTEM_FAIL_LIMIT < RUN_FAIL_KILL_LIMIT, \
        "down-answered calls counted failures"

    healthy = _run(tmp_path / "healthy", run_id="d1017-breaker-healthy",
                   verbs=elastic_ok(VerbRecorder()), turns=turns)
    assert [row["exit_code"] for row in healthy.own_rows] == [64] * 5 + [0], \
        "the healthy control did not leave five agent-fixable rows and one executed one"
    assert _breaker(healthy) == {}, "the healthy control tripped a breaker"


def test_the_run_kill_names_the_registry_not_the_models_strings(tmp_path, capsys):
    """D4/C17 — when the registry fault is part of what reaches `RUN_FAIL_KILL_LIMIT`, the
    `RunAborted` the breaker raises names `REGISTRY_BREAKER_KEY` among the unreachable systems
    — never `"elastic"` (a real, reachable system whose call the fault affected) nor the ghost
    the model named. Driven to the kill limit across three keys — the registry (tripped at
    two), a transport-faulting `cmdb` (two more) and `identity` (the fifth) — because a single
    tripped key stops counting, which is the point of the test above.

    The abort is observed the way the driver reports it: MAIN never resumed, the gather script
    stopped at the killing call, the breaker document holds the kill-limit total, and the
    driver's stderr line carries the breaker's own message.

    Observed failing by: `"elastic"` or `"ghostone"` among the breaker's systems, or the
    registry key absent from them."""
    from defender.runtime.query_tool import REGISTRY_BREAKER_KEY

    rec = VerbRecorder()
    faulting = raising(rec, TransportFault("down"), systems=("elastic", "cmdb", "identity"))
    turns = [
        _bad_args("elastic", verb="ghostverb"), q("ghostone", "ghostverb", PARAMS),
        q("cmdb", "probe", {}), q("cmdb", "probe", {}),
        q("identity", "probe", {}),
        q("elastic", "probe", {}), DONE,
    ]
    capsys.readouterr()
    r = _run(tmp_path, run_id="d1017-kill", verbs=_RegistryCannotList(faulting), turns=turns)
    err = capsys.readouterr().err

    assert r.main.calls == 1, "RunAborted was swallowed — the run kept going past the kill limit"
    assert r.gather.calls == 5, "the lead did not stop at the call that reached the kill limit"
    breaker = _breaker(r)
    assert breaker["total_failures"] == RUN_FAIL_KILL_LIMIT
    assert set(breaker["systems"]) == {REGISTRY_BREAKER_KEY, "cmdb", "identity"}, \
        f"the breaker's systems are {sorted(breaker['systems'])}"
    aborts = [line for line in err.splitlines() if "run aborted by circuit breaker" in line]
    assert len(aborts) == 1, f"the driver did not report the abort once: {err!r}"
    assert REGISTRY_BREAKER_KEY in aborts[0], "the abort does not name the registry"
    for reached in ("'elastic'", "ghostone"):
        assert reached not in aborts[0], \
            "the abort names a system the model reached (or one it invented) as unreachable"


@pytest.mark.parametrize(
    ("placement", "killing_turn"),
    [
        ("schema", _bad_args("elastic", verb="ghostverb")),
        ("grant", q("ghostone", "ghostverb", PARAMS)),
    ],
)
def test_a_registry_row_that_reaches_the_kill_limit_aborts_the_run_from_either_placement(
    tmp_path, capsys, placement, killing_turn,
):
    """D4/S3 — `RunAborted` PROPAGATES out of the placement's handler when the registry row is
    the failure that reaches `RUN_FAIL_KILL_LIMIT`: "it is the same abort the adapter-load path
    raises, and S3 says so". The kill test above drives the fifth failure from
    `wrap_tool_execute`, so an implementation that swallowed the abort at the placements —
    "so the model's rejection is never replaced" — stayed green there (adversary H4). Here the
    ORDER puts the registry row fifth: two transport faults on `cmdb`, one on `identity`, then
    the registry rejection at the placement under test. The run must end AT that call: MAIN
    never resumes, the gather script stops on the killing turn, the breaker document holds the
    kill-limit total with the registry key among its systems.

    The positive control is the same script against the healthy registry: the fifth call is
    an ordinary exit-64 rejection, no abort, the lead runs to DONE.

    Observed failing by: `gather.calls == len(turns)` (the lead ran on past the abort)."""
    from defender.runtime.query_tool import REGISTRY_BREAKER_KEY

    rec = VerbRecorder()
    faulting = raising(rec, TransportFault("down"), systems=("elastic", "cmdb", "identity"))
    turns = [
        q("cmdb", "probe", {}), q("cmdb", "probe", {}), q("identity", "probe", {}),
        killing_turn, q("elastic", "probe", {}), DONE,
    ]
    capsys.readouterr()
    r = _run(tmp_path / "broken", run_id=f"d1017-kill-{placement}",
             verbs=_RegistryCannotList(faulting), turns=turns)
    err = capsys.readouterr().err
    breaker = _breaker(r)
    # Lead-0's own item-1 call reaches the grant placement first, so the registry key already
    # holds one failure when the lead starts; the killing turn is then the second registry
    # row and the fifth failure overall.
    assert breaker["total_failures"] == RUN_FAIL_KILL_LIMIT, \
        f"{placement}: the killing turn did not reach the kill limit: {breaker}"
    assert REGISTRY_BREAKER_KEY in breaker["systems"]
    assert r.main.calls == 1, f"{placement}: RunAborted was swallowed at the placement"
    assert r.gather.calls == turns.index(killing_turn) + 1, \
        f"{placement}: the lead did not stop at the registry rejection that reached the kill limit"
    aborts = [line for line in err.splitlines() if "run aborted by circuit breaker" in line]
    assert len(aborts) == 1, f"{placement}: the driver did not report the abort once: {err!r}"
    assert REGISTRY_BREAKER_KEY in aborts[0], f"{placement}: the abort does not name the registry"

    healthy = _run(tmp_path / "healthy", run_id=f"d1017-kill-{placement}-healthy",
                   verbs=faulting, turns=turns)
    assert healthy.main.calls == 2, f"{placement}: the healthy control aborted"
    assert healthy.gather.calls == len(turns)
    assert [row["exit_code"] for row in healthy.own_rows][3] == 64


# ---------------------------------------------------------------------------------------
# D4 unit — `_system_of_record` raises rather than swallows
# ---------------------------------------------------------------------------------------


def test_system_of_record_raises_registry_unavailable_and_prints_nothing(tmp_path, capsys):
    """D4 unit — `QueryCapture._system_of_record("elastic")` over a registry whose `systems()`
    raises `PermissionError` raises `RegistryUnavailable` (and `_coarsen` lets it propagate)
    with NOTHING on stderr; over a healthy `ModuleVerbRegistry` the declared / undeclared
    answers are unchanged (`"elastic"` / `""`), as `test_869_parity` pins them.

    Observed failing by (today): `""` returned and a `[query_tool]` line printed."""
    from defender.runtime.query_tool import RegistryUnavailable

    capsys.readouterr()
    capture = QueryCapture(_RaisingRegistry())
    with pytest.raises(RegistryUnavailable):
        capture._system_of_record("elastic")
    with pytest.raises(RegistryUnavailable):
        capture._coarsen("elastic")
    with pytest.raises(RegistryUnavailable):
        capture._coarsen("ghostone")
    assert capsys.readouterr().err == "", "the registry fault is still printed to stderr"

    adapters = tmp_path / "adapters"
    adapters.mkdir()
    write(adapters / "elastic_adapter.py", "VERBS = {}\n")
    healthy = QueryCapture(ModuleVerbRegistry(adapters, DENY_ALL))
    assert healthy._system_of_record("elastic") == "elastic"
    assert healthy._system_of_record("ghostone") == ""
    assert healthy._coarsen("ghostone") == ("", record_query.system_fingerprint("ghostone", ""))
    assert healthy._coarsen("elastic") == ("elastic", "")


# ---------------------------------------------------------------------------------------
# S1 — the census: an infra row's raw system composes nothing offline
# ---------------------------------------------------------------------------------------


def test_an_infra_rows_raw_model_string_composes_no_corpus_record(tmp_path):
    """S1 census — the D4 row carries the model's RAW string (here `PHANTOM`, the segment an
    injected subagent would name to steer a corpus write) as `system`; driven through the real
    join and `collect_general_failures`, it composes NO record, because the collector keeps
    only `agent-fixable` rows (C8) and this one is `infra`. The positive control is the same
    schema-rejected shape against a declared system under the healthy registry: one record,
    `system="elastic"`, the pitfalls channel's ordinary input.

    Observed failing by: a record whose `system` is `PHANTOM` — the #855 leak reopened by way
    of the infra class."""
    turns = [_bad_args(PHANTOM, verb="ghostverb"), q("elastic", "query", PARAMS), DONE]
    broken = _run(tmp_path / "broken", run_id="d1017-census",
                  verbs=_RegistryCannotList(elastic_ok(VerbRecorder())), turns=turns)
    row = broken.own_rows[0]
    _assert_registry_row(row, system=PHANTOM)
    leads = broken.own_leads()
    assert any(lead.system == PHANTOM and lead.error_class == INFRA_ERROR_CLASS for lead in leads), \
        "the infra row did not reach the join, so the census below is over nothing"
    records = collect_general_failures(leads, broken.run_dir, catalog=[])
    assert [rec["system"] for rec in records] == [], \
        "an infra row's raw model string composed a corpus record"

    healthy = _run(tmp_path / "healthy", run_id="d1017-census-healthy",
                   verbs=elastic_ok(VerbRecorder()),
                   turns=[_bad_args("elastic", verb="ghostverb"), q("elastic", "query", PARAMS), DONE])
    records = collect_general_failures(healthy.own_leads(), healthy.run_dir, catalog=[])
    assert [rec["system"] for rec in records] == ["elastic"], \
        "a declared system's agent-fixable rejection no longer reaches the pitfalls channel"
    assert records[0]["error_class"] == AGENT_FIXABLE_ERROR_CLASS
