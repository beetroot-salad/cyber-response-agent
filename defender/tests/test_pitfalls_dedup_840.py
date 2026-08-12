"""#840 — the pitfalls RECORD SET is deduplicated, and the count survives the collapse.

`collect_general_failures` emits one record per failing ROW and `append_pitfalls` used to
append them untouched, so the incident that motivated #823 — `l-003` spending ~8 consecutive
turns brute-forcing DuckDB `unnest` against one envelope — enqueued ~8 near-identical records
and cleared #823's threshold of 3 on a single lesson. The curator then received eight copies
of one bullet, and a green threshold stopped being evidence that the channel had learned three
things (#823 O3 / C9).

WHAT THIS PINS
--------------
- The identity of a MISTAKE is `(system, stderr_digest)` (`persist.pitfall_key`) — NOT the
  row, not `query_id`, not the exact query. The l-003 shape varies the SQL while the adapter's
  diagnosis stays put, and two coined queries that earn the identical rejection teach one
  bullet.
- The collapse KEEPS THE COUNT (`occurrences: N`). N identical failures are evidence of
  severity as well as noise; a dedup that discarded the count would throw the severity away.
- The seam is the READ, not the append: the queue file keeps one line per failure (#719 D9
  leaves exactly one wholesale rewriter of a queue file, and it is the rotation), while both
  seams that consume the queue — the curation threshold and the curator's handoff — read it
  through `merge_pitfalls`. Counting rows counts failures; counting records counts lessons.

WHAT IT DELIBERATELY DOES NOT TOUCH
-----------------------------------
Row-level duplication in the queries table: `test_pitfalls_input_823.py::test_shim_row_never_
causes_a_trip` pins that three identical failing reduces write three rows, because shim rows
are observational and must not dead-end a lead (#823 N3). The duplication is by design at the
row level; #840 is only about whether it survives into the record level. The threshold VALUE
is #823 M4's and is out of scope here too.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from defender.learning.author import drain
from defender.learning.core import drains, persist
from defender.learning.core.config import LoopPaths
from defender.learning.leads import pitfalls_curator
from defender.learning.leads.lead_extraction import ExecutedLead, collect_general_failures
from defender.scripts.gather_tools.record_query import BASH_SHIM_QUERY_ID
from defender.tests._repo import seed_skills_repo

#: l-003's real failure in `reviewer-measure-0807-b` — the same DuckDB diagnosis, turn after
#: turn, while the SQL that provoked it changed every time.
UNNEST = "exit=1; Binder Error: No function matches unnest(JSON) - candidates: unnest(LIST)"
QUOTING = "exit=1; Parser Error: syntax error at or near \"@timestamp\""


@pytest.fixture
def paths(tmp_path: Path) -> LoopPaths:
    return LoopPaths(repo_root=seed_skills_repo(tmp_path / "repo"),
                     state_dir=tmp_path / "state")


def _lead(*, sql: str, digest: str = UNNEST, system: str = "elastic",
          query_index: int = 0) -> ExecutedLead:
    """One failing reducer row as the offline extraction sees it. `∅.bash-shim` is the
    routing identity #823 minted: it fails `_SAFE_ID_SEGMENT`, so the row falls past the
    draft synthesizer and the lead-author handoff into `collect_general_failures`."""
    return ExecutedLead(
        lead_id="l-003", query_index=query_index, is_multi_query=True, entry_index=0,
        query_id=BASH_SHIM_QUERY_ID, system=system, verb="bash",
        params={"command": f"cat 0.json | defender-sql '{sql}'"},
        raw_command=f"defender-sql '{sql}'", goal_text="reduce the elastic envelope",
        what_to_summarize=("auth events",), raw_ref=None, payload_status="error",
        payload_digest=digest, error_class="agent-fixable",
    )


def _row(pid: str, *, digest: str = UNNEST, system: str = "elastic", **extra) -> dict:
    """A queued record as it stands on disk — the pre-#840 shape, carrying no count."""
    return {"schema_version": 1, "pitfall_id": pid, "source_run": pid.split(":")[0],
            "system": system, "query_id": BASH_SHIM_QUERY_ID, "goal": "g",
            "executed_query": "SELECT unnest(data)", "stderr_digest": digest,
            "error_class": "agent-fixable", **extra}


def _pending(paths: LoopPaths) -> list[dict]:
    """The queue's ROWS — the evidence, one line per failure."""
    return persist.read_pitfalls(paths)


def _records(paths: LoopPaths) -> list[dict]:
    """The queue's RECORD SET — what the threshold counts and the curator receives."""
    return persist.merge_pitfalls(persist.read_pitfalls(paths))


# =============================================================================================
# The collapse itself — one looping lead is one lesson, and the loop is still legible.
# =============================================================================================


def test_one_looping_leads_eight_turns_become_one_record_carrying_its_count(paths):
    """The motivating incident, through the REAL collector. Eight brute-forced reduces, each
    with its own SQL and its own row, produce eight records — the collector stays per-row, as
    #823 N3 requires — and land in the queue as ONE record whose `occurrences` is 8."""
    executed = [_lead(sql=f"SELECT unnest(data, {i})", query_index=i) for i in range(8)]
    collected = collect_general_failures(executed, Path("reviewer-measure-0807-b"), catalog=[])
    assert len(collected) == 8, "the collector is per-row and #823 N3 keeps it that way"

    persist.append_pitfalls(collected, paths=paths)
    assert len(_pending(paths)) == 8, "the rows are the evidence and all eight are kept"
    records = _records(paths)
    assert len(records) == 1, "eight copies of one lesson were eight lessons"
    assert records[0]["occurrences"] == 8, "the collapse threw away the severity signal"
    assert records[0]["pitfall_id"] == "reviewer-measure-0807-b:l-003:0", (
        "the exemplar is the first failure, so the record still names a real row"
    )
    assert records[0]["stderr_digest"] == UNNEST


def test_two_different_mistakes_in_one_lead_stay_two_records(paths):
    """The negative that keeps the key from being coarser than a mistake: the same lead
    failing two DIFFERENT ways has learned two things, and both must reach the curator."""
    executed = [_lead(sql="SELECT unnest(data)"),
                _lead(sql="SELECT @timestamp", digest=QUOTING, query_index=1)]
    persist.append_pitfalls(
        collect_general_failures(executed, Path("r"), catalog=[]), paths=paths)
    assert sorted(r["stderr_digest"] for r in _records(paths)) == sorted([QUOTING, UNNEST])
    assert [r["occurrences"] for r in _records(paths)] == [1, 1]


def test_the_same_digest_from_two_systems_stays_two_records(paths):
    """`system` is half the key. One `execution.md` per system is the whole point of the
    channel — collapsing across systems would send a host-state lesson to elastic's file."""
    persist.append_pitfalls(
        [_row("r:l-001:0"), _row("r:l-002:0", system="host-state")], paths=paths)
    assert {r["system"] for r in _records(paths)} == {"elastic", "host-state"}


def test_two_distinct_queries_earning_one_rejection_are_one_lesson(paths):
    """The judgment `query_id` is out of the key encodes: what `execution.md` carries is the
    mistake the adapter diagnosed, and two differently-phrased queries rejected identically
    are one bullet. Pinned so widening the key is a decision rather than a drift."""
    rows = [_row("r:l-001:0", executed_query="FROM a | STATS x") | {"query_id": "elastic.a"},
            _row("r:l-002:0", executed_query="FROM b | STATS y") | {"query_id": "elastic.b"}]
    persist.append_pitfalls(rows, paths=paths)
    assert len(_records(paths)) == 1
    assert _records(paths)[0]["occurrences"] == 2


def test_a_later_run_repeating_the_mistake_bumps_the_count(paths):
    """Cross-run, which is the half a collector-side dedup could not reach: three runs that
    each make the same mistake once are still one lesson, and the queue says so."""
    for run in ("run-a", "run-b", "run-c"):
        persist.append_pitfalls([_row(f"{run}:l-001:0")], paths=paths)
    records = _records(paths)
    assert len(records) == 1
    assert records[0]["occurrences"] == 3
    assert records[0]["source_run"] == "run-a", "the exemplar's provenance moved"


def test_a_merged_record_keeps_the_exemplars_queue_bookkeeping(paths):
    """The merge copies the exemplar row whole, so whatever the drain has stamped on it is
    still there — here `attempts`, from a batch whose curation already failed once. A merge
    that rebuilt the record from selected fields would reset a recurring mistake's
    retirement clock and a batch that always fails could never reach the ceiling."""
    persist.append_pitfalls([_row("r:l-001:0"), _row("r2:l-001:0")], paths=paths)
    drain.retire(channel=paths.pitfalls, batch_ids=["r:l-001:0", "r2:l-001:0"],
                 reason="the curator exited nonzero", max_attempts=5)
    record = _records(paths)[0]
    assert record["attempts"] == 1, "the retire bump did not survive the merge"
    assert record["occurrences"] == 2, "a row that had been retried was dropped, not merged"


def test_merging_a_record_set_twice_changes_nothing(paths):
    """Two seams merge — the threshold gate and the handoff builder — and one feeds the
    other. The collapse is therefore idempotent by contract, not by luck of call order."""
    persist.append_pitfalls([_row(f"r:l-003:{i}") for i in range(5)], paths=paths)
    once = _records(paths)
    assert persist.merge_pitfalls(once) == once


def test_an_empty_append_leaves_the_queue_untouched(paths):
    """The rewrite must not fire on a no-op append — a run with no agent-fixable failure is
    the common case, and it has no business rewriting another run's queue."""
    persist.append_pitfalls([_row("r:l-001:0")], paths=paths)
    before = paths.pitfalls.file.read_text(encoding="utf-8")
    assert persist.append_pitfalls([], paths=paths) == 0
    assert paths.pitfalls.file.read_text(encoding="utf-8") == before


# =============================================================================================
# O3's repair — the threshold now counts distinct mistakes, so clearing it means the channel
# learned that many things.
# =============================================================================================


def _invoke_spy(calls: list) -> object:
    def _invoke(handoffs, *, repo_root, box=None):
        calls.append(handoffs)
        return 0
    return _invoke


def test_a_single_lesson_repeated_does_not_clear_the_threshold(paths, monkeypatch):
    """#840's headline. Eight copies of one mistake used to clear a threshold of 3 and spawn
    the curator; now they are one record and the queue waits — intact, not dropped — for two
    more distinct lessons."""
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "3")
    persist.append_pitfalls([_row(f"r:l-003:{i}") for i in range(8)], paths=paths)
    calls: list = []

    assert pitfalls_curator.run_pitfalls(paths=paths, invoke=_invoke_spy(calls)) == 0
    assert calls == [], "the curator ran on one lesson wearing eight hats"
    assert len(_records(paths)) == 1
    assert len(_pending(paths)) == 8, "the under-threshold queue lost its evidence"


def test_three_distinct_lessons_do_clear_it(paths, monkeypatch):
    """The positive control: the gate still opens, so the negative above is a dedup and not
    a channel that stopped working."""
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "3")
    persist.append_pitfalls(
        [_row(f"r:l-00{i}:0", digest=f"exit=1; distinct error {i}") for i in range(3)],
        paths=paths,
    )
    calls: list = []
    assert pitfalls_curator.run_pitfalls(paths=paths, invoke=_invoke_spy(calls)) == 0
    assert len(calls) == 1
    assert len(calls[0][0]["failures"]) == 3
    assert _pending(paths) == [], "the batch was curated but not rotated"


def test_the_wake_gate_counts_what_the_curation_gate_counts(paths, monkeypatch):
    """`_has_lead_author_work` is what spins the drain up. If it counted rows while
    `run_pitfalls` counted mistakes, every tick would start a lead-author drain that then
    declined to curate."""
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "3")
    persist.append_pitfalls([_row(f"r:l-003:{i}") for i in range(8)], paths=paths)
    assert drains._has_lead_author_work(paths) is False

    persist.append_pitfalls(
        [_row("r:l-004:0", digest="exit=1; a second error"),
         _row("r:l-005:0", digest="exit=1; a third error")], paths=paths)
    assert drains._has_lead_author_work(paths) is True


# =============================================================================================
# What the curator receives — collapsed, counted, severest first.
# =============================================================================================


def test_the_handoff_carries_the_count_and_leads_with_it(paths):
    """`occurrences` reaches the prompt, and the mistake made eight times is the first
    failure in its system's list — the curator's context budget is spent severity-first."""
    handoffs = pitfalls_curator._build_pitfalls_handoffs([
        _row("r:l-001:0", digest="exit=1; made once"),
        *[_row(f"r:l-003:{i}") for i in range(8)],
    ])
    failures = handoffs[0]["failures"]
    assert [f["occurrences"] for f in failures] == [8, 1]
    assert failures[0]["stderr_digest"] == UNNEST


def test_the_handoff_builder_collapses_raw_queue_rows_itself(paths):
    """The builder is handed queue ROWS, which carry no count of their own, and it is the
    last seam before the prompt. It merges rather than trusting its caller to have done it,
    so no future reader of the queue can hand the curator four copies of one bullet."""
    rows = [_row(f"r:l-003:{i}") for i in range(4)]
    for row in rows:
        assert "occurrences" not in row
    failures = pitfalls_curator._build_pitfalls_handoffs(rows)[0]["failures"]
    assert len(failures) == 1
    assert failures[0]["occurrences"] == 4


def test_every_duplicate_row_behind_a_curated_record_rotates(paths, monkeypatch):
    """The orphan hazard the collapse creates: the curator sees one record, but the batch is
    named by RAW `pitfall_id`s, so all four rows behind it leave the queue. A row left
    behind would sit in pending forever and re-clear the threshold with a curated lesson."""
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "1")
    persist.append_pitfalls([_row(f"r:l-003:{i}") for i in range(4)], paths=paths)

    calls: list = []
    assert pitfalls_curator.run_pitfalls(paths=paths, invoke=_invoke_spy(calls)) == 0
    assert len(calls[0][0]["failures"]) == 1, "the curator saw the duplicates"
    assert _pending(paths) == []
    consumed = [json.loads(ln) for ln in
                paths.pitfalls.consumed.read_text(encoding="utf-8").splitlines()]
    assert sorted(c["pitfall_id"] for c in consumed) == [f"r:l-003:{i}" for i in range(4)]
