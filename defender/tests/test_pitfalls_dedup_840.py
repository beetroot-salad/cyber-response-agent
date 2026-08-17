"""#840 — the pitfalls RECORD SET is deduplicated, and the count survives the collapse.

`collect_general_failures` emits one record per failing ROW and `append_pitfalls` used to
append them untouched, so the incident that motivated #823 — `l-003` spending ~8 consecutive
turns brute-forcing DuckDB `unnest` against one envelope — enqueued ~8 near-identical records
and cleared #823's threshold of 3 on a single lesson. The curator then received eight copies
of one bullet, and a green threshold stopped being evidence that the channel had learned three
things (#823 O3 / C9).

WHAT THIS PINS
--------------
- The identity of a MISTAKE is `(owner, stderr_digest)` (`persist.pitfall_key`) — NOT the row,
  not the exact query. The l-003 shape varies the SQL while the adapter's diagnosis stays put,
  and two coined queries that earn the identical rejection teach one bullet. The owner was
  `system` when #840 was written and is the SURFACE THE LESSON IS TAUGHT ON since #870, which
  added a second one: a `∅.bash-shim` row belongs to `defender-sql` however the reduce was
  attributed. `query_id` is still out of the key as an identity — it is read only to answer
  which surface owns the row, which is why `_row` defaults to a system id and `_shim` exists.
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


def _row(pid: str, *, digest: str = UNNEST, system: str = "elastic",
         query_id: str = "elastic.esql", **extra) -> dict:
    """A queued record as it stands on disk — the pre-#840 shape, carrying no count.

    A SYSTEM row by default, and that is #870's correction to this file rather than a drift.
    `query_id` defaulted to `∅.bash-shim` here, which every one of these tests read as an
    incidental field — #840 put `query_id` deliberately OUT of the mistake's identity, so the
    value could not matter. #870 made it matter in a different way: it is now what says WHICH
    SURFACE owns the lesson, so a sentinel row keys to the reducer whatever it is attributed
    to. Every demand in this file is about the collapse on the lane that has one `execution.md`
    per system, so the default is now spelled as what those demands always meant. The reducer
    half has its own arm (`the_reducer_owns_its_lesson_whatever_attributed_it`) and #870's own
    suites.
    """
    return {"schema_version": 1, "pitfall_id": pid, "source_run": pid.split(":")[0],
            "system": system, "query_id": query_id, "goal": "g",
            "executed_query": "SELECT unnest(data)", "stderr_digest": digest,
            "error_class": "agent-fixable", **extra}


def _shim(pid: str, *, digest: str = UNNEST, system: str = "", **extra) -> dict:
    """A queued REDUCER row: the reserved sentinel in `query_id`. `system` is a parameter and
    defaults to the post-M5′ `""`, because the population that separates the lane's spellings
    is the row queued BEFORE M5′ deployed, which carries the system it was attributed to."""
    return _row(pid, digest=digest, system=system,
                query_id=BASH_SHIM_QUERY_ID, **extra)


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
    """The OWNER is half the key. One `execution.md` per system is the whole point of the
    channel — collapsing across systems would send a host-state lesson to elastic's file."""
    persist.append_pitfalls(
        [_row("r:l-001:0"), _row("r:l-002:0", system="host-state",
                                 query_id="host-state.ps")], paths=paths)
    assert {r["system"] for r in _records(paths)} == {"elastic", "host-state"}


def test_the_reducer_owns_its_lesson_whatever_attributed_it(paths):
    """#870's half of the same key, and the two directions it moves.

    A reducer row's owner is the SURFACE its lesson is taught on, never the system whose
    envelope happened to provoke it (F1) — so the pre-M5′ row that still carries `elastic` and
    the post-M5′ one that carries `""` are ONE `defender-sql` mistake and merge. Keying on
    `system` alone made them two, which handed the curator the same bullet twice on the one
    entry whose whole purpose is collecting them.

    And the converse, which is the worse one: a SYSTEM row and a REDUCER row that happen to
    share a digest must stay two records. Under the old key they were one, and which surface
    the lesson then reached was decided by whichever row the merge happened to keep as
    exemplar — so a `defender-sql` lesson could be taught onto `elastic/execution.md` while its
    own queue row was held for a later tick.
    """
    persist.append_pitfalls(
        [_shim("r:l-001:0", system="elastic"), _shim("r:l-002:0"),
         _row("r:l-003:0")],
        paths=paths,
    )
    records = _records(paths)
    assert len(records) == 2, "the reducer rows did not merge, or swallowed the system row"
    by_owner = {persist.pitfall_key(r)[0]: r for r in records}
    assert set(by_owner) == {BASH_SHIM_QUERY_ID, "elastic"}
    assert by_owner[BASH_SHIM_QUERY_ID]["occurrences"] == 2, (
        "attribution still splits one defender-sql mistake into two lessons"
    )
    assert by_owner["elastic"]["occurrences"] == 1, (
        "a system row merged into the reducer's record and left with its fate"
    )


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
    persist.append_pitfalls(
        [*[_row(f"r:l-003:{i}") for i in range(5)],
         _row("r:l-004:0", digest=QUOTING),
         _row("r:l-005:0", system="host-state", query_id="host-state.ps"),
         _row("r:l-006:0", digest="")],
        paths=paths,
    )
    once = _records(paths)
    assert len(once) == 4
    assert persist.merge_pitfalls(once) == once


def test_a_row_whose_digest_carries_no_diagnosis_keys_to_itself(paths):
    """The absence of a verdict is not a verdict two rows hold in common. An adapter that
    fails with an empty stderr writes the SAME `exit=N;` envelope on every call, so keying on
    it would fold unrelated mistakes behind one exemplar — the curator would see one query,
    and `rotate_pitfalls` would then retire the rest as though they had been curated.

    The discriminating shape is N rows carrying the SAME empty digest — rows carrying
    DIFFERENT empty-ish strings would stay N records under any key, including the one this
    carve-out replaces."""
    same = [_row(f"r:l-00{i}:0", digest="exit=1; ", executed_query=f"SELECT {i}")
            for i in range(3)]
    persist.append_pitfalls(same, paths=paths)
    records = _records(paths)
    assert len(records) == 3, "three unrelated failures collapsed onto one empty diagnosis"
    assert [r["executed_query"] for r in records] == ["SELECT 0", "SELECT 1", "SELECT 2"], (
        "the curator would have received one exemplar and the other two would rotate away"
    )

    # The whole no-diagnosis family, each spelling of it repeated: a bare envelope with no
    # trailing space, nothing at all, and whitespace-only.
    for digest in ("exit=2;", "", "   "):
        p = LoopPaths(repo_root=paths.repo_root, state_dir=paths.state_dir / f"v{len(digest)}")
        persist.append_pitfalls(
            [_row(f"v:l-00{i}:0", digest=digest) for i in range(2)], paths=p)
        assert len(persist.merge_pitfalls(persist.read_pitfalls(p))) == 2, (
            f"two failures merged on the empty diagnosis {digest!r}"
        )


def test_the_merge_key_normalises_system_the_way_the_handoff_groups_it():
    """`_build_pitfalls_handoffs` groups on the STRIPPED system, so a key coarser than that
    grouping hands the curator N entries it reads as N bullets — the one thing the collapse
    exists to prevent."""
    rows = [_row("r:l-001:0"), _row("r:l-002:0", system="elastic "),
            _row("r:l-003:0", system=" elastic")]
    failures = pitfalls_curator._build_pitfalls_handoffs(
        rows, systems=frozenset({"elastic"}))[0]["failures"]
    assert len(failures) == 1, "one mistake reached the curator as three bullets"
    assert failures[0]["occurrences"] == 3


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
    """#840's headline, ON THE SYSTEM LANE. Eight copies of one mistake used to clear a
    threshold of 3 and spawn the curator; now they are one record and the queue waits —
    intact, not dropped — for two more distinct lessons.

    THE LANE IS THE DEMAND'S SCOPE, not an incidental of the fixture. #870 FK-3 decided the
    opposite for the REDUCER lane on purpose: there, one diagnosed mistake repeated N times is
    the strongest evidence the lane produces, and a count that could never reach 3 on it was
    anti-correlated with evidence quality. That disjunct is asserted by
    `an_attributed_reducer_lesson_repeated_does_clear_it` directly below, which is this
    demand's deliberate counterpart — the two differ in the row's `query_id` and in nothing
    else, so what separates them is visible rather than incidental.
    """
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "3")
    persist.append_pitfalls([_row(f"r:l-003:{i}") for i in range(8)], paths=paths)
    calls: list = []

    assert pitfalls_curator.run_pitfalls(paths=paths, invoke=_invoke_spy(calls)) == 0
    assert calls == [], "the curator ran on one lesson wearing eight hats"
    assert len(_records(paths)) == 1
    assert len(_pending(paths)) == 8, "the under-threshold queue lost its evidence"


def test_an_attributed_reducer_lesson_repeated_does_clear_it(paths, monkeypatch):
    """The same eight rows, differing only in `query_id`, DO open the lane — and they carry an
    attributed `system`, which is the population the lane's spellings used to disagree about.

    #870 FK-3's disjunct was written as `system == ""` while every other seam routed on the
    sentinel. Post-M5′ rows normalize `system` to `""`, so the two agreed on everything the
    collector had minted since — and disagreed on exactly the rows queued BEFORE it deployed,
    which still carry the system their payload was attributed to. Those rows were routed to the
    reducer surface, split per attributed system by the merge, and refused the lane: the
    round's own motivating incident (one unchanging `Binder Error` under eight varied attempts
    against an `elastic` envelope) could not reach the curator. The gate now asks the routing
    predicate, so the row that is treated as the reducer's everywhere else opens the lane too.
    """
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "3")
    persist.append_pitfalls(
        [_shim(f"r:l-003:{i}", system="elastic") for i in range(8)], paths=paths)

    records = _records(paths)
    assert len(records) == 1, "attribution still splits one reducer mistake"
    assert records[0]["occurrences"] == 8
    assert len(records) < 3, "the count alone clears it, so the disjunct is not what fired"

    assert drains._has_lead_author_work(paths) is True, "the drain never wakes for it"
    calls: list = []
    assert pitfalls_curator.run_pitfalls(paths=paths, invoke=_invoke_spy(calls)) == 0
    assert calls, "the tick gate refused the incident FK-3 exists to reach"
    assert [e["surface"] for e in calls[0]] == ["reducer"]


def test_three_distinct_lessons_do_clear_it(paths, monkeypatch):
    """The positive control: the gate still opens, so the negative above is a dedup and not
    a channel that stopped working.

    Driven on the SYSTEM lane (`_row`'s own default since #870): a `∅.bash-shim` row is a
    REDUCER row now, and a reducer row's rotation is governed by FK-7's confirmed-edit rule
    rather than by membership — which is a demand of that round
    (`a_no_edit_reducer_tick_holds_its_rows`) and not what #840's collapse-then-rotate seam is
    about. The merge key is `(owner, stderr_digest)` either way and the digests here are three
    distinct diagnoses, so the collapse under test is unchanged."""
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
    declined to curate.

    The two gates are ONE function (`persist.pitfalls_lane_is_open`) since #870 FK-3, so what
    this now discriminates is that neither reader grew a second opinion of it — including on
    the disjunct, whose own both-readers arm is
    `an_attributed_reducer_lesson_repeated_does_clear_it`."""
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


def test_the_handoff_carries_the_count_and_leads_with_it():
    """`occurrences` reaches the prompt, and the mistake made eight times is the first
    failure in its system's list — the curator's context budget is spent severity-first."""
    handoffs = pitfalls_curator._build_pitfalls_handoffs([
        _row("r:l-001:0", digest="exit=1; made once"),
        *[_row(f"r:l-003:{i}") for i in range(8)],
    ], systems=frozenset({"elastic"}))
    failures = handoffs[0]["failures"]
    assert [f["occurrences"] for f in failures] == [8, 1]
    assert failures[0]["stderr_digest"] == UNNEST


def test_the_handoff_builder_collapses_raw_queue_rows_itself():
    """The builder is handed queue ROWS, which carry no count of their own, and it is the
    last seam before the prompt. It merges rather than trusting its caller to have done it,
    so no future reader of the queue can hand the curator four copies of one bullet."""
    rows = [_row(f"r:l-003:{i}") for i in range(4)]
    for row in rows:
        assert "occurrences" not in row
    failures = pitfalls_curator._build_pitfalls_handoffs(
        rows, systems=frozenset({"elastic"}))[0]["failures"]
    assert len(failures) == 1
    assert failures[0]["occurrences"] == 4


def test_every_duplicate_row_behind_a_curated_record_rotates(paths, monkeypatch):
    """The orphan hazard the collapse creates: the curator sees one record, but the batch is
    named by RAW `pitfall_id`s, so all four rows behind it leave the queue. A row left
    behind would sit in pending forever and re-clear the threshold with a curated lesson.

    On the SYSTEM lane since #870, for the reason `three_distinct_lessons_do_clear_it` records:
    a `∅.bash-shim` row is a reducer row now and is HELD, not rotated, on a tick whose curator
    made no reducer edit."""
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "1")
    persist.append_pitfalls(
        [_row(f"r:l-003:{i}", query_id="elastic.esql") for i in range(4)], paths=paths,
    )

    calls: list = []
    assert pitfalls_curator.run_pitfalls(paths=paths, invoke=_invoke_spy(calls)) == 0
    assert len(calls[0][0]["failures"]) == 1, "the curator saw the duplicates"
    assert _pending(paths) == []
    consumed = [json.loads(ln) for ln in
                paths.pitfalls.consumed.read_text(encoding="utf-8").splitlines()]
    assert sorted(c["pitfall_id"] for c in consumed) == [f"r:l-003:{i}" for i in range(4)]
