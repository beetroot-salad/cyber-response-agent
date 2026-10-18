"""The pitfalls record set is deduplicated on read by (owner, stderr_digest) and the occurrence count survives the collapse."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from defender.learning.author import drain
from defender.learning.core import drains, persist
from defender.learning.core.config import LoopPaths
from defender.learning.core.state import PITFALLS
from defender.learning.leads import pitfalls_curator
from defender.learning.leads.lead_extraction import ExecutedLead, collect_general_failures
from defender._query_rules import BASH_SHIM_QUERY_ID
from defender.tests import _state1135
from defender.tests._repo import seed_skills_repo
from defender.tests._lead_author_1134 import lead_trees

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
    """A queued record as it stands on disk — the pre-#840 shape, carrying no count."""
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
    return persist.read_pitfalls(_state1135.state_for_paths(paths))


def _records(paths: LoopPaths) -> list[dict]:
    """The queue's RECORD SET — what the threshold counts and the curator receives."""
    return persist.merge_pitfalls(persist.read_pitfalls(_state1135.state_for_paths(paths)))


# The collapse itself — one looping lead is one lesson, and the loop is still legible.


def test_one_looping_leads_eight_turns_become_one_record_carrying_its_count(paths):
    """The motivating incident, through the REAL collector. Eight brute-forced reduces, each
    with its own SQL and its own row, produce eight records — the collector stays per-row, as
    #823 N3 requires — and land in the queue as ONE record whose `occurrences` is 8."""
    executed = [_lead(sql=f"SELECT unnest(data, {i})", query_index=i) for i in range(8)]
    collected = collect_general_failures(executed, Path("reviewer-measure-0807-b"), catalog=[])
    assert len(collected) == 8, "the collector is per-row and #823 N3 keeps it that way"

    persist.append_pitfalls(collected, state=_state1135.state_for_paths(paths))
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
        collect_general_failures(executed, Path("r"), catalog=[]), state=_state1135.state_for_paths(paths))
    assert sorted(r["stderr_digest"] for r in _records(paths)) == sorted([QUOTING, UNNEST])
    assert [r["occurrences"] for r in _records(paths)] == [1, 1]


def test_the_same_digest_from_two_systems_stays_two_records(paths):
    """The OWNER is half the key. One `execution.md` per system is the whole point of the
    channel — collapsing across systems would send a host-state lesson to elastic's file."""
    persist.append_pitfalls(
        [_row("r:l-001:0"), _row("r:l-002:0", system="host-state",
                                 query_id="host-state.ps")], state=_state1135.state_for_paths(paths))
    assert {r["system"] for r in _records(paths)} == {"elastic", "host-state"}


def test_the_reducer_owns_its_lesson_whatever_attributed_it(paths):
    """#870's half of the same key, and the two directions it moves."""
    persist.append_pitfalls(
        [_shim("r:l-001:0", system="elastic"), _shim("r:l-002:0"),
         _row("r:l-003:0")],
        state=_state1135.state_for_paths(paths),
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
    persist.append_pitfalls(rows, state=_state1135.state_for_paths(paths))
    assert len(_records(paths)) == 1
    assert _records(paths)[0]["occurrences"] == 2


def test_a_later_run_repeating_the_mistake_bumps_the_count(paths):
    """Cross-run, which is the half a collector-side dedup could not reach: three runs that
    each make the same mistake once are still one lesson, and the queue says so."""
    for run in ("run-a", "run-b", "run-c"):
        persist.append_pitfalls([_row(f"{run}:l-001:0")], state=_state1135.state_for_paths(paths))
    records = _records(paths)
    assert len(records) == 1
    assert records[0]["occurrences"] == 3
    assert records[0]["source_run"] == "run-a", "the exemplar's provenance moved"


def test_a_merged_record_keeps_the_exemplars_queue_bookkeeping(paths):
    """The merge copies the exemplar row whole, so whatever the drain has stamped on it is"""
    persist.append_pitfalls([_row("r:l-001:0"), _row("r2:l-001:0")], state=_state1135.state_for_paths(paths))
    drain.retire(_state1135.state_for_paths(paths), channel=PITFALLS, batch_ids=["r:l-001:0", "r2:l-001:0"],
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
        state=_state1135.state_for_paths(paths),
    )
    once = _records(paths)
    assert len(once) == 4
    assert persist.merge_pitfalls(once) == once


def test_a_row_whose_digest_carries_no_diagnosis_keys_to_itself(paths):
    """The absence of a verdict is not a verdict two rows hold in common."""
    same = [_row(f"r:l-00{i}:0", digest="exit=1; ", executed_query=f"SELECT {i}")
            for i in range(3)]
    persist.append_pitfalls(same, state=_state1135.state_for_paths(paths))
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
            [_row(f"v:l-00{i}:0", digest=digest) for i in range(2)], state=_state1135.state_for_paths(p))
        assert len(persist.merge_pitfalls(persist.read_pitfalls(_state1135.state_for_paths(p)))) == 2, (
            f"two failures merged on the empty diagnosis {digest!r}"
        )


# O3's repair — the threshold now counts distinct mistakes, so clearing it means the channel
# learned that many things.


def _invoke_spy(calls: list) -> object:
    def _invoke(handoffs, *, state, repo_root, box=None):
        calls.append(handoffs)
        return 0
    return _invoke


def test_a_single_lesson_repeated_does_not_clear_the_threshold(paths, monkeypatch):
    """#840's headline, ON THE SYSTEM LANE."""
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "3")
    persist.append_pitfalls([_row(f"r:l-003:{i}") for i in range(8)], state=_state1135.state_for_paths(paths))
    calls: list = []

    assert pitfalls_curator.run_pitfalls(paths=paths, invoke=_invoke_spy(calls),
                                         trees=lead_trees(paths)) == 0
    assert calls == [], "the curator ran on one lesson wearing eight hats"
    assert len(_records(paths)) == 1
    assert len(_pending(paths)) == 8, "the under-threshold queue lost its evidence"


def test_an_attributed_reducer_lesson_repeated_does_clear_it(paths, monkeypatch):
    """The same eight rows, differing only in `query_id`, DO open the lane — and they carry an"""
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "3")
    persist.append_pitfalls(
        [_shim(f"r:l-003:{i}", system="elastic") for i in range(8)], state=_state1135.state_for_paths(paths))

    records = _records(paths)
    assert len(records) == 1, "attribution still splits one reducer mistake"
    assert records[0]["occurrences"] == 8
    assert len(records) < 3, "the count alone clears it, so the disjunct is not what fired"

    assert drains._has_lead_author_work(_state1135.state_for_paths(paths)) is True, "the drain never wakes for it"
    calls: list = []
    assert pitfalls_curator.run_pitfalls(paths=paths, invoke=_invoke_spy(calls),
                                         trees=lead_trees(paths)) == 0
    assert calls, "the tick gate refused the incident FK-3 exists to reach"
    assert [e["surface"] for e in calls[0]] == ["reducer"]


def test_the_wake_gate_counts_what_the_curation_gate_counts(paths, monkeypatch):
    """`_has_lead_author_work` is what spins the drain up."""
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "3")
    persist.append_pitfalls([_row(f"r:l-003:{i}") for i in range(8)], state=_state1135.state_for_paths(paths))
    assert drains._has_lead_author_work(_state1135.state_for_paths(paths)) is False

    persist.append_pitfalls(
        [_row("r:l-004:0", digest="exit=1; a second error"),
         _row("r:l-005:0", digest="exit=1; a third error")], state=_state1135.state_for_paths(paths))
    assert drains._has_lead_author_work(_state1135.state_for_paths(paths)) is True


# What the curator receives — collapsed, counted, severest first.


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


def test_every_duplicate_row_behind_a_curated_record_rotates(paths, monkeypatch):
    """The orphan hazard the collapse creates: the curator sees one record, but the batch is"""
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "1")
    persist.append_pitfalls(
        [_row(f"r:l-003:{i}", query_id="elastic.esql") for i in range(4)], state=_state1135.state_for_paths(paths),
    )

    calls: list = []
    assert pitfalls_curator.run_pitfalls(paths=paths, invoke=_invoke_spy(calls),
                                         trees=lead_trees(paths)) == 0
    assert len(calls[0][0]["failures"]) == 1, "the curator saw the duplicates"
    assert _pending(paths) == []
    consumed = [json.loads(ln) for ln in
                (paths.state_root / PITFALLS.consumed).read_text(encoding="utf-8").splitlines()]
    assert sorted(c["pitfall_id"] for c in consumed) == [f"r:l-003:{i}" for i in range(4)]
