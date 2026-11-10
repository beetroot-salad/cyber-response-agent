"""The pitfalls record set is deduplicated on read by (owner, stderr_digest) and the occurrence count survives the collapse.

#1278: the rows are the claim's pitfall items (one per occurrence, design r8 Schema); `persist.merge_pitfalls` is pure and
unchanged. Retired: the file queue's `rotate` of duplicates into the consumed ledger (now: every duplicate is reported
committed with its record, below) and the retire-stamp bookkeeping test (`drain.retire`, gone; replaced by the exemplar-whole check)."""
from __future__ import annotations

from pathlib import Path

import pytest

from defender.learning.core import persist
from defender.learning.leads import pitfalls_curator
from defender.learning.leads.lead_extraction import ExecutedLead, collect_general_failures
from defender.knowledge._query_rules import BASH_SHIM_QUERY_ID
from defender.tests.support.learning.core._store1278 import call, migrated_database, world  # noqa: F401 — fixtures
from defender.tests.tenancy.tenant_1108_p4.conftest import p4_tenant  # noqa: F401 — fixture `world` is built on
from defender.tests.support.shared.contracts._repo import seed_skills_repo
from defender.tests.support.learning.curation import _curator1134 as C

#: l-003's real failure in `reviewer-measure-0807-b` — the same DuckDB diagnosis, turn after
#: turn, while the SQL that provoked it changed every time.
UNNEST = "exit=1; Binder Error: No function matches unnest(JSON) - candidates: unnest(LIST)"
QUOTING = "exit=1; Parser Error: syntax error at or near \"@timestamp\""


class _Queue:
    """The claim's pitfall rows, one per occurrence (design r8 Schema: "pitfalls stay one row per occurrence"), over the
    product checkout `repo_root` that holds the adapters."""

    def __init__(self, repo_root: Path) -> None:
        self.repo_root = repo_root
        self.rows: list[dict] = []

    def append(self, rows: list[dict]) -> None:
        self.rows.extend(rows)

    def items(self) -> list[tuple[str, str, dict]]:
        return [("pitfall", r["pitfall_id"], r) for r in self.rows]


@pytest.fixture
def paths(tmp_path: Path) -> _Queue:
    return _Queue(seed_skills_repo(tmp_path / "repo"))


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
    """A queued REDUCER row: the reserved sentinel in `query_id`. `system` defaults to `""`;
    it is a parameter because older reducer rows carry the system they were attributed to, and
    those are the rows that separate the lane's spellings."""
    return _row(pid, digest=digest, system=system,
                query_id=BASH_SHIM_QUERY_ID, **extra)


def _records(rows: list[dict]) -> list[dict]:
    """The queue's RECORD SET — what the threshold counts and the curator receives."""
    return persist.merge_pitfalls(rows)


# The collapse itself — one looping lead is one lesson, and the loop is still legible.


def test_one_looping_leads_eight_turns_become_one_record_carrying_its_count(paths):
    executed = [_lead(sql=f"SELECT unnest(data, {i})", query_index=i) for i in range(8)]
    collected = collect_general_failures(executed, Path("reviewer-measure-0807-b"), catalog=[])
    assert len(collected) == 8, "the collector no longer returns one record per row"

    paths.append(collected)
    assert len(paths.rows) == 8, "the rows are the evidence and all eight are kept"
    records = _records(paths.rows)
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
    paths.append(collect_general_failures(executed, Path("r"), catalog=[]))
    assert sorted(r["stderr_digest"] for r in _records(paths.rows)) == sorted([QUOTING, UNNEST])
    assert [r["occurrences"] for r in _records(paths.rows)] == [1, 1]


def test_the_same_digest_from_two_systems_stays_two_records(paths):
    """The OWNER is half the key. One `execution.md` per system is the whole point of the
    channel — collapsing across systems would send a host-state lesson to elastic's file."""
    paths.append([_row("r:l-001:0"), _row("r:l-002:0", system="host-state",
                                 query_id="host-state.ps")])
    assert {r["system"] for r in _records(paths.rows)} == {"elastic", "host-state"}


def test_the_reducer_owns_its_lesson_whatever_attributed_it(paths):
    """The reducer owns its key: attributed to a system or not, reducer rows merge with each
    other and never with a system row."""
    paths.append([_shim("r:l-001:0", system="elastic"), _shim("r:l-002:0"),
         _row("r:l-003:0")])
    records = _records(paths.rows)
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
    rows = [_row("r:l-001:0", executed_query="FROM a | STATS x") | {"query_id": "elastic.a"},
            _row("r:l-002:0", executed_query="FROM b | STATS y") | {"query_id": "elastic.b"}]
    paths.append(rows)
    assert len(_records(paths.rows)) == 1
    assert _records(paths.rows)[0]["occurrences"] == 2


def test_a_later_run_repeating_the_mistake_bumps_the_count(paths):
    """Cross-run, which is the half a collector-side dedup could not reach: three runs that
    each make the same mistake once are still one lesson, and the queue says so."""
    for run in ("run-a", "run-b", "run-c"):
        paths.append([_row(f"{run}:l-001:0")])
    records = _records(paths.rows)
    assert len(records) == 1
    assert records[0]["occurrences"] == 3
    assert records[0]["source_run"] == "run-a", "the exemplar's provenance moved"


def test_a_merged_record_keeps_the_exemplars_row_whole(paths):
    """The merge copies the exemplar row whole, so what the claim stamped on it (an `attempts` count) survives, and the
    retried row is merged, not dropped. (`drain.retire`, which stamped it on the file queue, is gone, #1278)"""
    paths.append([_row("r:l-001:0", attempts=1), _row("r2:l-001:0")])
    record = _records(paths.rows)[0]
    assert record["attempts"] == 1, "the exemplar's own fields did not survive the merge"
    assert record["occurrences"] == 2, "a row that had been retried was dropped, not merged"


def test_merging_a_record_set_twice_changes_nothing(paths):
    """Two seams merge — the threshold gate and the handoff builder — and one feeds the
    other. The collapse is therefore idempotent by contract, not by luck of call order."""
    paths.append([*[_row(f"r:l-003:{i}") for i in range(5)],
         _row("r:l-004:0", digest=QUOTING),
         _row("r:l-005:0", system="host-state", query_id="host-state.ps"),
         _row("r:l-006:0", digest="")])
    once = _records(paths.rows)
    assert len(once) == 4
    assert persist.merge_pitfalls(once) == once


def test_a_row_whose_digest_carries_no_diagnosis_keys_to_itself(paths):
    """The absence of a verdict is not a verdict two rows hold in common."""
    same = [_row(f"r:l-00{i}:0", digest="exit=1; ", executed_query=f"SELECT {i}")
            for i in range(3)]
    paths.append(same)
    records = _records(paths.rows)
    assert len(records) == 3, "three unrelated failures collapsed onto one empty diagnosis"
    assert [r["executed_query"] for r in records] == ["SELECT 0", "SELECT 1", "SELECT 2"], (
        "the curator would have received one exemplar and the other two would rotate away"
    )

    # The whole no-diagnosis family, each spelling of it repeated: a bare envelope with no
    # trailing space, nothing at all, and whitespace-only.
    for digest in ("exit=2;", "", "   "):
        assert len(persist.merge_pitfalls([_row(f"v:l-00{i}:0", digest=digest) for i in range(2)])) == 2, (
            f"two failures merged on the empty diagnosis {digest!r}"
        )


# The threshold counts distinct mistakes, so clearing it means the channel learned that many
# things.


def _run_pitfalls(queue: _Queue, invoke: object, tmp_path: Path, *, captured: list | None = None, outcomes: dict | None = None) -> int:
    """`run_pitfalls(..., batch=, items=)` over a batch draft of the tenant (the lane commits only into a batch), handed the
    queue's rows as the claim's items; `queue.repo_root` is the product checkout holding the adapters."""
    lane = C.draft_lane(tmp_path, lanes=C.LEAD_LANES, product=queue.repo_root)
    with C.draft_trees(lane) as trees:
        return pitfalls_curator.run_pitfalls(paths=lane.paths, invoke=invoke, trees=trees, batch=lane.batch, items=queue.items(),
                                             outcomes=outcomes if outcomes is not None else {},
                                             on_curated=(captured if captured is not None else []).append)


def _invoke_spy(calls: list) -> object:
    def _invoke(handoffs, *, state, repo_root, box=None):
        calls.append(handoffs)
        return 0
    return _invoke


def test_a_single_lesson_repeated_does_not_clear_the_threshold(paths, monkeypatch, tmp_path):
    """On the system lane, eight rows of one mistake are one record: under threshold 3."""
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "3")
    paths.append([_row(f"r:l-003:{i}") for i in range(8)])
    calls: list = []

    assert _run_pitfalls(paths, _invoke_spy(calls), tmp_path) == 0
    assert calls == [], "the curator ran on one lesson wearing eight hats"
    assert len(_records(paths.rows)) == 1
    assert len(paths.rows) == 8, "the under-threshold queue lost its evidence"


def test_an_attributed_reducer_lesson_repeated_does_clear_it(paths, monkeypatch, tmp_path):
    """The same eight rows as attributed REDUCER rows DO open the lane: one record whose
    `occurrences` alone clears the threshold, handed off on the reducer surface."""
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "3")
    paths.append([_shim(f"r:l-003:{i}", system="elastic") for i in range(8)])

    records = _records(paths.rows)
    assert len(records) == 1, "attribution still splits one reducer mistake"
    assert records[0]["occurrences"] == 8

    calls: list = []
    assert _run_pitfalls(paths, _invoke_spy(calls), tmp_path) == 0
    assert calls, "the tick gate refused the attributed reducer record"
    assert [e["surface"] for e in calls[0]] == ["reducer"]


@pytest.mark.postgres
def test_the_wake_gate_counts_what_the_curation_gate_counts(world, monkeypatch):  # noqa: F811 — the imported fixture
    """The lead lane's wake gate (the store claim) is what spins the drain up: eight rows of one mistake do not wake it under
    threshold 3, a second and a third distinct mistake do."""
    from defender.learning.core.store_tick import LEAD_LANE, lane_waiting
    from defender.learning.store import blocking

    w = world
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "3")

    def waiting() -> bool:
        with blocking(w.dsn) as store:
            return lane_waiting(store, w.t.tenant_id, LEAD_LANE)

    for row in [_row(f"r:l-003:{i}") for i in range(8)]:
        call(w.dsn, "add_pitfall", w.t.tenant_id, row)
    assert waiting() is False, "eight rows of one mistake woke a lane whose threshold counts mistakes"

    for row in (_row("r:l-004:0", digest="exit=1; a second error"), _row("r:l-005:0", digest="exit=1; a third error")):
        call(w.dsn, "add_pitfall", w.t.tenant_id, row)
    assert waiting() is True


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


def test_every_duplicate_row_behind_a_curated_record_is_reported_committed(paths, monkeypatch, tmp_path):
    """The orphan hazard the collapse creates: the curator sees one record, but every duplicate row behind it is reported
    committed with it (so it stays in the batch for the merge, instead of one being held and the rest waiting for ever)."""
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "1")
    paths.append([_row(f"r:l-003:{i}", query_id="elastic.esql") for i in range(4)])

    calls: list = []
    captured: list = []
    outcomes: dict = {}
    assert _run_pitfalls(paths, _invoke_spy(calls), tmp_path, captured=captured, outcomes=outcomes) == 0
    assert len(calls[0][0]["failures"]) == 1, "the curator saw the duplicates"
    assert sorted(captured[-1].committed_ids) == [f"r:l-003:{i}" for i in range(4)]
    assert outcomes == {}, "a duplicate behind a curated record was decided as other than committed"
