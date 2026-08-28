"""#870 — the threshold under normalization, and the three readers of the count it moves.

Every test here is one demand of `spec-flow/specs/spec_graph_870.yaml`, named after that
demand's `discharged_by` pointer and carrying its prose in its docstring. The seam contract
lives in `defender/tests/_declared870.py`.

M5′ moves `pitfall_key`'s `system` component, which moves the record set, which moves the
count THREE readers gate or report on: `run_pitfalls`' tick gate, `drains._has_lead_author_
work`' wake gate, and `lead_author.py:607`'s per-run log line. FK-3 changes what the first two
gate ON — a `system == ""` record clears on its OWN `occurrences`, and no longer contributes
to the distinct COUNT — because the old arithmetic was anti-correlated with evidence quality:
the round's motivating incident is ONE merged record and could never clear a threshold of 3
alone, while N silent failures are N records and did.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from defender.learning import lead_repository
from defender.learning.core import drains, persist
from defender.learning.core.config import LoopPaths, pitfalls_threshold
from defender.learning.leads import lead_author, pitfalls_curator
from defender.learning.leads.lead_extraction import (
    collect_general_failures,
    extract_from_joined,
)
from defender.scripts.gather_tools.record_query import (
    BASH_SHIM_QUERY_ID,
    append_query_row,
)
from defender.tests._declared870 import (
    BINDER,
    Spawn,
    by_surface,
    commit_all,
    curate_execution_md,
    graveyard_by_id,
    loop_log,
    pitfall_row,
    queue_ids,
    seed_tree,
    shim_lead,
    shim_row,
    silent_shim_row,
    write,
    write_reducer_surface,
)


@pytest.fixture
def scene(tmp_path: Path):
    repo = seed_tree(tmp_path, adapters=("elastic", "cmdb"), markers=("elastic",),
                     skills=("elastic",), catalog=(), non_systems=("gather",))
    write_reducer_surface(repo)
    commit_all(repo, "seed the reducer surface")
    return repo, LoopPaths(repo_root=repo, state_dir=tmp_path / "state")


def _tick(paths) -> Spawn:
    """One curation tick with a curator that declines to edit — so what is observed is the
    GATE (was the curator reached at all), never what the curator then did."""
    spawn = Spawn(None)
    assert pitfalls_curator.run_pitfalls(paths=paths, invoke=spawn) == 0
    assert spawn.calls, "the tick gate refused the batch — the curator was never spawned"
    return spawn


# FK-3 — the arrival condition.


def test_the_threshold_gates_on_a_records_own_occurrences(scene, monkeypatch):
    """Three `∅.bash-shim` rows sharing one `stderr_digest` merge to ONE record with
    `occurrences=3` (C8/C17, executed), and at `threshold=3` that single record DOES trip the
    tick gate and DOES wake the drain.

    Normalizing `system` to `""` merges what attribution used to split, which moves the count
    both threshold readers see. What FK-3 changes is WHAT is gated: a `system == ""` record is
    measured by its own `occurrences`, not by the number of distinct merged records.

    REJECTED — gating on the COUNT of distinct merged records, the original #840-applied-
    verbatim reading: under it this exact record is `len(merge_pitfalls(rows)) == 1`, forever
    below 3, so the anti-correlation with evidence quality was the shipped behaviour. That
    arithmetic is asserted here as the thing being left behind, not as the contract.
    """
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "3")
    _repo, paths = scene
    persist.append_pitfalls([shim_row(f"r:l-003:{i}") for i in range(3)], paths=paths)

    records = persist.merge_pitfalls(persist.read_pitfalls(paths))
    assert len(records) == 1, "the three shim rows did not merge to one record"
    assert records[0]["occurrences"] == 3
    assert len(records) < pitfalls_threshold(), (
        "the record-counting reading no longer refuses this batch, so the demand is vacuous"
    )

    assert drains._has_lead_author_work(paths) is True, "the drain never wakes for it"
    assert by_surface(_tick(paths).handoffs)["reducer"], "the tick gate refused it"


def test_the_motivating_incident_reaches_the_curator_alone(scene, monkeypatch):
    """The round's own motivating incident, reproduced: one lead, one unchanging
    `Binder Error`, eight varied attempts — one merged record, `occurrences=8`. BOTH
    `run_pitfalls`' tick and `drains._has_lead_author_work`' wake clear on this record ALONE,
    with no second unrelated mistake required.

    A deployment whose only pending work is this ONE diagnosed reducer mistake reaches the
    curator and wakes the drain — reversing the unreachability FK-3 found under the old,
    record-counting gate, where the lane could only ever fire by riding on ≥2 unrelated
    distinct mistakes that happened to be in the same queue window.

    The rows are produced by the REAL collector over eight real `ExecutedLead`s, so the
    `occurrences` count is the lane's own arithmetic rather than a number this test wrote.
    `threshold_counts_distinct_reducer_mistakes` is the positive control at the merge seam;
    this demand is the same criterion observed end to end at both readers.
    """
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "3")
    _repo, paths = scene
    persist.append_pitfalls(
        collect_general_failures(
            [shim_lead(sql=f"SELECT unnest(data, {i})", query_index=i) for i in range(8)],
            Path("reviewer-measure-0807-b"), catalog=[],
        ),
        paths=paths,
    )
    records = persist.merge_pitfalls(persist.read_pitfalls(paths))
    assert [r["occurrences"] for r in records] == [8], "the eight reduces did not merge to one"
    assert records[0]["system"] == ""

    assert drains._has_lead_author_work(paths) is True
    spawn = _tick(paths)
    assert [e["surface"] for e in spawn.handoffs] == ["reducer"]
    assert spawn.handoffs[0]["failures"][0]["occurrences"] == 8


def test_silent_reducer_failures_alone_do_not_open_the_lane(scene, monkeypatch):
    """Silent reducer failures never open the lane on their OWN EVIDENCE: no number of them
    ever satisfies the criterion FK-3 adds.

    PO-R2 (executed): a content-less digest — nothing but the `exit=N; ` envelope — keys to
    `(system, "\\x00" + pitfall_id)`, unique per row, so every one merges to its own record and
    the whole class is pinned at `occurrences: 1` forever. FK-3's new disjunct asks a
    `system == ""` record for `occurrences >= threshold`, and 1 is never 3.

    WHAT THIS DEMAND DOES NOT CLAIM, because FK-3 does not: the pre-existing DISTINCT-COUNT
    gate is untouched, so N >= threshold content-less rows still trip it, exactly as they do on
    main (PO-R2: 3 content-less rows -> 3 records -> gate cleared). FK-3 ADDS a disjunct; it
    removes nothing, and a systemless record still counts. The wider encoding — a systemless
    record leaving the count entirely — was REJECTED at phase F, because it would have raised
    the SYSTEM lane's own bar as a side effect; that is
    `the_system_lanes_arrival_condition_is_unchanged`'s demand, not this one's to decide.

    So the drive is in two arms and the second discriminates. Below threshold the lane stays
    shut at both readers. At and above it the lane opens — and this demand asserts WHICH ROUTE
    opened it: every record still carries `occurrences == 1`, so the COUNT is what cleared and
    the new disjunct provably did not fire. An implementation that summed occurrences over
    systemless records, or opened on the mere presence of one, agrees with the correct one on
    the count alone and fails here.

    THE COMPOSITION THIS ROUND CREATES IS PINNED HERE TOO, because no other demand sees it: on
    main such a batch produced ZERO handoffs (every systemless row failed the membership
    filter) and graveyarded; after M6 it produces a reducer entry full of undiagnosable
    failures, which `lead_pitfalls.md`'s "skip that failure; never invent one" rule turns into
    a no-edit tick. FK-7 is what keeps that safe rather than lossy, and the last block drives
    exactly that: the rows are HELD, neither consumed nor graveyarded.

    `the_motivating_incident_reaches_the_curator_alone` is the positive control — one record
    whose occurrences DO reach the threshold opens both readers with the count at 1.
    """
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "3")
    _repo, paths = scene
    below = [silent_shim_row(f"r:l-00{i}:0") for i in range(2)]
    persist.append_pitfalls(below, paths=paths)

    records = persist.merge_pitfalls(persist.read_pitfalls(paths))
    assert len(records) == 2, "the two silent rows did not merge to two distinct records"
    assert {r["occurrences"] for r in records} == {1}
    assert drains._has_lead_author_work(paths) is False, "silent noise woke the drain"
    shut = Spawn(None)
    assert pitfalls_curator.run_pitfalls(paths=paths, invoke=shut) == 0
    assert shut.calls == [], "silent noise alone reached the curator"
    assert queue_ids(paths) == [r["pitfall_id"] for r in below]

    # Above threshold the COUNT clears it — the pre-existing route, unchanged — while every
    # record is still worth exactly one occurrence, so FK-3's disjunct cannot be what fired.
    persist.append_pitfalls(
        [silent_shim_row(f"r:l-01{i}:0") for i in range(6)], paths=paths,
    )
    records = persist.merge_pitfalls(persist.read_pitfalls(paths))
    assert len(records) == 8
    assert max(r["occurrences"] for r in records) == 1, (
        "a content-less digest accumulated, so PO-R2's invariant no longer holds and this "
        "demand's whole ground is gone"
    )
    assert drains._has_lead_author_work(paths) is True, (
        "the pre-existing distinct-count gate stopped opening — FK-3 adds a disjunct, it "
        "does not remove the count"
    )
    offered = Spawn(None)
    assert pitfalls_curator.run_pitfalls(paths=paths, invoke=offered) == 0
    assert offered.calls, "the tick gate refused a batch its own count clears"
    assert [e["surface"] for e in offered.calls[-1]["handoffs"]] == ["reducer"]
    assert len(queue_ids(paths)) == 8, (
        "the undiagnosable batch was consumed on the tick it was merely offered — FK-7's "
        "hold is what makes this round's noisier arrival safe rather than lossy"
    )
    assert graveyard_by_id(paths) == {}


def test_the_system_lane_still_curates_at_its_own_threshold(scene, monkeypatch):
    """Two declared-system mistakes plus one reducer record clear a threshold of 3 and the
    SYSTEM lane still curates — the arrival condition merged code already had, unchanged.

    FK-3 is a decision about the REDUCER lane's reachability. Its resolution adds a disjunct
    (`a system == "" record clears on its own occurrences`) and touches nothing else, so a
    systemless record still contributes to the distinct count exactly as it does on main. The
    encoding phase E first wrote was wider — a systemless record leaving the count — and it
    would have raised the system lane's bar without anyone deciding to: this same queue clears
    3 on main and teaches both system lessons, and under the wider reading it would curate
    NOTHING until a third SYSTEM mistake arrived, with the two system rows waiting in the
    queue for it.

    That is the survival demand `merged_work_is_not_reopened` asks for in prose: O1/O2/O5/O6
    and M1-M4 are merged and are not re-implemented here, and where merged behaviour is
    re-asserted it is because a branch now sits in front of it — never because this round
    quietly moved it. Both readers are driven, because the wake gate is the one that would
    strand the batch before the tick ever ran.
    """
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "3")
    repo, paths = scene
    persist.append_pitfalls(
        [pitfall_row("r:l-000:0", "elastic"),
         pitfall_row("r:l-001:0", "cmdb"),
         shim_row("r:l-003:0")],
        paths=paths,
    )
    records = persist.merge_pitfalls(persist.read_pitfalls(paths))
    assert len(records) == 3, "the fixture no longer sits exactly on the count boundary"
    assert max(r["occurrences"] for r in records) == 1, (
        "some record clears the new disjunct on its own, so this says nothing about the count"
    )

    assert drains._has_lead_author_work(paths) is True, (
        "the wake gate stopped counting the reducer record, so the system rows never even "
        "reach a tick"
    )
    spawn = Spawn(curate_execution_md("elastic"))
    assert pitfalls_curator.run_pitfalls(paths=paths, invoke=spawn) == 0
    assert spawn.calls, "the tick gate refused a batch that clears its own count"
    # Read shape-independently: whether the system lane still curates is a question about the
    # GATE, and it must not be answerable only through the key M6 adds.
    assert sorted(
        str(h["system"]) for h in spawn.calls[-1]["handoffs"] if h.get("system")
    ) == ["cmdb", "elastic"], "the system lane stopped curating at its own threshold"
    assert by_surface(spawn.handoffs)["reducer"], (
        "the reducer entry vanished from the mixed batch"
    )
    assert repo.is_dir()


def test_a_threshold_of_zero_curates_every_tick(scene, monkeypatch):
    """`LEARNING_PITFALLS_THRESHOLD=0` is VALID and means every tick with pending work
    curates.

    `0` is the falsy member of this domain — the `x or DEFAULT` coercion shape R4 exists for,
    which silently turns an operator's deliberate 0 into the shipped 3 — and the round adds a
    second way to swallow it: a gate rewritten around `occurrences >= threshold` has to keep
    answering yes at 0 for a record whose occurrences are 1. Both readers are driven.
    """
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "0")
    _repo, paths = scene
    assert pitfalls_threshold() == 0, "the falsy member was coerced away at the read"

    persist.append_pitfalls([shim_row("r:l-003:0")], paths=paths)
    assert drains._has_lead_author_work(paths) is True
    assert by_surface(_tick(paths).handoffs)["reducer"]


def test_a_threshold_of_one_curates_on_the_first_mistake(scene, monkeypatch):
    """`LEARNING_PITFALLS_THRESHOLD=1` is retire-or-curate-on-first, for both classes: one
    reducer record with `occurrences=1` and one attributed record each open the lane.

    The boundary member either side of the falsy one, and the one an operator running a fresh
    deployment actually sets. A gate that compared `occurrences > threshold` rather than `>=`
    passes every other test in this file and fails here.
    """
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "1")
    _repo, paths = scene
    persist.append_pitfalls([shim_row("r:l-003:0")], paths=paths)
    assert drains._has_lead_author_work(paths) is True
    assert by_surface(_tick(paths).handoffs)["reducer"]

    attributed = LoopPaths(repo_root=paths.repo_root, state_dir=paths.state_root / "b")
    persist.append_pitfalls([pitfall_row("r:l-000:0", "elastic")], paths=attributed)
    assert drains._has_lead_author_work(attributed) is True
    assert by_surface(_tick(attributed).handoffs)["system"]


# The other two readers of the same moved count.


def test_the_lead_author_log_line_counts_post_normalization_records(scene, tmp_path, capsys):
    """`lead_author.py:607`'s "N distinct mistake(s) in this run" line reports the
    POST-normalization count.

    It reads the SAME `pitfalls.jsonl` `run_pitfalls` reads — `append_pitfalls(failures,
    paths=deps.paths)` one line earlier in the same lead-author tick, `failures` being
    `collect_general_failures`' own output, not a sibling lane's own queue (the R8 census,
    `47-census-merge-pitfalls.md`). So M5′ reaches this count in the SAME TICK it reaches the
    two gates, and it is a THIRD keyed reader of the field this round re-mints.

    Driven with three `∅.bash-shim` rows sharing one digest, collected from reduces attributed
    to elastic, cmdb and nothing: the line reports ONE distinct mistake, not three. Nothing
    before this demand asserted it — the census that found the edge deliberately left the
    demand unauthored.
    """
    repo, paths = scene
    run_dir = tmp_path / "run-870"
    run_dir.mkdir()
    executed = [
        shim_lead(system="elastic", lead_id="l-001", sql="SELECT unnest(data)"),
        shim_lead(system="cmdb", lead_id="l-002", sql="SELECT unnest(data, 1)"),
        shim_lead(system="", lead_id="l-003", sql="SELECT unnest(data, 2)"),
    ]
    deps = lead_author.LeadAuthorDeps(
        paths=paths,
        systems=frozenset({"elastic", "cmdb"}),
        invoke_agent=lambda *a, **k: 0,
        extract=lambda _run_dir: ([], executed),
        synthesize=lambda *a, **k: [],
        build_handoff=lambda *a, **k: [],
        discover_system_drafts=lambda: [],
        acquire_queue_lock=lambda: object(),
        release_queue_lock=lambda _fh: None,
    )
    capsys.readouterr()

    assert lead_author.run(run_dir, deps=deps) == 0

    log = loop_log(capsys)
    counted = [ln for ln in log.splitlines() if "distinct mistake(s) in this run" in ln]
    assert counted, f"the per-run count line is gone: {log}"
    assert "1 distinct mistake(s) in this run" in counted[0], (
        f"the log line counts pre-normalization rows: {counted[0]!r}"
    )
    assert len(persist.read_pitfalls(paths)) == 3, "the rows themselves are still the evidence"
    assert {r["system"] for r in persist.read_pitfalls(paths)} == {""}
    assert repo.is_dir()


def test_the_learning_side_join_still_splits_the_sentinel_row(tmp_path):
    """`lead_repository.joined` still puts a `∅.bash-shim` row on `JoinedLead.sentinels`, not
    on `.queries`, and still remerges both onto `.rows` in the table's own seq order —
    unchanged by M5′.

    The unmoved reader of a moved source: `joined` → `extract_from_joined` is what hands
    `collect_general_failures` its rows, and #841's remerge is documented as the ONE reader
    that must not take the split. M5′ changes what the LANE does with a sentinel row; this
    demand observes that the reader in front of it did not move — asserted at that reader's
    own edge, because a demand at the boundary is green when the other readers moved.

    The row is written through the production writer and read back through the production
    join, which also executes the arm C21 closed on a READ and never on a run: the
    UNATTRIBUTED shim row survives `extract_from_joined`'s raw-ref gate, because the shim
    writer passes `payload_text=""` precisely so the sidecar exists.
    """
    (tmp_path / "gather_raw").mkdir(parents=True)
    write(tmp_path / "gather_raw" / "l-001.lead.json",
          json.dumps({"goal": "reduce the elastic envelope", "what_to_summarize": []}) + "\n")
    append_query_row(
        tmp_path, lead_id="l-001", system="elastic", verb="query", query_id="elastic.esql",
        params={"native_query": "FROM logs"}, raw_command="elastic query",
        payload_text="[]", exit_code=0, payload_status="ok", payload_digest="2 bytes",
    )
    append_query_row(
        tmp_path, lead_id="l-001", system="", verb="bash", query_id=BASH_SHIM_QUERY_ID,
        params={"command": "cat 0.json | defender-sql 'SELECT unnest(data)'"},
        raw_command="defender-sql", payload_text="", exit_code=1, payload_status="error",
        payload_digest=BINDER,
    )

    joined = [jl for jl in lead_repository.joined(tmp_path) if jl.lead_id == "l-001"]
    assert len(joined) == 1
    lead = joined[0]
    assert [q.query_id for q in lead.queries] == ["elastic.esql"], (
        "the sentinel leaked into the issued-query projection"
    )
    assert [q.query_id for q in lead.sentinels] == [BASH_SHIM_QUERY_ID]
    assert [q.seq for q in lead.rows] == [0, 1], "the remerge lost the table's own order"

    executed = extract_from_joined(joined)
    assert len(executed) == 2, "the shim row's sidecar did not survive the raw-ref gate"
    collected = collect_general_failures(executed, tmp_path, catalog=[])
    assert [(r["query_id"], r["system"]) for r in collected] == [(BASH_SHIM_QUERY_ID, "")]
