"""#869 at the sink: what a real granted call records.

#869: the queries-table row names the system the call was dispatched to.

#869: a dropped row is reported, never silently absorbed, and leaves a durable record.

The mixed pitfalls tick runs over a batch draft (`_curator1134.draft_lane`) with adapters in a
product checkout; what landed is read from the batch branch (`agent/...`).
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip('pydantic_ai')

from defender.tests.e2e.test_pitfalls_input import _dispatch, _run  # noqa: E402
from defender.tests.e2e._replay_harness import Turn, VerbRecorder  # noqa: E402
from defender.tests.e2e.test_query_tool import DONE, elastic_ok, q  # noqa: E402
from defender.learning.leads.draft_synthesis import (
    _draft_basename,
    _draft_candidate_segments,
)
from defender.investigation.query_tool import resolve_query_id
from defender.tests.support.tenancy._launch_publish_p4 import directory_for_root
from defender.tests.support.shared._locations_1210 import location_path
from defender.learning.core import drains, persist
from defender.learning.core.config import LoopPaths
from defender.learning.leads.lead_extraction import LeadAuthorError
from defender.tests.support.runtime.engine._declared869 import (
    Spawn,
    agent_marker_file,
    pitfall_row,
    read_rows,
    seed_agent_files,
    seed_product,
    seed_tree,
    write,
)
from defender.tests.support.learning.curation import _curator1134 as C
from defender.tests.support.learning.curation._curator1134 import open_state
from defender.tests.support.learning.curation._lead_author_1134 import run_pitfalls
from defender.tests.support.learning.core._state1135 import curation_row, curation_run_dir, drained_for
from defender.learning.core.state import PITFALLS


PARAMS = {"native_query": "FROM logs"}


@pytest.mark.e2e
def test_granted_call_records_its_own_system(tmp_path):
    rec = VerbRecorder()
    res = _run(
        tmp_path,
        turns=[
            q("elastic", "query", PARAMS, query_id="fakesys.hunt-creds"),
            q("elastic", "query", PARAMS, query_id="elastic.hunt-creds"),
            DONE,
        ],
        run_id="qid-869",
        verbs=elastic_ok(rec),
        main_turns=[
            Turn(tool_calls=[_dispatch()]), Turn(text="Investigation complete."),
        ],
    )

    dispatched = _dispatch()[1]["system"]
    granted = [r for r in res.own_rows if r["exit_code"] == 0]
    assert len(rec.calls) == 2, "the verb was not reached, so no call was granted and executed"
    assert len(granted) == 2

    refused, kept = granted
    assert refused["system"] == dispatched
    assert refused["query_id"] == f"{dispatched}.{refused['verb']}"
    assert "fakesys" not in refused["query_id"]

    assert kept["query_id"] == "elastic.hunt-creds"

    # And nothing else this run wrote disagrees with its own dispatched system either.
    for row in res.own_rows:
        if row["query_id"].startswith("∅."):
            continue          # a writer-only sentinel names no system by construction
        assert row["query_id"].split(".", 1)[0] == row["system"]


def test_resolve_query_id_refuses_a_foreign_prefix():
    assert resolve_query_id("elastic", "esql", "fakesys.hunt-creds") == "elastic.esql"
    # The screen's other refusals still hold: a reserved sentinel prefix and a traversal-bearing id.
    assert resolve_query_id("elastic", "esql", "∅.bash-shim") == "elastic.esql"
    assert resolve_query_id("elastic", "esql", "../x") == "elastic.esql"


def test_resolve_query_id_keeps_a_matching_prefix():
    assert resolve_query_id("elastic", "esql", "elastic.hunt-creds") == "elastic.hunt-creds"
    assert resolve_query_id("cmdb", "get-host", "cmdb.crown-jewels") == "cmdb.crown-jewels"


def test_resolve_query_id_enforces_the_whole_schema_shape():
    assert resolve_query_id("elastic", "esql", "elastic") == "elastic.esql"
    assert resolve_query_id("elastic", "esql", "elastic.") == "elastic.esql"
    assert resolve_query_id("elastic", "esql", "elastic.foo.bar") == "elastic.esql"

    system, basename = _draft_candidate_segments(
        "elastic.foo.bar", "esql", set(), row_system="elastic")
    assert system == "elastic"
    assert basename == _draft_basename("elastic.foo.bar")
    assert "foo" not in basename
    assert "." not in basename
    assert _draft_candidate_segments(
        resolve_query_id("elastic", "esql", "elastic.foo.bar"), "esql", set(),
        row_system="elastic",
    ) is None

    # The control on the same address: a well-formed coined id still survives.
    assert resolve_query_id("elastic", "esql", "elastic.hunt-creds") == "elastic.hunt-creds"


def _mixed_batch(tmp_path: Path, monkeypatch, *, name: str = "repo"):
    """Two `elastic` rows, one undeclared `elastik` row, and a curator edit that makes a real
    commit: only a batch that commits gives the dropped row a sha it could wrongly inherit (an
    all-dropped batch's sha is `None`)."""
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "2")
    product = seed_product(tmp_path, adapters=("elastic",), name=f"product-{name}")
    lane = C.draft_lane(tmp_path, lanes=C.LEAD_LANES, product=product,
                        files=seed_agent_files(markers=("elastic",), skills=("elastic",),
                                               catalog=()),
                        state_dir=tmp_path / f"state-{name}")
    paths = lane.paths
    state = open_state(paths)
    persist.append_pitfalls(
        [pitfall_row("r:l-000:0", "elastic"),
         pitfall_row("r:l-001:0", "elastic"),
         pitfall_row("r:l-002:0", "elastik")],
        state=state,
    )
    spawn = Spawn(lambda root: write(
        agent_marker_file(root, "elastic"), "# elastic\n## Common pitfalls\n- curated\n",
    ), root=lane.root)
    return lane, paths, spawn


def test_a_dropped_row_is_never_labelled_committed(tmp_path, monkeypatch):
    lane, paths, spawn = _mixed_batch(tmp_path, monkeypatch)
    state = open_state(paths)
    run_pitfalls(lane, state, spawn)

    consumed = {r["pitfall_id"]: r for r in read_rows(location_path(paths.state_root) / PITFALLS.consumed)}
    assert set(consumed) == {"r:l-000:0", "r:l-001:0", "r:l-002:0"}
    assert "agent/skills/elastic/execution.md" in lane.landed()

    dropped = consumed["r:l-002:0"]
    assert dropped["consumed_category"] != "consumed_committed"
    assert dropped.get("consumed_commit") is None

    for kept in ("r:l-000:0", "r:l-001:0"):
        assert consumed[kept]["consumed_category"] == "consumed_committed"
        assert consumed[kept]["consumed_commit"]


def test_a_dropped_row_takes_a_terminal_undeclared_category(tmp_path, monkeypatch):
    lane, paths, spawn = _mixed_batch(tmp_path, monkeypatch, name="undeclared")
    state = open_state(paths)
    run_pitfalls(lane, state, spawn)

    consumed = {r["pitfall_id"]: r for r in read_rows(location_path(paths.state_root) / PITFALLS.consumed)}
    assert consumed["r:l-002:0"]["consumed_category"] == "consumed_unattributable"
    assert "consumed_commit" not in consumed["r:l-002:0"]
    assert consumed["r:l-000:0"]["consumed_category"] == "consumed_committed"

    assert persist.read_pitfalls(state) == [], "pending must go empty; the row is terminal"
    graveyard = {r.get("pitfall_id") for r in read_rows(location_path(paths.state_root) / PITFALLS.deadletter)}
    assert "r:l-002:0" in graveyard, (
        "the dropped row leaves no durable record, so nothing reaches human review"
    )
    assert "r:l-000:0" not in graveyard
    assert "agent/skills/elastic/execution.md" in lane.landed()


def test_a_membership_refusal_is_terminal_and_leaves_a_re_drivable_record(tmp_path, capsys):
    repo = seed_tree(tmp_path, adapters=("elastic",), markers=("elastic",), skills=("elastic",),
                     catalog=())
    # A run folder the drain rehydrates the row from: the row is its address.
    run_dir = curation_run_dir("run-x")
    paths = drained_for(LoopPaths(repo_root=repo, state_dir=tmp_path / "state"), run_dir)  # r10.1 C1: paths.tenant
    state = open_state(paths)
    (run_dir / "gather_raw").mkdir()
    write(location_path(paths.state_root) / "author-queue" / "case-1.json",
          json.dumps(curation_row("case-1", run_dir)) + "\n")

    calls: list[Path] = []

    def refusing_lane(_paths, _state, run, *, box=None, **_kw):
        calls.append(run.run_dir)
        raise LeadAuthorError(
            "lead author refused: mcpsys is not a declared system in this tree")

    capsys.readouterr()
    for _tick in range(5):
        drains._drain_lead_author_markers(paths, state, refusing_lane,
                                          directory=directory_for_root())

    assert len(calls) == 1, f"the refusal was retried: {len(calls)} invocations"
    assert not (location_path(paths.state_root) / "author-queue" / "case-1.json").exists()
    assert not list((location_path(paths.state_root) / "author-queue" / "inflight").glob("*.json"))

    failed = location_path(paths.state_root) / "author-queue" / "failed" / "case-1.json"
    assert failed.is_file()
    record = json.loads(failed.read_text())
    assert "mcpsys" in record["failed"]
    assert (record["tenant_id"], record["run_id"]) == (run_dir.parent.parent.name, run_dir.name)
    assert record["case_id"] == "case-1"
    assert "attempts" not in record, (
        "an attempts counter means the retriable class was taken, which §7 declined"
    )
