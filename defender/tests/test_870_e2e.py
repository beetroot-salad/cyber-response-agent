"""#870 O3 — the round's own oracle, end to end and across the process boundary.

This file carries ONE demand of `spec-flow/specs/spec_graph_870.yaml`, named after that
demand's `discharged_by` pointer and carrying its prose in its docstring. The seam contract
lives in `defender/tests/_declared870.py`.

IT LIVES AT THE TOP LEVEL OF `defender/tests/` ON PURPOSE, not under `tests/e2e/`: the graph
declares `tests: defender/tests`, and the checkers glob `<dir>/*.py` without recursing — a
replay-driven test placed under `e2e/` falls outside that scan and its demand reports as a
prose orphan. Importing `defender.tests.e2e._replay_harness` from here is established practice
(`test_869_queries_row.py`, `test_record_query.py` and ~15 others).

It crosses the process boundary FF-7 names: the row is written by the RUNTIME process and read
by the LEARNING process with no import edge between them, so the two halves are driven in one
test rather than joined by a shared assumption about what the table holds.
"""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender.agents import GATHER_DEF  # noqa: E402
from defender.learning.core import persist  # noqa: E402
from defender.learning.core.config import LoopPaths  # noqa: E402
from defender.learning.leads import pitfalls_curator  # noqa: E402
from defender.learning.leads.lead_extraction import collect_general_failures  # noqa: E402
from defender.runtime import permission  # noqa: E402
from defender.runtime.agent_definition import compile_policy_for  # noqa: E402
from defender.scripts.gather_tools.record_query import BASH_SHIM_QUERY_ID  # noqa: E402
from defender.tests._declared870 import (  # noqa: E402
    BINDER,
    REDUCER_REL,
    Spawn,
    by_surface,
    commit_all,
    consumed_by_id,
    curate_reducer_surface,
    git,
    head_files,
    queue_ids,
    seed_tree,
    write_reducer_surface,
)
from defender.tests.e2e._replay_harness import GOLDEN_AB3, materialize  # noqa: E402
from defender.tests.e2e.test_pitfalls_input_823 import _reduce, _run  # noqa: E402
from defender.tests.e2e.test_query_tool_611 import DONE, q  # noqa: E402

pytestmark = pytest.mark.e2e


def test_e2e_a_failed_reducer_pipe_becomes_a_reducer_handoff(tmp_path: Path, monkeypatch):
    """O3's own oracle, end to end: a replay run whose gather lane fails a terminal
    `cat <payload> | defender-sql …` leaves `∅.bash-shim` rows in the pitfalls queue, and the
    next curation tick hands the curator a handoff whose `path` is the reducer surface — which
    the curator then writes and the loop commits.

    Asserted on the QUEUE ROW and the HANDOFF TARGET and the COMMIT, because "the drop counter
    is 0" would pass a build that never wrote the row at all.

    The whole chain is production code between two fakes: the model is scripted and the box
    returns a scripted failure (the real `defender-sql` is not exercised — a test that
    depended on it would be asserting about the machine's duckdb install, and at this base the
    shim exits `EXIT_NO_RUNTIME` here, which the translation table calls infra and the lane
    correctly refuses to teach). Everything between — the permission gate, `_record_shim_
    failure`'s four conjunctive preconditions, `terminal_reducer`'s structural test, the
    queries table, the join, the extraction, the collector, the merge, the threshold, the
    handoff builder, the path rule, the content rule and the commit — is the real thing.

    THE THRESHOLD IS PART OF THE ORACLE, not a fixture detail. Three failing reduces of one
    unchanging diagnosis are ONE merged record with `occurrences=3`, and under FK-3's gate
    that record clears a threshold of 3 on its own. Under the record-counting reading it never
    could, and the motivating incident would have been unreachable end to end — which is what
    made FK-3 a decision about whether this lane fires at all rather than a tuning question.
    """
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "3")
    run_dir = materialize(tmp_path, GOLDEN_AB3)
    res = _run(
        tmp_path, run_dir=run_dir, run_id="d870-e2e",
        turns=[
            q("elastic", "query", {"native_query": "FROM logs"}),
            _reduce(run_dir, sql="SELECT unnest(data)"),
            _reduce(run_dir, sql="SELECT unnest(data, 1)"),
            _reduce(run_dir, sql="SELECT unnest(data, 2)"),
            DONE,
        ],
    )

    # --- the runtime half: the table really carries the sentinel rows ---------------------
    shim = [r for r in res.own_rows if r["query_id"] == BASH_SHIM_QUERY_ID]
    assert len(shim) == 3, "the terminal reduce recorded nothing, so there is nothing to teach"
    assert {r["payload_digest"] for r in shim} == {BINDER}
    assert {r["error_class"] for r in shim} == {"agent-fixable"}

    # --- the learning half: the same rows, through the real join and the real collector ---
    collected = collect_general_failures(res.own_leads(), run_dir, catalog=[])
    assert len(collected) == 3, "the rows did not survive the offline extraction"
    assert {r["system"] for r in collected} == {""}, (
        "a defender-sql mistake reached the queue attributed to a system"
    )

    repo = seed_tree(tmp_path, adapters=("elastic",), markers=("elastic",),
                     skills=("elastic",), catalog=(), non_systems=("gather",))
    write_reducer_surface(repo)
    commit_all(repo, "seed the reducer surface")
    paths = LoopPaths(repo_root=repo, state_dir=tmp_path / "state")
    persist.append_pitfalls(collected, paths=paths)

    records = persist.merge_pitfalls(persist.read_pitfalls(paths))
    assert [r["occurrences"] for r in records] == [3]

    # --- the curation tick: the handoff names the surface, and the commit carries it ------
    spawn = Spawn(curate_reducer_surface("keep the unnest argument a LIST"))
    head_before = git(repo, "rev-parse", "HEAD").stdout.strip()
    assert pitfalls_curator.run_pitfalls(paths=paths, invoke=spawn) == 0

    reducer = by_surface(spawn.handoffs)["reducer"]
    assert len(reducer) == 1
    assert reducer[0]["path"] == REDUCER_REL
    assert reducer[0]["failures"][0]["stderr_digest"] == BINDER
    assert "defender-sql" in reducer[0]["failures"][0]["executed_query"]

    # THIS TICK's commit, not HEAD's file list: the fixture seeds the reducer surface in its
    # own commit, so the literal is in `head_files` from the seed whenever the tick commits
    # nothing — which is exactly the build this demand exists to catch.
    assert git(repo, "rev-parse", "HEAD").stdout.strip() != head_before, (
        "the taught lesson never reached a commit of its own"
    )
    assert REDUCER_REL in head_files(repo), "the tick committed, but not the reducer surface"
    assert "keep the unnest argument a LIST" in (
        (repo / REDUCER_REL).read_text(encoding="utf-8")
    )
    assert queue_ids(paths) == []
    assert all(
        r["consumed_category"] == "consumed_committed" for r in consumed_by_id(paths).values()
    )

    # --- and the loop closes: the NEXT reduce can read what this one was taught -----------
    # O3's own reachability claim (G23), executed as a break attempt rather than believed
    # from two definitions: the gather role's REAL read gate, compiled against the tree the
    # tick just committed into, admits the reducer surface and refuses the paths outside the
    # corpus that prove it is still a gate. Without this arm the whole round ends at a
    # committed file nobody has shown anyone reads.
    policy = compile_policy_for(GATHER_DEF, run_dir=run_dir, defender_dir=repo / "defender")

    def _readable(path: Path) -> bool:
        return permission.decide_read(
            path, run_dir=run_dir, defender_dir=repo / "defender", policy=policy,
        ).allow

    assert _readable(repo / REDUCER_REL), (
        "the committed lesson is unreachable to the lane it was written for"
    )
    for denied in (repo / "defender" / "SKILL.md",
                   repo / "defender" / "learning" / "leads" / "lead_pitfalls.md",
                   Path("/etc/passwd")):
        assert not _readable(denied), f"the read gate admits {denied}, so the positive is free"
