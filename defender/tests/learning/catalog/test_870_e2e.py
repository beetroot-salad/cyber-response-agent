"""#870 O3 — the round's own oracle, end to end and across the process boundary."""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender.learning.core import persist  # noqa: E402
from defender.learning.core.config import LoopPaths  # noqa: E402
from defender.learning.leads import pitfalls_curator  # noqa: E402
from defender.learning.leads.lead_extraction import collect_general_failures  # noqa: E402
from defender.runtime import permission  # noqa: E402
from defender.runtime.agent_definition import compile_policy_for  # noqa: E402
from defender._query_rules import BASH_SHIM_QUERY_ID
from defender.tests.support.learning.core._declared870 import (  # noqa: E402
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
from defender.tests.support.tenancy import _tenants1106 as T1106
from defender.tests.support.learning.core import _state1135
from defender.tests.support.learning.curation._lead_author_1134 import lead_trees  # noqa: E402

pytestmark = pytest.mark.e2e


def test_e2e_a_failed_reducer_pipe_becomes_a_reducer_handoff(tmp_path: Path, monkeypatch):
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

    # the runtime half: the table really carries the sentinel rows
    shim = [r for r in res.own_rows if r["query_id"] == BASH_SHIM_QUERY_ID]
    assert len(shim) == 3, "the terminal reduce recorded nothing, so there is nothing to teach"
    assert {r["payload_digest"] for r in shim} == {BINDER}
    assert {r["error_class"] for r in shim} == {"agent-fixable"}

    # the learning half: the same rows, through the real join and the real collector
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
    persist.append_pitfalls(collected, state=_state1135.state_for_paths(paths))

    records = persist.merge_pitfalls(persist.read_pitfalls(_state1135.state_for_paths(paths)))
    assert [r["occurrences"] for r in records] == [3]

    # the curation tick: the handoff names the surface, and the commit carries it
    spawn = Spawn(curate_reducer_surface("keep the unnest argument a LIST"))
    head_before = git(repo, "rev-parse", "HEAD").stdout.strip()
    assert pitfalls_curator.run_pitfalls(paths=paths, invoke=spawn, trees=lead_trees(paths)) == 0

    reducer = by_surface(spawn.handoffs)["reducer"]
    assert len(reducer) == 1
    assert reducer[0]["path"] == REDUCER_REL
    assert reducer[0]["failures"][0]["stderr_digest"] == BINDER
    assert "defender-sql" in reducer[0]["failures"][0]["executed_query"]

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

    policy = compile_policy_for(T1106.fixture_gather_def(), run_dir=run_dir, defender_dir=repo / "defender")

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
