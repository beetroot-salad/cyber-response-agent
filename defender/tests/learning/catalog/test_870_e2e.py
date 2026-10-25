"""#870 O3 — the round's own oracle, end to end and across the process boundary.

#1108 P4 (O7): the reducer surface the lane teaches is the tenant's pitfalls add-on, written into a
batch draft and committed by the commit-maker; the run reads it from its copy's agent root."""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender.learning.core import persist  # noqa: E402
from defender.learning.core.config import LoopPaths  # noqa: E402
from defender.learning.leads import pitfalls_curator  # noqa: E402
from defender.learning.leads.lead_extraction import collect_general_failures  # noqa: E402
from defender.runtime import permission  # noqa: E402
from defender.runtime.agent_definition import RunScope, compile_policy_for  # noqa: E402
from defender.knowledge._query_rules import BASH_SHIM_QUERY_ID
from defender.tests.support.learning.core._declared870 import (  # noqa: E402
    BINDER,
    PITFALLS_SECTION,
    Spawn,
    by_surface,
    consumed_by_id,
    queue_ids,
)
from defender.tests.e2e._replay_harness import GOLDEN_AB3, materialize  # noqa: E402
from defender.tests.e2e.test_pitfalls_input_823 import _reduce, _run  # noqa: E402
from defender.tests.e2e.test_query_tool_611 import DONE, q  # noqa: E402
from defender.tests.support.tenancy import _tenants1106 as T1106
from defender.tests.support.learning.core import _state1135
from defender.tests.support.learning.curation import _curator1134 as C  # noqa: E402
from defender.tests.support.runtime.engine._declared869 import write_adapter  # noqa: E402
from defender._git import REPO_ROOT  # noqa: E402

pytestmark = pytest.mark.e2e

DEFENDER = REPO_ROOT / "defender"
#: The tenant's learned-SQL-pitfalls add-on (carried decision, A1 path), repo-relative (OD6).
ADDON_REL = "agent/skills/gather/defender-sql.pitfalls.md"
ADDON = T1106.FIXTURE_AGENT / "skills" / "gather" / "defender-sql.pitfalls.md"


def _curate_addon(bullet: str):
    """A compliant curator's edit of the add-on: one bullet appended under its
    `## Common pitfalls`, under the root the spawn is handed."""

    def _edit(root: Path) -> None:
        path = root / ADDON_REL
        text = path.read_text(encoding="utf-8")
        assert PITFALLS_SECTION in text
        path.write_text(text.rstrip("\n") + f"\n- {bullet}\n", encoding="utf-8")

    return _edit


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

    # #1108 P4 (O7): the curation tick writes a batch draft holding the declared marker and
    # the tenant's pitfalls add-on (the reducer surface the tenant owns, carried decision);
    # adapters stay in the product checkout.
    product = tmp_path / "product"
    write_adapter(product, "elastic")
    lane = C.draft_lane(tmp_path, lanes=C.LEAD_LANES, product=product, files={
        "skills/elastic/execution.md": "# execution\n",
        "skills/gather/defender-sql.pitfalls.md": ADDON.read_text(encoding="utf-8"),
    })
    paths = LoopPaths(repo_root=product, state_dir=tmp_path / "state")
    persist.append_pitfalls(collected, state=_state1135.state_for_paths(paths))

    records = persist.merge_pitfalls(persist.read_pitfalls(_state1135.state_for_paths(paths)))
    assert [r["occurrences"] for r in records] == [3]

    # the curation tick: the handoff names the surface, and the commit carries it
    # (ASSUMED SEAM, S-H: `run_pitfalls(..., batch=)`; the spawn's `repo_root` is the draft root)
    spawn = Spawn(_curate_addon("keep the unnest argument a LIST"))
    assert pitfalls_curator.run_pitfalls(
        paths=paths, invoke=spawn, trees=C.draft_trees(lane), batch=lane.batch) == 0

    reducer = by_surface(spawn.handoffs)["reducer"]
    assert len(reducer) == 1
    assert reducer[0]["path"] == ADDON_REL
    assert reducer[0]["failures"][0]["stderr_digest"] == BINDER
    assert "defender-sql" in reducer[0]["failures"][0]["executed_query"]

    assert lane.commits(), "the taught lesson never reached a commit of its own"
    assert lane.landed() == [ADDON_REL], "the tick committed, but not the reducer surface"
    assert "keep the unnest argument a LIST" in (lane.text_at_tip(ADDON_REL) or "")
    assert queue_ids(paths) == []
    assert all(
        r["consumed_category"] == "consumed_committed" for r in consumed_by_id(paths).values()
    )

    # The next run reads it from its copy's agent root: the batch's committed tree, which the
    # draft holds after the claim (P3 reset re-syncs it to the branch tip).
    agent = lane.agent
    policy = compile_policy_for(T1106.fixture_gather_def(), run_dir=run_dir, defender_dir=DEFENDER,
                                scope=RunScope(tenant_agent=agent))

    def _readable(path: Path) -> bool:
        return permission.decide_read(
            path, run_dir=run_dir, defender_dir=DEFENDER, policy=policy,
        ).allow

    assert _readable(agent / "skills" / "gather" / "defender-sql.pitfalls.md"), (
        "the committed lesson is unreachable to the lane it was written for"
    )
    for denied in (DEFENDER / "SKILL.md",
                   DEFENDER / "learning" / "leads" / "lead_pitfalls.md",
                   Path("/etc/passwd")):
        assert not _readable(denied), f"the read gate admits {denied}, so the positive is free"
