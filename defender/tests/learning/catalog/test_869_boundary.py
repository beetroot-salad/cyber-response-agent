"""#869 M2/O1 — resolve once at the boundary, thread the value inward non-Optional."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

import dataclasses
import json
from pathlib import Path

import pytest

from defender import _git
from defender.learning.core import drains, persist
from defender.learning.core.config import LoopPaths
from defender.learning.leads import lead_author, pitfalls_curator
from defender.learning.leads.lead_extraction import ExecutedLead, LeadAuthorError
from defender.tests.support.runtime.engine._declared869 import (
    SKILLS_REL,
    LeadAuthorSpawn,
    Spawn,
    adapter_declared_systems,
    commit_paths,
    declared_systems,
    git,
    head_sha,
    loop_log,
    marker_file,
    pitfall_row,
    seed_tree,
    skill_md,
    write,
    write_adapter,
)
from defender.learning.core.config import LEAD_AUTHOR_DRAIN_LABEL
from defender.tests.support.learning.curation._curator1134 import open_state
from defender.tests.support.learning.curation._lead_author_1134 import lead_deps, lead_trees
from defender.tests.support.learning.core._state1135 import curation_row, curation_run_dir, run_of


def _lead(query_id: str, *, system: str = "elastic", verb: str = "esql") -> ExecutedLead:
    return ExecutedLead(
        lead_id="l-001", query_index=0, is_multi_query=False, entry_index=0,
        query_id=query_id, system=system, verb=verb, params={"query": "FROM logs"},
        raw_command="", goal_text="probe the thing", what_to_summarize=(),
        raw_ref=Path("gather_raw/l-001/0.json"), payload_status="ok",
        payload_digest="2 bytes", error_class=None,
    )


def _run_dir() -> Path:
    """A natural run where the drain rehydrates a row (`curation_run_dir`, #1105 PR 2); hand it
    to the lane as `run_of(_run_dir())`."""
    d = curation_run_dir("run-x")
    (d / "gather_raw").mkdir(exist_ok=True)
    return d


def _lead_author_deps(paths: LoopPaths, spawn: LeadAuthorSpawn):
    """The real deps for `paths`, with only the seams a hermetic drive must own replaced.

    `acquire_queue_lock` is replaced because the shipped one keys on a module-global path
    inside the REAL checkout; `extract` because the two tables are a different seam with its
    own suite. `systems` is NOT replaced — the value this lane resolves at its boundary is
    the thing under test."""
    return dataclasses.replace(
        lead_deps(paths),
        invoke_agent=spawn,
        extract=lambda _run_dir: ([], []),
    )


def test_run_pitfalls_resolves_systems_before_the_curator_is_spawned(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "2")
    repo = seed_tree(tmp_path, adapters=("elastic",), markers=("elastic", "mcpsys"),
                     skills=("elastic",), catalog=())
    paths = LoopPaths(repo_root=repo, state_dir=tmp_path / "state")
    state = open_state(paths)
    persist.append_pitfalls(
        [pitfall_row("r:l-000:0", "elastic"),
         pitfall_row("r:l-001:0", "late"),
         pitfall_row("r:l-002:0", "mcpsys")],
        state=state,
    )

    def edit(root: Path) -> None:
        commit_paths(root, write_adapter(root, "late"), message="an adapter lands mid-tick")
        write(marker_file(root, "elastic"), "# elastic\n## Common pitfalls\n- x\n")

    spawn = Spawn(edit)
    capsys.readouterr()
    assert pitfalls_curator.run_pitfalls(paths=paths, state=state, invoke=spawn, trees=lead_trees(paths)) == 0

    assert spawn.systems_seen == ["elastic"]
    assert "late" in declared_systems(repo)     # the tree DOES declare it, by the end
    assert "mcpsys" in declared_systems(repo)   # and the union names it all along
    log = loop_log(capsys)
    # both dropped and both reported, before the spawn ever happened
    assert "late" in log
    assert "mcpsys" in log


def test_pitfalls_resolves_the_tree_it_commits_into(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "2")
    repo = seed_tree(tmp_path, adapters=("wtonly",), markers=("wtonly",), skills=(),
                     catalog=(), name="worktree")
    assert "wtonly" not in declared_systems(_git.REPO_ROOT)

    paths = LoopPaths(repo_root=repo, state_dir=tmp_path / "state")
    state = open_state(paths)
    persist.append_pitfalls(
        [pitfall_row("r:l-000:0", "wtonly"), pitfall_row("r:l-001:0", "wtonly")], state=state,
    )
    spawn = Spawn(lambda root: write(marker_file(root, "wtonly"), "# pitfalls\n- x\n"))
    capsys.readouterr()

    assert pitfalls_curator.run_pitfalls(paths=paths, state=state, invoke=spawn, trees=lead_trees(paths)) == 0
    assert spawn.systems_seen == ["wtonly"]
    assert spawn.handoffs[0]["path"] == "defender/skills/wtonly/execution.md"
    assert persist.read_pitfalls(state) == []


def test_a_marker_planted_during_the_tick_does_not_declare_its_system(tmp_path, monkeypatch):
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "2")
    monkeypatch.setenv("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", "1")

    repo = seed_tree(tmp_path, adapters=("elastic",), markers=("elastic",), skills=("elastic",),
                     catalog=("elastic",))
    paths = LoopPaths(repo_root=repo, state_dir=tmp_path / "state")
    state = open_state(paths)
    persist.append_pitfalls(
        [pitfall_row("r:l-000:0", "elastic"), pitfall_row("r:l-001:0", "elastic")], state=state,
    )

    def land_an_adapter_then_plant(root: Path) -> None:
        commit_paths(root, write_adapter(root, "mcpsys"),
                     message="the adapter lands mid-tick")
        write(marker_file(root, "mcpsys"), "# mcpsys\n## Common pitfalls\n- planted\n")

    before = head_sha(repo)
    with pytest.raises(LeadAuthorError, match="mcpsys"):
        pitfalls_curator.run_pitfalls(paths=paths, state=state, invoke=Spawn(land_an_adapter_then_plant),
                                      trees=lead_trees(paths))
    # The tree agrees ON THIS LANE'S OWN VALUE by the end of the tick — the TICK does not.
    assert "mcpsys" in adapter_declared_systems(repo)
    assert "mcpsys" in declared_systems(repo)
    assert persist.read_pitfalls(state), "the batch must survive a refused tick"
    assert before != head_sha(repo), "the plant's own commit is the mid-tick change"

    other = seed_tree(tmp_path, adapters=("elastic",), markers=("elastic",),
                      skills=("elastic",), catalog=("elastic",), name="lane2")
    write(other / SKILLS_REL / "elastic" / "_draft" / "lift-me.md",
          "---\nid: elastic.lift-me\nstatus: draft\n---\n\n## Goal\n\nx\n")
    git(other, "add", "-A")
    git(other, "commit", "-q", "-m", "a pending draft")
    lane2 = LoopPaths(repo_root=other, state_dir=tmp_path / "state2")

    def plant_adapter(_rd: Path) -> None:
        commit_paths(other, write_adapter(other, "mcpsys"),
                     message="the adapter lands mid-tick")
        write(skill_md(other, "mcpsys"), "---\nname: defender-mcpsys\n---\n# mcpsys\n")

    deps = _lead_author_deps(lane2, LeadAuthorSpawn(plant_adapter))
    assert "mcpsys" not in deps.systems
    with pytest.raises(LeadAuthorError, match="mcpsys"):
        lead_author.run(run_of(_run_dir()), label=LEAD_AUTHOR_DRAIN_LABEL, paths=lane2, deps=deps)
    assert "mcpsys" in declared_systems(other)


def test_uncommitted_residue_does_not_cross_lanes(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "2")
    repo = seed_tree(tmp_path, adapters=("elastic",), markers=("elastic",), skills=("elastic",),
                     catalog=("elastic",))
    paths = LoopPaths(repo_root=repo, state_dir=tmp_path / "state")
    state = open_state(paths)
    persist.append_pitfalls(
        [pitfall_row("r:l-000:0", "elastic"), pitfall_row("r:l-001:0", "elastic")], state=state,
    )
    # The drain's own input: one queued lead-author request, which lane 1 will refuse.
    write(location_path(paths.state_root) / "author-queue" / "case-1.json",
          json.dumps(curation_row("case-1", _run_dir())) + "\n")

    residue = "residue that lane 1 left behind\n"
    lane1_calls: list[Path] = []

    def lane1(_paths, _state, run, *, box=None, **_kw):
        lane1_calls.append(run.run_dir)
        skill_md(repo, "elastic").write_text(residue, encoding="utf-8")
        raise LeadAuthorError("lane 1 refuses this marker")

    def lane2(_paths, _state, *, box=None, **_kw):
        return pitfalls_curator.run_pitfalls(
            paths=_paths, state=_state, invoke=Spawn(
                lambda root: write(marker_file(root, "elastic"), "# e\n## Common pitfalls\n- x\n")
            ),
            trees=lead_trees(_paths),
        )

    capsys.readouterr()
    drains._drain_lead_author(paths, state, lane1, lane2,
                             accept_tenant=drains._tenant_acceptor(paths.tenant))

    # Both lanes actually ran, and lane 1 actually refused: without this the residue claim
    # would be green over a drain that never reached either lane.
    assert lane1_calls, "lane 1 was never served, so it left no residue to carry"
    assert (location_path(paths.state_root) / "author-queue" / "failed" / "case-1.json").is_file()

    committed = git(repo, "log", "--all", "-p", "--", str(skill_md(repo, "elastic").relative_to(repo))).stdout
    assert residue.strip() not in committed
    assert skill_md(repo, "elastic").read_text() != residue
    assert "execution.md pitfalls" in git(repo, "log", "--oneline").stdout
