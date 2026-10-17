"""#869 M2/O1 — resolve once at the boundary, thread the value inward non-Optional."""
from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest

from defender import _git
from defender.learning.core import drains, persist
from defender.learning.core.config import LoopPaths
from defender.learning.leads import lead_author, pitfalls_curator
from defender.learning.leads.lead_extraction import ExecutedLead, LeadAuthorError
from defender.tests._declared869 import (
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
from defender.tests._curator1134 import open_state
from defender.tests._lead_author_1134 import lead_deps, lead_trees
from defender.tests._state1135 import curation_row, curation_run_dir, run_of


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
    """`run_pitfalls` resolves membership ONCE, at its boundary, BEFORE the agent it spawns
    can change the answer — and the value it resolves is the ADAPTER HALF ALONE.

    CALL SITE 1 OF 2 FOR NF2 — read this with
    `test_lead_author_resolves_systems_before_the_agent_is_spawned`, which is handed the
    UNION. C40 is the reason the halves differ here: a row's `system` is narrowed to the
    adapter registry at the writer, so an MCP system can never reach this queue, and the union
    would buy nothing at M6 while newly permitting the curator to edit an MCP system's own
    marker file.

    The drive makes the tree DISAGREE WITH ITSELF across the spawn: the agent's own edit
    commits a `late_adapter.py`, so by the end of the tick the tree declares `late` — and the
    handoffs the curator was given still do not name it, and the queued `late` row was already
    dropped and reported before the spawn happened. A lane that resolved at first use, or
    twice, cannot produce that.
    """
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
    """`run_pitfalls` answers from the tree it COMMITS INTO — `paths.repo_root`, the drain
    worktree — never from the process's own checkout.

    `tree_root` is a key axis, not plumbing: the worktree and the process checkout are two
    different address spaces for one relative path. Driven with `paths.repo_root` pointing at
    a worktree whose sources declare `wtonly`, a system this process's own checkout does not
    declare, the tick admits it and builds its handoff — unlike `_build_pitfalls_handoffs`'s
    own default today, which still anchors on the process-global `SKILLS_DIR` (G14).
    """
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
    """Every gate in a tick answers from the set resolved BEFORE the spawn, so a system that
    becomes declared DURING the tick is still refused by that tick.

    WHICH CONTROL THIS IS. Under NF1 the marker never counts until it is committed, so the
    planted-marker route is closed three times over: this ordering, the commit gate
    (`marker_is_not_agent_committable`), and the committed-tree read itself. This test
    exercises the ORDERING, and it is the only control that covers the ADAPTER half — which
    still reads the working tree — so both arms make the mid-tick change one a re-derivation
    WOULD see:

    * pitfalls lane — the agent's edit gets `scripts/adapters/mcpsys_adapter.py` COMMITTED and
      then writes `skills/mcpsys/execution.md`, so the ADAPTER HALF — the value THIS lane
      resolves under NF2, and the only half that reads the working tree — now names `mcpsys`;
      the tick must still refuse it;
    * lead-author lane — the agent's edit gets `scripts/adapters/mcpsys_adapter.py` COMMITTED
      and then writes `skills/mcpsys/SKILL.md`, so the working-tree adapter source now names
      `mcpsys`; the commit gate must still refuse it.

    THE MID-TICK CHANGE ON ARM 1 IS AN ADAPTER, NOT A MARKER, AND THAT IS THE REPAIR (phase F,
    F6). A committed marker does not discriminate at this lane: under NF2 the pitfalls lane
    reads only the adapter half, so an implementation that re-resolved AFTER the spawn would
    return the same set and pass — the arm asserted a discrimination it did not have. An
    adapter is the change a re-derivation on THIS lane's own value would see, mirroring arm 2.
    (The re-derivation fault at this lane is separately covered by
    `consumers_do_not_rederive`; what this arm owns is the ORDERING observable.)
    """
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
    """A corpus file lane 1 leaves behind after refusing is not committed by lane 2.

    J3 — the BETWEEN-LANE half of resolve-before-spawn, named in no design sentence and found
    by phase C: `ClaimGit.reset` (`git reset --hard` + `git clean -fdqx` over skills/) runs in a
    `finally` after every lead-author marker and after the pitfalls leg, and `commit_corpus`
    stages the WHOLE `defender/skills` pathspec rather than the rule's own `changed` list — so
    a change that removes or narrows that `finally` changes what lane 2 can commit. Both lanes
    run serially against ONE worktree, which is what makes this a deterministic drive rather
    than a race.

    THIS DEMAND MUST NOT BE AUTHORED, READ OR CITED AS DISCHARGING MARKER INTEGRITY. Under
    NF1 the marker's integrity is the committed-tree read plus the commit gate, and a refused
    marker surviving the sweep would declare nothing anyway. The residue driven here is
    deliberately a NON-marker corpus file — an edit to `skills/elastic/SKILL.md`, which lane 2
    would otherwise stage and commit as its own.
    """
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "2")
    repo = seed_tree(tmp_path, adapters=("elastic",), markers=("elastic",), skills=("elastic",),
                     catalog=("elastic",))
    paths = LoopPaths(repo_root=repo, state_dir=tmp_path / "state")
    state = open_state(paths)
    persist.append_pitfalls(
        [pitfall_row("r:l-000:0", "elastic"), pitfall_row("r:l-001:0", "elastic")], state=state,
    )
    # The drain's own input: one queued lead-author request, which lane 1 will refuse.
    write(paths.state_root / "author-queue" / "case-1.json",
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
    drains._drain_lead_author(paths, state, lane1, lane2, data_root=drains._data_root())

    # Both lanes actually ran, and lane 1 actually refused: without this the residue claim
    # would be green over a drain that never reached either lane.
    assert lane1_calls, "lane 1 was never served, so it left no residue to carry"
    assert (paths.state_root / "author-queue" / "failed" / "case-1.json").is_file()

    committed = git(repo, "log", "--all", "-p", "--", str(skill_md(repo, "elastic").relative_to(repo))).stdout
    assert residue.strip() not in committed
    assert skill_md(repo, "elastic").read_text() != residue
    assert "execution.md pitfalls" in git(repo, "log", "--oneline").stdout


