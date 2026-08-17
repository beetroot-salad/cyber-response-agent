"""#869 M2/O1 — resolve once at the boundary, thread the value inward non-Optional.

Every test here is one demand of `spec-flow/specs/spec_graph_869.yaml`, named after that
demand's `discharged_by` pointer and carrying its prose in its docstring. The seam contract
and the not-yet-written shim live in `defender/tests/_declared869.py`.

TWO MEMBERSHIP VALUES LIVE IN ONE TICK (NF2, §7), deliberately, with C40 as the reason: the
PITFALLS lane is handed the ADAPTER HALF ALONE, and the PATH-COMPOSITION gates are handed the
UNION. That is a documented exception to M2's "one value, threaded", not a slip. No demand in
this spec asserts that the two values agree, because under NF2 they need not — a reader who
conflates them will read one lane's demands as covering the other's.
"""
from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest

from defender import _git
from defender._paths import PATHS, DefenderPaths
from defender.learning.core import drains, persist
from defender.learning.core.config import LoopPaths
from defender.learning.leads import lead_author, pitfalls_curator
from defender.learning.leads.draft_synthesis import synthesize_drafts
from defender.learning.leads.lead_extraction import ExecutedLead, LeadAuthorError
from defender.tests._declared869 import (
    SKILLS_REL,
    LeadAuthorSpawn,
    Spawn,
    adapter_declared_systems,
    adapter_file,
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


def _lead(query_id: str, *, system: str = "elastic", verb: str = "esql") -> ExecutedLead:
    return ExecutedLead(
        lead_id="l-001", query_index=0, is_multi_query=False, entry_index=0,
        query_id=query_id, system=system, verb=verb, params={"query": "FROM logs"},
        raw_command="", goal_text="probe the thing", what_to_summarize=(),
        raw_ref=Path("gather_raw/l-001/0.json"), payload_status="ok",
        payload_digest="2 bytes", error_class=None,
    )


def _run_dir(tmp_path: Path) -> Path:
    d = tmp_path / "run-x"
    (d / "gather_raw").mkdir(parents=True)
    return d


def _lead_author_deps(paths: LoopPaths, spawn: LeadAuthorSpawn):
    """The real deps for `paths`, with only the seams a hermetic drive must own replaced.

    `acquire_queue_lock` is replaced because the shipped one keys on a module-global path
    inside the REAL checkout; `extract` because the two tables are a different seam with its
    own suite. `systems` is NOT replaced — the value this lane resolves at its boundary is
    the thing under test."""
    return dataclasses.replace(
        lead_author.build_lead_author_deps(paths),
        invoke_agent=spawn,
        extract=lambda _run_dir: ([], []),
        acquire_queue_lock=lambda: object(),
        release_queue_lock=lambda _fh: None,
    )


def test_paths_owns_both_source_directory_names(tmp_path):
    """`DefenderPaths` owns BOTH source directory names, and a worktree-rooted `LoopPaths`
    answers for the worktree at BOTH.

    C25/G14: the literal `scripts/adapters` is spelled at four sites today and `DefenderPaths`
    owns `skills_dir` but no `adapters_dir`, while the worktree-correct values are threaded
    per call unevenly. #0 part 3 moves this: the resolver takes ONE tree root, so both
    directory names have to hang off the same paths object or a worktree drive answers for
    the process's own checkout at one of them. Each name is spelled once — the directory is
    the root joined to the paths object's own relative spelling, not a second literal — and
    the resolver reads exactly those two places, which is what makes a re-rooted paths object
    change the answer.
    """
    wt = seed_tree(tmp_path, adapters=("wtonly",), markers=("wtonly",), skills=(),
                   catalog=(), name="worktree")

    paths = DefenderPaths(repo_root=wt)
    assert paths.adapters_dir == wt / DefenderPaths.adapters_rel
    assert paths.skills_dir == wt / DefenderPaths.skills_rel
    assert paths.adapters_dir == wt / "defender" / "scripts" / "adapters"
    assert paths.skills_dir == wt / "defender" / "skills"

    rerooted = LoopPaths(repo_root=PATHS.repo_root).with_repo_root(wt)
    assert rerooted.adapters_dir == paths.adapters_dir
    assert rerooted.skills_dir == paths.skills_dir

    # And the resolver reads THOSE directories: `wtonly` is declared out of the worktree the
    # paths object names, and is not a system the process's own checkout knows.
    assert declared_systems(rerooted.repo_root) == frozenset({"wtonly"})
    assert "wtonly" not in declared_systems(PATHS.repo_root)


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
    persist.append_pitfalls(
        [pitfall_row("r:l-000:0", "elastic"),
         pitfall_row("r:l-001:0", "late"),
         pitfall_row("r:l-002:0", "mcpsys")],
        paths=paths,
    )

    def edit(root: Path) -> None:
        commit_paths(root, write_adapter(root, "late"), message="an adapter lands mid-tick")
        write(marker_file(root, "elastic"), "# elastic\n## Common pitfalls\n- x\n")

    spawn = Spawn(edit)
    capsys.readouterr()
    assert pitfalls_curator.run_pitfalls(paths=paths, invoke=spawn) == 0

    assert spawn.systems_seen == ["elastic"]
    assert "late" in declared_systems(repo)     # the tree DOES declare it, by the end
    assert "mcpsys" in declared_systems(repo)   # and the union names it all along
    log = loop_log(capsys)
    # both dropped and both reported, before the spawn ever happened
    assert "late" in log
    assert "mcpsys" in log


def test_lead_author_resolves_systems_before_the_agent_is_spawned(tmp_path, monkeypatch):
    """`build_lead_author_deps` resolves membership ONCE from `paths` and threads it inward
    non-Optional, so a `LeadAuthorDeps` built for a worktree carries THAT worktree's set —
    and the resolution happens before `_spawn_author_agent`, not merely before use.

    CALL SITE 2 OF 2 FOR NF2 — read this with
    `test_run_pitfalls_resolves_systems_before_the_curator_is_spawned`. The value resolved
    HERE is the UNION (adapter ∪ committed marker), and it governs all three path-composition
    consumers on this lane: the marker-only `mcpsys` IS a member here and is NOT one at the
    pitfalls lane. The two sets are different questions asked in the same tick, deliberately.

    The ordering is observable rather than asserted about the source: the deps object already
    carries the resolved value when the agent is handed its work, and the agent's own
    mid-tick commit of a `late_adapter.py` does not join the set the tick spends.
    """
    monkeypatch.setenv("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", "1")
    repo = seed_tree(tmp_path, adapters=("elastic",), markers=("elastic", "mcpsys"),
                     skills=("elastic",), catalog=("elastic",))
    write(repo / SKILLS_REL / "elastic" / "_draft" / "lift-me.md",
          "---\nid: elastic.lift-me\nstatus: draft\n---\n\n## Goal\n\nx\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "a pending draft")
    paths = LoopPaths(repo_root=repo, state_dir=tmp_path / "state")

    spawn = LeadAuthorSpawn(lambda _rd: commit_paths(
        repo, write_adapter(repo, "late"), message="an adapter lands mid-tick",
    ))
    deps = _lead_author_deps(paths, spawn)

    resolved = deps.systems
    assert resolved == declared_systems(repo)
    assert "mcpsys" in resolved, "this lane is handed the UNION, not the adapter half"
    assert "late" not in resolved

    assert lead_author.run(_run_dir(tmp_path), paths=paths, deps=deps) == 0
    assert spawn.calls, "the agent was never spawned, so the ordering claim is vacuous"
    assert deps.systems == resolved
    assert "late" in declared_systems(repo)


def test_no_membership_consumer_reprobes_the_tree(tmp_path):
    """No membership consumer re-derives the set from the tree: each answers from the
    `systems=` value it was handed, and from nothing else.

    PROMOTED from hygiene to a load-bearing control by C33, which executed the break: with
    `skills/mcpsys/` empty `_pitfalls_path_rule` RAISES, and after planting the marker file as
    the agent would, the SAME call ADMITS. Every consumer is therefore driven here with a set
    that CONTRADICTS the tree under it — which is exactly the fault a re-derivation produces —
    in both directions, so the observation channel is shown to see the difference:

    * handed `{"mcpsys"}` over a tree that carries no `mcpsys` anywhere, all four ADMIT it;
    * handed `frozenset()` over a tree that carries `elastic` in both sources, all four REFUSE.

    NF2 note: `synthesize_drafts` and `_skills_path_rule` answer from the UNION they were
    handed and `_pitfalls_path_rule` and `_build_pitfalls_handoffs` from the ADAPTER HALF —
    "no consumer re-derives" is about the argument, never about the two arguments being equal.
    """
    repo = seed_tree(tmp_path, adapters=("elastic",), markers=("elastic",), skills=("elastic",),
                     catalog=("elastic",))
    cat = repo / "defender" / "skills" / "gather" / "queries"
    contradicts = frozenset({"mcpsys"})
    empty = frozenset()

    assert not (repo / SKILLS_REL / "mcpsys").exists()
    assert not adapter_file(repo, "mcpsys").exists()

    # --- handed a name the tree does not carry: every consumer admits it anyway ---
    assert pitfalls_curator._pitfalls_path_rule(
        "A ", "defender/skills/mcpsys/execution.md", systems=contradicts) is None
    assert [
        h["system"] for h in pitfalls_curator._build_pitfalls_handoffs(
            [pitfall_row("r:0", "mcpsys")], systems=contradicts)
    ] == ["mcpsys"]
    assert lead_author._skills_path_rule(
        repo, "A ", "defender/skills/mcpsys/SKILL.md", systems=contradicts) is None
    assert synthesize_drafts(
        [_lead("mcpsys.new-verb", system="mcpsys")], catalog_dir=cat, catalog=[],
        systems=contradicts,
    ) == [cat / "mcpsys" / "_draft" / "new-verb.md"]

    # --- handed nothing, over a tree that carries elastic in both sources: every one refuses ---
    assert marker_file(repo, "elastic").is_file()
    assert adapter_file(repo, "elastic").is_file()
    with pytest.raises(LeadAuthorError):
        pitfalls_curator._pitfalls_path_rule(
            "A ", "defender/skills/elastic/execution.md", systems=empty)
    assert pitfalls_curator._build_pitfalls_handoffs(
        [pitfall_row("r:1", "elastic")], systems=empty) == []
    with pytest.raises(LeadAuthorError):
        lead_author._skills_path_rule(
            repo, "A ", "defender/skills/elastic/SKILL.md", systems=empty)
    assert synthesize_drafts(
        [_lead("elastic.other-verb")], catalog_dir=cat, catalog=[], systems=empty) == []


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
    persist.append_pitfalls(
        [pitfall_row("r:l-000:0", "wtonly"), pitfall_row("r:l-001:0", "wtonly")], paths=paths,
    )
    spawn = Spawn(lambda root: write(marker_file(root, "wtonly"), "# pitfalls\n- x\n"))
    capsys.readouterr()

    assert pitfalls_curator.run_pitfalls(paths=paths, invoke=spawn) == 0
    assert spawn.systems_seen == ["wtonly"]
    assert spawn.handoffs[0]["path"] == "defender/skills/wtonly/execution.md"
    assert persist.read_pitfalls(paths) == []


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
    persist.append_pitfalls(
        [pitfall_row("r:l-000:0", "elastic"), pitfall_row("r:l-001:0", "elastic")], paths=paths,
    )

    def land_an_adapter_then_plant(root: Path) -> None:
        commit_paths(root, write_adapter(root, "mcpsys"),
                     message="the adapter lands mid-tick")
        write(marker_file(root, "mcpsys"), "# mcpsys\n## Common pitfalls\n- planted\n")

    before = head_sha(repo)
    with pytest.raises(LeadAuthorError, match="mcpsys"):
        pitfalls_curator.run_pitfalls(paths=paths, invoke=Spawn(land_an_adapter_then_plant))
    # The tree agrees ON THIS LANE'S OWN VALUE by the end of the tick — the TICK does not.
    assert "mcpsys" in adapter_declared_systems(repo)
    assert "mcpsys" in declared_systems(repo)
    assert persist.read_pitfalls(paths), "the batch must survive a refused tick"
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
        lead_author.run(_run_dir(tmp_path), paths=lane2, deps=deps)
    assert "mcpsys" in declared_systems(other)


def test_uncommitted_residue_does_not_cross_lanes(tmp_path, monkeypatch, capsys):
    """A corpus file lane 1 leaves behind after refusing is not committed by lane 2.

    J3 — the BETWEEN-LANE half of resolve-before-spawn, named in no design sentence and found
    by phase C: `_discard_worktree_changes` (`git reset --hard` + `git clean -fdq`) runs in a
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
    persist.append_pitfalls(
        [pitfall_row("r:l-000:0", "elastic"), pitfall_row("r:l-001:0", "elastic")], paths=paths,
    )
    # The drain's own input: one queued lead-author request, which lane 1 will refuse.
    write(paths.author_queue_dir / "case-1.json",
          json.dumps({"case_id": "case-1", "run_dir": str(_run_dir(tmp_path))}) + "\n")

    residue = "residue that lane 1 left behind\n"
    lane1_calls: list[Path] = []

    def lane1(_paths, _run_dir, *, box=None):
        lane1_calls.append(_run_dir)
        skill_md(repo, "elastic").write_text(residue, encoding="utf-8")
        raise LeadAuthorError("lane 1 refuses this marker")

    def lane2(_paths, *, box=None):
        return pitfalls_curator.run_pitfalls(
            paths=_paths, invoke=Spawn(
                lambda root: write(marker_file(root, "elastic"), "# e\n## Common pitfalls\n- x\n")
            ),
        )

    capsys.readouterr()
    drains._drain_lead_author(paths, lane1, lane2)

    # Both lanes actually ran, and lane 1 actually refused: without this the residue claim
    # would be green over a drain that never reached either lane.
    assert lane1_calls, "lane 1 was never served, so it left no residue to carry"
    assert (paths.author_queue_dir / "failed" / "case-1.json").is_file()

    committed = git(repo, "log", "--all", "-p", "--", str(skill_md(repo, "elastic").relative_to(repo))).stdout
    assert residue.strip() not in committed
    assert skill_md(repo, "elastic").read_text() != residue
    assert "execution.md pitfalls" in git(repo, "log", "--oneline").stdout


def test_the_pitfalls_lane_is_handed_the_adapter_half_and_the_gates_the_union(
    tmp_path, monkeypatch, capsys,
):
    """ONE tick over ONE tree carrying a MARKER-ONLY system, both lanes observed: the pitfalls
    lane does NOT declare it and the path-composition gates DO (NF2, §7).

    `skills/mcpsys/execution.md` is committed and no `mcpsys_adapter.py` exists, so `mcpsys`
    is in the union and not in the adapter half. Then:

    * the pitfalls lane drops a queued `mcpsys` row and reports it, and `_pitfalls_path_rule`
      — spending the value that lane resolved for itself — refuses
      `skills/mcpsys/execution.md`, which is what keeps the curator out of an MCP system's own
      marker file;
    * the lead-author lane declares it: its deps carry `mcpsys`, `_skills_path_rule` admits
      `skills/mcpsys/SKILL.md`, and `synthesize_drafts` mints for `mcpsys.<kebab>`.

    A test that drove only one lane, or that used a tree whose two sources agree (which every
    real tree does today — C31), would assert nothing: the split is invisible unless the
    fixture contains a name the two sources disagree about. THE COST, RECORDED: no demand in
    this spec asserts that the two values are equal, and `path_composition_parity` is
    forbidden from using a marker-only name, so this is the only test that goes red if a
    future change collapses the two values back into one.
    """
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "2")
    repo = seed_tree(tmp_path, adapters=("elastic",), markers=("elastic", "mcpsys"),
                     skills=("elastic",), catalog=("elastic",))
    assert not adapter_file(repo, "mcpsys").exists()
    paths = LoopPaths(repo_root=repo, state_dir=tmp_path / "state")
    persist.append_pitfalls(
        [pitfall_row("r:l-000:0", "elastic"), pitfall_row("r:l-001:0", "mcpsys")], paths=paths,
    )

    capsys.readouterr()
    with pytest.raises(LeadAuthorError, match="mcpsys"):
        pitfalls_curator.run_pitfalls(
            paths=paths,
            invoke=Spawn(lambda root: write(marker_file(root, "mcpsys"), "# curated\n")),
        )
    log = loop_log(capsys)
    assert "mcpsys" in log, "the dropped row must be reported by name"

    deps = lead_author.build_lead_author_deps(paths)
    assert "mcpsys" in deps.systems
    assert lead_author._skills_path_rule(
        repo, "A ", "defender/skills/mcpsys/SKILL.md", systems=deps.systems) is None
    cat = repo / "defender" / "skills" / "gather" / "queries"
    assert synthesize_drafts(
        [_lead("mcpsys.new-verb", system="mcpsys")], catalog_dir=cat, catalog=[],
        systems=deps.systems,
    ) == [cat / "mcpsys" / "_draft" / "new-verb.md"]
