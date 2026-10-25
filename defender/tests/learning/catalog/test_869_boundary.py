"""#869 M2/O1 — resolve once at the boundary, thread the value inward non-Optional.

#1108 P4 (O7, OD12 class ii): each lane runs over a batch draft (`_curator1134.draft_lane`, the
tenant's `agent/skills`), its adapters in a scratch product checkout (`seed_product`, #1172);
the lane entries take the batch (ASSUMED SEAMS S-H `run_pitfalls(..., batch=)`,
`build_lead_author_deps(..., batch=)`). "Mid-tick" adapter landings commit to that product
checkout; mid-tick markers/skills are written into the draft the box writes."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

import json
from pathlib import Path

import pytest

from defender import _git
from defender.learning.core import drains, persist
from defender.learning.leads import lead_author, pitfalls_curator
from defender.learning.leads.lead_extraction import ExecutedLead, LeadAuthorError
from defender.tests.support.runtime.engine._declared869 import (
    LeadAuthorSpawn,
    Spawn,
    adapter_declared_systems,
    agent_marker_file,
    agent_skill_md,
    commit_paths,
    declared_systems,
    head_sha,
    loop_log,
    pitfall_row,
    seed_agent_files,
    seed_product,
    write,
    write_adapter,
)
from defender.learning.core.config import LEAD_AUTHOR_DRAIN_LABEL
from defender.tests.support.learning.curation import _curator1134 as C
from defender.tests.support.learning.curation._curator1134 import open_state
from defender.tests.support.learning.curation._lead_author_1134 import draft_lead_deps
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


def _lane(tmp_path: Path, *, adapters: tuple[str, ...], markers: tuple[str, ...],
          skills: tuple[str, ...], catalog: tuple[str, ...], name: str = "product",
          extra: dict[str, str] | None = None):
    """`seed_tree` after P4: the product checkout (`adapters`) and a batch draft of the tenant
    (`markers`/`skills`/`catalog`, plus `extra`, agent-relative) over the lead lane."""
    product = seed_product(tmp_path, adapters=adapters, name=name)
    files = {**seed_agent_files(markers=markers, skills=skills, catalog=catalog), **(extra or {})}
    return product, C.draft_lane(tmp_path, lanes=C.LEAD_LANES, product=product, files=files,
                                 state_dir=tmp_path / f"state-{name}")


def _pitfalls(lane, state, spawn: Spawn) -> int:
    with C.draft_trees(lane) as trees:
        return pitfalls_curator.run_pitfalls(paths=lane.paths, state=state, invoke=spawn,
                                             trees=trees, batch=lane.batch)


def _in_base(lane, rel: str) -> bool:
    """`rel` (`agent/...`) is in the batch base's committed tree (what the marker half reads)."""
    return lane.git("cat-file", "-e", f"{lane.base}:{rel}", check=False).returncode == 0


def _lead_author_deps(lane, spawn: LeadAuthorSpawn):
    """The real deps over the draft lane, with only the seams a hermetic drive must own
    replaced: the spawn and `extract` (the two tables are a different seam with its own suite).
    `systems` is NOT replaced — the value this lane resolves at its boundary is the thing under
    test."""
    return draft_lead_deps(lane, invoke_agent=spawn, extract=lambda _run_dir: ([], []))


def test_run_pitfalls_resolves_systems_before_the_curator_is_spawned(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "2")
    product, lane = _lane(tmp_path, adapters=("elastic",), markers=("elastic", "mcpsys"),
                          skills=("elastic",), catalog=())
    state = open_state(lane.paths)
    persist.append_pitfalls(
        [pitfall_row("r:l-000:0", "elastic"),
         pitfall_row("r:l-001:0", "late"),
         pitfall_row("r:l-002:0", "mcpsys")],
        state=state,
    )

    def edit(root: Path) -> None:
        commit_paths(product, write_adapter(product, "late"), message="an adapter lands mid-tick")
        write(agent_marker_file(root, "elastic"), "# elastic\n## Common pitfalls\n- x\n")

    spawn = Spawn(edit, root=lane.root)
    capsys.readouterr()
    assert _pitfalls(lane, state, spawn) == 0

    assert spawn.systems_seen == ["elastic"]
    assert "late" in adapter_declared_systems(product)   # the tree DOES declare it, by the end
    # and the tenant's committed marker names mcpsys all along (the union's marker half)
    assert _in_base(lane, "agent/skills/mcpsys/execution.md")
    log = loop_log(capsys)
    # both dropped and both reported, before the spawn ever happened
    assert "late" in log
    assert "mcpsys" in log


def test_pitfalls_resolves_the_tree_it_commits_into(tmp_path, monkeypatch, capsys):
    """The lane resolves from ITS product checkout (`paths.repo_root`) and ITS tenant draft —
    never from the process's own product repo (`_git.REPO_ROOT`), which declares no `wtonly`."""
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "2")
    _product, lane = _lane(tmp_path, adapters=("wtonly",), markers=("wtonly",), skills=(),
                           catalog=(), name="worktree")
    assert "wtonly" not in declared_systems(_git.REPO_ROOT)

    state = open_state(lane.paths)
    persist.append_pitfalls(
        [pitfall_row("r:l-000:0", "wtonly"), pitfall_row("r:l-001:0", "wtonly")], state=state,
    )
    spawn = Spawn(lambda root: write(agent_marker_file(root, "wtonly"), "# pitfalls\n- x\n"),
                  root=lane.root)
    capsys.readouterr()

    assert _pitfalls(lane, state, spawn) == 0
    assert spawn.systems_seen == ["wtonly"]
    assert spawn.handoffs[0]["path"] == "agent/skills/wtonly/execution.md"
    assert persist.read_pitfalls(state) == []
    assert lane.text_at_tip("agent/skills/wtonly/execution.md") == "# pitfalls\n- x\n"


def test_a_marker_planted_during_the_tick_does_not_declare_its_system(tmp_path, monkeypatch):
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "2")
    monkeypatch.setenv("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", "1")

    product, lane = _lane(tmp_path, adapters=("elastic",), markers=("elastic",),
                          skills=("elastic",), catalog=("elastic",))
    state = open_state(lane.paths)
    persist.append_pitfalls(
        [pitfall_row("r:l-000:0", "elastic"), pitfall_row("r:l-001:0", "elastic")], state=state,
    )

    def land_an_adapter_then_plant(root: Path) -> None:
        commit_paths(product, write_adapter(product, "mcpsys"),
                     message="the adapter lands mid-tick")
        write(agent_marker_file(root, "mcpsys"), "# mcpsys\n## Common pitfalls\n- planted\n")

    before = head_sha(product)
    with pytest.raises(LeadAuthorError, match="mcpsys"):
        _pitfalls(lane, state, Spawn(land_an_adapter_then_plant, root=lane.root))
    # The tree agrees ON THIS LANE'S OWN VALUE by the end of the tick — the TICK does not.
    assert "mcpsys" in adapter_declared_systems(product)
    assert persist.read_pitfalls(state), "the batch must survive a refused tick"
    assert before != head_sha(product), "the plant's own commit is the mid-tick change"
    assert lane.commits() == [], "the refused tick committed into the batch"

    other_product, lane2 = _lane(
        tmp_path, adapters=("elastic",), markers=("elastic",), skills=("elastic",),
        catalog=("elastic",), name="lane2",
        extra={"skills/elastic/_draft/lift-me.md":
               "---\nid: elastic.lift-me\nstatus: draft\n---\n\n## Goal\n\nx\n"})

    def plant_adapter(_rd: Path) -> None:
        commit_paths(other_product, write_adapter(other_product, "mcpsys"),
                     message="the adapter lands mid-tick")
        write(agent_skill_md(lane2.root, "mcpsys"), "---\nname: defender-mcpsys\n---\n# mcpsys\n")

    deps = _lead_author_deps(lane2, LeadAuthorSpawn(plant_adapter))
    assert "mcpsys" not in deps.systems
    with pytest.raises(LeadAuthorError, match="mcpsys"):
        lead_author.run(run_of(_run_dir()), label=LEAD_AUTHOR_DRAIN_LABEL, paths=lane2.paths,
                        deps=deps)
    assert "mcpsys" in adapter_declared_systems(other_product)
    assert lane2.commits() == [], "the refused run committed into the batch"


def test_uncommitted_residue_does_not_cross_lanes(tmp_path, monkeypatch, capsys):
    """Lane 1 (lead author) leaves residue in the draft and refuses; lane 2 (pitfalls) then
    commits into the same batch. The residue never lands: the drain re-syncs the draft per
    claim (OD15), handed the tick's batch (OD16; ASSUMED SEAM `_drain_lead_author(...,
    batch=)`, the spelling the drain's steps take)."""
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "2")
    _product, lane = _lane(tmp_path, adapters=("elastic",), markers=("elastic",),
                           skills=("elastic",), catalog=("elastic",))
    paths = lane.paths
    state = open_state(paths)
    persist.append_pitfalls(
        [pitfall_row("r:l-000:0", "elastic"), pitfall_row("r:l-001:0", "elastic")], state=state,
    )
    # The drain's own input: one queued lead-author request, which lane 1 will refuse.
    write(location_path(paths.state_root) / "author-queue" / "case-1.json",
          json.dumps(curation_row("case-1", _run_dir())) + "\n")

    residue = "residue that lane 1 left behind\n"
    lane1_calls: list[Path] = []
    skill_rel = "agent/skills/elastic/SKILL.md"

    def lane1(_paths, _state, run, *, box=None, **_kw):
        lane1_calls.append(run.run_dir)
        agent_skill_md(lane.root, "elastic").write_text(residue, encoding="utf-8")
        raise LeadAuthorError("lane 1 refuses this marker")

    def lane2(_paths, _state, *, box=None, **_kw):
        return _pitfalls(lane, _state, Spawn(
            lambda root: write(agent_marker_file(root, "elastic"), "# e\n## Common pitfalls\n- x\n"),
            root=lane.root))

    capsys.readouterr()
    drains._drain_lead_author(paths, state, lane1, lane2, batch=lane.batch,
                              accept_tenant=drains._tenant_acceptor(paths.tenant))

    # Both lanes actually ran, and lane 1 actually refused: without this the residue claim
    # would be green over a drain that never reached either lane.
    assert lane1_calls, "lane 1 was never served, so it left no residue to carry"
    assert (location_path(paths.state_root) / "author-queue" / "failed" / "case-1.json").is_file()

    assert lane.commits(), "lane 2 never committed, so the residue claim is vacuous"
    committed = lane.git("log", lane.tip(), "-p", "--", skill_rel).stdout
    assert residue.strip() not in committed
    assert lane.text_at_tip(skill_rel) != residue
    assert agent_skill_md(lane.root, "elastic").read_text() != residue
    assert "execution.md pitfalls" in lane.git("log", "--oneline", lane.tip()).stdout
