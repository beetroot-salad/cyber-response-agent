"""#869: a lane resolves its systems once, at the boundary, and threads the value inward.

Each lane runs over a batch draft of the tenant's `agent/skills` (`_curator1134.draft_lane`) with
its adapters in a scratch product checkout (`seed_product`), and takes the batch. Mid-tick adapter
landings commit to that product checkout; mid-tick markers and skills go into the draft."""
from __future__ import annotations

from pathlib import Path

import pytest

from defender import _git
from defender.learning.core import drains
from defender.learning.leads import lead_author
from defender.learning.store import Outcome
from defender.learning.leads.lead_extraction import LeadAuthorError
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
    write,
    write_adapter,
)
from defender.learning.core.config import LEAD_AUTHOR_DRAIN_LABEL
from defender.tests.support.learning.core._declared870 import Claim, tick
from defender.tests.support.learning.curation._lead_author_1134 import (
    draft_lead_deps,
    lead_lane,
    run_pitfalls,
)
from defender.tests.support.learning.core._state1135 import curation_row, curation_run_dir, curation_tenant, run_of


def _run_dir() -> Path:
    """A run folder the drain rehydrates a row from; hand it to the lane as `run_of(_run_dir())`."""
    d = curation_run_dir("run-x")
    (d / "gather_raw").mkdir(exist_ok=True)
    return d


def _in_base(lane, rel: str) -> bool:
    """`rel` (`agent/...`) is in the batch base's committed tree (what the marker half reads)."""
    return lane.git("cat-file", "-e", f"{lane.base}:{rel}", check=False).returncode == 0


def _lead_author_deps(lane, spawn: LeadAuthorSpawn):
    """The real deps over the draft lane with only the spawn and `extract` replaced; `systems`
    stays real, since the value resolved at the boundary is under test."""
    return draft_lead_deps(lane, invoke_agent=spawn, extract=lambda _run_dir: ([], []))


def test_run_pitfalls_resolves_systems_before_the_curator_is_spawned(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "2")
    product, lane = lead_lane(tmp_path, adapters=("elastic",), markers=("elastic", "mcpsys"),
                              skills=("elastic",), catalog=())
    claim = Claim()
    claim.add(pitfall_row("r:l-000:0", "elastic"), pitfall_row("r:l-001:0", "late"), pitfall_row("r:l-002:0", "mcpsys"))

    def edit(root: Path) -> None:
        commit_paths(product, write_adapter(product, "late"), message="an adapter lands mid-tick")
        write(agent_marker_file(root, "elastic"), "# elastic\n## Common pitfalls\n- x\n")

    spawn = Spawn(edit, root=lane.root)
    capsys.readouterr()
    assert tick(lane, spawn, claim) == 0

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
    _product, lane = lead_lane(tmp_path, adapters=("wtonly",), markers=("wtonly",), skills=(),
                               catalog=(), name="worktree")
    assert "wtonly" not in declared_systems(_git.REPO_ROOT)

    claim = Claim()
    claim.add(pitfall_row("r:l-000:0", "wtonly"), pitfall_row("r:l-001:0", "wtonly"))
    spawn = Spawn(lambda root: write(agent_marker_file(root, "wtonly"), "# pitfalls\n- x\n"),
                  root=lane.root)
    capsys.readouterr()

    assert tick(lane, spawn, claim) == 0
    assert spawn.systems_seen == ["wtonly"]
    assert spawn.handoffs[0]["path"] == "agent/skills/wtonly/execution.md"
    assert claim.committed == {"r:l-000:0", "r:l-001:0"}
    assert claim.outcomes == {}
    assert lane.text_at_tip("agent/skills/wtonly/execution.md") == "# pitfalls\n- x\n"


def test_a_marker_planted_during_the_tick_does_not_declare_its_system(tmp_path, monkeypatch):
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "2")
    monkeypatch.setenv("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", "1")

    product, lane = lead_lane(tmp_path, adapters=("elastic",), markers=("elastic",),
                              skills=("elastic",), catalog=("elastic",))
    claim = Claim()
    claim.add(pitfall_row("r:l-000:0", "elastic"), pitfall_row("r:l-001:0", "elastic"))

    def land_an_adapter_then_plant(root: Path) -> None:
        commit_paths(product, write_adapter(product, "mcpsys"),
                     message="the adapter lands mid-tick")
        write(agent_marker_file(root, "mcpsys"), "# mcpsys\n## Common pitfalls\n- planted\n")

    before = head_sha(product)
    with pytest.raises(LeadAuthorError, match="mcpsys"):
        tick(lane, Spawn(land_an_adapter_then_plant, root=lane.root), claim)
    # By the end of the tick the tree declares mcpsys; the tick's resolved value still does not.
    assert "mcpsys" in adapter_declared_systems(product)
    assert claim.outcomes == {}, "a refused tick decided the claim's rows"
    assert claim.committed == set(), "a refused tick decided the claim's rows"
    assert before != head_sha(product), "the plant's own commit is the mid-tick change"
    assert lane.commits() == [], "the refused tick committed into the batch"

    other_product, lane2 = lead_lane(
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
    commits into the same batch. The residue never lands: the drain re-syncs the draft per claim."""
    from types import SimpleNamespace

    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "2")
    _product, lane = lead_lane(tmp_path, adapters=("elastic",), markers=("elastic",),
                               skills=("elastic",), catalog=("elastic",), tenant=curation_tenant())
    paths = lane.paths
    run_dir = _run_dir()
    rows = [pitfall_row("r:l-000:0", "elastic"), pitfall_row("r:l-001:0", "elastic")]
    # The claim the store hands the drain: one queued lead-author request (which lane 1 will refuse) and two pitfalls.
    held = SimpleNamespace(items=[("curation_request", "case-1", curation_row("case-1", run_dir)),
                                  *[("pitfall", r["pitfall_id"], r) for r in rows]])

    residue = "residue that lane 1 left behind\n"
    lane1_calls: list[Path] = []
    skill_rel = "agent/skills/elastic/SKILL.md"

    def lane1(_paths, _state, run, *, box=None, **_kw):
        lane1_calls.append(run.run_dir)
        agent_skill_md(lane.root, "elastic").write_text(residue, encoding="utf-8")
        raise LeadAuthorError("lane 1 refuses this marker")

    def lane2(_paths, _state, *, items, outcomes, on_curated, **_kw):
        return run_pitfalls(lane, None, Spawn(
            lambda root: write(agent_marker_file(root, "elastic"), "# e\n## Common pitfalls\n- x\n"),
            root=lane.root), items=items, outcomes=outcomes, on_curated=on_curated)

    capsys.readouterr()
    outcomes: dict = {}
    drains._store_lead_work(paths, lane1, lane2, box=None, batch=lane.batch, held=held, feedback=None, outcomes=outcomes)

    # Both lanes actually ran, and lane 1 actually refused: without this the residue claim
    # would be green over a drain that never reached either lane.
    assert lane1_calls, "lane 1 was never served, so it left no residue to carry"
    assert outcomes.get(("curation_request", "case-1")) == Outcome.waiting(), "lane 1 refusal was not answered with a wait"

    assert lane.commits(), "lane 2 never committed, so the residue claim is vacuous"
    committed = lane.git("log", lane.tip(), "-p", "--", skill_rel).stdout
    assert residue.strip() not in committed
    assert lane.text_at_tip(skill_rel) != residue
    assert agent_skill_md(lane.root, "elastic").read_text() != residue
    assert "execution.md pitfalls" in lane.git("log", "--oneline", lane.tip()).stdout
