"""#869 — the cross-site universal, the second empty-set boundary, and the two unmoved readers.

#1108 P4 (O7, OD6): the lead lane's tree is a batch's git-free draft (`agent/skills/...`); "nothing
written" is the batch's `ChangeSet` and branch. ASSUMED SEAMS (S-H): the path rules keep their
`(xy, path)` shape over `agent/...` spellings; `build_lead_author_deps(paths, *, state, trees,
batch)` (`_curator1134`'s seam list).
"""
from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest

from defender.learning.core.config import LEAD_AUTHOR_DRAIN_LABEL
from defender.learning.core.lane_trees import DrainTrees
from defender.learning.leads import lead_author, pitfalls_curator
from defender.learning.leads.draft_synthesis import _draft_basename, synthesize_drafts
from defender.learning.leads.lead_extraction import ExecutedLead, LeadAuthorError
from defender.tests.support.learning.core._state1135 import curation_run_dir, run_of
from defender.tests.support.learning.curation import _curator1134 as C
from defender.tests.support.learning.curation._lead_author_1134 import drafts_under, skills_view
from defender.tests.support.runtime.engine._declared869 import LeadAuthorSpawn

PHANTOM = "fakesys"

DECLARED = frozenset({"elastic"})


def _lead(query_id: str, *, system: str) -> ExecutedLead:
    return ExecutedLead(
        lead_id="l-001", query_index=0, is_multi_query=False, entry_index=0,
        query_id=query_id, system=system, verb="esql", params={"query": "FROM logs"},
        raw_command="", goal_text="probe the thing", what_to_summarize=(),
        raw_ref=Path("gather_raw/l-001/0.json"), payload_status="ok",
        payload_digest="2 bytes", error_class=None,
    )


def _skill(system: str) -> str:
    return f"---\nname: defender-{system}\n---\n# {system}\n"


def test_every_path_composition_site_refuses_an_undeclared_name(tmp_path, monkeypatch):
    """#869 universal: all four path-composition sites refuse an undeclared system and admit a
    declared one; the claim carries nothing for the phantom."""
    monkeypatch.setenv("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", "1")
    lane = C.draft_lane(tmp_path, lanes=C.LEAD_LANES, files={
        "skills/elastic/SKILL.md": _skill("elastic"),
        "skills/elastic/execution.md": "# execution\n",
        "skills/gather/SKILL.md": _skill("gather"),
        "skills/gather/queries/elastic/auth-events.md":
            "---\nid: elastic.auth-events\nstatus: established\n---\n\n## Goal\n\nprobe\n",
        f"skills/{PHANTOM}/_draft/hunt-creds.md":
            f"---\nid: {PHANTOM}.hunt-creds\nstatus: draft\n---\n\n## Goal\n\nx\n",
        "skills/elastic/_draft/lift-me.md":
            "---\nid: elastic.lift-me\nstatus: draft\n---\n\n## Goal\n\nx\n",
    })
    root = lane.root
    skills = lane.skills_dir
    catalog = skills / "gather" / "queries"
    tree_for = DrainTrees.open((skills,)).tree_for

    # site 1 — the pitfalls gate
    with pytest.raises(LeadAuthorError):
        pitfalls_curator._pitfalls_path_rule(
            "A ", f"agent/skills/{PHANTOM}/execution.md", systems=DECLARED)
    assert pitfalls_curator._pitfalls_path_rule(
        "A ", "agent/skills/elastic/execution.md", systems=DECLARED) is None

    # site 2 — the lead-author commit gate, over all three in-scope forms
    for form in (
        f"agent/skills/{PHANTOM}/SKILL.md",
        f"agent/skills/{PHANTOM}/_draft/hunt-creds.md",
        f"agent/skills/gather/queries/{PHANTOM}/hunt-creds.md",
    ):
        with pytest.raises(LeadAuthorError):
            lead_author._skills_path_rule(root, "A ", form, systems=DECLARED, tree_for=tree_for)
    assert lead_author._skills_path_rule(
        root, "A ", "agent/skills/elastic/_draft/lift-me.md", systems=DECLARED,
        tree_for=tree_for) is None

    # site 3 — the host-side draft writer
    assert synthesize_drafts(
        [_lead(f"{PHANTOM}.hunt-creds", system=PHANTOM)],
        **drafts_under(catalog), catalog=[], systems=DECLARED,
    ) == []
    assert synthesize_drafts(
        [_lead("elastic.hunt-creds", system="elastic")],
        **drafts_under(catalog), catalog=[], systems=DECLARED,
    ) == [catalog / "elastic" / "_draft" / f"{_draft_basename('elastic.hunt-creds')}.md"]

    # site 4 — the draft discovery that hands the agent its work
    found = lead_author.discover_system_drafts(skills=skills_view(skills), where=skills,
                                               systems=DECLARED)
    handed = lead_author.build_system_draft_handoffs(found, repo_root=root)
    assert [h["system"] for h in handed] == ["elastic"]

    # and NOTHING anywhere in the draft was written for the phantom by any of the four: the
    # claim the batch derives holds only the declared draft site 3 wrote.
    assert not (catalog / PHANTOM).exists()
    claim = [change.path for change in lane.batch.change_set()]
    assert [p for p in claim if PHANTOM in p] == [], claim
    assert claim == [
        f"agent/skills/gather/queries/elastic/_draft/{_draft_basename('elastic.hunt-creds')}.md"]
    assert lane.landed() == []


def test_an_empty_declared_set_refuses_the_lead_author_lane(tmp_path, monkeypatch):
    """#869: a product checkout declaring no adapter and a draft with no marker refuse the lane
    before any spawn; the batch commits nothing."""
    monkeypatch.setenv("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", "1")
    product = tmp_path / "product"
    (product / "defender" / "integrations").mkdir(parents=True)
    lane = C.draft_lane(tmp_path, lanes=C.LEAD_LANES, product=product, files={
        "skills/gather/SKILL.md": _skill("gather"),
        "skills/gather/_draft/lift-me.md":
            "---\nid: gather.lift-me\nstatus: draft\n---\n\n## Goal\n\nx\n",
    })
    paths = lane.paths
    spawn = LeadAuthorSpawn()
    deps = dataclasses.replace(
        lead_author.build_lead_author_deps(
            paths, state=C.open_state(paths), trees=C.draft_trees(lane), batch=lane.batch),
        invoke_agent=spawn, extract=lambda _rd: ([], []),
    )
    assert deps.systems == frozenset()

    run_dir = curation_run_dir("run-x")
    (run_dir / "gather_raw").mkdir()
    with pytest.raises(LeadAuthorError):
        lead_author.run(run_of(run_dir), label=LEAD_AUTHOR_DRAIN_LABEL, paths=paths, deps=deps)

    assert spawn.calls == [], "the agent must not be spawned against an empty declared set"
    assert lane.landed() == []
    assert len(lane.batch.change_set()) == 0
