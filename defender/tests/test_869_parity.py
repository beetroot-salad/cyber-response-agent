"""#869 — the cross-site universal, the second empty-set boundary, and the two unmoved readers."""
from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest

from defender.learning.core.config import LoopPaths
from defender.learning.leads import lead_author, pitfalls_curator
from defender.learning.leads.draft_synthesis import _draft_basename, synthesize_drafts
from defender.learning.leads.lead_extraction import ExecutedLead, LeadAuthorError
from defender.tests._declared869 import (
    CATALOG_REL,
    SKILLS_REL,
    LeadAuthorSpawn,
    git,
    head_files,
    seed_tree,
    write,
)
from defender.learning.core.config import LEAD_AUTHOR_DRAIN_LABEL
from defender.tests._lead_author_1134 import drafts_under, lane_tree_for, lead_deps, skills_view
from defender.tests._state1135 import curation_run_dir, run_of

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


def test_every_path_composition_site_refuses_an_undeclared_name(tmp_path, monkeypatch):
    monkeypatch.setenv("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", "1")
    repo = seed_tree(tmp_path, adapters=("elastic",), markers=("elastic",),
                     skills=("elastic",), catalog=("elastic",), non_systems=("gather",))
    skills = repo / SKILLS_REL
    catalog = repo / CATALOG_REL
    write(skills / PHANTOM / "_draft" / "hunt-creds.md",
          f"---\nid: {PHANTOM}.hunt-creds\nstatus: draft\n---\n\n## Goal\n\nx\n")
    write(skills / "elastic" / "_draft" / "lift-me.md",
          "---\nid: elastic.lift-me\nstatus: draft\n---\n\n## Goal\n\nx\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "a phantom draft dir and a real one")
    before = head_files(repo)

    # site 1 — the pitfalls gate
    with pytest.raises(LeadAuthorError):
        pitfalls_curator._pitfalls_path_rule(
            "A ", f"defender/skills/{PHANTOM}/execution.md", systems=DECLARED)
    assert pitfalls_curator._pitfalls_path_rule(
        "A ", "defender/skills/elastic/execution.md", systems=DECLARED) is None

    # site 2 — the lead-author commit gate, over all three in-scope forms
    for form in (
        f"defender/skills/{PHANTOM}/SKILL.md",
        f"defender/skills/{PHANTOM}/_draft/hunt-creds.md",
        f"defender/skills/gather/queries/{PHANTOM}/hunt-creds.md",
    ):
        with pytest.raises(LeadAuthorError):
            lead_author._skills_path_rule(repo, "A ", form, systems=DECLARED,
                                          tree_for=lane_tree_for(repo))
    assert lead_author._skills_path_rule(
        repo, "A ", "defender/skills/elastic/_draft/lift-me.md", systems=DECLARED,
        tree_for=lane_tree_for(repo)) is None

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
    handed = lead_author.build_system_draft_handoffs(found, repo_root=repo)
    assert [h["system"] for h in handed] == ["elastic"]

    # and NOTHING anywhere under the tree was written for the phantom by any of the four.
    assert not (catalog / PHANTOM).exists()
    assert sorted(p for p in git(repo, "status", "--porcelain").stdout.split() if PHANTOM in p) == []
    assert head_files(repo) == before


def test_an_empty_declared_set_refuses_the_lead_author_lane(tmp_path, monkeypatch):
    monkeypatch.setenv("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", "1")
    repo = seed_tree(tmp_path, adapters=(), markers=(), skills=(), catalog=(),
                     non_systems=("gather",))
    write(repo / SKILLS_REL / "gather" / "_draft" / "lift-me.md",
          "---\nid: gather.lift-me\nstatus: draft\n---\n\n## Goal\n\nx\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "a pending draft under a tree that declares nothing")
    before = head_files(repo)

    paths = LoopPaths(repo_root=repo, state_dir=tmp_path / "state")
    spawn = LeadAuthorSpawn()
    deps = dataclasses.replace(
        lead_deps(paths),
        invoke_agent=spawn, extract=lambda _rd: ([], []),
    )
    assert deps.systems == frozenset()

    run_dir = curation_run_dir("run-x")
    (run_dir / "gather_raw").mkdir()
    with pytest.raises(LeadAuthorError):
        lead_author.run(run_of(run_dir), label=LEAD_AUTHOR_DRAIN_LABEL, paths=paths, deps=deps)

    assert spawn.calls == [], "the agent must not be spawned against an empty declared set"
    assert head_files(repo) == before
    assert git(repo, "status", "--porcelain").stdout == ""
