"""#869 M4/U1 — draft synthesis screens membership (site 3, the HOST-side writer)."""
from __future__ import annotations

import dataclasses
from pathlib import Path

from defender.learning.leads import lead_author
from defender.learning.leads.draft_synthesis import (
    _draft_basename,
    synthesize_drafts,
)
from defender.learning.leads.lead_extraction import ExecutedLead
from defender.learning.core.config import LoopPaths
from defender.tests._declared869 import (
    SKILLS_REL,
    LeadAuthorSpawn,
    declared_systems,
    git,
    log_lines_naming,
    loop_log,
    seed_tree,
    write,
)
from defender.learning.core.config import LEAD_AUTHOR_DRAIN_LABEL
from defender.tests._lead_author_1134 import drafts_under, lead_deps, skills_view
from defender.tests._state1135 import curation_run_dir, run_of

DECLARED = frozenset({"elastic"})


def _lead(query_id: str, *, system: str = "elastic", verb: str = "esql") -> ExecutedLead:
    return ExecutedLead(
        lead_id="l-001", query_index=0, is_multi_query=False, entry_index=0,
        query_id=query_id, system=system, verb=verb, params={"query": "FROM logs"},
        raw_command="", goal_text="probe the thing", what_to_summarize=(),
        raw_ref=Path("gather_raw/l-001/0.json"), payload_status="ok",
        payload_digest="2 bytes", error_class=None,
    )


def _catalog(tmp_path: Path) -> Path:
    cat = tmp_path / "skills" / "gather" / "queries"
    (cat / "elastic").mkdir(parents=True)
    write(cat / "elastic" / "proc-tree.md",
          "---\nid: elastic.proc-tree\nstatus: established\n---\n\n## Goal\n\nx\n")
    return cat


def test_synthesize_drafts_refuses_an_undeclared_system(tmp_path):
    """`synthesize_drafts` writes NOTHING for a lead whose `query_id` names a system the
    tree does not declare — no file, and no directory either.

    The directory is half the finding: the write is `draft.parent.mkdir(parents=True)` plus
    `draft.write_text`, so a phantom `<catalog>/fakesys/_draft/` exists on disk the moment the
    call is made, and G4 then shows the commit gate committing it. Both surfaces are bound:
    the returned list is empty AND nothing named `fakesys` exists anywhere under the catalog
    afterwards.
    """
    cat = _catalog(tmp_path)
    created = synthesize_drafts(
        [_lead("fakesys.hunt-creds", system="fakesys")],
        **drafts_under(cat), catalog=[], systems=DECLARED,
    )
    assert created == []
    assert not (cat / "fakesys").exists()
    assert list(cat.rglob("*fakesys*")) == []
    # Nothing at ALL was written, rather than nothing under one expected name: since #917's
    # review the basename is a digest, so an assertion spelling `hunt-creds.md` would pass
    # against a draft that had been minted under its derived name and would be checking
    # nothing. `rglob("*.md")` is what the catalog fixture seeded and no more.
    assert sorted(p.name for p in cat.rglob("*.md")) == ["proc-tree.md"]


def test_synthesize_drafts_still_mints_for_a_declared_system(tmp_path):
    """The screen refuses undeclared NAMES, not drafting.

    `draft_synthesis_refuses_undeclared`'s positive control on the same address: a lead whose
    coined id names a DECLARED system still mints its `_draft/` skeleton, with the id in its
    frontmatter, so a screen that refused everything would satisfy the negative and silently
    retire the whole draft lane.

    THE TWO ASSERTIONS THIS RE-ENCODES (G9/R7, and phase C settles that they were WRONG under
    U1 rather than merely flipped): `test_lead_author_synth.py`'s `stub-cmdb.network-map` and
    `custom.tagged` positive controls both name prefixes no adapter and no marker declares, so
    under U1 they must assert REFUSAL. Both are driven here beside the declared case, so the
    corrected intent survives independently of what happens to that file.
    """
    cat = _catalog(tmp_path)
    created = synthesize_drafts(
        [_lead("elastic.hunt-creds")], **drafts_under(cat), catalog=[], systems=DECLARED,
    )
    draft = cat / "elastic" / "_draft" / f"{_draft_basename('elastic.hunt-creds')}.md"
    assert created == [draft]
    assert f"id: elastic.{_draft_basename('elastic.hunt-creds')}" in draft.read_text()
    # …and the coined name it was minted for is kept, as the dedup key and as provenance.
    assert "covers:" in draft.read_text()
    assert "elastic.hunt-creds" in draft.read_text()

    for undeclared in ("stub-cmdb.network-map", "custom.tagged"):
        system = undeclared.split(".", 1)[0]
        assert system not in DECLARED
        assert synthesize_drafts(
            [_lead(undeclared, system=system, verb="map")],
            **drafts_under(cat), catalog=[], systems=DECLARED,
        ) == []
        assert not (cat / system).exists()


def test_discover_system_drafts_hands_out_no_undeclared_directory(
    tmp_path, monkeypatch, capsys,
):
    """`discover_system_drafts` hands the agent no work under a directory the tree does not
    declare — the FOURTH composition site (FK-4, §7).

    Today it walks EVERY child of the skills tree and emits `{"system": <dirname>,
    "skill_path": "defender/skills/<dirname>/SKILL.md"}` with no membership filter (C29,
    executed), so a `_draft/` under an undeclared directory becomes work the agent is
    INSTRUCTED to do and the commit gate then refuses — an instructed-then-rejected loop with
    no retirement path. It is handed this lane's UNION (NF2) and skips undeclared directories.

    VACUOUS ON TODAY'S TREE by construction (C22: only `elastic/_draft` and `cmdb/_draft`
    exist, and both are declared), so the fixture is CONSTRUCTED — a `gather/_draft/` one
    `mkdir` from live — which is what makes the demand real rather than green by accident. The
    declared system's own draft in the same walk is the positive control: a filter that
    returned nothing would satisfy the refusal and silently retire the lift lane.

    AND THE REFUSAL IS VISIBLE HERE TOO (phase F, closing the blind reader's Q7 gap). FK-3
    resolved that O3 reaches every composition site, and FK-4 then GREW that census from three
    sites to four — this one. Nothing pinned a trace at it: a skipped directory left only "no
    work was handed out", which from a queue's outside is indistinguishable from a tree that
    had none. The skipped name is named on a line of its own, `repr`'d for the reason
    `resolver_refuses_shape_anomalous_names` gives (a name may be the empty string), and the
    control is the SAME walk over the SAME tree with the name declared: nothing is skipped and
    no such line appears, so the channel is shown to distinguish rather than firing on every
    walk. The commit gate's own raise is the other half of that gap, and it is pinned where
    the raise happens — `undeclared_names_reported`'s site-2 arm asserts the message carries
    the undeclared name rather than an unrelated reason.
    """
    monkeypatch.setenv("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", "1")
    repo = seed_tree(tmp_path, adapters=("elastic",), markers=("elastic",), skills=("elastic",),
                     catalog=("elastic",), non_systems=("gather",))
    write(repo / SKILLS_REL / "elastic" / "_draft" / "lift-me.md",
          "---\nid: elastic.lift-me\nstatus: draft\n---\n\n## Goal\n\nx\n")
    write(repo / SKILLS_REL / "gather" / "_draft" / "phantom.md",
          "---\nid: gather.phantom\nstatus: draft\n---\n\n## Goal\n\nx\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "a declared draft and an undeclared one")

    systems = declared_systems(repo)
    assert "gather" not in systems
    assert "elastic" in systems

    capsys.readouterr()
    found = lead_author.discover_system_drafts(
        skills=skills_view(repo / SKILLS_REL), where=repo / SKILLS_REL, systems=systems)
    assert [p.name for p in found] == ["lift-me.md"]

    assert log_lines_naming(loop_log(capsys), repr("gather")), (
        "the undeclared directory was skipped with no trace at all — a refusal with zero "
        "trace is what O3 forbids, and this is the fourth composition site FK-4 added"
    )
    # The control on the same address: declare it, and the same walk says nothing.
    capsys.readouterr()
    lead_author.discover_system_drafts(
        skills=skills_view(repo / SKILLS_REL), where=repo / SKILLS_REL,
        systems=systems | {"gather"})
    assert log_lines_naming(loop_log(capsys), repr("gather")) == [], (
        "a line that fires on a walk with nothing to skip reports nothing"
    )

    # And through the lane, so the drive edge is exercised rather than inspected: the pending
    # drafts the agent is handed never name the undeclared directory.
    paths = LoopPaths(repo_root=repo, state_dir=tmp_path / "state")
    spawn = LeadAuthorSpawn()
    deps = dataclasses.replace(
        lead_deps(paths),
        invoke_agent=spawn, extract=lambda _rd: ([], []),
    )
    run_dir = curation_run_dir("run-x")
    (run_dir / "gather_raw").mkdir()
    lead_author.run(run_of(run_dir), label=LEAD_AUTHOR_DRAIN_LABEL, paths=paths, deps=deps)

    handed = spawn.calls[-1]["pending_drafts"]
    assert [d["system"] for d in handed] == ["elastic"]
