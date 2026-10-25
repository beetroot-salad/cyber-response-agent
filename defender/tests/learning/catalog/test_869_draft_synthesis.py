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
from defender.tests.support.runtime.engine._declared869 import (
    LeadAuthorSpawn,
    log_lines_naming,
    loop_log,
    write,
    write_adapter,
)
from defender.learning.core.config import LEAD_AUTHOR_DRAIN_LABEL
from defender.tests.support.learning.curation import _curator1134 as C
from defender.tests.support.learning.curation._lead_author_1134 import drafts_under, skills_view
from defender.tests.support.learning.core._state1135 import curation_run_dir, run_of

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
    cat = _catalog(tmp_path)
    created = synthesize_drafts(
        [_lead("fakesys.hunt-creds", system="fakesys")],
        **drafts_under(cat), catalog=[], systems=DECLARED,
    )
    assert created == []
    assert not (cat / "fakesys").exists()
    assert list(cat.rglob("*fakesys*")) == []
    assert sorted(p.name for p in cat.rglob("*.md")) == ["proc-tree.md"]


def test_synthesize_drafts_still_mints_for_a_declared_system(tmp_path):
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
    """#869 M4 site 4: discovery over the batch draft hands out no undeclared directory, says so
    in the log, and the lane hands the agent only the declared draft (#1108 P4: draft lane)."""
    monkeypatch.setenv("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", "1")
    product = tmp_path / "product"
    write_adapter(product, "elastic")
    lane = C.draft_lane(tmp_path, lanes=C.LEAD_LANES, product=product, files={
        "skills/elastic/execution.md": "# execution\n",
        "skills/gather/SKILL.md": "---\nname: defender-gather\n---\n# gather\n",
        "skills/gather/queries/elastic/auth-events.md":
            "---\nid: elastic.auth-events\nstatus: established\n---\n\n## Goal\n\nprobe\n",
        "skills/elastic/_draft/lift-me.md":
            "---\nid: elastic.lift-me\nstatus: draft\n---\n\n## Goal\n\nx\n",
        "skills/gather/_draft/phantom.md":
            "---\nid: gather.phantom\nstatus: draft\n---\n\n## Goal\n\nx\n",
    })
    skills = lane.skills_dir
    paths = lane.paths
    spawn = LeadAuthorSpawn()
    # ASSUMED SEAM (S-H): `batch=`; the deps' declared set is the product's adapters joined with
    # the draft's committed markers (gap: r3 does not spell the marker half over a draft).
    deps = dataclasses.replace(
        lead_author.build_lead_author_deps(
            paths, state=C.open_state(paths), trees=C.draft_trees(lane), batch=lane.batch),
        invoke_agent=spawn, extract=lambda _rd: ([], []),
    )
    systems = deps.systems
    assert "gather" not in systems
    assert "elastic" in systems

    capsys.readouterr()
    found = lead_author.discover_system_drafts(
        skills=skills_view(skills), where=skills, systems=systems)
    assert [p.name for p in found] == ["lift-me.md"]

    assert log_lines_naming(loop_log(capsys), repr("gather")), (
        "the undeclared directory was skipped with no trace at all — a refusal with zero "
        "trace is what O3 forbids, and this is the fourth composition site FK-4 added"
    )
    # The control on the same address: declare it, and the same walk says nothing.
    capsys.readouterr()
    lead_author.discover_system_drafts(
        skills=skills_view(skills), where=skills, systems=systems | {"gather"})
    assert log_lines_naming(loop_log(capsys), repr("gather")) == [], (
        "a line that fires on a walk with nothing to skip reports nothing"
    )

    # And through the lane, so the drive edge is exercised rather than inspected: the pending
    # drafts the agent is handed never name the undeclared directory.
    run_dir = curation_run_dir("run-x")
    (run_dir / "gather_raw").mkdir()
    lead_author.run(run_of(run_dir), label=LEAD_AUTHOR_DRAIN_LABEL, paths=paths, deps=deps)

    handed = spawn.calls[-1]["pending_drafts"]
    assert [d["system"] for d in handed] == ["elastic"]
