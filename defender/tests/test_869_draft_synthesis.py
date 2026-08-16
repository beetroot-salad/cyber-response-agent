"""#869 M4/U1 — draft synthesis screens membership (site 3, the HOST-side writer).

Every test here is one demand of `spec-flow/specs/spec_graph_869.yaml`, named after that
demand's `discharged_by` pointer and carrying its prose in its docstring. The seam contract
lives in `defender/tests/_declared869.py`.

Site 3 is the one the design's own table calls reachable TODAY: `synthesize_drafts` does a
`mkdir(parents=True)` + `write_text` at `<catalog>/<system>/_draft/<suffix>.md` from a
model-supplied `query_id`, on the HOST, BEFORE the agent is spawned and before
`baseline_stray` is taken — and the only guards between are `_SAFE_ID_SEGMENT` and an
`is_relative_to` check, neither of which is a membership question (G3, executed).
"""
from __future__ import annotations

import dataclasses
from pathlib import Path

from defender.learning.leads import lead_author
from defender.learning.leads.draft_synthesis import _draft_candidate_segments, synthesize_drafts
from defender.learning.leads.lead_extraction import ExecutedLead, extract
from defender.learning.core.config import LoopPaths
from defender.tests._declared869 import (
    SKILLS_REL,
    LeadAuthorSpawn,
    declared_systems,
    git,
    log_lines_naming,
    loop_log,
    seed_executed_query,
    seed_tree,
    write,
)

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
    cat = tmp_path / "queries"
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
        catalog_dir=cat, catalog=[], systems=DECLARED,
    )
    assert created == []
    assert not (cat / "fakesys").exists()
    assert list(cat.rglob("*fakesys*")) == []
    assert list(cat.rglob("hunt-creds.md")) == []


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
        [_lead("elastic.hunt-creds")], catalog_dir=cat, catalog=[], systems=DECLARED,
    )
    draft = cat / "elastic" / "_draft" / "hunt-creds.md"
    assert created == [draft]
    assert "id: elastic.hunt-creds" in draft.read_text()

    for undeclared in ("stub-cmdb.network-map", "custom.tagged"):
        system = undeclared.split(".", 1)[0]
        assert system not in DECLARED
        assert synthesize_drafts(
            [_lead(undeclared, system=system, verb="map")],
            catalog_dir=cat, catalog=[], systems=DECLARED,
        ) == []
        assert not (cat / system).exists()


def test_synthesize_drafts_screens_a_row_recorded_before_the_writer_rule(tmp_path):
    """A row carrying a foreign-prefixed `query_id` that was recorded BEFORE M3's writer rule
    existed is still screened at site 3.

    Why depth is worth having behind M3: the queries table is append-only, so a row written
    by the old writer keeps its phantom id forever, and `synthesize_drafts` reads those rows
    on every later tick. The row here is appended through the PRODUCTION writer and read back
    through the production join and extraction, so it is a real historical row rather than
    this test's idea of one — and the shared predicate still calls it a draft candidate,
    which is exactly why the membership screen has to be the thing that refuses it.
    """
    run_dir = tmp_path / "run-x"
    seed_executed_query(run_dir, query_id="fakesys.hunt-creds")
    _joined, executed = extract(run_dir)
    assert [lead.query_id for lead in executed] == ["fakesys.hunt-creds"]
    assert _draft_candidate_segments("fakesys.hunt-creds", "esql", set()) == (
        "fakesys", "hunt-creds",
    )

    cat = _catalog(tmp_path)
    assert synthesize_drafts(
        executed, catalog_dir=cat, catalog=[], systems=DECLARED) == []
    assert not (cat / "fakesys").exists()


def test_synthesize_drafts_names_what_it_refused(tmp_path, capsys):
    """Site 3 REPORTS a membership refusal — it mints the reporting surface, because there is
    none today (FK-3, §7).

    O3 is unqualified and a universal discharged at two of three sites is not discharged, and
    this was the one fork in the run where two independent readers stated directly opposite
    outcomes — so the resolution is pinned here rather than inferred from O3's wording. Today
    `_draft_candidate_segments` returns `None` and site 3 drops SILENTLY (F7), so unlike the
    site-1 log line this demand requires a new edge to exist at all.

    The observable: a tick whose executed leads carry `fakesys.hunt-creds` mints no draft AND
    emits a line naming `fakesys` and the reason. The control is in the same test — a drive
    that refuses nothing emits no such line, so the channel is shown to distinguish the two
    rather than being noisy on every tick.

    NOT ASSERTED, deliberately: what happens when the log write itself fails. That was offered
    as a secondary and never put to the human, so this demand neither requires nor forbids
    anything there.
    """
    cat = _catalog(tmp_path)

    capsys.readouterr()
    assert synthesize_drafts(
        [_lead("fakesys.hunt-creds", system="fakesys")],
        catalog_dir=cat, catalog=[], systems=DECLARED,
    ) == []
    refusal = loop_log(capsys)
    assert "fakesys" in refusal
    named = [ln for ln in refusal.splitlines() if "fakesys" in ln]
    assert named, "the refusal is not reported at all"

    capsys.readouterr()
    assert synthesize_drafts(
        [_lead("elastic.hunt-creds")], catalog_dir=cat, catalog=[], systems=DECLARED,
    ) != []
    quiet = loop_log(capsys)
    assert "fakesys" not in quiet
    assert not [ln for ln in quiet.splitlines() if "refus" in ln.lower()], (
        "a line that fires on a tick with nothing to refuse reports nothing"
    )


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
        skills_dir=repo / SKILLS_REL, systems=systems)
    assert [p.name for p in found] == ["lift-me.md"]

    assert log_lines_naming(loop_log(capsys), repr("gather")), (
        "the undeclared directory was skipped with no trace at all — a refusal with zero "
        "trace is what O3 forbids, and this is the fourth composition site FK-4 added"
    )
    # The control on the same address: declare it, and the same walk says nothing.
    capsys.readouterr()
    lead_author.discover_system_drafts(
        skills_dir=repo / SKILLS_REL, systems=systems | {"gather"})
    assert log_lines_naming(loop_log(capsys), repr("gather")) == [], (
        "a line that fires on a walk with nothing to skip reports nothing"
    )

    # And through the lane, so the drive edge is exercised rather than inspected: the pending
    # drafts the agent is handed never name the undeclared directory.
    paths = LoopPaths(repo_root=repo, state_dir=tmp_path / "state")
    spawn = LeadAuthorSpawn()
    deps = dataclasses.replace(
        lead_author.build_lead_author_deps(paths),
        invoke_agent=spawn, extract=lambda _rd: ([], []),
        acquire_queue_lock=lambda: object(), release_queue_lock=lambda _fh: None,
    )
    run_dir = tmp_path / "run-x"
    (run_dir / "gather_raw").mkdir(parents=True)
    lead_author.run(run_dir, paths=paths, deps=deps)

    handed = spawn.calls[-1]["pending_drafts"]
    assert [d["system"] for d in handed] == ["elastic"]
