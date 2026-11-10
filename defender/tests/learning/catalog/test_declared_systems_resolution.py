"""#869: `declared_systems`, the resolver as a value.

#869: a lane resolves its systems once, at the boundary, and threads the value inward.

Each lane runs over a batch draft of the tenant's `agent/skills` (`_curator1134.draft_lane`) with
its adapters in a scratch product checkout (`seed_product`), and takes the batch. Mid-tick adapter
landings commit to that product checkout; mid-tick markers and skills go into the draft.

#869: every path-composition site refuses an undeclared system, and an empty declared set
refuses the lead-author lane.

The lead lane's tree is a batch's git-free draft (`agent/skills/...`); "nothing written" means the
batch's `ChangeSet` and branch carry nothing.
"""
from __future__ import annotations

import shutil
from pathlib import Path
import json
import dataclasses

import pytest

from defender.tests.support.shared._locations_1210 import location_path
from defender.learning.author.version_control import DeliveryRefused
from defender.learning.core import drains, persist
from defender.learning.core.config import LoopPaths
from defender.learning.leads.lead_extraction import LeadAuthorError
from defender.systems import verbs
from defender.tests.support.runtime.engine._declared869 import (
    ADAPTERS_REL,
    AGENT_NESTED_MARKER_RELS,
    AGENT_SKILLS_REL,
    NESTED_MARKER_PARENT,
    agent_marker_file,
    declared_systems,
    loop_log,
    pitfall_row,
    seed_tree,
    write_adapter,
    write_agent_marker,
    write_marker,
)
from defender.tests.support.learning.curation import _curator1134 as C
from defender.tests.support.learning.curation._lead_author_1134 import draft_lead_deps, lead_lane
from defender.learning.core.config import LEAD_AUTHOR_DRAIN_LABEL
from defender.tests.support.learning.core import _state1135
from defender.learning.core.state import PITFALLS
from defender.tests.support.tenancy._launch_publish_p4 import directory_for_root
from defender import _git
from defender.learning.leads import lead_author
from defender.tests.support.runtime.engine._declared869 import (
    LeadAuthorSpawn,
    Spawn,
    adapter_declared_systems,
    agent_skill_md,
    commit_paths,
    head_sha,
    write,
)
from defender.tests.support.learning.curation._curator1134 import open_state
from defender.tests.support.learning.curation._lead_author_1134 import (
    run_pitfalls,
)
from defender.tests.support.learning.core._state1135 import curation_row, curation_run_dir, curation_tenant, run_of
from defender.learning.core.lane_trees import DrainTrees
from defender.learning.leads import pitfalls_curator
from defender.learning.leads.draft_synthesis import _draft_basename, synthesize_drafts
from defender.learning.leads.lead_extraction import ExecutedLead
from defender.tests.support.learning.curation._lead_author_1134 import drafts_under, skills_view


#: The system the platform serves on every roster, with no adapter file (#1390).
PLATFORM_SERVED = "tacit-knowledge"


def _adapter_half_of(repo: Path) -> set[str]:
    """The adapter half, computed here from the working tree: an independent oracle, never a call
    into the resolver."""
    d = repo / ADAPTERS_REL
    return {
        verbs._system_of(p)
        for p in d.glob("*" + verbs.ADAPTER_SUFFIX)
    } | {PLATFORM_SERVED} if d.is_dir() else set()


def _committed_agent_paths(lane: C.DraftLane) -> list[str]:
    """Every `agent/...` path of the batch's base commit, asked of git in the tenant clone — the
    committed tree, listed independently of `Batch.base` (which is what the resolver is handed)."""
    listing = lane.git("ls-tree", "-r", "-z", "--name-only", lane.tip(), "--", "agent").stdout
    return [rel for rel in listing.split("\0") if rel]


def _marker_half_of(paths: object) -> set[str]:
    """The marker half, computed here from a committed tree's repo-relative paths.

    `len(parts) == 2` is the depth rule: the marker address is `agent/skills/<name>/execution.md`
    and nothing deeper. Without it this helper is `_recursive_marker_read_of`, the bug."""
    out = set()
    for rel in paths:
        if not rel.startswith(AGENT_SKILLS_REL):
            continue
        parts = rel[len(AGENT_SKILLS_REL):].split("/")
        if len(parts) == 2 and parts[1] == "execution.md":
            out.add(parts[0])
    return out


def _recursive_marker_read_of(paths: object) -> set[str]:
    """The wrong, depth-unbounded answer (every `execution.md` under `agent/skills/`), computed so
    the depth test can show its fixture really separates the two readings."""
    return {
        Path(rel).parent.name for rel in paths
        if rel.startswith(AGENT_SKILLS_REL) and rel.endswith("/execution.md")
    }


# The markers are the tenant's (`agent/skills/<name>/execution.md`), read from a committed tree
# handed in as `declared_systems(repo_root, *, agent=<its repo-relative paths>)`; the adapter half
# is the product checkout's working tree. The committed-vs-working-tree rule is pinned at the
# resolver and at the lane (`test_the_lead_lane_hands_the_resolver_the_batch_base_never_the_draft`).


def test_declared_systems_unions_the_adapter_glob_and_the_marker(tmp_path):
    product, lane = lead_lane(tmp_path, adapters=("elastic", "cmdb"),
                              markers=("elastic", "mcpsys"), skills=("elastic",))
    base = lane.batch.base()
    assert set(base) == set(_committed_agent_paths(lane)), "base() is not the committed tree"
    got = declared_systems(product, agent=base)

    assert got == frozenset({"elastic", "cmdb", "mcpsys", PLATFORM_SERVED})
    assert type(got) is frozenset
    assert set(got) == _adapter_half_of(product) | _marker_half_of(base)
    assert _adapter_half_of(product) < set(got)
    assert _marker_half_of(base) < set(got)

    other, lane2 = lead_lane(tmp_path, adapters=("ticket",), markers=("ticket",),
                             name="other-product")
    assert declared_systems(other, agent=lane2.batch.base()) == frozenset({"ticket", PLATFORM_SERVED})


def test_the_marker_half_reads_the_committed_tree_and_the_adapter_half_does_not(tmp_path):
    product, lane = lead_lane(tmp_path, adapters=("elastic",), markers=("elastic",),
                              skills=("elastic",))
    # A `mcpsys` marker on disk, uncommitted, in every working tree the resolver could stat (the
    # draft, the product checkout under both spellings); only an uncommitted adapter counts.
    write_agent_marker(lane.root, "mcpsys")
    write_agent_marker(product, "mcpsys")
    write_marker(product, "mcpsys")
    write_adapter(product, "newsys")
    base = lane.batch.base()
    assert f"{AGENT_SKILLS_REL}mcpsys/execution.md" not in base

    on_disk_only = declared_systems(product, agent=base)
    assert agent_marker_file(lane.root, "mcpsys").is_file()
    assert "mcpsys" not in on_disk_only          # the marker half ignores every working tree
    assert "newsys" in on_disk_only              # the adapter half does not
    assert "elastic" in on_disk_only             # and the committed baseline still answers

    lane.batch.commit(lane.batch.change_set(), "land the marker")
    landed = lane.batch.base()
    assert f"{AGENT_SKILLS_REL}mcpsys/execution.md" in _committed_agent_paths(lane)
    assert "mcpsys" in declared_systems(product, agent=landed)


def test_the_marker_source_is_exactly_depth_one(tmp_path):
    product, lane = lead_lane(
        tmp_path, adapters=("elastic",), markers=("elastic", "cmdb"), skills=("elastic",),
        catalog=("elastic",),
        extra={rel.removeprefix("agent/"): "# a marker whose parent directory name the model chose\n"
               for rel in AGENT_NESTED_MARKER_RELS},
    )
    committed = _committed_agent_paths(lane)
    for rel in AGENT_NESTED_MARKER_RELS:
        assert rel in committed, f"{rel} is not committed, so the test drives nothing"
    base = lane.batch.base()
    # The wrong answer, measured rather than remembered: the depth-unbounded read DOES pick the
    # model-chosen parent name up out of this very tree.
    assert NESTED_MARKER_PARENT in _recursive_marker_read_of(base)
    assert NESTED_MARKER_PARENT not in _marker_half_of(base)

    got = declared_systems(product, agent=base)
    assert NESTED_MARKER_PARENT not in got, (
        f"a nested execution.md declared {NESTED_MARKER_PARENT!r}: the marker read is "
        f"recursive, and every path in {list(AGENT_NESTED_MARKER_RELS)} is agent-committable"
    )
    assert got == frozenset({"elastic", "cmdb", PLATFORM_SERVED})
    assert "cmdb" in got, "the depth-1 marker-only control is not declared either"


def test_declared_systems_raises_when_the_adapter_half_is_unresolvable(tmp_path):
    """An unreadable adapter half raises whatever the markers say. The committed tree is the
    caller's to read, so an unresolvable one is pinned where it is read:
    `test_the_lead_lane_hands_the_resolver_the_batch_base_never_the_draft`."""
    product, lane = lead_lane(tmp_path, adapters=("elastic",), markers=("elastic",))
    base = lane.batch.base()
    assert declared_systems(product, agent=base) == frozenset({"elastic", PLATFORM_SERVED})   # the control

    no_adapters, lane2 = lead_lane(tmp_path, adapters=(), markers=("elastic",), skills=("elastic",),
                                   name="no-adapters")
    (no_adapters / ADAPTERS_REL).rmdir()
    base2 = lane2.batch.base()
    with pytest.raises(LeadAuthorError):
        declared_systems(no_adapters, agent=base2)
    # Not the conjunctive reading, and not a silent empty set: the marker half alone WOULD
    # have been an answer here, and it must not be the one.
    assert _marker_half_of(base2) == {"elastic"}


def test_the_lead_lane_hands_the_resolver_the_batch_base_never_the_draft(tmp_path):
    """The lane-level half of the committed-vs-working-tree rule."""
    product, lane = lead_lane(tmp_path, adapters=("elastic",), markers=("elastic", "basesys"),
                              skills=("elastic",))
    write_agent_marker(lane.root, "draftsys")      # in the draft, never committed
    assert agent_marker_file(lane.root, "draftsys").is_file()
    assert f"{AGENT_SKILLS_REL}draftsys/execution.md" not in _committed_agent_paths(lane)

    deps = draft_lead_deps(lane)
    assert "basesys" in deps.systems, "the committed marker-only system is not declared"
    assert "draftsys" not in deps.systems, (
        "a marker the box wrote into the draft declared its system: the lane resolved over "
        "the draft, not the batch base")
    assert deps.systems == declared_systems(product, agent=lane.batch.base())

    # An unresolvable committed tree refuses the deps; it never degrades to the adapter half.
    _p2, broken = lead_lane(tmp_path, adapters=("elastic",), markers=("elastic", "basesys"),
                            name="broken")
    shutil.rmtree(broken.clone / ".git" / "objects")
    with pytest.raises((DeliveryRefused, LeadAuthorError)):
        draft_lead_deps(broken)


def test_a_resolver_failure_is_not_a_successful_tick(tmp_path, capsys, monkeypatch):
    assert not issubclass(LeadAuthorError, OSError), (
        "an OSError subclass is swallowed by _run_curator_module and becomes rc 0"
    )
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "2")
    repo = seed_tree(tmp_path, adapters=(), markers=("elastic",), skills=("elastic",),
                     catalog=())
    (repo / ADAPTERS_REL).rmdir()
    paths = LoopPaths(repo_root=repo, state_dir=tmp_path / "state")
    persist.append_pitfalls(
        [pitfall_row("r:l-000:0", "mcpsys"), pitfall_row("r:l-001:0", "mcpsys")],
        state=_state1135.state_for_paths(paths),
    )
    capsys.readouterr()

    with pytest.raises(LeadAuthorError):
        drains._invoke_pitfalls(
            paths, _state1135.state_for_paths(paths), on_curated=lambda _d: None, label=LEAD_AUTHOR_DRAIN_LABEL)

    assert len(persist.read_pitfalls(_state1135.state_for_paths(paths))) == 2
    assert not (location_path(paths.state_root) / PITFALLS.consumed).exists()
    assert "(continuing)" not in loop_log(capsys)


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
    assert run_pitfalls(lane, state, spawn) == 0

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

    state = open_state(lane.paths)
    persist.append_pitfalls(
        [pitfall_row("r:l-000:0", "wtonly"), pitfall_row("r:l-001:0", "wtonly")], state=state,
    )
    spawn = Spawn(lambda root: write(agent_marker_file(root, "wtonly"), "# pitfalls\n- x\n"),
                  root=lane.root)
    capsys.readouterr()

    assert run_pitfalls(lane, state, spawn) == 0
    assert spawn.systems_seen == ["wtonly"]
    assert spawn.handoffs[0]["path"] == "agent/skills/wtonly/execution.md"
    assert persist.read_pitfalls(state) == []
    assert lane.text_at_tip("agent/skills/wtonly/execution.md") == "# pitfalls\n- x\n"


def test_a_marker_planted_during_the_tick_does_not_declare_its_system(tmp_path, monkeypatch):
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "2")
    monkeypatch.setenv("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", "1")

    product, lane = lead_lane(tmp_path, adapters=("elastic",), markers=("elastic",),
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
        run_pitfalls(lane, state, Spawn(land_an_adapter_then_plant, root=lane.root))
    # By the end of the tick the tree declares mcpsys; the tick's resolved value still does not.
    assert "mcpsys" in adapter_declared_systems(product)
    assert persist.read_pitfalls(state), "the batch must survive a refused tick"
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
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "2")
    _product, lane = lead_lane(tmp_path, adapters=("elastic",), markers=("elastic",),
                               skills=("elastic",), catalog=("elastic",), tenant=curation_tenant())
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
        return run_pitfalls(lane, _state, Spawn(
            lambda root: write(agent_marker_file(root, "elastic"), "# e\n## Common pitfalls\n- x\n"),
            root=lane.root))

    capsys.readouterr()
    drains._drain_lead_author(paths, state, lane1, lane2, batch=lane.batch,
                              claims=state.has_requests(), directory=directory_for_root())

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
    """All four sites refuse an undeclared system and admit a declared one; the claim carries
    nothing for the phantom."""
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
    """A tenant declaring no system of its own (no adapter in the product checkout, no marker in
    the draft; the platform-served system admits paths but does not count, #1390 A14) is refused
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
    assert deps.systems == frozenset({"tacit-knowledge"})

    run_dir = curation_run_dir("run-x")
    (run_dir / "gather_raw").mkdir()
    with pytest.raises(LeadAuthorError):
        lead_author.run(run_of(run_dir), label=LEAD_AUTHOR_DRAIN_LABEL, paths=paths, deps=deps)

    assert spawn.calls == [], "the agent must not be spawned against an empty declared set"
    assert lane.landed() == []
    assert len(lane.batch.change_set()) == 0


def test_1366_o1_the_lead_lanes_declared_systems_are_the_tenants_records_not_the_product_checkouts(tmp_path):
    """The product checkout carries cmdb and elastic adapters; the draft commits no marker: a tenant with no cmdb
    record declares elastic and the platform-served system, one with it declares cmdb too. (#1366 O1 learning)"""
    from defender.tests.support.shared.contracts._data_root_1078 import current_data_root, tenant_directory
    from defender.tests.support.shared.contracts._repo import seed_adapter_stubs
    from defender.tests.support.tenancy import _systems1366 as R

    product = tmp_path / "product"
    (product / "defender" / "integrations").mkdir(parents=True)
    seed_adapter_stubs(product / "defender", ("elastic", "cmdb"))
    tenant = _state1135.curation_tenant()
    lane = C.draft_lane(tmp_path, lanes=C.LEAD_LANES, product=product, tenant=tenant, files={
        "skills/gather/SKILL.md": "---\nname: gather\n---\n\nbody\n"})
    whole = R.fixture_records()
    assert {"cmdb", "elastic"} <= set(whole.systems), "fixture premise: the records can hold both systems"

    declared = {}
    for name, spec in (("a", R.without(whole, "cmdb")), ("b", whole)):
        directory = tenant_directory(current_data_root(), tenant.id, records=spec)
        deps = lead_author.build_lead_author_deps(
            lane.paths, state=C.open_state(lane.paths), trees=C.draft_trees(lane), batch=lane.batch, directory=directory)
        declared[name] = deps.systems

    assert {"elastic", PLATFORM_SERVED} <= declared["a"], declared["a"]
    assert "cmdb" not in declared["a"], declared["a"]
    assert {"cmdb", "elastic", PLATFORM_SERVED} <= declared["b"], declared["b"]
