from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

import dataclasses
import errno
import logging
import os
from pathlib import Path
from typing import Any

import pytest

from defender import _git
from defender.configuration._env import FatalConfigError
from defender.learning.core import drains, persist
from defender.learning.core.config import LEAD_AUTHOR_DRAIN_LABEL, LoopPaths
from defender.learning.core.lane_trees import DrainTrees
from defender.learning.leads import lead_author, lead_neighbors, pitfalls_curator
from defender.learning.leads.draft_synthesis import synthesize_drafts
from defender.tests.support.learning.core import _state1135
from defender.tests.support.learning.curation._tree_listing_1134 import RealOs, fd_path
from defender.tests.support.runtime.engine._declared869 import LeadAuthorSpawn, pitfall_row
from defender.tests.support.learning.core._declared870 import (
    REDUCER_REL,
    Spawn,
    reducer_surface_text,
    seed_agent_files,
    seed_product,
    shim_row,
)
from defender.tests.support.learning.curation import _curator1134 as C
from defender.tests.support.learning.curation._lead_author_1134 import (
    OUT_MARK,
    Scene,
    clear,
    draft_lead_deps,
    draft_scene_over,
    lead_trees,
    logged,
    outcome,
    place,
    plant_state,
    raised,
    write,
)
from defender.tests.support.shared.contracts._repo import query_template, seed_skills_repo
from defender.tests.support.learning.curation._shared_readers_1134 import RefusesFolder, kernel_watch
from defender.tests.shared.filesystem.test_1111_rooted_io import census, in_time
from defender.tests.support.learning.core._state1135 import run_of
from defender.tests.learning.curation.test_1134_lead_author_handle import (
    CONTENT_CASES,
    DECLARED,
    ELASTIC_LEAD,
    MINTED_NAME,
    NO_MODEL,
    REFUSALS,
    SKILL_MD_NAME,
    TEMPLATE_NAME,
    WAZUH_LEAD,
    _lead,
    _refusing_trees,
    _run_dir,
    _worktree,
    bare_skills,
    content_verdict,
    draft_of,
    marked_template,
    said_for,
)
from defender.learning.core.state import PITFALLS

LEAD = LEAD_AUTHOR_DRAIN_LABEL


def _head_mode(repo: Path, rel: str, rev: str = "HEAD") -> str:
    """The git mode `rel` is committed with at `rev` (`100644` a file, `120000` a link)."""
    # The code under test (the pitfalls / lead commit) runs no `ls-tree`: the query shape this
    # shares is tenant.py's committed-id read (#1120), which no test here exercises.
    return _git.git(["ls-tree", rev, "--", rel], cwd=repo).split(" ", 1)[0]  # lint-oracle: ok — not the code under test's query


def _outcome(fn: Any) -> tuple:
    """`outcome`, plus P3's commit-maker refusal: `("raised", "DeliveryRefused", message)`. A
    link or hard link the box leaves in its lane is a ChangeSet refusal (OD18/OD23; owner ruling
    2026-10-23: no hard-linked entry is ever committed), which the direct entry raises and the
    drain routes as a U10 refused claim (`test_refused_claims.py`)."""
    from defender.learning.author.version_control import DeliveryRefused

    try:
        return outcome(fn)
    except DeliveryRefused as e:
        return ("raised", "DeliveryRefused", str(e))


#: The curator's edit: one pitfall appended under the reducer's `## Common pitfalls`, a
#: document the content rule accepts, carrying the mark.
EDITED_REDUCER = reducer_surface_text(bullets=(OUT_MARK,))


def _pitfalls_lane(tmp_path: Path) -> C.DraftLane:
    """#1108 P4 (O7, OD6, OD12 class ii): a started batch whose draft carries the reducer add-on
    (`REDUCER_REL`, in the batch base) and the `elastic` marker and skill, the product checkout
    holding the `elastic` and `cmdb` adapters, and three queued reducer rows (a `defender-sql`
    mistake each), so the tick offers the reducer surface to its curator."""
    product = seed_product(tmp_path, adapters=("elastic", "cmdb"))
    files = {**seed_agent_files(markers=("elastic",), skills=("elastic",), catalog=(),
                                non_systems=("gather",)),
             REDUCER_REL.removeprefix("agent/"): reducer_surface_text()}
    lane = C.draft_lane(tmp_path, lanes=C.LEAD_LANES, files=files, product=product)
    location_path(lane.paths.state_root).mkdir(parents=True, exist_ok=True)  # never created lazily (#1135)
    persist.append_pitfalls([shim_row(f"r:l-003:{i}") for i in range(3)],
                            state=_state1135.state_for_paths(lane.paths))
    return lane


@pytest.mark.parametrize("left", ["plain", "link", "hardlink"])
def test_the_pitfalls_gate_reads_the_reducer_the_curator_left_through_the_trees(
        tmp_path: Path, monkeypatch, left: str):
    """Over a batch draft (ASSUMED SEAM `run_pitfalls(..., batch=)`); what landed is read from
    the batch branch, whose tip stands where HEAD stood."""
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "1")
    lane = _pitfalls_lane(tmp_path)
    target = write(tmp_path / "outside" / "reducer.md", EDITED_REDUCER)

    def curate(root: Path) -> None:
        at = root / REDUCER_REL
        at.unlink()
        if left == "plain":
            write(at, EDITED_REDUCER)
        elif left == "link":
            at.symlink_to(target)
        else:
            os.link(target, at)

    head = lane.base
    watch = {"opens": [target]} if left == "link" else {"reads": [target]}
    with C.draft_trees(lane) as trees, kernel_watch(**watch) as events:
        got = _outcome(lambda: pitfalls_curator.run_pitfalls(
            paths=lane.paths, trees=trees, batch=lane.batch,
            invoke=Spawn(curate, root=Path(lane.batch.draft_root))))
        seen = events()

    assert seen == [], f"the gate opened or read the outside file: {seen}"
    assert _head_mode(lane.clone, REDUCER_REL, lane.tip()) == "100644"
    if left == "plain":
        assert got == ("returned", 0), got
        assert lane.tip() != head, "the control's edit was not committed"
        assert lane.text_at_tip(REDUCER_REL) == EDITED_REDUCER
        return
    # #1108 P4 (OD18/OD23, owner ruling 2): the ChangeSet refuses the claim whole, naming the
    # entry by its repo-relative path; the lane's own gate never reads it.
    assert raised(got, "DeliveryRefused", REDUCER_REL), got
    assert OUT_MARK not in got[2], got
    assert lane.tip() == head, "a link or a hard link was committed"


def _lead_lane(tmp_path: Path) -> C.DraftLane:
    """#1108 P4 (O7, OD6, OD12 class ii): `_worktree`'s tree as a started batch's draft (the
    `elastic` and `wazuh` markers and catalogs, the `elastic` skill, the catalog schema, in the
    batch base), its `elastic` and `wazuh` adapters in the product checkout."""
    product = seed_product(tmp_path, adapters=("elastic", "wazuh"))
    files = {**seed_agent_files(markers=("elastic", "wazuh"), skills=("elastic",),
                                catalog=("elastic", "wazuh")),
             "skills/gather/queries/SCHEMA.md": "# template schema\n"}
    lane = C.draft_lane(tmp_path, lanes=C.LEAD_LANES, files=files, product=product)
    location_path(lane.paths.state_root).mkdir(parents=True, exist_ok=True)  # never created lazily (#1135)
    return lane


@dataclasses.dataclass(frozen=True)
class Left:
    """What the agent leaves below `skills/`: the name, the bytes, how the gate refuses the
    plain file (`None`: it passes and is committed). A link or a hard link to an outside file
    holding the same bytes is refused by the ChangeSet before any gate (#1108 P4, OD18/OD23)."""

    id: str
    name: str
    text: str
    plain_refusal: str | None


LEFTS = [
    # A well-formed template whose id names another system: a gate that reads it refuses it
    # for its id, quoting the mark.
    Left("template", "gather/queries/wazuh/left.md", marked_template(f"elastic.{OUT_MARK}"),
         plain_refusal="disagreeing with its directory"),
    # A declared system's SKILL.md whose frontmatter is valid: read, it passes.
    Left("skill_md", "elastic/SKILL.md",
         f"---\nname: defender-elastic\n---\n# elastic\n\n- {OUT_MARK}\n",
         plain_refusal=None),
]


@pytest.mark.parametrize("left", ["plain", "link", "hardlink"])
@pytest.mark.parametrize("what", LEFTS, ids=lambda w: w.id)
def test_the_runs_commit_gate_reads_what_the_agent_left_through_the_trees(
        tmp_path: Path, what: Left, left: str, caplog):
    """#1108 P4 (O7, OD6, OD12 class ii): over a batch draft (`_worktree`'s tree as the tenant's
    `agent/skills`, its adapters in the product checkout), the lane's deps built on the batch
    (ASSUMED SEAM `build_lead_author_deps(..., batch=)`, `draft_lead_deps`); what landed is read
    from the batch branch, whose tip stands where HEAD stood."""
    product = seed_product(tmp_path, adapters=("elastic", "wazuh"))
    lane = C.draft_lane(tmp_path, lanes=C.LEAD_LANES, product=product, files=seed_agent_files(
        markers=("elastic", "wazuh"), skills=("elastic",), catalog=("elastic", "wazuh")))
    paths = lane.paths
    location_path(paths.state_root).mkdir(parents=True, exist_ok=True)  # never created lazily (#1135)
    run_dir = _run_dir()
    target = write(tmp_path / "outside" / Path(what.name).name, what.text)
    at = lane.skills_dir / what.name

    def leave(_run_dir: Path) -> None:
        at.unlink(missing_ok=True)
        if left == "plain":
            write(at, what.text)
        elif left == "link":
            at.symlink_to(target)
        else:
            os.link(target, at)

    spawn = LeadAuthorSpawn(leave)
    head = lane.base
    watch = {"opens": [target]} if left == "link" else {"reads": [target]}
    deps = draft_lead_deps(lane, invoke_agent=spawn, extract=lambda _rd: ([], [ELASTIC_LEAD]))
    with kernel_watch(**watch) as events:
        got = _outcome(lambda: lead_author.run(run_of(run_dir), label=LEAD, paths=paths, deps=deps))
        seen = events()

    assert spawn.calls, "the agent was never reached, so the gate never ran"
    assert seen == [], f"the commit gate opened or read the outside file: {seen}"
    rel = at.relative_to(lane.batch.draft_root).as_posix()
    if left == "plain" and what.plain_refusal is None:
        assert got == ("returned", 0), got
        assert lane.text_at_tip(rel) == what.text, "the control was not committed"
        assert _head_mode(lane.clone, rel, lane.tip()) == "100644"
        return
    assert lane.tip() == head, "something was committed"
    if left == "plain":
        assert raised(got, "LeadAuthorError", what.plain_refusal), got
        assert OUT_MARK in got[2], "the control's file was not read"
        return
    # #1108 P4 (OD18/OD23, owner ruling 2): a link or hard link in the lane is a ChangeSet
    # refusal of the whole claim, naming the entry; nothing behind it is read.
    assert raised(got, "DeliveryRefused", rel), got
    assert OUT_MARK not in repr(got) + repr(logged(caplog)), got


#: Each checked name, the bytes a plain file there passes with, and how the content rule
#: refuses what it cannot read there.
CHECKED = [pytest.param(TEMPLATE_NAME, CONTENT_CASES[1].good, "not a readable query template",
                        id="template"),
           pytest.param(SKILL_MD_NAME, CONTENT_CASES[0].good, "could not be read", id="skill_md")]


@pytest.mark.parametrize("plant", ["plain", "link", "dangling", "fifo"])
@pytest.mark.parametrize(("name", "good", "says"), CHECKED)
def test_the_content_rule_refuses_a_non_file_at_a_checked_name(
        scene: Scene, name: str, good: str, says: str, plant: str):
    at = scene.at(name)
    target = None
    if plant in ("plain", "link"):
        target = place(scene, name, good, plant)
    else:
        clear(at)
        if plant == "dangling":
            at.symlink_to(scene.outside / "no-such.md")
        else:
            os.mkfifo(at)
    before = (census(scene.outside), plant_state(at))

    with kernel_watch(opens=[target] if target else []) as events:
        got = in_time(lambda: content_verdict(scene, name), fifo=at if plant == "fifo" else None)
        seen = events()

    assert seen == [], f"the link's target was opened: {seen}"
    assert (census(scene.outside), plant_state(at)) == before, "the entry was not left"
    if plant == "plain":
        assert got == ("returned", None), got
        return
    assert raised(got, "LeadAuthorError", says), got
    assert OUT_MARK not in repr(got), got


class NoSpaceUnder(RealOs):
    """The real `os` handed to `DrainTrees.open` as `os_`, except that creating a file in or
    below the real folder `folder` (an `open` with `O_CREAT` off a descriptor naming it) fails
    with ENOSPC. `refused` counts the refusals (non-vacuity)."""

    def __init__(self, folder: Path) -> None:
        self.folder = os.path.realpath(folder)
        self.refused = 0

    def open(self, path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        base = fd_path(kwargs.get("dir_fd"))
        inside = base is not None and (base == self.folder
                                       or base.startswith(self.folder + os.sep))
        if flags & os.O_CREAT and inside:
            self.refused += 1
            raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC), os.fsdecode(path))
        return os.open(path, flags, *args, **kwargs)


@pytest.mark.parametrize("full", [False, True], ids=["control", "ENOSPC"])
def test_the_draft_is_created_through_the_held_mount(tmp_path: Path, full: bool, caplog):
    repo = bare_skills(tmp_path)
    skills_dir = repo / "defender" / "skills"
    seam = NoSpaceUnder(skills_dir / "gather/queries/elastic") if full else RealOs()
    with DrainTrees.open((skills_dir,), os_=seam) as trees:
        created = synthesize_drafts([ELASTIC_LEAD], skills=trees.mount(skills_dir),
                                    where=skills_dir, catalog=[], systems=DECLARED)

    name, text = draft_of(ELASTIC_LEAD)
    if not full:
        assert created == [skills_dir / name]
        assert (skills_dir / name).read_text(encoding="utf-8") == text
        return
    assert seam.refused > 0, "the write never reached the held mount's os_"
    assert created == []
    assert not os.path.lexists(skills_dir / name), "the draft was written some other way"
    said = said_for(caplog, ELASTIC_LEAD, skills_dir)
    assert len(said) == 1, said
    assert os.strerror(errno.ENOSPC) in said[0]


def test_two_claims_over_one_paths_each_mint_through_their_own_trees(
        tmp_path: Path, monkeypatch, caplog):
    """#1108 P4 (O7, OD12 class ii): two claims over one batch draft (ASSUMED SEAM
    `_invoke_lead_author(..., batch=)`). Each claim's minted draft is observed after its own
    serve: the draft is re-synced per claim (OD15), so a later claim may not see an earlier's."""
    caplog.set_level(logging.DEBUG)
    monkeypatch.setenv("LEAD_AUTHOR_MODEL", NO_MODEL)
    lane = _lead_lane(tmp_path)
    paths = lane.paths
    reached: list[str] = []
    minted: dict[str, bool] = {}
    for i, lead in enumerate((WAZUH_LEAD, ELASTIC_LEAD)):
        run_dir = _run_dir((lead.query_id, lead.system, lead.verb), run_id=f"claim-{i}")
        try:
            drains._invoke_lead_author(paths, _state1135.state_for_paths(paths), run_of(run_dir),
                                       label=LEAD, batch=lane.batch, on_done=lambda _sha: None)
        except FatalConfigError:
            reached.append(lead.query_id)
        minted[lead.query_id] = (lane.skills_dir / draft_of(lead)[0]).is_file()

    for lead in (WAZUH_LEAD, ELASTIC_LEAD):
        assert minted[lead.query_id], f"{lead.query_id}'s claim minted no draft"
    bad = [r.getMessage() for r in caplog.records if "Bad file descriptor" in r.getMessage()]
    assert bad == [], bad
    assert reached == [WAZUH_LEAD.query_id, ELASTIC_LEAD.query_id]


CONTRADICTING = (f"---\nid: elastic.contradicts\nstatus: draft\ncontradicts_skill: true\n---\n"
                 f"# {OUT_MARK}\n")


@pytest.mark.parametrize("left", ["plain", "hardlink"])
def test_the_lift_bypass_reads_a_pending_draft_through_the_trees(
        tmp_path: Path, monkeypatch, left: str):
    """#1108 P4 (O7, OD6, OD12 class ii): over a batch draft, the deps built on the batch
    (ASSUMED SEAM `build_lead_author_deps(..., batch=)`); the pending draft is named
    repo-relative in the tenant repo (`agent/skills/...`)."""
    monkeypatch.delenv("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", raising=False)
    lane = _lead_lane(tmp_path)
    paths = lane.paths
    run_dir = _run_dir()
    target = write(tmp_path / "outside" / "contradicts.md", CONTRADICTING)
    at = lane.skills_dir / "elastic/_draft/contradicts.md"
    if left == "plain":
        write(at, CONTRADICTING)
    else:
        at.parent.mkdir(parents=True, exist_ok=True)
        os.link(target, at)
    spawn = LeadAuthorSpawn()
    deps = draft_lead_deps(lane, invoke_agent=spawn, extract=lambda _run_dir: ([], []))

    with kernel_watch(reads=[target]) as events:
        got = _outcome(lambda: lead_author.run(run_of(run_dir), label=LEAD, paths=paths, deps=deps))
        seen = events()

    assert seen == [], f"the hard link's outside file was read: {seen}"
    if left == "plain":
        assert [[d["draft_path"] for d in c["pending_drafts"]] for c in spawn.calls] == [
            [at.relative_to(lane.batch.draft_root).as_posix()]], "the control's draft did not bypass"
        return
    assert got == ("returned", 0), got
    assert spawn.calls == [], "a hard link's outside bytes bypassed the lift threshold"


@pytest.mark.parametrize("refused", [False, True], ids=["control", "EIO"])
def test_the_runs_catalog_loads_go_through_the_deps_held_mount(tmp_path: Path, refused: bool):
    """#1108 P4 (O7, OD6, OD12 class ii): over a batch draft, the deps built on the batch
    (ASSUMED SEAM `build_lead_author_deps(..., batch=)`) under trees holding its skills."""
    lane = _lead_lane(tmp_path)
    paths = lane.paths
    run_dir = _run_dir()
    write(lane.skills_dir / TEMPLATE_NAME, marked_template("wazuh.probe"))
    lead = _lead("wazuh.probe", system="wazuh", verb="noverb", params={"index": "idx-7"})
    spawn = LeadAuthorSpawn(rc=1)
    refuser = RefusesFolder(lane.skills_dir / "gather/queries", "reopen", errno.EIO)
    seam = {"os_": refuser} if refused else {}

    with DrainTrees.open((lane.skills_dir,), **seam) as trees:
        deps = dataclasses.replace(
            lead_author.build_lead_author_deps(paths, state=_state1135.state_for_paths(paths),
                                               trees=trees, batch=lane.batch),
            invoke_agent=spawn, extract=lambda _run_dir: ([], [lead]))
        rc = lead_author.run(run_of(run_dir), label=LEAD, paths=paths, deps=deps)

    if not refused:
        assert rc == 2
        assert [h["query_id"] for h in spawn.handoffs] == ["wazuh.probe"]
        return
    assert refuser.refused > 0
    assert spawn.calls == [], "a catalog the held mount refuses was read some other way"
    assert rc == 0


@pytest.fixture
def scene(tmp_path: Path):
    """#1108 P4 (O7, OD6, OD12 class ii): the skills tree as a tenant-shaped root
    (`draft_scene_over`: the mount `<root>/agent/skills`, names `agent/skills/...`, committed as
    the batch base); the adapters stay in the product checkout."""
    with draft_scene_over(tmp_path, seed_skills_repo(tmp_path / "repo")) as s:
        yield s


def _respelled(paths: list[Path], s: Scene, where: Path) -> list[Path]:
    return [where / p.relative_to(s.skills_dir) for p in paths]


def test_where_only_spells_for_the_readers(scene: Scene, tmp_path: Path):
    elsewhere = tmp_path / "spelled-elsewhere"
    view, home = scene.view, scene.skills_dir

    found = lead_author.discover_system_drafts(skills=view, where=elsewhere, systems=DECLARED)
    found_home = lead_author.discover_system_drafts(skills=view, where=home, systems=DECLARED)
    assert found_home, "precondition: the seeded tree has pending system drafts"
    assert found == _respelled(found_home, scene, elsewhere)

    cat = lead_neighbors.load_lane_catalog(view, where=elsewhere)
    cat_home = lead_neighbors.load_lane_catalog(view, where=home)
    assert cat_home, "precondition: the seeded tree has a catalog"
    assert [(t.id, t.path) for t in cat] == [
        (t.id, elsewhere / t.path.relative_to(home)) for t in cat_home]

    write(scene.at(MINTED_NAME), query_template(
        "wazuh.0a1b2c3d4e5f", "draft", covers=["wazuh.0a1b2c3d4e5f", "wazuh.hunt-creds"]))
    drafts = [scene.at(MINTED_NAME)]
    minted = lead_author._minted_identities(view, _respelled(drafts, scene, elsewhere),
                                            where=elsewhere)
    minted_home = lead_author._minted_identities(view, drafts, where=home)
    assert minted_home, "precondition: the draft records identities"
    assert minted == dict(zip(_respelled(list(minted_home), scene, elsewhere),
                              minted_home.values(), strict=True))
    assert not os.path.lexists(elsewhere), "where= was made"


@pytest.mark.parametrize("how", ["lane_trees", *REFUSALS])
def test_run_pitfalls_checks_its_trees_before_it_reads_its_queue(
        tmp_path: Path, monkeypatch, how: str):
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "99")
    if how == "lane_trees":
        paths = LoopPaths(repo_root=_worktree(tmp_path), state_dir=tmp_path / "state")
        location_path(paths.state_root).mkdir(parents=True, exist_ok=True)  # never created lazily (#1135)
        trees = lead_trees(paths)
    else:
        paths, trees = _refusing_trees(tmp_path)[how]()
    persist.append_pitfalls([pitfall_row("r:l-000:0", "elastic")], state=_state1135.state_for_paths(paths))
    queue = location_path(paths.state_root) / PITFALLS.queue
    spawn = Spawn()

    with trees, kernel_watch(reads=[queue], opens=[queue]) as events:
        got = _outcome(lambda: pitfalls_curator.run_pitfalls(paths=paths, trees=trees,
                                                            invoke=spawn))
        seen = events()

    assert spawn.calls == []
    if how == "lane_trees":
        assert got == ("returned", 0), got
        assert seen, "the control never read its queue, so the watch proves nothing"
        return
    assert raised(got, "LeadAuthorError", ""), got
    assert seen == [], f"the queue was read before the trees were checked: {seen}"
