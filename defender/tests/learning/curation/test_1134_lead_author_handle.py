from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

import dataclasses
import errno
import json
import logging
import os
import shutil
from collections.abc import Callable
from pathlib import Path, PurePosixPath
from typing import Any

import pytest

from defender import _git
from defender.systems import _scaffold_rules
from defender.configuration._env import FatalConfigError
from defender.learning.core import drains
from defender.learning.core.config import AUTHOR_DRAIN_LABEL, LEAD_AUTHOR_DRAIN_LABEL, LoopPaths
from defender.learning.core.lane_trees import DrainTrees, open_drain_trees, read_at
from defender.learning.leads import lead_author, lead_neighbors, lead_render, pitfalls_curator
from defender.learning.leads.draft_synthesis import (
    _draft_basename,
    _draft_params,
    _draft_skeleton,
    _executed_query,
    synthesize_drafts,
)
from defender.learning.leads.lead_extraction import (
    ExecutedLead,
    LeadAuthorError,
    collect_general_failures,
)
from defender.learning.leads.path_validation import SKILLS_PREFIX as SKILLS_REL
from defender.systems.verbs import engine_for
from defender.tests.support.runtime.engine._declared869 import LeadAuthorSpawn, seed_executed_query, seed_tree
from defender.tests.support.learning.curation._lead_author_1134 import (
    OUT_ID,
    OUT_MARK,
    Scene,
    ancestors,
    clear,
    draft_lead_deps,
    draft_scene_over,
    errors,
    lane_scene,
    lead_trees,
    logged,
    outcome,
    place,
    plant_folder,
    plant_state,
    product_lane,
    raised,
    scene_over,
    write,
)
from defender.tests.support.shared.contracts._repo import query_template, seed_skills_repo
from defender.tests.support.learning.core._declared870 import REDUCER_REL as ADDON_REL
from defender.tests.support.learning.core._state1135 import curation_row, curation_run_dir, run_of, state_for_paths
from defender.tests.support.learning.curation._shared_readers_1134 import RefusesFolder, kernel_watch
from defender.tests.support.sandbox._spec791 import author_markers
from defender.tests.support.learning.curation._tree_listing_1134 import descriptors_under
from defender.tests.shared.filesystem.test_1111_rooted_io import census, in_time

LEAD = LEAD_AUTHOR_DRAIN_LABEL

#: `seed_skills_repo`'s declared systems (its two adapters).
DECLARED = frozenset({"elastic", "wazuh"})

#: The addresses the rows plant at, as names under the `skills/` mount.
TEMPLATE_NAME = "gather/queries/wazuh/probe.md"
DRAFT_NAME = "gather/queries/wazuh/_draft/probe.md"
MINTED_NAME = "gather/queries/wazuh/_draft/0a1b2c3d4e5f.md"
SKILL_DRAFT_NAME = "elastic/_draft/probe.md"
SKILL_MD_NAME = "elastic/SKILL.md"
#: #1108 P4 (O7, OD6): the reducer surface is the tenant's pitfalls add-on (`_declared870.
#: REDUCER_REL`, the test's own oracle, not the production constant), as a name under the mount.
REDUCER_NAME = ADDON_REL.removeprefix("agent/skills/")
TWIN_NAME = DRAFT_NAME

#: A `## Query` whose rendered body carries the mark, so `render_query` and the handoff show it.
MARKED_QUERY = f"```query\nverb: search\nparams:\n  index: ${{index}}\n  note: {OUT_MARK}\n```"


def marked_template(tid: str, status: str = "established", *, covers=()) -> str:
    """A well-formed query template (the content gate accepts it) whose query carries the mark."""
    return query_template(tid, status, body=MARKED_QUERY, covers=covers)


@pytest.fixture
def scene(tmp_path: Path):
    """`seed_skills_repo` (a wazuh adapter with real verbs, a catalog with an established
    template and a draft, an `elastic` SKILL.md with a pending skill draft; committed), a folder
    outside it, and the lead drain's trees over it, open for the test.

    #1108 P4 (O7, OD6, OD12 class ii): the skills tree is a tenant-shaped root
    (`draft_scene_over`: the mount `<root>/agent/skills`, names `agent/skills/...`, committed as
    the batch base the rules compare against); the adapters stay in the product checkout."""
    with draft_scene_over(tmp_path, seed_skills_repo(tmp_path / "repo")) as s:
        yield s


def resolver(s: Scene) -> _scaffold_rules.VerbResolver:
    """The adapters' verbs, read from the product checkout (#1172), never the tenant root."""
    product = getattr(s, "product", None)
    return _scaffold_rules.VerbResolver((product if product is not None else s.repo) / "defender")


def _lead(query_id: str, *, system: str, verb: str, params: dict | None = None,
          error_class: str | None = None) -> ExecutedLead:
    return ExecutedLead(
        lead_id="l-001", query_index=0, is_multi_query=False, entry_index=0,
        query_id=query_id, system=system, verb=verb, params=params or {},
        raw_command="cli", goal_text="probe the thing", what_to_summarize=(), raw_ref=None,
        payload_status="ok", payload_digest="2 bytes", error_class=error_class,
    )


def _noop(_s: Scene) -> None:
    pass


def _load_catalog_first(s: Scene) -> None:
    """`build_handoff` is handed a catalog read while the template was still a plain file, so
    the render is what reaches the (then planted) name."""
    place(s, TEMPLATE_NAME, marked_template("wazuh.probe"), "plain")
    s.memo["catalog"] = lead_neighbors.load_lane_catalog(s.view, where=s.skills_dir)
    assert [t.id for t in s.memo["catalog"] if t.id == "wazuh.probe"], "the probe was not loaded"


def _stranded_draft(s: Scene) -> None:
    """A plain draft on disk recording `OUT_ID`: the half-promote probe fires on it iff the
    established template's `covers:` (read through the handle) took `OUT_ID` over."""
    write(s.at("gather/queries/wazuh/_draft/stranded.md"),
          query_template("wazuh.stranded", "draft", covers=[OUT_ID]))


REDUCER_TEXT = (
    f"---\nname: defender-sql\n---\n\n# defender-sql\n\n## Common pitfalls\n\n- {OUT_MARK}\n"
)


def _commit_reducer(s: Scene) -> None:
    """The add-on committed at the base with `REDUCER_TEXT`, so a draft holding the same bytes is
    an unchanged document."""
    assert s.rel(REDUCER_NAME) == ADDON_REL
    write(s.at(REDUCER_NAME), REDUCER_TEXT)
    _git.git(["add", "-A"], cwd=s.repo)
    _git.git(["commit", "-q", "-m", "reducer surface"], cwd=s.repo)


def _handoff_render(got: tuple) -> str | None:
    if got[0] != "returned" or len(got[1]) != 1:
        return None
    return got[1][0]["invocations"][0]["rendered_query"]


@dataclasses.dataclass(frozen=True)
class Row:
    """One reader or rule: the address it reads, what that address holds, the call through the
    new shape, and its answer when the entry was read (`took`) and when it was not (`refused`).
    `always` holds in both (the rest of the tree is still read), checked where the plant is at
    the name. `hard` is the answer for a hard link at the name when it is not `refused` (a
    listing calls a hard link a file; the read refuses it). `folders`: also plant at each
    holding folder. `reads`: the control's call reads the entry's bytes (a listing does not)."""

    id: str
    name: str
    text: str
    call: Callable[[Scene], Any]
    took: Callable[[Scene, tuple], bool]
    refused: Callable[[Scene, tuple], bool]
    prepare: Callable[[Scene], None] = _noop
    always: Callable[[Scene, tuple], bool] | None = None
    hard: Callable[[Scene, tuple], bool] | None = None
    folders: bool = True
    reads: bool = True


ROWS = [
    Row("minted_identities", MINTED_NAME,
        marked_template("wazuh.0a1b2c3d4e5f", "draft", covers=["wazuh.0a1b2c3d4e5f", OUT_ID]),
        lambda s: lead_author._minted_identities(s.view, [s.at(MINTED_NAME)], where=s.skills_dir),
        took=lambda s, got: got == ("returned", {s.at(MINTED_NAME): ("wazuh.0a1b2c3d4e5f", OUT_ID)}),
        refused=lambda s, got: got == ("returned", {})),
    # A listing, not a read: a hard link is a plain file to `list_tree`, so it is listed (every
    # later read refuses it). A symlink or a planted folder is never returned or entered.
    Row("discover_system_drafts", SKILL_DRAFT_NAME,
        f"---\nid: elastic.probe\nstatus: draft\n---\n# {OUT_MARK}\n",
        lambda s: lead_author.discover_system_drafts(
            skills=s.view, where=s.skills_dir, systems=DECLARED),
        took=lambda s, got: got[0] == "returned" and s.at(SKILL_DRAFT_NAME) in got[1],
        refused=lambda s, got: got[0] == "returned" and s.at(SKILL_DRAFT_NAME) not in got[1],
        always=lambda s, got: s.at("elastic/_draft/falco-na.md") in got[1],
        hard=lambda s, got: got[0] == "returned" and s.at(SKILL_DRAFT_NAME) in got[1],
        reads=False),
    Row("draft_contradicts_skill", SKILL_DRAFT_NAME,
        f"---\nid: elastic.probe\nstatus: draft\ncontradicts_skill: true\n---\n# {OUT_MARK}\n",
        lambda s: lead_author._draft_contradicts_skill(
            s.view, s.at(SKILL_DRAFT_NAME), where=s.skills_dir),
        took=lambda s, got: got == ("returned", True),
        refused=lambda s, got: got == ("returned", False)),
    Row("render_query", TEMPLATE_NAME, marked_template("wazuh.probe"),
        lambda s: lead_render.render_query(s.view, TEMPLATE_NAME, {"index": "idx-7"}),
        took=lambda s, got: (got[0] == "returned" and OUT_MARK in got[1]
                             and "index: idx-7" in got[1]),
        refused=lambda s, got: (got[0] == "raised" and got[1] != "LeadAuthorError"
                                and TEMPLATE_NAME in got[2])),
    Row("build_handoff_rendered_query", TEMPLATE_NAME, marked_template("wazuh.probe"),
        lambda s: lead_author.build_handoff(
            s.run_dir, [_lead("wazuh.probe", system="wazuh", verb="noverb",
                              params={"index": "idx-7"})],
            [], repo_root=s.repo, skills=s.view, where=s.skills_dir, catalog=s.memo["catalog"]),
        took=lambda s, got: OUT_MARK in (_handoff_render(got) or ""),
        refused=lambda s, got: _handoff_render(got) == "",
        prepare=_load_catalog_first),
    Row("frontmatter_id", TEMPLATE_NAME, marked_template(OUT_ID),
        lambda s: lead_author._frontmatter_id(s.repo, s.rel(TEMPLATE_NAME), tree_for=s.tree_for),
        took=lambda s, got: got == ("returned", OUT_ID),
        refused=lambda s, got: got == ("returned", None)),
    Row("skills_path_rule_id_check", TEMPLATE_NAME, marked_template(f"elastic.{OUT_MARK}"),
        lambda s: lead_author._skills_path_rule(
            s.repo, "A ", s.rel(TEMPLATE_NAME), systems=DECLARED, tree_for=s.tree_for),
        took=lambda s, got: raised(got, "LeadAuthorError", "disagreeing with its directory"),
        refused=lambda s, got: got == ("returned", None)),
    Row("check_promoted_template", TEMPLATE_NAME, marked_template("wazuh.probe"),
        lambda s: lead_author._check_promoted_template(
            s.repo, resolver(s), s.rel(TEMPLATE_NAME), tree_for=s.tree_for),
        took=lambda s, got: got == ("returned", None),
        refused=lambda s, got: raised(got, "LeadAuthorError", "not a readable query template")),
    Row("covers_rule_after_read", TEMPLATE_NAME, marked_template("wazuh.probe", covers=[OUT_ID]),
        lambda s: lead_author._covers_rule(
            s.repo, {}, [("A ", s.rel(TEMPLATE_NAME))], tree_for=s.tree_for),
        took=lambda s, got: raised(got, "LeadAuthorError", "half-promote"),
        refused=lambda s, got: got == ("returned", None),
        prepare=_stranded_draft),
    Row("refuse_half_promote", DRAFT_NAME,
        marked_template("wazuh.probe", "draft", covers=[OUT_ID]),
        lambda s: lead_author._refuse_half_promote(s.repo, {OUT_ID}, tree_for=s.tree_for),
        took=lambda s, got: raised(got, "LeadAuthorError", "half-promote"),
        refused=lambda s, got: got == ("returned", None)),
    Row("answered_after_batch", TEMPLATE_NAME, marked_template(OUT_ID),
        lambda s: lead_author._answered_after_batch(s.repo, tree_for=s.tree_for),
        took=lambda s, got: got[0] == "returned" and OUT_ID in got[1],
        refused=lambda s, got: got[0] == "returned" and OUT_ID not in got[1],
        always=lambda s, got: "wazuh.auth-events" in got[1]),
    # `_run_locked`'s two catalog loads.
    Row("load_lane_catalog", TEMPLATE_NAME, marked_template(OUT_ID),
        lambda s: {t.id for t in lead_neighbors.load_lane_catalog(s.view, where=s.skills_dir)},
        took=lambda s, got: got[0] == "returned" and OUT_ID in got[1],
        refused=lambda s, got: got[0] == "returned" and OUT_ID not in got[1],
        always=lambda s, got: "wazuh.auth-events" in got[1]),
    # `wazuh.search`'s suffix is its verb, so the row is no draft candidate: it is answered by
    # the catalog (no pitfall) or it is pitfalls residue. Nothing else decides it.
    Row("collect_general_failures", TEMPLATE_NAME, marked_template("wazuh.search"),
        lambda s: collect_general_failures(
            [_lead("wazuh.search", system="wazuh", verb="search", error_class="agent-fixable")],
            s.run_dir, skills=s.view, where=s.skills_dir),
        took=lambda s, got: got == ("returned", []),
        refused=lambda s, got: (got[0] == "returned"
                                and [r["query_id"] for r in got[1]] == ["wazuh.search"])),
    Row("readable_pair", REDUCER_NAME, REDUCER_TEXT,
        lambda s: pitfalls_curator._readable_pair(
            s.repo, s.rel(REDUCER_NAME), tree_for=s.tree_for),
        took=lambda s, got: got == ("returned", (REDUCER_TEXT, REDUCER_TEXT)),
        refused=lambda s, got: raised(got, "LeadAuthorError", "unreadable as a file"),
        hard=lambda s, got: raised(got, "LeadAuthorError", "unreadable as UTF-8 text"),
        prepare=_commit_reducer),
    Row("pitfalls_content_rule", REDUCER_NAME, REDUCER_TEXT,
        lambda s: pitfalls_curator._pitfalls_content_rule(
            s.repo, " M", s.rel(REDUCER_NAME), tree_for=s.tree_for),
        took=lambda s, got: got == ("returned", None),
        refused=lambda s, got: raised(got, "LeadAuthorError", "unreadable as a file"),
        hard=lambda s, got: raised(got, "LeadAuthorError", "unreadable as UTF-8 text"),
        prepare=_commit_reducer),
    Row("check_system_skill_view", SKILL_MD_NAME,
        f"---\nname: defender-elastic\n---\n# {OUT_MARK}\n",
        lambda s: [f.code for f in _scaffold_rules.check_system_skill(
            s.view, "elastic", SKILL_MD_NAME)],
        took=lambda s, got: got == ("returned", []),
        refused=lambda s, got: got == ("returned", ["skill-unreadable"])),
    Row("check_system_skill_path_form", SKILL_MD_NAME,
        f"---\nname: defender-elastic\n---\n# {OUT_MARK}\n",
        lambda s: [f.code for f in _scaffold_rules.check_system_skill(
            s.at(SKILL_MD_NAME), "elastic")],
        took=lambda s, got: got == ("returned", []),
        refused=lambda s, got: got == ("returned", ["skill-unreadable"]),
        folders=False),
    Row("read_at", TEMPLATE_NAME, marked_template("wazuh.probe"),
        lambda s: read_at(s.repo, s.tree_for, s.rel(TEMPLATE_NAME)),
        took=lambda s, got: got == ("returned", (marked_template("wazuh.probe"), None)),
        refused=lambda s, got: (got[0] == "returned" and got[1][0] is None
                                and bool(got[1][1]))),
]

FOLDER_ROWS = [pytest.param(row, site, kind, id=f"{row.id}@{site}-{kind}")
               for row in ROWS if row.folders for site in ancestors(row.name)
               for kind in ("link", "file")]


def _read_events(seen: list[tuple[str, str]], at: Path) -> list[tuple[str, str]]:
    return [e for e in seen if e[0] == str(at) and e[1] == "read"]


@pytest.mark.parametrize("row", ROWS, ids=lambda r: r.id)
def test_a_plain_file_at_the_entry_is_read(scene: Scene, row: Row):
    row.prepare(scene)
    place(scene, row.name, row.text, "plain")

    with kernel_watch(reads=[scene.at(row.name)]) as events:
        got = outcome(lambda: row.call(scene))
        seen = events()

    assert row.took(scene, got), got
    if row.always is not None:
        assert row.always(scene, got), got
    if row.reads:
        assert _read_events(seen, scene.at(row.name)), f"the watch saw no read: {seen}"


def _guarded(scene: Scene, row: Row, got: tuple, caplog, *, verdict, always: bool) -> None:
    """The "not read" verdict, no mark in the answer or anything logged, and (for a plant at
    the name, where the rest of the tree is intact) the rest still read."""
    assert verdict(scene, got), got
    assert OUT_MARK not in repr(got) + repr(logged(caplog, logging.DEBUG)), (
        got, logged(caplog, logging.DEBUG))
    if always and row.always is not None:
        assert row.always(scene, got), got


@pytest.mark.parametrize("row", ROWS, ids=lambda r: r.id)
def test_a_symlink_at_the_entry_is_not_followed(scene: Scene, row: Row, caplog):
    caplog.set_level(logging.DEBUG)
    row.prepare(scene)
    target = place(scene, row.name, row.text, "link")
    before = (census(scene.outside), plant_state(scene.at(row.name)))
    caplog.clear()

    with kernel_watch(opens=[target]) as events:
        got = outcome(lambda: row.call(scene))
        seen = events()

    assert seen == [], f"the link's target was opened or read: {seen}"
    assert not row.took(scene, got), got
    _guarded(scene, row, got, caplog, verdict=row.refused, always=True)
    assert (census(scene.outside), plant_state(scene.at(row.name))) == before


@pytest.mark.parametrize("row", ROWS, ids=lambda r: r.id)
def test_a_hard_link_at_the_entry_is_not_read(scene: Scene, row: Row, caplog):
    caplog.set_level(logging.DEBUG)
    row.prepare(scene)
    target = place(scene, row.name, row.text, "hardlink")
    before = census(scene.outside)
    caplog.clear()

    with kernel_watch(reads=[target]) as events:
        got = outcome(lambda: row.call(scene))
        seen = events()

    assert seen == [], f"the hard link's file was read: {seen}"
    if row.hard is None:
        assert not row.took(scene, got), got
    _guarded(scene, row, got, caplog, verdict=row.hard or row.refused, always=True)
    assert census(scene.outside) == before
    assert os.stat(scene.at(row.name)).st_ino == os.stat(target).st_ino, "the plant was not left"


@pytest.mark.parametrize(("row", "site", "kind"), FOLDER_ROWS)
def test_a_planted_holding_folder_is_not_followed(scene: Scene, row: Row, site: str, kind: str,
                                                  caplog):
    caplog.set_level(logging.DEBUG)
    row.prepare(scene)
    place(scene, row.name, row.text, "plain")
    moved = plant_folder(scene, site, kind)
    probe = moved / PurePosixPath(row.name).relative_to(site)
    before = (census(scene.outside), plant_state(scene.at(site)))
    caplog.clear()

    with kernel_watch(opens=[moved, probe]) as events:
        got = outcome(lambda: row.call(scene))
        seen = events()

    assert seen == [], f"the folder behind the plant was opened or read: {seen}"
    assert not row.took(scene, got), got
    _guarded(scene, row, got, caplog, verdict=row.refused, always=False)
    assert (census(scene.outside), plant_state(scene.at(site))) == before


@dataclasses.dataclass(frozen=True)
class ContentCase:
    id: str
    name: str
    good: str
    bad: str
    bad_says: str


CONTENT_CASES = [
    ContentCase("system_skill_md", SKILL_MD_NAME,
                f"---\nname: defender-elastic\n---\n# {OUT_MARK}\n",
                f"---\nname: defender-{OUT_MARK}\n---\n# elastic\n",
                "frontmatter name is not"),
    ContentCase("established_template", TEMPLATE_NAME, marked_template("wazuh.probe"),
                query_template("wazuh.probe", "established",
                               body=f"```query\nverb: search\nparams:\n  index: "
                                    f"${{{OUT_MARK.replace('-', '_')}}}\n```"),
                OUT_MARK.replace("-", "_")),
]


def content_verdict(s: Scene, name: str) -> tuple:
    return outcome(lambda: lead_author._skills_content_rule(
        s.repo, resolver(s), "A ", s.rel(name), tree_for=s.tree_for))


@pytest.mark.parametrize("case", CONTENT_CASES, ids=lambda c: c.id)
def test_the_content_rule_reads_a_plain_file_and_refuses_a_bad_one(scene: Scene, case):
    place(scene, case.name, case.good, "plain")
    assert content_verdict(scene, case.name) == ("returned", None)

    place(scene, case.name, case.bad, "plain")
    assert raised(content_verdict(scene, case.name), "LeadAuthorError", case.bad_says)


@pytest.mark.parametrize("case", CONTENT_CASES, ids=lambda c: c.id)
def test_the_content_rule_gives_a_link_one_verdict_whatever_it_points_at(scene: Scene, case):
    verdicts: dict[str, str] = {}
    for label, text in (("good", case.good), ("bad", case.bad)):
        target = place(scene, case.name, text, "link")
        with kernel_watch(opens=[target]) as events:
            got = content_verdict(scene, case.name)
            assert events() == [], f"{label}: the link's target was opened or read"
        assert case.bad_says not in repr(got), (label, got)
        assert OUT_MARK not in repr(got), (label, got)
        assert os.readlink(scene.at(case.name)) == str(target)
        verdicts[label] = repr(got)

    clear(scene.at(case.name))
    scene.at(case.name).symlink_to(scene.outside / "no-such.md")
    got = content_verdict(scene, case.name)
    assert case.bad_says not in repr(got), got
    verdicts["dangling"] = repr(got)
    assert scene.at(case.name).is_symlink()

    assert len(set(verdicts.values())) == 1, verdicts


def test_the_half_promote_twin_probe_refuses_a_plain_twin_and_passes_an_absent_one(scene: Scene):
    """The twin probe's control: an established template whose `_draft/` twin is a plain file is
    a half-promote; with no twin it passes."""
    place(scene, TEMPLATE_NAME, marked_template("wazuh.probe"), "plain")
    assert content_verdict(scene, TEMPLATE_NAME) == ("returned", None)

    place(scene, TWIN_NAME, marked_template("wazuh.probe", "draft"), "plain")
    assert raised(content_verdict(scene, TEMPLATE_NAME), "LeadAuthorError", "half-promote")


@pytest.mark.parametrize("plant", ["link", "dangling_link", "folder", "fifo", "hardlink"])
def test_anything_at_the_twin_refuses_the_half_promote_and_nothing_is_followed(
        scene: Scene, plant: str):
    place(scene, TEMPLATE_NAME, marked_template("wazuh.probe"), "plain")
    at = scene.at(TWIN_NAME)
    target = None
    if plant in ("link", "hardlink"):
        target = place(scene, TWIN_NAME, marked_template("wazuh.probe", "draft"), plant)
    elif plant == "dangling_link":
        at.symlink_to(scene.outside / "no-such.md")
    elif plant == "folder":
        write(at / "inner.md", "a folder where the twin goes\n")
    else:
        os.mkfifo(at)
    before = (census(scene.outside), plant_state(at))

    with kernel_watch(reads=[target] if target else []) as events:
        got = in_time(lambda: content_verdict(scene, TEMPLATE_NAME),
                      fifo=at if plant == "fifo" else None)
        seen = events()

    assert seen == []
    assert raised(got, "LeadAuthorError", "half-promote"), got
    assert OUT_MARK not in repr(got)
    assert (census(scene.outside), plant_state(at)) == before


MINTED_IDS = ("wazuh.0a1b2c3d4e5f", OUT_ID)


@pytest.mark.parametrize(("state", "departed"), [
    ("plain", False), ("absent", True), ("link", False), ("dangling_link", False),
    ("hardlink", False),
])
def test_a_minted_draft_departs_only_when_nothing_stands_at_its_name(scene, state, departed):
    minted = {scene.at(MINTED_NAME): MINTED_IDS}
    if state in ("plain", "link", "hardlink"):
        place(scene, MINTED_NAME, marked_template("wazuh.0a1b2c3d4e5f", "draft"), state)
    elif state == "dangling_link":
        scene.at(MINTED_NAME).symlink_to(scene.outside / "no-such.md")

    got = lead_author._departed_drafts(scene.repo, minted, [], tree_for=scene.tree_for)
    verdict = outcome(lambda: lead_author._covers_rule(
        scene.repo, minted, [], tree_for=scene.tree_for))

    assert got == ([(scene.rel(MINTED_NAME), MINTED_IDS)] if departed else [])
    if departed:
        assert raised(verdict, "LeadAuthorError", "without attributing"), verdict
    else:
        assert verdict == ("returned", None)
    if state in ("link", "dangling_link"):
        assert scene.at(MINTED_NAME).is_symlink(), "the plant was not left in place"


SYSTEMS = frozenset({"elastic", "wazuh"})
WAZUH_LEAD = _lead("wazuh.hunt-creds", system="wazuh", verb="esql", params={"query": "FROM logs"})
ELASTIC_LEAD = _lead("elastic.hunt-creds", system="elastic", verb="esql",
                     params={"query": "FROM logs"})


def draft_of(lead: ExecutedLead) -> tuple[str, str]:
    """The draft's name under `skills/` and its bytes, re-derived: the name is spelled from the
    catalog's place under the mount, the bytes from the writer's own skeleton."""
    suffix = _draft_basename(lead.query_id)
    record = _executed_query(lead) or "# (no command captured for this query)"
    text = _draft_skeleton(
        lead.query_id, f"{lead.system}.{suffix}", lead.verb, _draft_params(lead),
        lead.goal_text, record, engine_for(lead.system, lead.verb),
    )
    return f"gather/queries/{lead.system}/_draft/{suffix}.md", text


def bare_skills(tmp_path: Path) -> Path:
    """A bare `skills/` tree (no git) holding the catalog, with real `wazuh/_draft` and
    `elastic` folders; returns the repo root."""
    repo = tmp_path / "repo"
    skills = repo / "defender" / "skills"
    write(skills / "gather" / "SKILL.md", "---\nname: gather\n---\n")
    write(skills / "gather/queries/SCHEMA.md", "# template schema\n")
    write(skills / "gather/queries/wazuh/auth-events.md",
          query_template("wazuh.auth-events", "established"))
    write(skills / "gather/queries/wazuh/_draft/.keep", "")
    write(skills / "gather/queries/elastic/.keep", "")
    return repo


@pytest.fixture
def bare(tmp_path: Path):
    with scene_over(tmp_path, bare_skills(tmp_path)) as s:
        yield s


def new_files(before: dict, after: dict) -> set[str]:
    return {k for k, row in after.items() if k not in before and row[0] == "file"}


def unchanged(before: dict, after: dict) -> bool:
    """No entry that was there before is gone or different (new entries are allowed)."""
    return {k: after.get(k) for k in before} == before


def mint(s: Scene, leads: list[ExecutedLead], catalog: list | None = None) -> list[Path]:
    return synthesize_drafts(leads, skills=s.skills, where=s.skills_dir, catalog=catalog,
                             systems=SYSTEMS)


def wrote_errors(caplog) -> list[str]:
    return [m for m in errors(caplog) if "synthesize_drafts: could not write" in m]


def said_for(caplog, lead: ExecutedLead, skills_dir: Path) -> list[str]:
    """The ERROR lines naming `lead`'s draft (spelled `where / name`) and its query id."""
    draft = str(skills_dir / draft_of(lead)[0])
    return [m for m in wrote_errors(caplog) if draft in m and repr(lead.query_id) in m]


def test_the_writer_mints_each_draft_under_the_skills_mount_with_its_bytes(bare: Scene, caplog):
    before = census(bare.tmp)

    created = mint(bare, [WAZUH_LEAD, ELASTIC_LEAD])

    (w_name, w_text), (e_name, e_text) = draft_of(WAZUH_LEAD), draft_of(ELASTIC_LEAD)
    assert created == [bare.skills_dir / w_name, bare.skills_dir / e_name]
    assert bare.at(w_name).read_text(encoding="utf-8") == w_text
    assert bare.at(e_name).read_text(encoding="utf-8") == e_text
    after = census(bare.tmp)
    assert unchanged(before, after)
    assert new_files(before, after) == {f"repo/defender/skills/{w_name}",
                                        f"repo/defender/skills/{e_name}"}
    assert errors(caplog) == []


WRITER_SITES = ("gather", "gather/queries", "gather/queries/wazuh", "gather/queries/wazuh/_draft")


@pytest.mark.parametrize("catalog", [None, []], ids=["catalog_none", "catalog_given"])
@pytest.mark.parametrize("kind", ["link", "file"])
@pytest.mark.parametrize("site", WRITER_SITES)
def test_a_planted_folder_on_the_drafts_path_refuses_the_write_and_the_claim_goes_on(
    bare: Scene, site: str, kind: str, catalog, caplog,
):
    moved = plant_folder(bare, site, kind)
    plant_before = plant_state(bare.at(site))
    before = census(bare.tmp)

    with kernel_watch(opens=[moved]) as events:
        created = mint(bare, [WAZUH_LEAD, ELASTIC_LEAD], catalog=catalog)
        seen = events()

    assert seen == [], f"the folder behind the plant was opened or listed: {seen}"
    elastic_blocked = site in ("gather", "gather/queries")
    e_name, e_text = draft_of(ELASTIC_LEAD)
    assert created == ([] if elastic_blocked else [bare.skills_dir / e_name])
    after = census(bare.tmp)
    assert unchanged(before, after), "an entry that was there before changed (or was written)"
    assert new_files(before, after) == (
        set() if elastic_blocked else {f"repo/defender/skills/{e_name}"})
    if not elastic_blocked:
        assert bare.at(e_name).read_text(encoding="utf-8") == e_text
    assert plant_state(bare.at(site)) == plant_before

    blocked = [WAZUH_LEAD, *([ELASTIC_LEAD] if elastic_blocked else [])]
    for lead in blocked:
        assert len(said_for(caplog, lead, bare.skills_dir)) == 1, (lead.query_id, wrote_errors(caplog))
    assert len(wrote_errors(caplog)) == len(blocked), wrote_errors(caplog)
    assert all(r.levelno == logging.ERROR for r in caplog.records
               if "synthesize_drafts: could not write" in r.getMessage())


@pytest.mark.parametrize("kind", ["file", "dir", "hardlink", "link", "dangling_link", "fifo"])
def test_an_occupied_draft_name_is_skipped_and_a_non_plain_one_is_refused(
    bare: Scene, kind: str, caplog,
):
    w_name, _ = draft_of(WAZUH_LEAD)
    e_name, e_text = draft_of(ELASTIC_LEAD)
    at = bare.at(w_name)
    target = None
    if kind == "file":
        write(at, "an earlier draft\n")
    elif kind == "dir":
        write(at / "inner.md", "a folder where the draft goes\n")
    elif kind in ("link", "hardlink"):
        target = place(bare, w_name, f"{OUT_MARK}\n", kind)
    elif kind == "dangling_link":
        at.symlink_to(bare.outside / "no-such.md")
    else:
        os.mkfifo(at)
    before = census(bare.tmp)

    with kernel_watch(reads=[target] if target else []) as events:
        created = in_time(lambda: mint(bare, [WAZUH_LEAD, ELASTIC_LEAD]),
                          fifo=at if kind == "fifo" else None)
        seen = events()

    assert seen == []
    assert created == [bare.skills_dir / e_name]
    assert bare.at(e_name).read_text(encoding="utf-8") == e_text
    after = census(bare.tmp)
    assert unchanged(before, after), "the plant (or anything else) changed"
    assert new_files(before, after) == {f"repo/defender/skills/{e_name}"}
    said = said_for(caplog, WAZUH_LEAD, bare.skills_dir)
    if kind in ("file", "dir", "hardlink"):
        assert said == [], "an occupied name is skipped, not an error"
    else:
        assert len(said) == 1, errors(caplog)


#: The holding folders of the wazuh draft that only wazuh's path crosses.
WAZUH_FOLDERS = ("gather/queries/wazuh/_draft", "gather/queries/wazuh")


@pytest.mark.parametrize("err", [None, errno.EACCES, errno.EIO],
                         ids=["control", "EACCES", "EIO"])
@pytest.mark.parametrize("site", WAZUH_FOLDERS)
def test_a_kind_fault_at_a_drafts_holding_folder_is_logged_and_the_mint_goes_on(
        tmp_path: Path, site: str, err: int | None, caplog):
    repo = bare_skills(tmp_path)
    skills_dir = repo / "defender" / "skills"
    refuser = RefusesFolder(skills_dir / site, "step", err) if err is not None else None
    with DrainTrees.open((skills_dir,), **({"os_": refuser} if refuser else {})) as trees:
        created = synthesize_drafts([WAZUH_LEAD, ELASTIC_LEAD], skills=trees.mount(skills_dir),
                                    where=skills_dir, catalog=[], systems=SYSTEMS)

    (w_name, w_text), (e_name, e_text) = draft_of(WAZUH_LEAD), draft_of(ELASTIC_LEAD)
    assert (skills_dir / e_name).read_text(encoding="utf-8") == e_text
    if err is None:
        assert created == [skills_dir / w_name, skills_dir / e_name]
        assert (skills_dir / w_name).read_text(encoding="utf-8") == w_text
        assert wrote_errors(caplog) == []
        return
    assert refuser is not None
    assert refuser.refused > 0, "the fault was never reached"
    assert created == [skills_dir / e_name]
    assert not os.path.lexists(skills_dir / w_name)
    said = [m for m in wrote_errors(caplog)
            if str(skills_dir / w_name) in m and repr(WAZUH_LEAD.query_id) in m]
    assert len(said) == 1, wrote_errors(caplog)
    assert os.strerror(err) in said[0], said


def _worktree(tmp_path: Path, name: str = "repo") -> Path:
    return seed_tree(tmp_path, adapters=("elastic", "wazuh"), markers=("elastic", "wazuh"),
                     skills=("elastic",), catalog=("elastic", "wazuh"), name=name)


def _run_dir(*rows: tuple[str, str, str], run_id: str = "run-1") -> Path:
    """A run dir whose queries table holds `rows` (`(query_id, system, verb)`), in order,
    written through the production writer, one lead each. A natural run where run setup leaves
    one (`_state1135.curation_run_dir`: `<data root>/<T>/runs/<run_id>`, #1105 PR 2), so the
    lane's entry points take it as the `Run` the drain opens (`run_of`) and a row naming it
    rehydrates; `run_id` tells apart the runs of one test."""
    run_dir = curation_run_dir(run_id)
    (run_dir / "gather_raw").mkdir(parents=True, exist_ok=True)
    for i, (qid, system, verb) in enumerate(rows):
        seed_executed_query(run_dir, query_id=qid, lead_id=f"l-00{i + 1}", system=system,
                            verb=verb)
    return run_dir


def _deps(paths: LoopPaths, trees: DrainTrees, spawn: LeadAuthorSpawn,
          leads: list[ExecutedLead]):
    """The real deps for `paths` under the open `trees`, with only the seams a hermetic drive
    must own replaced: the agent spawn, the two tables, and the queue lock."""
    return dataclasses.replace(
        lead_author.build_lead_author_deps(paths, state=state_for_paths(paths), trees=trees),
        invoke_agent=spawn,
        extract=lambda _run_dir: ([], list(leads)),
    )


#: A model name no provider routes: an agent spawn the drive reaches raises `FatalConfigError`
#: at its key lookup instead of calling a model, so "reached the agent" is observable.
NO_MODEL = "no-such-model-1134"


@pytest.mark.parametrize("err", [None, errno.EACCES], ids=["control", "EACCES"])
def test_a_kind_fault_does_not_unwind_the_claim_through_run_under_held_queue_lock(
        tmp_path: Path, err: int | None, monkeypatch, caplog):
    monkeypatch.setenv("LEAD_AUTHOR_MODEL", NO_MODEL)
    repo = _worktree(tmp_path)
    paths = LoopPaths(repo_root=repo, state_dir=tmp_path / "state")
    run_dir = _run_dir(("wazuh.hunt-creds", "wazuh", "esql"),
                       ("elastic.hunt-creds", "elastic", "esql"))
    site = paths.skills_dir / "gather/queries/wazuh/_draft"
    site.mkdir(parents=True, exist_ok=True)
    refuser = RefusesFolder(site, "step", err) if err is not None else None
    done: list[str | None] = []

    with DrainTrees.open((paths.skills_dir,), **({"os_": refuser} if refuser else {})) as trees, \
            pytest.raises(FatalConfigError, match=NO_MODEL):
        lead_author.run_under_held_queue_lock(run_of(run_dir), paths=paths, state=state_for_paths(paths), trees=trees,
                                              on_done=done.append)

    w_draft = paths.skills_dir / f"gather/queries/wazuh/_draft/{_draft_basename('wazuh.hunt-creds')}.md"
    e_draft = paths.skills_dir / f"gather/queries/elastic/_draft/{_draft_basename('elastic.hunt-creds')}.md"
    assert "elastic.hunt-creds" in e_draft.read_text(encoding="utf-8")
    assert done == [], "the run recorded itself done before its agent"
    if err is None:
        assert "wazuh.hunt-creds" in w_draft.read_text(encoding="utf-8")
        assert wrote_errors(caplog) == []
        return
    assert refuser is not None
    assert refuser.refused > 0
    assert not os.path.lexists(w_draft)
    assert [m for m in wrote_errors(caplog) if str(w_draft) in m and "wazuh.hunt-creds" in m]


@pytest.mark.parametrize("site", [None, "gather", "gather/queries"])
def test_run_writes_no_draft_outside_skills_through_a_linked_catalog(
    tmp_path: Path, site: str | None, caplog,
):
    # #1108 P4 (O7, OD6, OD16): the run serves one claim of a real batch over its git-free draft
    # (`product_lane`); handoff and commit paths are repo-relative `agent/skills/...` (the test's
    # own spelling), and what landed is read from the batch branch.
    lane = product_lane(tmp_path, _worktree(tmp_path))
    run_dir = _run_dir()
    spawn = LeadAuthorSpawn()
    names = {lead.query_id: draft_of(lead) for lead in (WAZUH_LEAD, ELASTIC_LEAD)}
    with lane_scene(tmp_path, lane) as s:
        if site is not None:
            plant_folder(s, site, "link")
        planted = plant_state(s.at(site)) if site is not None else None
        before = census(s.outside)
        deps = draft_lead_deps(lane, invoke_agent=spawn,
                               extract=lambda _run_dir: ([], [WAZUH_LEAD, ELASTIC_LEAD]))
        rc = lead_author.run(run_of(run_dir), label=LEAD, paths=lane.paths, deps=deps)

    assert rc == 0
    if site is None:
        assert len(spawn.calls) == 1
        assert {h["executed_template_path"] for h in spawn.handoffs} == {
            f"agent/skills/{name}" for name, _ in names.values()}
        for name, text in names.values():
            assert lane.text_at_tip(f"agent/skills/{name}") == text
        assert {f"agent/skills/{name}" for name, _ in names.values()} <= set(lane.landed())
        return
    assert spawn.calls == [], "the agent was handed drafts written behind the link"
    assert census(s.outside) == before, "a draft was written outside skills/"
    assert plant_state(s.at(site)) == planted
    for qid, (name, _) in names.items():
        assert any("synthesize_drafts: could not write" in m and name in m and repr(qid) in m
                   for m in errors(caplog)), (qid, errors(caplog))
    assert (run_dir / "lead_author" / "done").read_text().startswith("commit: none")


@pytest.mark.parametrize("kind", ["file", "link"])
def test_run_goes_on_past_a_refused_draft_folder(tmp_path: Path, kind: str, caplog):
    repo = _worktree(tmp_path)
    paths = LoopPaths(repo_root=repo, state_dir=tmp_path / "state")
    run_dir = _run_dir()
    outside = tmp_path / "outside"
    outside.mkdir()
    spawn = LeadAuthorSpawn(rc=1)
    site = paths.skills_dir / "gather/queries/wazuh/_draft"
    if kind == "file":
        write(site, "a plain file where a folder belongs\n")
    else:
        (outside / "elsewhere").mkdir()
        site.symlink_to(outside / "elsewhere", target_is_directory=True)
    planted = plant_state(site)
    before = census(outside)

    with lead_trees(paths) as trees:
        rc = lead_author.run(run_of(run_dir), label=LEAD, paths=paths,
                             deps=_deps(paths, trees, spawn, [WAZUH_LEAD, ELASTIC_LEAD]))

    assert rc == 2, "the run did not reach the (failing) agent"
    assert len(spawn.calls) == 1
    (w_name, _), (e_name, e_text) = draft_of(WAZUH_LEAD), draft_of(ELASTIC_LEAD)
    assert [h["executed_template_path"] for h in spawn.handoffs] == [f"{SKILLS_REL}{e_name}"]
    assert (paths.skills_dir / e_name).read_text(encoding="utf-8") == e_text
    assert census(outside) == before
    assert plant_state(site) == planted
    assert any("synthesize_drafts: could not write" in m and w_name in m
               and repr(WAZUH_LEAD.query_id) in m for m in errors(caplog)), errors(caplog)


class PlantingBox:
    """The P4 drain's `start_box`/`stop_box` seams (#1108 P4 flow 4): records the batch box's
    request and applies `plant` to the draft root it mounts (`staged`) — the state a box
    process running beside the lead author leaves before the claim's host work runs."""

    def __init__(self, plant: Callable[[Path], None]) -> None:
        from defender.tests.tenancy.tenant_1108_p4._drain_support import BoxSpy

        self._spy = BoxSpy()
        self._plant = plant
        self.drafts: list[Path] = []

    def start(self, request: Any, **kw: Any) -> Any:
        executor = self._spy.start(request, **kw)
        [draft] = [Path(m.source) for m in request.mounts if m.kind == "staged"]
        self._plant(draft)
        self.drafts.append(draft)
        return executor

    def stop(self, box: Any, **kw: Any) -> None:
        self._spy.stop(box, **kw)


def _failed(paths: LoopPaths) -> list[dict]:
    failed = location_path(paths.state_root) / "author-queue" / "failed"
    return [json.loads(p.read_text()) for p in sorted(failed.glob("*.json"))] \
        if failed.is_dir() else []


def _lead_tick(tmp_path: Path, data_root: Path, plant: Callable[[Path], None]):
    """One real P4 lead-author drain tick over the fixture tenant's draft (#1108 P4 flow 4), a
    curation request queued for a run whose one executed query coins `elastic.newthing`, the
    box planting `plant` into the draft. Returns `(rc, box, paths, run_dir, tenant)`; the tenant's
    forge lives only inside the call, so its observations are taken here."""
    from defender.tests.tenancy.tenant_1108_p4._drain_support import (
        LEAD_PREFIX, drain_paths, drains, remote_branches, run_stage)
    from defender.tests.tenancy.tenant_1108_p4._support import bind_forge, published_tenant

    box = PlantingBox(plant)
    with published_tenant(tmp_path / "forge", root=data_root) as t:
        bind_forge(t)
        paths = drain_paths(t, _worktree(tmp_path, name="product"))
        run_dir = curation_run_dir("run-1", tenant_id=t.tenant_id)
        seed_executed_query(run_dir, query_id="elastic.newthing", system="elastic", verb="esql")
        state_for_paths(paths).enqueue_curation("case-1", curation_row("case-1", run_dir))
        rc = run_stage(lambda: drains().lead_author_drain(
            paths, client=t.forge.client, identity=t.vault.identity(),
            start_box=box.start, stop_box=box.stop))
        delivered = (remote_branches(t.remote, prefix=LEAD_PREFIX), list(t.forge.creates))
    return rc, box, paths, run_dir, delivered


def test_the_drain_default_seams_carry_the_label_and_write_nothing_outside_skills(
    tmp_path: Path, data_root: Path, monkeypatch, caplog,
):
    """#1134 over the P4 drain's draft: with a box having swapped the draft's catalog folder for
    a link out, the lane's default seams (label carried to the held `skills/` mount) refuse every
    draft write behind the link, write nothing outside, and deliver nothing. (The claim's fate
    after a box-planted link is P3's ChangeSet refusal, not pinned here.)"""
    monkeypatch.setenv("LEAD_AUTHOR_MODEL", NO_MODEL)
    outside = tmp_path / "outside"
    outside.mkdir()
    planted: list[dict] = []

    def plant(draft: Path) -> None:
        queries = draft / "agent" / "skills" / "gather" / "queries"
        os.replace(queries, outside / "elsewhere-queries")
        queries.symlink_to(outside / "elsewhere-queries", target_is_directory=True)
        planted.append(census(outside))

    rc, box, _paths, run_dir, delivered = _lead_tick(tmp_path, data_root, plant)

    assert box.drafts, "the batch's box never started over a draft"
    [before] = planted
    assert census(outside) == before, "a draft was written outside skills/"
    hexname = _draft_basename("elastic.newthing")
    assert any("synthesize_drafts: could not write" in m
               and f"skills/gather/queries/elastic/_draft/{hexname}.md" in m
               for m in errors(caplog)), errors(caplog)
    assert (run_dir / "lead_author" / "pitfalls_collected").is_file()
    assert delivered == ({}, []), "a batch whose drafts were refused delivered something"
    assert rc in (0, 2), rc


def test_a_seam_that_cannot_hold_skills_dead_letters_the_claim(
        tmp_path: Path, data_root: Path, caplog):
    """#1134 over the P4 drain's draft: a box that removed the draft's `skills/` lane leaves the
    lead author nothing to hold: the claim is dead-lettered `lead-author-error` naming
    `FileNotFoundError`, never re-queued as a transient, and the run gets no lead-author state."""
    def plant(draft: Path) -> None:
        shutil.rmtree(draft / "agent" / "skills")

    _rc, box, paths, run_dir, delivered = _lead_tick(tmp_path, data_root, plant)

    assert box.drafts, "the batch's box never started over a draft"
    failed = _failed(paths)
    assert len(failed) == 1, failed
    assert failed[0]["failed"].startswith("lead-author-error"), failed
    assert "FileNotFoundError" in failed[0]["failed"], failed
    assert author_markers(paths) == [], "the claim was re-queued as a transient"
    assert not (run_dir / "lead_author").exists()
    assert delivered == ({}, [])


def _lifetime_paths(tmp_path: Path) -> tuple[LoopPaths, Path]:
    repo = _worktree(tmp_path)
    return LoopPaths(repo_root=repo, state_dir=tmp_path / "state"), repo


def _unresolved_run() -> Path:
    """A run whose one executed row resolves to no catalog template and is no draft candidate
    (`wazuh.search`: its suffix is its verb), so the run reaches `on_done(None)` (nothing to
    hand the agent) through every reader of the claim, and never the agent."""
    return _run_dir(("wazuh.search", "wazuh", "search"))


def test_the_lead_author_seam_holds_skills_only_while_its_call_runs(tmp_path: Path, caplog):
    caplog.set_level(logging.DEBUG)
    paths, repo = _lifetime_paths(tmp_path)
    run_dir = _unresolved_run()
    during: list[tuple[str | None, list[str]]] = []
    assert descriptors_under(repo) == []

    drains._invoke_lead_author(
        paths, state_for_paths(paths), run_of(run_dir), label=LEAD,
        on_done=lambda sha: during.append((sha, sorted(descriptors_under(repo)))))

    assert during == [(None, [os.path.realpath(paths.skills_dir)])], during
    assert descriptors_under(repo) == [], "a handle on the leaf outlived the seam"
    assert (run_dir / "lead_author" / "pitfalls_collected").is_file()
    bad = [r.getMessage() for r in caplog.records if "Bad file descriptor" in r.getMessage()]
    assert bad == [], bad


@pytest.mark.parametrize("fault", ["RuntimeError", "OSError"])
def test_the_lead_author_seam_releases_skills_when_its_call_raises(tmp_path: Path, fault: str):
    paths, repo = _lifetime_paths(tmp_path)
    run_dir = _unresolved_run()
    during: list[list[str]] = []

    def on_done(_sha: str | None) -> None:
        during.append(sorted(descriptors_under(repo)))
        raise RuntimeError("on_done blew up") if fault == "RuntimeError" else OSError(
            errno.EIO, "on_done io fault")

    expected = RuntimeError if fault == "RuntimeError" else drains._LeadAuthorRetry
    with pytest.raises(expected):
        drains._invoke_lead_author(
            paths, state_for_paths(paths), run_of(run_dir), label=LEAD, on_done=on_done)

    assert during == [[os.path.realpath(paths.skills_dir)]], during
    assert descriptors_under(repo) == [], "a handle on the leaf outlived the raising seam"


def _lessons(paths: LoopPaths) -> None:
    """The author drain's two corpora, made in the leaf, so its trees can be opened there (the
    refusal under test is then the lane's, not the open's)."""
    for tree in AUTHOR_DRAIN_LABEL.writable_trees(paths):
        tree.mkdir(parents=True, exist_ok=True)


def _refusing_trees(tmp_path: Path) -> dict[str, Callable[[], tuple[LoopPaths, DrainTrees]]]:
    """Each way the lane's trees can fail to hold `skills/` exactly, as `(paths, open trees)`:
    the author member's trees, and trees whose one mount is moved off `skills/`, lies above it
    (`defender/`) or below it. Since #1179's amendment a member answers its own trees, so the
    wrong mount sets are opened directly (`DrainTrees.open`)."""
    repo = _worktree(tmp_path)
    plain = LoopPaths(repo_root=repo, state_dir=tmp_path / "state")
    _lessons(plain)
    (repo / "moved-skills").mkdir()
    return {
        "author_label": lambda: (plain, open_drain_trees(plain, AUTHOR_DRAIN_LABEL)),
        "moved_mount": lambda: (plain, DrainTrees.open((repo / "moved-skills",))),
        "mount_above": lambda: (plain, DrainTrees.open((plain.defender_dir,))),
        "mount_below": lambda: (plain, DrainTrees.open((plain.skills_dir / "gather",))),
    }


REFUSALS = ("author_label", "moved_mount", "mount_above", "mount_below")


@pytest.mark.parametrize("how", REFUSALS)
def test_trees_that_do_not_hold_skills_exactly_are_refused(tmp_path: Path, how: str, caplog,
                                                           monkeypatch):
    from defender.learning.core import persist
    from defender.tests.support.runtime.engine._declared869 import Spawn, pitfall_row

    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "1")
    paths, trees = _refusing_trees(tmp_path)[how]()
    persist.append_pitfalls([pitfall_row("r:l-000:0", "elastic")], state=state_for_paths(paths))
    spawn = Spawn()
    with trees:
        with pytest.raises(LeadAuthorError):
            lead_author.build_lead_author_deps(paths, state=state_for_paths(paths), trees=trees)
        with pytest.raises(LeadAuthorError):
            pitfalls_curator.run_pitfalls(paths=paths, trees=trees, invoke=spawn)
    assert spawn.calls == []
    assert [r["pitfall_id"] for r in persist.read_pitfalls(state_for_paths(paths))] == ["r:l-000:0"]
