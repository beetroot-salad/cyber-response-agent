from __future__ import annotations

import errno
import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from defender.configuration._env import FatalConfigError
from defender.learning.core.config import LEAD_AUTHOR_DRAIN_LABEL
from defender.learning.core.lane_trees import DrainTrees, kind_at
from defender.learning.leads import lead_author
from defender.learning.leads.draft_synthesis import _draft_basename, synthesize_drafts
from defender.tests.support.learning.curation._lead_author_1134 import outcome, place, raised, scene_over, write
from defender.tests.support.shared.contracts._repo import seed_skills_repo
from defender.tests.support.learning.curation import _curator1134 as C
from defender.tests.support.learning.curation._shared_readers_1134 import REFUSAL_ROUTES, RefusesFolder
from defender.tests.support.learning.curation._tree_listing_1134 import descriptors_under
from defender.tests.support.learning.core._state1135 import run_of
from defender.tests.learning.curation.test_1134_lead_author_handle import (
    ELASTIC_LEAD,
    MINTED_IDS,
    MINTED_NAME,
    NO_MODEL,
    SYSTEMS,
    TEMPLATE_NAME,
    TWIN_NAME,
    WAZUH_LEAD,
    _run_dir,
    _worktree,
    bare_skills,
    draft_of,
    marked_template,
    resolver,
    wrote_errors,
)

LEAD = LEAD_AUTHOR_DRAIN_LABEL
#: Step 4's uncommon errnos (`test_1134_shared_readers.UNCOMMON_ERRNOS`): faults no row names
#: by hand, so a reader special-casing the common ones is caught.
UNCOMMON_ERRNOS = (errno.ENOMEM, errno.EMFILE, errno.ESTALE, errno.ENOTCONN)
#: Every errno a refused listing is driven with here.
REFUSED_ERRNOS = (errno.EACCES, errno.EIO, *UNCOMMON_ERRNOS)


def _bad_fd(caplog) -> list[str]:
    return [r.getMessage() for r in caplog.records if "Bad file descriptor" in r.getMessage()]


def _draft_lane(tmp_path: Path) -> C.DraftLane:
    """`_worktree`'s seeded tree after P4: its `skills/` as the tenant's `agent/skills` (one
    export commit) under a P3 batch with the lead lane `skills`; the product checkout keeps the
    adapters and no corpus (O1, #1172)."""
    repo = _worktree(tmp_path)
    agent = tmp_path / "agent-src"
    shutil.copytree(repo / "defender" / "skills", agent / "skills")
    subprocess.run(["git", "rm", "-r", "-q", "defender/skills"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "the product holds no corpus"], cwd=repo,
                   check=True)
    return C.draft_lane(tmp_path, lanes=C.LEAD_LANES, agent=agent, product=repo)


def test_run_without_deps_mints_and_reaches_its_agent_inside_its_own_trees(
        tmp_path: Path, monkeypatch, caplog):
    """#1134 + #1108 P4 O7: with no deps the tick opens its own trees over the batch's draft,
    mints each draft there and reaches its agent, leaving no descriptor open below the draft.
    ASSUMED SEAM (S-H): `lead_author.run(run, *, label, paths, batch)`."""
    monkeypatch.setenv("LEAD_AUTHOR_MODEL", NO_MODEL)
    caplog.set_level(logging.DEBUG)
    lane = _draft_lane(tmp_path)
    run_dir = _run_dir(("wazuh.hunt-creds", "wazuh", "esql"),
                       ("elastic.hunt-creds", "elastic", "esql"))

    with pytest.raises(FatalConfigError, match=NO_MODEL):
        lead_author.run(run_of(run_dir), label=LEAD, paths=lane.paths, batch=lane.batch)

    for system in ("wazuh", "elastic"):
        qid = f"{system}.hunt-creds"
        draft = lane.skills_dir / f"gather/queries/{system}/_draft/{_draft_basename(qid)}.md"
        assert qid in draft.read_text(encoding="utf-8"), draft
    assert not (run_dir / "lead_author" / "done").exists(), "recorded done before its agent"
    assert _bad_fd(caplog) == []
    assert wrote_errors(caplog) == []
    assert descriptors_under(lane.agent) == []


@pytest.mark.parametrize("route", ["scandir", "reopen"])
@pytest.mark.parametrize("err", [errno.EACCES, errno.EIO], ids=["EACCES", "EIO"])
def test_a_refused_listing_alone_does_not_refuse_the_draft(
        tmp_path: Path, route: str, err: int, caplog):
    repo = bare_skills(tmp_path)
    skills_dir = repo / "defender" / "skills"
    refuser = RefusesFolder(skills_dir / "gather/queries/wazuh/_draft", route, err)
    with DrainTrees.open((skills_dir,), os_=refuser) as trees:
        created = synthesize_drafts([WAZUH_LEAD, ELASTIC_LEAD], skills=trees.mount(skills_dir),
                                    where=skills_dir, catalog=[], systems=SYSTEMS)

    assert refuser.refused == 1, "the probe never met the refused listing, so the row is void"
    (w_name, w_text), (e_name, e_text) = draft_of(WAZUH_LEAD), draft_of(ELASTIC_LEAD)
    assert created == [skills_dir / w_name, skills_dir / e_name]
    assert (skills_dir / w_name).read_text(encoding="utf-8") == w_text
    assert (skills_dir / e_name).read_text(encoding="utf-8") == e_text
    assert wrote_errors(caplog) == []


@pytest.fixture
def scene(tmp_path: Path):
    """The handle file's scene: `seed_skills_repo`, committed, a folder outside it, the lead
    drain's trees over it, open for the test."""
    with scene_over(tmp_path, seed_skills_repo(tmp_path / "repo")) as s:
        yield s


DRAFT_FOLDER = "gather/queries/wazuh/_draft"


@pytest.mark.parametrize("route", REFUSAL_ROUTES)
@pytest.mark.parametrize("err", REFUSED_ERRNOS, ids=errno.errorcode.get)
def test_kind_at_answers_other_for_every_refused_listing(scene, err: int, route: str):
    (scene.skills_dir / DRAFT_FOLDER).mkdir(parents=True, exist_ok=True)
    rel = scene.rel(MINTED_NAME)
    assert kind_at(scene.repo, scene.tree_for, rel) == "absent"
    refuser = RefusesFolder(scene.skills_dir / DRAFT_FOLDER, route, err)
    with DrainTrees.open((scene.skills_dir,), os_=refuser) as trees:
        assert kind_at(scene.repo, trees.tree_for, rel) == "other"
    assert refuser.refused > 0


@pytest.mark.parametrize("route", REFUSAL_ROUTES)
@pytest.mark.parametrize("err", REFUSED_ERRNOS, ids=errno.errorcode.get)
def test_a_refused_draft_folder_neither_clears_the_twin_nor_departs_a_draft(
        scene, err: int, route: str):
    (scene.skills_dir / DRAFT_FOLDER).mkdir(parents=True, exist_ok=True)
    place(scene, TEMPLATE_NAME, marked_template("wazuh.probe"), "plain")
    assert not os.path.lexists(scene.at(TWIN_NAME))
    minted = {scene.at(MINTED_NAME): MINTED_IDS}

    def gates(tree_for) -> tuple[Any, Any]:
        twin = outcome(lambda: lead_author._skills_content_rule(
            scene.repo, resolver(scene), "A ", scene.rel(TEMPLATE_NAME), tree_for=tree_for))
        return twin, lead_author._departed_drafts(scene.repo, minted, [], tree_for=tree_for)

    twin, departed = gates(scene.tree_for)
    assert twin == ("returned", None)
    assert departed == [(scene.rel(MINTED_NAME), MINTED_IDS)]

    refuser = RefusesFolder(scene.skills_dir / DRAFT_FOLDER, route, err)
    with DrainTrees.open((scene.skills_dir,), os_=refuser) as trees:
        twin, departed = gates(trees.tree_for)
    assert refuser.refused > 0
    assert raised(twin, "LeadAuthorError", "half-promote"), twin
    assert departed == []


@pytest.mark.parametrize("route", ["reopen", "scandir"])
def test_kind_at_on_the_mount_point_answers_from_its_own_listing(scene, route: str):
    rel = "defender/skills"
    assert kind_at(scene.repo, scene.tree_for, rel) == "dir"
    refuser = RefusesFolder(scene.skills_dir, route, errno.EIO)
    with DrainTrees.open((scene.skills_dir,), os_=refuser) as trees:
        assert kind_at(scene.repo, trees.tree_for, rel) == "other"
    assert refuser.refused > 0
    with DrainTrees.open((scene.skills_dir,)) as closed:
        assert kind_at(scene.repo, closed.tree_for, rel) == "dir"
    assert kind_at(scene.repo, closed.tree_for, rel) == "other"


SKILL_SYSTEMS = frozenset({"elastic", "wazuh"})
GHOST = "discover_system_drafts: skipped undeclared directory 'ghost'"


@pytest.fixture
def skills(tmp_path: Path) -> Path:
    """A `skills/` tree: two declared systems with a pending draft each, and an undeclared
    `ghost` with one."""
    root = tmp_path / "repo" / "defender" / "skills"
    write(root / "elastic" / "_draft" / "a.md", "---\nname: a\n---\nelastic draft\n")
    write(root / "wazuh" / "_draft" / "b.md", "---\nname: b\n---\nwazuh draft\n")
    write(root / "ghost" / "_draft" / "c.md", "---\nname: c\n---\nundeclared\n")
    return root


def _discover(skills: Path, os_: Any) -> list[Path]:
    with DrainTrees.open((skills,), os_=os_) as trees:
        return lead_author.discover_system_drafts(
            skills=trees.mount(skills).view(), where=skills, systems=SKILL_SYSTEMS)


def _warnings(caplog) -> list[str]:
    return [r.getMessage() for r in caplog.records
            if r.levelno >= logging.WARNING and r.name.startswith("defender")]


@pytest.mark.parametrize("route", REFUSAL_ROUTES)
@pytest.mark.parametrize("deny", ["wazuh", "wazuh/_draft"])
def test_discover_takes_a_refused_folders_one_listing_as_final(
        skills: Path, deny: str, route: str, caplog):
    refuser = RefusesFolder(skills / deny, route, errno.EACCES, once=True)
    assert _discover(skills, refuser) == [skills / "elastic/_draft/a.md"]
    assert refuser.asked == 1, f"the folder was asked for {refuser.asked} times"
    assert _warnings(caplog) == [GHOST, f"warn: skipping {skills / deny} ({os.strerror(errno.EACCES)})"]


@pytest.mark.parametrize("route", REFUSAL_ROUTES)
@pytest.mark.parametrize("err", UNCOMMON_ERRNOS, ids=errno.errorcode.get)
@pytest.mark.parametrize("deny", ["wazuh", "wazuh/_draft"])
def test_discover_warns_an_uncommon_refusal_in_its_own_words(
        skills: Path, deny: str, err: int, route: str, caplog):
    refuser = RefusesFolder(skills / deny, route, err)
    assert _discover(skills, refuser) == [skills / "elastic/_draft/a.md"]
    assert refuser.refused > 0
    assert _warnings(caplog) == [GHOST, f"warn: skipping {skills / deny} ({os.strerror(err)})"]
