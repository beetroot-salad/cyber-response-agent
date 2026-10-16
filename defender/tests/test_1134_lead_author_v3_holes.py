"""V3 holes in the lead author's listings: serving a claim after its trees closed, refused listings alone not refusing
a draft, `kind_at` mapping a refusal to absent, discovery re-listing a refused folder or rewording its reason.
Faults go through `DrainTrees.open`'s `os_` seam.
"""
from __future__ import annotations

import errno
import logging
import os
from pathlib import Path
from typing import Any

import pytest

from defender._env import FatalConfigError
from defender.learning.core.config import LEAD_AUTHOR_DRAIN_LABEL, LoopPaths
from defender.learning.core.lane_trees import DrainTrees, kind_at
from defender.learning.leads import lead_author
from defender.learning.leads.draft_synthesis import _draft_basename, synthesize_drafts
from defender.tests._lead_author_1134 import outcome, place, raised, scene_over, write
from defender.tests._repo import seed_skills_repo
from defender.tests._shared_readers_1134 import REFUSAL_ROUTES, RefusesFolder
from defender.tests._tree_listing_1134 import descriptors_under
from defender.tests._state1135 import run_of
from defender.tests.test_1134_lead_author_handle import (
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


# ---------------------------------------------------------------------------------------
# V3-H1: the CLI route serves its claim inside the trees it opened
# ---------------------------------------------------------------------------------------


def test_run_without_deps_mints_and_reaches_its_agent_inside_its_own_trees(
        tmp_path: Path, monkeypatch, caplog):
    """`lead_author.run(run, label=, paths=)` with no deps (what `main()` calls): the run
    opens its own trees under the queue lock and serves the whole claim inside them. Both coined
    rows' drafts land with their ids, the agent spawn is reached (`FatalConfigError` from the
    unroutable model), nothing is recorded done, no log line says `Bad file descriptor`, and
    once the run has unwound nothing under the worktree is held.

    Catches: `_run_locked` called after the `with` that opened the trees closed them, which
    answers every read and write `Bad file descriptor`: no draft, no agent, and a done
    sentinel with no commit."""
    monkeypatch.setenv("LEAD_AUTHOR_MODEL", NO_MODEL)
    caplog.set_level(logging.DEBUG)
    repo = _worktree(tmp_path)
    (tmp_path / "state").mkdir()  # the state root is never created lazily (#1135)
    paths = LoopPaths(repo_root=repo, state_dir=tmp_path / "state")
    run_dir = _run_dir(("wazuh.hunt-creds", "wazuh", "esql"),
                       ("elastic.hunt-creds", "elastic", "esql"))

    with pytest.raises(FatalConfigError, match=NO_MODEL):
        lead_author.run(run_of(run_dir), label=LEAD, paths=paths)

    for system in ("wazuh", "elastic"):
        qid = f"{system}.hunt-creds"
        draft = paths.skills_dir / f"gather/queries/{system}/_draft/{_draft_basename(qid)}.md"
        assert qid in draft.read_text(encoding="utf-8"), draft
    assert not (run_dir / "lead_author" / "done").exists(), "recorded done before its agent"
    assert _bad_fd(caplog) == []
    assert wrote_errors(caplog) == []
    assert descriptors_under(repo) == []


# ---------------------------------------------------------------------------------------
# V3-H2: a refused listing falls through to the write; only the write's refusal is the draft's
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("route", ["scandir", "reopen"])
@pytest.mark.parametrize("err", [errno.EACCES, errno.EIO], ids=["EACCES", "EIO"])
def test_a_refused_listing_alone_does_not_refuse_the_draft(
        tmp_path: Path, route: str, err: int, caplog):
    """The trees held over an `os_` that refuses only the LISTING of the wazuh draft's `_draft`
    folder (its `scandir`, or the reopen of `.` for reading), not the step into it: the
    existence probe's `entry_kind` answers that listing's `reason` (asked and refused once), the
    probe falls through to the write, and the write lands. Both drafts are created with their
    bytes, in order, and nothing is logged.

    Catches: a probe that treats `.reason` as the draft's refusal (or as "already there") and
    skips the write: the wazuh draft is lost to a fault the write never met."""
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


# ---------------------------------------------------------------------------------------
# V3-H3 / V3-H6: every refusal is "other" to `kind_at`, the mount point included
# ---------------------------------------------------------------------------------------


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
    """A holding folder whose listing is refused with any errno, on any route: `kind_at`
    answers `"other"` for a name below it, never `"absent"` and never a raise. Control: the same
    trees over the real `os` answer `"absent"` for the absent name."""
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
    """Through the gates: with the wazuh `_draft` folder's listing refused (any errno, any
    route), the half-promote twin probe refuses an established template (something it cannot
    see past stands where the twin goes), and a minted draft below it is not counted departed.
    Control: the same folder listed for real, with no twin and no draft, passes the twin probe
    and departs the draft.

    Catches: a refusal mapped to `"absent"`, which lets an established template land beside a
    draft twin nobody could see and calls a draft departed that may still stand."""
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
    """`kind_at` on the mount point itself (`tree_for` answers `"."`): `"dir"` over open trees;
    `"other"` when the mount's own listing is refused (EIO) and after the trees closed (`Bad
    file descriptor`). Never hardcoded, never a raise."""
    rel = "defender/skills"
    assert kind_at(scene.repo, scene.tree_for, rel) == "dir"
    refuser = RefusesFolder(scene.skills_dir, route, errno.EIO)
    with DrainTrees.open((scene.skills_dir,), os_=refuser) as trees:
        assert kind_at(scene.repo, trees.tree_for, rel) == "other"
    assert refuser.refused > 0
    with DrainTrees.open((scene.skills_dir,)) as closed:
        assert kind_at(scene.repo, closed.tree_for, rel) == "dir"
    assert kind_at(scene.repo, closed.tree_for, rel) == "other"


# ---------------------------------------------------------------------------------------
# V3-H4 / V3-H5: discover's refused folders — one listing decides, its reason verbatim
# ---------------------------------------------------------------------------------------

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
    """A transient refusal (`once=True`: only the first listing of the folder is refused, a
    second would answer): the folder is asked for exactly once, its draft is not discovered,
    and its one warning is given. Catches: a discover that lists a refused folder again and
    splices in the second answer, in silence."""
    refuser = RefusesFolder(skills / deny, route, errno.EACCES, once=True)
    assert _discover(skills, refuser) == [skills / "elastic/_draft/a.md"]
    assert refuser.asked == 1, f"the folder was asked for {refuser.asked} times"
    assert _warnings(caplog) == [GHOST, f"warn: skipping {skills / deny} ({os.strerror(errno.EACCES)})"]


@pytest.mark.parametrize("route", REFUSAL_ROUTES)
@pytest.mark.parametrize("err", UNCOMMON_ERRNOS, ids=errno.errorcode.get)
@pytest.mark.parametrize("deny", ["wazuh", "wazuh/_draft"])
def test_discover_warns_an_uncommon_refusal_in_its_own_words(
        skills: Path, deny: str, err: int, route: str, caplog):
    """A declared folder refused with an errno no other row names: ONE
    `warn: skipping <where>/<name> (<strerror>)`, the listing's reason verbatim; every other
    system is still discovered."""
    refuser = RefusesFolder(skills / deny, route, err)
    assert _discover(skills, refuser) == [skills / "elastic/_draft/a.md"]
    assert refuser.refused > 0
    assert _warnings(caplog) == [GHOST, f"warn: skipping {skills / deny} ({os.strerror(err)})"]


# ---------------------------------------------------------------------------------------
# V3-H7 / V3-L1: B2's helpers are the one lister, and their stand-in suppression is gone
# ---------------------------------------------------------------------------------------








