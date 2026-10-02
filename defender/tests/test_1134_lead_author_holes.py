"""#1134 step 6 (v3, addendum 2): the holes an adversarial implementation of v1's step 6 left open
while passing its handle file, each retargeted at `DrainTrees` / `Held` / `Bound` and addendum 2's
`entry_kind` / `list_tree`, plus the listing consumers' refused / gone folder handling. The scene and the rows are `test_1134_lead_author_handle.py`'s.

- H1, a hard link at the name: in the handle file's plant matrix (`test_a_hard_link_...`).
- H1b, the entry swapped for a link between `entry_kind` and the read. The trees are held
  over an `os_` that, at the entry's first open or no-follow stat (`entry_kind` judges from the
  parent's listing and touches neither, so in v3 that is the read), replaces the plain file with
  a symlink to an outside file.
  A reader that asks the handle and then opens the `Path` follows the swap; one that reads
  through the handle refuses it.
- H2, `_run_locked`'s catalog loads through a `Path` inside the mount, which follows a link at
  `gather` or `gather/queries` to a catalog that answers the lead, so following it changes what
  the run does. And H6, the `catalog=None` fallbacks (`synthesize_drafts`, `build_handoff`,
  `collect_general_failures`) loading the same way.
- H3, a pitfalls seam carrying the wrong label: in the handle file
  (`test_the_drain_seams_consult_the_label`, `test_trees_that_do_not_hold_skills_exactly_...`).
- H4, a folder planted above an entry. "Is there anything at this name" asked by a following
  probe (`os.path.lexists(repo_root / path)` follows every folder above the leaf) answers by
  the link's target.
- H5, the `tree_for` taken and discarded: a check that builds its own lookup, or probes the plain
  path beside it; and (the step-6 adversary's E1) a composite gate, `_skills_rule`,
  `_verify_skills_state`, `_pitfalls_rule` or `_verify_pitfalls_state`, handing its parts
  something other than the `tree_for` it was given. (The label consulted, and a mount list
  whose lead mount is moved or above `skills/`: in the handle file.)
- H7 and H8, the lane binding the wrong constant into a default seam, or the CLI running under
  the wrong label, where a hermetic drive cannot see it: AST pins, each label resolved through
  `_astlib`'s scopes to `config`'s binding (E3: a local alias named like the constant). (Step 3
  pins the batch calls' label and the one spelling of each label in `drains`.)
- Refused / gone folders: `discover_system_drafts` and `_refuse_half_promote` (through the step-4
  selection) skip a declared `<sys>` or `_draft` whose own listing is refused with one warning
  (the listing's reason verbatim) and still read every other system; one found gone is silent; a
  refused listing of the top warns once and yields nothing; a link at a
  `<sys>`, a `_draft` or a draft name is never entered or returned.

Linux only in practice, like the file it extends: the read watch is inotify.
"""
from __future__ import annotations

import ast
import dataclasses
import errno
import inspect
import logging
import os
import shutil
from collections.abc import Callable
from pathlib import Path, PurePosixPath
from typing import Any

import pytest

from defender._io import ALIAS_READ_REFUSAL
from defender._scaffold_rules import check_system_skill
from defender.learning.author import shared as _author_shared
from defender.learning.core import drains
from defender.learning.core.config import LEAD_AUTHOR_DRAIN_LABEL
from defender._tree_listing import list_tree
from defender.learning.core.lane_trees import DrainTrees, read_at
from defender.learning.leads import lead_author, lead_render, pitfalls_curator
from defender.learning.leads.lead_extraction import collect_general_failures
from defender.learning.leads.path_validation import CATALOG_REL, SKILLS_REL
from defender.tests._tree_listing_1134 import SWAP_PLANTS, RealOs, SwapsOnStep, fd_path
from defender.tests._by_path import import_lint_lib
from defender.tests._declared869 import LeadAuthorSpawn
from defender.tests._lead_author_1134 import (
    OUT_ID,
    OUT_MARK,
    Scene,
    clear,
    errors,
    logged,
    outcome,
    place,
    plant_folder,
    plant_state,
    raised,
    scene_over,
    write,
)
from defender.tests._repo import query_template, seed_skills_repo
from defender.tests._shared_readers_1134 import REFUSAL_ROUTES, RefusesFolder, kernel_watch
from defender.tests.test_1111_rooted_io import census, in_time
from defender.tests.test_1134_mount_list import CONFIG_MODULE, _foreign_imports, _rebindings
from defender.tests.test_1134_lead_author_handle import (
    CONTENT_CASES,
    DECLARED,
    DRAFT_NAME,
    ELASTIC_LEAD,
    MINTED_IDS,
    MINTED_NAME,
    REDUCER_NAME,
    REDUCER_TEXT,
    SKILL_DRAFT_NAME,
    SKILL_MD_NAME,
    TEMPLATE_NAME,
    TWIN_NAME,
    WAZUH_LEAD,
    _commit_reducer,
    _deps,
    _lead,
    _run_dir,
    _worktree,
    bare_skills,
    content_verdict,
    draft_of,
    marked_template,
    mint,
    resolver,
)

LEAD = LEAD_AUTHOR_DRAIN_LABEL


@pytest.fixture
def scene(tmp_path: Path):
    """The handle file's scene: `seed_skills_repo`, committed, a folder outside it, the lead
    drain's trees over it, open for the test."""
    with scene_over(tmp_path, seed_skills_repo(tmp_path / "repo")) as s:
        yield s


#: The same template as `marked_template`, with no mark in its query: what a plain entry holds
#: where the target of a link (or a swap) holds the marked one.
PLAIN_QUERY = "```query\nverb: search\nparams:\n  index: ${index}\n```"


def plain_template(tid: str, status: str = "established", *, covers=()) -> str:
    return query_template(tid, status, body=PLAIN_QUERY, covers=covers)


# ---------------------------------------------------------------------------------------
# H1b: the entry swapped for a link after `entry_kind` answered
# ---------------------------------------------------------------------------------------


class SwapsAfterKind(RealOs):
    """The real `os`, handed to `DrainTrees.open` as `os_`, with a race at one entry: the plain
    file at `victim` is replaced by a symlink to `target` the moment a no-follow stat of it
    answers, or at its first open if that comes first. `entry_kind` asks neither (it judges the
    entry from its parent's listing), so the swap lands after it answered, at the read's open. With `swap=False` it is the real `os` (the control). `swapped` says the
    race fired (non-vacuity)."""

    def __init__(self, victim: Path, target: Path, *, swap: bool = True) -> None:
        self.victim = os.path.join(os.path.realpath(victim.parent), victim.name)
        self.target = target
        self.swap = swap
        self.swapped = False

    def _is_victim(self, path: Any, dir_fd: Any) -> bool:
        if not isinstance(path, (str, bytes, os.PathLike)):
            return False
        spelled = os.fsdecode(path)
        base = fd_path(dir_fd) if dir_fd is not None else None
        full = os.path.join(base, spelled) if base is not None else spelled
        return full == self.victim

    def _swap(self) -> None:
        if self.swap and not self.swapped:
            os.unlink(self.victim)
            os.symlink(self.target, self.victim)
            self.swapped = True

    def stat(self, path: Any, *args: Any, **kwargs: Any) -> os.stat_result:
        st = os.stat(path, *args, **kwargs)
        if self._is_victim(path, kwargs.get("dir_fd")):
            self._swap()
        return st

    def open(self, path: Any, *args: Any, **kwargs: Any) -> int:
        if self._is_victim(path, kwargs.get("dir_fd")):
            self._swap()
        return os.open(path, *args, **kwargs)


@dataclasses.dataclass(frozen=True)
class Race:
    """One reader: the plain entry before the swap and the outside target after it, the call
    (given trees held over the swapping `os_`), its answer when the plain entry is read
    (`read_plain`), and its "refused" answer, which it must give once the entry is a link at
    read time."""

    id: str
    name: str
    plain: str
    target: str
    call: Callable[[Scene, DrainTrees], Any]
    read_plain: Callable[[tuple], bool]
    refused: Callable[[tuple], bool]
    prepare: Callable[[Scene], None] = lambda s: None


def _view(s: Scene, trees: DrainTrees):
    return trees.mount(s.skills_dir).view()


GOOD_SKILL_MD = CONTENT_CASES[0].good

RACES = [
    Race("frontmatter_id", TEMPLATE_NAME, plain_template("wazuh.probe"), marked_template(OUT_ID),
         lambda s, t: lead_author._frontmatter_id(
             s.repo, s.rel(TEMPLATE_NAME), tree_for=t.tree_for),
         read_plain=lambda got: got == ("returned", "wazuh.probe"),
         refused=lambda got: got == ("returned", None)),
    Race("read_at", TEMPLATE_NAME, plain_template("wazuh.probe"), marked_template(OUT_ID),
         lambda s, t: read_at(s.repo, t.tree_for, s.rel(TEMPLATE_NAME)),
         read_plain=lambda got: got == ("returned", (plain_template("wazuh.probe"), None)),
         refused=lambda got: got[0] == "returned" and got[1][0] is None),
    Race("readable_pair", REDUCER_NAME, REDUCER_TEXT, REDUCER_TEXT,
         lambda s, t: pitfalls_curator._readable_pair(
             s.repo, pitfalls_curator.REDUCER_REL, tree_for=t.tree_for),
         read_plain=lambda got: got == ("returned", (REDUCER_TEXT, REDUCER_TEXT)),
         refused=lambda got: raised(got, "LeadAuthorError", "unreadable"),
         prepare=_commit_reducer),
    Race("skills_content_rule_skill_md", SKILL_MD_NAME,
         "---\nname: defender-elastic\n---\n# elastic\n", GOOD_SKILL_MD,
         lambda s, t: lead_author._skills_content_rule(
             s.repo, resolver(s), "A ", s.rel(SKILL_MD_NAME), tree_for=t.tree_for),
         read_plain=lambda got: got == ("returned", None),
         refused=lambda got: raised(got, "LeadAuthorError", "could not be read")),
    Race("check_promoted_template", TEMPLATE_NAME, plain_template("wazuh.probe"),
         marked_template("wazuh.probe"),
         lambda s, t: lead_author._check_promoted_template(
             s.repo, resolver(s), s.rel(TEMPLATE_NAME), tree_for=t.tree_for),
         read_plain=lambda got: got == ("returned", None),
         refused=lambda got: raised(got, "LeadAuthorError", "not a readable query template")),
    Race("render_query", TEMPLATE_NAME, plain_template("wazuh.probe"),
         marked_template("wazuh.probe"),
         lambda s, t: lead_render.render_query(_view(s, t), TEMPLATE_NAME, {"index": "idx-7"}),
         read_plain=lambda got: got[0] == "returned" and "index: idx-7" in got[1],
         refused=lambda got: got[0] == "raised" and got[1] != "LeadAuthorError"),
    Race("check_system_skill_view", SKILL_MD_NAME,
         "---\nname: defender-elastic\n---\n# elastic\n", GOOD_SKILL_MD,
         lambda s, t: [f.code for f in check_system_skill(_view(s, t), "elastic", SKILL_MD_NAME)],
         read_plain=lambda got: got == ("returned", []),
         refused=lambda got: got == ("returned", ["skill-unreadable"])),
    Race("draft_contradicts_skill", SKILL_DRAFT_NAME,
         "---\nid: elastic.probe\nstatus: draft\ncontradicts_skill: true\n---\n# elastic\n",
         f"---\nid: elastic.probe\nstatus: draft\ncontradicts_skill: true\n---\n# {OUT_MARK}\n",
         lambda s, t: lead_author._draft_contradicts_skill(
             _view(s, t), s.at(SKILL_DRAFT_NAME), where=s.skills_dir),
         read_plain=lambda got: got == ("returned", True),
         refused=lambda got: got == ("returned", False)),
    Race("minted_identities", MINTED_NAME,
         plain_template("wazuh.0a1b2c3d4e5f", "draft", covers=["wazuh.0a1b2c3d4e5f"]),
         marked_template("wazuh.0a1b2c3d4e5f", "draft", covers=[OUT_ID]),
         lambda s, t: lead_author._minted_identities(
             _view(s, t), [s.at(MINTED_NAME)], where=s.skills_dir),
         read_plain=lambda got: got[0] == "returned" and list(got[1].values()) == [
             ("wazuh.0a1b2c3d4e5f",)],
         refused=lambda got: got == ("returned", {})),
]


@pytest.mark.parametrize("race", RACES, ids=lambda r: r.id)
def test_the_race_control_reads_the_plain_entry(scene: Scene, race: Race):
    """The control for the race: the same trees over the same `os_` stand-in, not swapping,
    read the plain entry, so the reader does go through the trees it is given."""
    race.prepare(scene)
    place(scene, race.name, race.plain, "plain")
    seam = SwapsAfterKind(scene.at(race.name), scene.outside / "unused", swap=False)

    with DrainTrees.open((scene.skills_dir,), os_=seam) as trees:
        got = outcome(lambda: race.call(scene, trees))

    assert race.read_plain(got), got


@pytest.mark.parametrize("race", RACES, ids=lambda r: r.id)
def test_an_entry_swapped_for_a_link_after_kind_answered_is_not_followed(
    scene: Scene, race: Race, caplog,
):
    """The entry is a plain file when `entry_kind` answers and a symlink to an outside
    file when it is read: the reader gives its "refused" answer (not the plain one, not the
    target's), the kernel saw no open and no read of the target, and the link is left.

    Catches: `entry_kind(view, name).kind == "file"` followed by `(root / name).read_text()`
    (or `read_text_soft`), which opens by a following spelling the name the listing vouched for."""
    race.prepare(scene)
    place(scene, race.name, race.plain, "plain")
    target = write(scene.outside / "race-target", race.target)
    seam = SwapsAfterKind(scene.at(race.name), target)
    caplog.clear()

    with DrainTrees.open((scene.skills_dir,), os_=seam) as trees, \
            kernel_watch(opens=[target]) as events:
        got = outcome(lambda: race.call(scene, trees))
        seen = events()

    assert seam.swapped, "the reader never asked the trees about the entry"
    assert seen == [], f"the swapped-in link's target was opened or read: {seen}"
    assert not race.read_plain(got), got
    assert race.refused(got), got
    assert OUT_MARK not in repr(got) + repr(logged(caplog)), (got, logged(caplog))
    assert os.readlink(scene.at(race.name)) == str(target), "the link was not left in place"


# ---------------------------------------------------------------------------------------
# H2 and H6: the catalog is loaded through the held view, never by a `Path` inside the mount
# ---------------------------------------------------------------------------------------

#: The folders above the catalog below the mount: a `Path` rooted at `skills_dir / folder`
#: opens both by their spelling.
CATALOG_SITES = [None, "gather", "gather/queries"]


def _moved(moved: Path, name: str, site: str) -> Path:
    return moved / PurePosixPath(name).relative_to(site)


@pytest.mark.parametrize("site", CATALOG_SITES)
def test_run_resolves_no_lead_through_a_linked_catalog(tmp_path: Path, site, caplog):
    """H2, through `lead_author.run(label=, deps=)`: an executed lead whose `query_id` only a
    template behind a link at `skills/gather` or `skills/gather/queries` answers. The run's
    catalog loads read nothing behind the link, so the lead resolves to no template, no handoff
    is built from the outside template, and the agent is never spawned.

    `site=None` is the control: the same template in the plain catalog resolves the lead, and
    the agent is handed it, rendered (the fake fails, rc 1, so the run stops at the spawn, rc 2).

    Catches: `_run_locked` (or the handoff) loading the catalog as `load_catalog(skills_dir /
    "gather/queries")` or `bind(catalog_dir)`."""
    repo = _worktree(tmp_path)
    run_dir = _run_dir(tmp_path)
    lead = _lead("wazuh.probe", system="wazuh", verb="noverb", params={"index": "idx-7"})
    spawn = LeadAuthorSpawn(rc=1)
    with scene_over(tmp_path, repo) as s:
        # Untracked, so only a catalog loader reaches it: the run's `git status` re-hashes a
        # TRACKED file behind a linked holding folder, which is git's read (N-a), not the lane's.
        write(s.at(TEMPLATE_NAME), marked_template("wazuh.probe"))
        template = s.at(TEMPLATE_NAME)
        if site is not None:
            template = _moved(plant_folder(s, site, "link"), TEMPLATE_NAME, site)
        caplog.clear()
        with kernel_watch(opens=[template]) as events:
            rc = lead_author.run(run_dir, label=LEAD, paths=s.paths,
                                 deps=_deps(s.paths, s.trees, spawn, [lead]))
            seen = events()

    if site is None:
        assert rc == 2, "the run did not reach the (failing) agent"
        assert [h["executed_template_path"] for h in spawn.handoffs] == [s.rel(TEMPLATE_NAME)]
        assert OUT_MARK in spawn.handoffs[0]["invocations"][0]["rendered_query"]
        return
    assert seen == [], "the template behind the link was opened or read"
    assert spawn.calls == [], "the agent was handed the template behind the link"
    assert rc == 0
    assert (run_dir / "lead_author" / "done").read_text().startswith("commit: none")
    assert OUT_MARK not in repr(logged(caplog))


@pytest.mark.parametrize("site", CATALOG_SITES)
def test_the_writer_loads_no_catalog_through_a_linked_folder(tmp_path: Path, site, caplog):
    """H6, `synthesize_drafts(catalog=None)`: the catalog behind a link at `skills/gather` or
    `skills/gather/queries` holds a template answering the wazuh lead. The writer's own load
    reads nothing behind the link, so the wazuh lead is still a draft candidate: its write is
    refused and logged, like the elastic one, and nothing outside the repo changes.

    `site=None` is the control: the answering template, read, suppresses the wazuh draft, and
    only the elastic one is written.

    Catches: the writer's fallback loading through a `Path` (`load_catalog(skills_dir /
    CATALOG_FOLDER)`), which reads the outside catalog and so drops the wazuh draft silently."""
    with scene_over(tmp_path, bare_skills(tmp_path)) as s:
        answering = "gather/queries/wazuh/hunt-creds.md"
        write(s.at(answering), query_template(WAZUH_LEAD.query_id, "established"))
        template = s.at(answering)
        if site is not None:
            template = _moved(plant_folder(s, site, "link"), answering, site)
        before = census(s.outside)
        (w_name, _), (e_name, _) = draft_of(WAZUH_LEAD), draft_of(ELASTIC_LEAD)

        with kernel_watch(opens=[template]) as events:
            created = mint(s, [WAZUH_LEAD, ELASTIC_LEAD])
            seen = events()

    said = [m for m in errors(caplog) if "synthesize_drafts: could not write" in m]
    if site is None:
        assert created == [s.skills_dir / e_name]
        assert not s.at(w_name).exists()
        assert said == []
        return
    assert seen == [], "the catalog behind the link was opened or read"
    assert created == []
    assert census(s.outside) == before
    for lead in (WAZUH_LEAD, ELASTIC_LEAD):
        name = draft_of(lead)[0]
        assert any(name in m and repr(lead.query_id) in m for m in said), (lead.query_id, said)


@pytest.mark.parametrize("site", CATALOG_SITES)
def test_build_handoff_loads_no_catalog_through_a_linked_folder(scene: Scene, site, caplog):
    """H6, `build_handoff(catalog=None, skills=, where=)`: the only template answering the lead
    lies behind a link at `skills/gather` or `skills/gather/queries`. It is not read, so the lead
    resolves to nothing and no handoff is built. `site=None` is the control: the plain template
    resolves the lead and is rendered."""
    place(scene, TEMPLATE_NAME, marked_template("wazuh.probe"), "plain")
    template = scene.at(TEMPLATE_NAME)
    if site is not None:
        template = _moved(plant_folder(scene, site, "link"), TEMPLATE_NAME, site)
    lead = _lead("wazuh.probe", system="wazuh", verb="noverb", params={"index": "idx-7"})
    caplog.clear()

    with kernel_watch(opens=[template]) as events:
        got = lead_author.build_handoff(
            scene.run_dir, [lead], [], repo_root=scene.repo, skills=scene.view,
            where=scene.skills_dir)
        seen = events()

    if site is None:
        assert [h["executed_template_path"] for h in got] == [scene.rel(TEMPLATE_NAME)]
        assert OUT_MARK in got[0]["invocations"][0]["rendered_query"]
        return
    assert seen == [], "the template behind the link was opened or read"
    assert got == []
    assert OUT_MARK not in repr(logged(caplog))


@pytest.mark.parametrize("site", CATALOG_SITES)
def test_collect_general_failures_loads_no_catalog_through_a_linked_folder(
        scene: Scene, site, caplog):
    """H6, `collect_general_failures(catalog=None, skills=, where=)`: the only template
    answering an agent-fixable row lies behind a link: not read, so the row is pitfalls residue.
    `site=None` is the control: the plain template answers it, so it is no pitfall."""
    place(scene, TEMPLATE_NAME, marked_template("wazuh.search"), "plain")
    template = scene.at(TEMPLATE_NAME)
    if site is not None:
        template = _moved(plant_folder(scene, site, "link"), TEMPLATE_NAME, site)
    row = _lead("wazuh.search", system="wazuh", verb="search", error_class="agent-fixable")

    with kernel_watch(opens=[template]) as events:
        got = collect_general_failures([row], scene.run_dir, skills=scene.view,
                                       where=scene.skills_dir)
        seen = events()

    if site is None:
        assert got == []
        return
    assert seen == []
    assert [r["query_id"] for r in got] == ["wazuh.search"]


# ---------------------------------------------------------------------------------------
# H4: a planted folder above an entry gives one verdict, whatever it points at
# ---------------------------------------------------------------------------------------

#: The plants at a folder: (a) a link to the real folder, moved outside, holding the entry (a
#: good one and a bad one where content decides), (b) a link to an empty outside folder, (c) a
#: dangling link, (d) a plain file.
PLANTS = ("a-good", "a-bad", "b-empty", "c-dangling", "d-file")

BAD_TEMPLATE = CONTENT_CASES[1].bad
BAD_SKILL_MD = CONTENT_CASES[0].bad


def _seed_departed(s: Scene, plant: str) -> None:
    place(s, MINTED_NAME, marked_template("wazuh.0a1b2c3d4e5f", "draft", covers=list(MINTED_IDS)),
          "plain")


def _seed_twin(s: Scene, plant: str) -> None:
    place(s, TEMPLATE_NAME, marked_template("wazuh.probe"), "plain")
    place(s, TWIN_NAME, marked_template("wazuh.probe", "draft"), "plain")


def _seed_template(s: Scene, plant: str) -> None:
    place(s, TEMPLATE_NAME, BAD_TEMPLATE if plant == "a-bad" else marked_template("wazuh.probe"),
          "plain")


def _seed_skill_md(s: Scene, plant: str) -> None:
    place(s, SKILL_MD_NAME, BAD_SKILL_MD if plant == "a-bad" else GOOD_SKILL_MD, "plain")


def _departed_verdict(s: Scene) -> tuple:
    minted = {s.at(MINTED_NAME): MINTED_IDS}
    return (
        lead_author._departed_drafts(s.repo, minted, [], tree_for=s.tree_for),
        outcome(lambda: lead_author._covers_rule(s.repo, minted, [], tree_for=s.tree_for)),
    )


def _half_promote(got: tuple) -> bool:
    return raised(got, "LeadAuthorError", "half-promote")


@dataclasses.dataclass(frozen=True)
class FolderGate:
    """A gate that asks "is there an entry at `entry`", its folder plant `site`, how to seed
    the entries before planting, the verdict, and the verdict the honest gate gives for every
    plant (a no-follow probe sees "other" at the folder, whatever it points at)."""

    id: str
    site: str
    entry: str
    seed: Callable[[Scene, str], None]
    verdict: Callable[[Scene], tuple]
    expect: Callable[[tuple], bool]


FOLDER_GATES = [
    # A minted draft is departed only when nothing stands at its name; a planted folder above
    # it is something, left for the scrub.
    FolderGate("departed@_draft", "gather/queries/wazuh/_draft", MINTED_NAME, _seed_departed,
               _departed_verdict, lambda got: got == ([], ("returned", None))),
    FolderGate("departed@sys", "gather/queries/wazuh", MINTED_NAME, _seed_departed,
               _departed_verdict, lambda got: got == ([], ("returned", None))),
    # The twin probe: anything but "absent" at the twin is a half-promote.
    FolderGate("twin@_draft", "gather/queries/wazuh/_draft", TWIN_NAME, _seed_twin,
               lambda s: content_verdict(s, TEMPLATE_NAME), _half_promote),
    FolderGate("twin@sys", "gather/queries/wazuh", TWIN_NAME, _seed_twin,
               lambda s: content_verdict(s, TEMPLATE_NAME), _half_promote),
    # The template gate lies behind the twin probe, which sees the planted `<sys>` folder first.
    FolderGate("template@sys", "gather/queries/wazuh", TEMPLATE_NAME, _seed_template,
               lambda s: content_verdict(s, TEMPLATE_NAME), _half_promote),
    # The SKILL.md gate reads whatever stands at the name unless it is absent or a folder;
    # through a planted `<sys>` that read refuses, so the SKILL.md is refused unread.
    FolderGate("skill_md@sys", "elastic", SKILL_MD_NAME, _seed_skill_md,
               lambda s: content_verdict(s, SKILL_MD_NAME),
               lambda got: raised(got, "LeadAuthorError", "could not be read")),
]


def _plant(s: Scene, site: str, plant: str) -> Path | None:
    """Replace the folder at `site` by `plant`; the moved folder is returned for (a) and (d)."""
    if plant.startswith("a-"):
        return plant_folder(s, site, "link")
    if plant == "d-file":
        return plant_folder(s, site, "file")
    clear(s.at(site))
    if plant == "b-empty":
        empty = s.outside / "empty-folder"
        empty.mkdir()
        s.at(site).symlink_to(empty, target_is_directory=True)
    else:
        s.at(site).symlink_to(s.outside / "no-such-folder", target_is_directory=True)
    return None


@pytest.mark.parametrize("gate", FOLDER_GATES, ids=lambda g: g.id)
def test_a_planted_folder_gives_one_verdict_whatever_it_points_at(
    tmp_path: Path, gate: FolderGate, caplog,
):
    """The folder above the gate's entry replaced by a link to the real folder (holding a good
    or a bad entry), to an empty folder, to nothing, or by a plain file: the verdict is the same
    for all four links (whatever they point at), each of the five is the no-follow gate's,
    nothing behind the plant is opened or read, and the plant is left. (The plain file may
    differ from the links in the refusal's wording only: the SKILL.md gate's read says `Not a
    directory` there.)

    Catches: `os.path.lexists(repo_root / path)` / `(repo_root / path).is_file()`, which do not
    follow a link at the leaf but do follow every folder above it, so the verdict tracks the
    target: "present" for (a), "departed" / "no twin" / "no SKILL.md" for (b) and (c)."""
    verdicts: dict[str, str] = {}
    for plant in PLANTS:
        with scene_over(tmp_path / plant, seed_skills_repo(tmp_path / plant / "repo")) as s:
            gate.seed(s, plant)
            moved = _plant(s, gate.site, plant)
            before = plant_state(s.at(gate.site))
            watched = [moved, _moved(moved, gate.entry, gate.site)] if moved is not None else []
            caplog.clear()

            with kernel_watch(opens=watched) as events:
                got = gate.verdict(s)
                seen = events()

            assert seen == [], (plant, "the entry behind the planted folder was opened or read")
            assert gate.expect(got), (plant, got)
            assert OUT_MARK not in repr(got) + repr(logged(caplog)), (plant, got)
            assert plant_state(s.at(gate.site)) == before, (plant, "the plant was not left")
            verdicts[plant] = repr(got)

    links = {plant: v for plant, v in verdicts.items() if plant != "d-file"}
    assert len(set(links.values())) == 1, verdicts


# ---------------------------------------------------------------------------------------
# H5: every check reads through the `tree_for` it is handed, never one of its own
# ---------------------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class Follow:
    """A check whose answer differs between the lane's tree and a copy of it: `seed` sets the
    lane's tree up, `diverge` then changes the copy; `lane` is the answer through the lane's
    `tree_for`, `copy` the answer through a `tree_for` that maps `skills/` to the copy."""

    id: str
    seed: Callable[[Scene], None]
    diverge: Callable[[Path], None]
    call: Callable[[Scene, Callable], Any]
    lane: Callable[[tuple], bool]
    copy: Callable[[tuple], bool]


def _put(root: Path, name: str, text: str) -> None:
    clear(root / name)
    write(root / name, text)


def _minted(s: Scene) -> dict:
    return {s.at(MINTED_NAME): MINTED_IDS}


def _seed_reducer_edit(s: Scene) -> None:
    """The reducer surface committed, then one pitfall appended under its `## Common
    pitfalls` in the lane's tree: an edit the content rule accepts, which git status lists."""
    _commit_reducer(s)
    write(s.at(REDUCER_NAME), REDUCER_TEXT + "- one more pitfall\n")


def _rewrite_reducer_frontmatter(copy: Path) -> None:
    _put(copy, REDUCER_NAME, REDUCER_TEXT.replace("name: defender-sql", "name: rewritten"))


def _strays(s: Scene) -> list[str]:
    """The working copy's changes outside `skills/` as the call is made (the copy of the
    tree among them), the baseline a verifier is handed so that only `skills/` is judged."""
    return _author_shared.changes_outside(s.repo, SKILLS_REL)


FOLLOWS = [
    Follow("_frontmatter_id",
           lambda s: place(s, TEMPLATE_NAME, marked_template("wazuh.probe"), "plain"),
           lambda c: _put(c, TEMPLATE_NAME, marked_template(OUT_ID)),
           lambda s, tf: lead_author._frontmatter_id(s.repo, s.rel(TEMPLATE_NAME), tree_for=tf),
           lane=lambda got: got == ("returned", "wazuh.probe"),
           copy=lambda got: got == ("returned", OUT_ID)),
    Follow("_check_promoted_template",
           lambda s: place(s, TEMPLATE_NAME, marked_template("wazuh.probe"), "plain"),
           lambda c: _put(c, TEMPLATE_NAME, BAD_TEMPLATE),
           lambda s, tf: lead_author._check_promoted_template(
               s.repo, resolver(s), s.rel(TEMPLATE_NAME), tree_for=tf),
           lane=lambda got: got == ("returned", None),
           copy=lambda got: raised(got, "LeadAuthorError", CONTENT_CASES[1].bad_says)),
    Follow("_skills_content_rule_twin",
           lambda s: place(s, TEMPLATE_NAME, marked_template("wazuh.probe"), "plain"),
           lambda c: _put(c, TWIN_NAME, marked_template("wazuh.probe", "draft")),
           lambda s, tf: lead_author._skills_content_rule(
               s.repo, resolver(s), "A ", s.rel(TEMPLATE_NAME), tree_for=tf),
           lane=lambda got: got == ("returned", None),
           copy=_half_promote),
    Follow("_skills_content_rule_skill_md",
           lambda s: place(s, SKILL_MD_NAME, GOOD_SKILL_MD, "plain"),
           lambda c: _put(c, SKILL_MD_NAME, BAD_SKILL_MD),
           lambda s, tf: lead_author._skills_content_rule(
               s.repo, resolver(s), "A ", s.rel(SKILL_MD_NAME), tree_for=tf),
           lane=lambda got: got == ("returned", None),
           copy=lambda got: raised(got, "LeadAuthorError", CONTENT_CASES[0].bad_says)),
    Follow("_skills_path_rule",
           lambda s: place(s, TEMPLATE_NAME, marked_template("wazuh.probe"), "plain"),
           lambda c: _put(c, TEMPLATE_NAME, marked_template(f"elastic.{OUT_MARK}")),
           lambda s, tf: lead_author._skills_path_rule(
               s.repo, "A ", s.rel(TEMPLATE_NAME), systems=DECLARED, tree_for=tf),
           lane=lambda got: got == ("returned", None),
           copy=lambda got: raised(got, "LeadAuthorError", "disagreeing with its directory")),
    Follow("_answered_after_batch",
           lambda s: None,
           lambda c: _put(c, TEMPLATE_NAME, marked_template(OUT_ID)),
           lambda s, tf: lead_author._answered_after_batch(s.repo, tree_for=tf),
           lane=lambda got: got[0] == "returned" and OUT_ID not in got[1],
           copy=lambda got: got[0] == "returned" and OUT_ID in got[1]),
    Follow("_refuse_half_promote",
           lambda s: None,
           lambda c: _put(c, DRAFT_NAME, marked_template("wazuh.probe", "draft", covers=[OUT_ID])),
           lambda s, tf: lead_author._refuse_half_promote(s.repo, {OUT_ID}, tree_for=tf),
           lane=lambda got: got == ("returned", None),
           copy=_half_promote),
    Follow("_departed_drafts",
           lambda s: _seed_departed(s, "plain"),
           lambda c: (c / MINTED_NAME).unlink(),
           lambda s, tf: lead_author._departed_drafts(s.repo, _minted(s), [], tree_for=tf),
           lane=lambda got: got == ("returned", []),
           copy=lambda got: got[0] == "returned" and [p for p, _ in got[1]] == [
               f"{SKILLS_REL}{MINTED_NAME}"]),
    Follow("_covers_rule",
           lambda s: _seed_departed(s, "plain"),
           lambda c: (c / MINTED_NAME).unlink(),
           lambda s, tf: lead_author._covers_rule(s.repo, _minted(s), [], tree_for=tf),
           lane=lambda got: got == ("returned", None),
           copy=lambda got: raised(got, "LeadAuthorError", "without attributing")),
    Follow("_readable_pair",
           _commit_reducer,
           _rewrite_reducer_frontmatter,
           lambda s, tf: pitfalls_curator._readable_pair(
               s.repo, pitfalls_curator.REDUCER_REL, tree_for=tf),
           lane=lambda got: got == ("returned", (REDUCER_TEXT, REDUCER_TEXT)),
           copy=lambda got: raised(got, "LeadAuthorError", "frontmatter")),
    # The four composites (the per-path gates and the whole-tree verifiers over git status):
    # each must hand its parts the `tree_for` it was given (adversary E1).
    Follow("_skills_rule",
           lambda s: place(s, TEMPLATE_NAME, marked_template("wazuh.probe"), "plain"),
           lambda c: _put(c, TEMPLATE_NAME, BAD_TEMPLATE),
           lambda s, tf: lead_author._skills_rule(
               s.repo, resolver(s), "??", s.rel(TEMPLATE_NAME), systems=DECLARED, tree_for=tf),
           lane=lambda got: got == ("returned", None),
           copy=lambda got: raised(got, "LeadAuthorError", CONTENT_CASES[1].bad_says)),
    Follow("_verify_skills_state",
           lambda s: place(s, TEMPLATE_NAME, marked_template("wazuh.probe"), "plain"),
           lambda c: _put(c, TEMPLATE_NAME, BAD_TEMPLATE),
           lambda s, tf: lead_author._verify_skills_state(
               s.repo, _strays(s), systems=DECLARED, tree_for=tf),
           lane=lambda got: got[0] == "returned" and got[1] == [f"{SKILLS_REL}{TEMPLATE_NAME}"],
           copy=lambda got: raised(got, "LeadAuthorError", CONTENT_CASES[1].bad_says)),
    Follow("_pitfalls_rule",
           _seed_reducer_edit,
           _rewrite_reducer_frontmatter,
           lambda s, tf: pitfalls_curator._pitfalls_rule(
               s.repo, " M", pitfalls_curator.REDUCER_REL, systems=DECLARED,
               reducer_offered=True, tree_for=tf),
           lane=lambda got: got == ("returned", None),
           copy=lambda got: raised(got, "LeadAuthorError", "frontmatter")),
    Follow("_verify_pitfalls_state",
           _seed_reducer_edit,
           _rewrite_reducer_frontmatter,
           lambda s, tf: pitfalls_curator._verify_pitfalls_state(
               s.repo, _strays(s), systems=DECLARED, reducer_offered=True, tree_for=tf),
           lane=lambda got: got == ("returned", [pitfalls_curator.REDUCER_REL]),
           copy=lambda got: raised(got, "LeadAuthorError", "frontmatter")),
]


@pytest.mark.parametrize("follow", FOLLOWS, ids=lambda f: f.id)
def test_every_check_reads_through_the_tree_for_it_is_handed(scene: Scene, follow: Follow):
    """The lane's tree and a copy of it that differs at one entry: through the lane's
    `tree_for` the check gives the lane's answer; through a spy `tree_for` that places every
    `skills/` path in the copy's held mount it gives the copy's, and it asked that spy.

    Catches: a check that takes `tree_for` and discards it for a lookup it builds itself (a
    fresh `open_drain_trees(LoopPaths(repo_root=...), ...)`), or that probes the plain
    `repo_root / path` beside it."""
    follow.seed(scene)
    # Inside the repo, as every mount is: the refusals spell their paths repo-relative.
    copy = scene.repo / "defender" / "skills-copy"
    shutil.copytree(scene.skills_dir, copy, symlinks=True)
    follow.diverge(copy)
    asked: list[Path | str] = []
    with DrainTrees.open((copy,)) as copies:
        held_copy = copies.mount(copy)

        def spy(path: Path | str):
            asked.append(path)
            try:
                rel = Path(path).relative_to(scene.skills_dir)
            except ValueError:
                return None
            return held_copy, rel.as_posix() or "."

        lane = outcome(lambda: follow.call(scene, scene.tree_for))
        via_copy = outcome(lambda: follow.call(scene, spy))

    assert follow.lane(lane), lane
    assert follow.copy(via_copy), via_copy
    assert asked, "the check never asked the tree_for it was handed"


# ---------------------------------------------------------------------------------------
# H7 and H8: the lane binds its own label into both default seams; the CLI runs under it
# ---------------------------------------------------------------------------------------
#
# Source checks, because no hermetic drive tells these apart: the drain's pitfalls seam reads
# its label only at its open (a wrong one fails the curation, logged), and the CLI takes the
# checkout's own queue lock and resolves the real repo's systems. The honest drive of the
# default seams is `test_the_drain_default_seams_carry_the_label_and_write_nothing_outside_skills`.


#: Where the lead drain's label is bound: every spelling of it must resolve here.
LEAD_ORIGIN = f"{CONFIG_MODULE}.LEAD_AUTHOR_DRAIN_LABEL"


def _tree(module: Any) -> ast.Module:
    return ast.parse(inspect.getsource(module))


def _function(tree: ast.Module, name: str) -> ast.FunctionDef:
    [fn] = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == name]
    return fn


def _callee(call: ast.Call) -> str | None:
    f = call.func
    return f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else None


def _label_kw(call: ast.Call) -> ast.expr | None:
    return next((k.value for k in call.keywords if k.arg == "label"), None)


def _named(value: ast.expr | None) -> str | None:
    """The name `value` spells: a bare name, or the attribute of a dotted one."""
    if isinstance(value, ast.Name):
        return value.id
    if isinstance(value, ast.Attribute):
        return value.attr
    return None


def test_the_lead_author_drain_binds_its_own_label_into_both_default_seams():
    """In `lead_author_drain`, the default `run_lead_author` and `run_pitfalls` are
    `partial(_invoke_lead_author, ..., label=LEAD_AUTHOR_DRAIN_LABEL)` and
    `partial(_invoke_pitfalls, ..., label=LEAD_AUTHOR_DRAIN_LABEL)`: the constant itself, by
    name, resolved through `_astlib` (the gates' scope-aware resolver) to `config`'s binding,
    never a local alias (the contract forbids one), never the curators' constant; and
    `AUTHOR_DRAIN_LABEL` is not named in the function at all. (That nothing in `drains` binds
    the name again is step 3's pin.)

    Catches: `partial(_invoke_pitfalls, ..., label=AUTHOR_DRAIN_LABEL)`, a local
    `LEAD_AUTHOR_DRAIN_LABEL = ...` in the lane, and a seam left without its label (each
    `_invoke_*` requires it, so that one is a `TypeError` per claim)."""
    astlib = import_lint_lib("_astlib")
    tree = _tree(drains)
    env = astlib.module_env(tree)
    fn = _function(tree, "lead_author_drain")
    bound: dict[str, list[ast.expr | None]] = {}
    for call in (n for n in ast.walk(fn) if isinstance(n, ast.Call)):
        if _callee(call) == "partial" and call.args:
            target = _named(call.args[0])
            if target in ("_invoke_lead_author", "_invoke_pitfalls"):
                bound.setdefault(target, []).append(_label_kw(call))

    assert sorted(bound) == ["_invoke_lead_author", "_invoke_pitfalls"], bound
    for target, values in bound.items():
        assert [_named(v) for v in values] == ["LEAD_AUTHOR_DRAIN_LABEL"], (
            target, [ast.dump(v) if v else v for v in values])
        assert [astlib.origin(v, env) for v in values] == [LEAD_ORIGIN], target
    assert not [n for n in ast.walk(fn)
                if isinstance(n, ast.Name) and n.id == "AUTHOR_DRAIN_LABEL"], \
        "lead_author_drain names the curators' label"


def test_the_cli_runs_under_the_lead_label():
    """H7, structurally: `lead_author.main` calls `run(..., label=...)` with a label that
    resolves, through `_astlib` (the gates' scope-aware resolver), to `config`'s
    `LEAD_AUTHOR_DRAIN_LABEL` (`_loop_config.LEAD_AUTHOR_DRAIN_LABEL`); and nothing in
    `lead_author/__init__.py` binds that name again: no local, parameter or module-level
    assignment, and no import of it from elsewhere, in any scope.

    Catches: a local alias in `main` named like the constant
    (`LEAD_AUTHOR_DRAIN_LABEL = _loop_config.AUTHOR_DRAIN_LABEL`; the resolver answers `None`
    for a local), and any other spelling of the label at the call.

    Not driven: `main` takes the queue lock at `DEFAULT_PATHS` (this checkout's own state dir)
    and resolves the real repo's systems; a hermetic seam for either would be invented for this
    test."""
    astlib = import_lint_lib("_astlib")
    tree = _tree(lead_author)
    env = astlib.module_env(tree)
    fn = _function(tree, "main")
    runs = [n for n in ast.walk(fn) if isinstance(n, ast.Call) and _callee(n) == "run"]
    assert len(runs) == 1, [ast.dump(r) for r in runs]
    value = _label_kw(runs[0])
    assert value is not None, ast.dump(runs[0])
    assert astlib.origin(value, env) == LEAD_ORIGIN, ast.unparse(value)
    assert _rebindings(tree, "LEAD_AUTHOR_DRAIN_LABEL") == []
    assert _foreign_imports(env, "LEAD_AUTHOR_DRAIN_LABEL", LEAD_ORIGIN) == []


# ---------------------------------------------------------------------------------------
# The listing consumers: refused and gone folders, a refused top, and links at a system,
# `_draft` or draft
# ---------------------------------------------------------------------------------------

DENIED = os.strerror(errno.EACCES)
SKILL_SYSTEMS = frozenset({"elastic", "wazuh"})


def _warnings(caplog) -> list[str]:
    return [r.getMessage() for r in caplog.records
            if r.levelno >= logging.WARNING and r.name.startswith("defender")]


@pytest.fixture
def skills(tmp_path: Path) -> Path:
    """A `skills/` tree: two declared systems with a pending draft each, an undeclared `ghost`
    with one, and a declared system's `_draft` README (never a draft)."""
    root = tmp_path / "repo" / "defender" / "skills"
    write(root / "elastic" / "_draft" / "a.md", "---\nname: a\n---\nelastic draft\n")
    write(root / "elastic" / "_draft" / "README.md", "# surface declaration\n")
    write(root / "wazuh" / "_draft" / "b.md", "---\nname: b\n---\nwazuh draft\n")
    write(root / "ghost" / "_draft" / "c.md", "---\nname: c\n---\nundeclared\n")
    return root


def _discover(skills: Path, os_: Any | None = None) -> list[Path]:
    with DrainTrees.open((skills,), **({"os_": os_} if os_ is not None else {})) as trees:
        return lead_author.discover_system_drafts(
            skills=trees.mount(skills).view(), where=skills, systems=SKILL_SYSTEMS)


GHOST = "discover_system_drafts: skipped undeclared directory 'ghost'"


def test_discover_control_lists_every_declared_system(skills: Path, caplog):
    """The control: every declared system's drafts, in listing (path-parts) order, spelled `where / name`; the
    README is not a draft; the undeclared directory is warned once."""
    assert _discover(skills) == [skills / "elastic/_draft/a.md", skills / "wazuh/_draft/b.md"]
    assert _warnings(caplog) == [GHOST]


@pytest.mark.parametrize("route", REFUSAL_ROUTES)
@pytest.mark.parametrize("deny", ["wazuh", "wazuh/_draft"])
def test_discover_skips_only_the_unlistable_system(skills: Path, deny: str, route: str, caplog):
    """A declared `<sys>` or `<sys>/_draft` whose own listing is refused (in `list_tree`'s
    `refused`; EACCES on any of the three routes listing a folder takes): ONE
    `warn: skipping <where>/<name> (Permission denied)`, the listing's reason verbatim, and every
    other system is still read."""
    refuser = RefusesFolder(skills / deny, route, errno.EACCES)
    assert _discover(skills, refuser) == [skills / "elastic/_draft/a.md"]
    assert refuser.refused > 0
    assert _warnings(caplog) == [GHOST, f"warn: skipping {skills / deny} ({DENIED})"]


@pytest.mark.parametrize("route", REFUSAL_ROUTES)
def test_discover_keeps_the_undeclared_warning_for_an_unlistable_undeclared_folder(
        skills: Path, route: str, caplog):
    """An unlistable UNDECLARED top-level folder keeps its "skipped undeclared directory"
    warning (and nothing else); every declared system is read."""
    refuser = RefusesFolder(skills / "ghost", route, errno.EACCES)
    assert _discover(skills, refuser) == [skills / "elastic/_draft/a.md",
                                          skills / "wazuh/_draft/b.md"]
    assert _warnings(caplog) == [GHOST]


@pytest.mark.parametrize("route", ["reopen", "scandir"])
def test_a_refused_listing_warns_once_and_discovers_nothing(skills: Path, route: str, caplog):
    """The listing of the mount itself refused (an EIO listing `skills/`): ONE
    `warn: skipping <where> (<the listing's reason>)` and no drafts at all."""
    refuser = RefusesFolder(skills, route, errno.EIO)
    with DrainTrees.open((skills,), os_=refuser) as trees:
        reason = list_tree(trees.mount(skills).view(), depth=3).reason
    assert reason == os.strerror(errno.EIO), "precondition: this fault refuses the listing"
    assert _discover(skills, RefusesFolder(skills, route, errno.EIO)) == []
    assert _warnings(caplog) == [f"warn: skipping {skills} ({reason})"]


#: Each folder below the mount is listed on its own (#1134 addendum 2, B2): a fault there costs
#: that folder, never the whole listing (v2's walk refused everything on an EIO below the top).
@pytest.mark.parametrize("route", REFUSAL_ROUTES)
@pytest.mark.parametrize("err", [errno.EIO, errno.EACCES], ids=["EIO", "EACCES"])
@pytest.mark.parametrize("deny", ["elastic", "elastic/_draft"])
def test_a_fault_below_the_mount_costs_only_that_system(
        skills: Path, deny: str, err: int, route: str, caplog):
    """An EIO (or EACCES) listing a declared `<sys>` or its `_draft`: ONE
    `warn: skipping <where>/<name> (<strerror>)` with the listing's reason verbatim, and every
    other system is still discovered."""
    refuser = RefusesFolder(skills / deny, route, err)
    assert _discover(skills, refuser) == [skills / "wazuh/_draft/b.md"]
    assert refuser.refused > 0
    assert _warnings(caplog) == [f"warn: skipping {skills / deny} ({os.strerror(err)})", GHOST]


@pytest.mark.parametrize("route", ["step", "reopen"])
@pytest.mark.parametrize("gone", ["wazuh", "wazuh/_draft", "ghost"])
def test_a_folder_found_gone_by_its_own_listing_is_passed_over_silently(
        skills: Path, gone: str, route: str, caplog):
    """A folder its parent listed as a directory and found missing by its own listing (ENOENT:
    the listing's `gone`): passed over in silence, as a missing folder always was; every other
    system is discovered, and an undeclared `ghost` keeps only its undeclared warning."""
    refuser = RefusesFolder(skills / gone, route, errno.ENOENT)
    a, b = skills / "elastic/_draft/a.md", skills / DRAFT_B
    assert _discover(skills, refuser) == ([a, b] if gone == "ghost" else [a])
    assert refuser.refused > 0
    assert _warnings(caplog) == [GHOST]


#: What a plant left at a swapped folder's name makes of that folder's own listing: refused
#: with `_step`'s reason (a link: the alias refusal; a file or FIFO: ENOTDIR), or None: gone.
SWAPPED_REASON = {"symlink": ALIAS_READ_REFUSAL, "file": os.strerror(errno.ENOTDIR),
                  "fifo": os.strerror(errno.ENOTDIR), "nothing": None}


@pytest.mark.parametrize("plant", SWAP_PLANTS)
@pytest.mark.parametrize("site", ["wazuh", "wazuh/_draft"])
def test_a_folder_swapped_between_listings_is_refused_or_gone_and_never_listed_through(
        skills: Path, site: str, plant: str, caplog):
    """`skills/`'s listing shows `site` as a real directory; the moment `site`'s own listing
    steps into it, the folder is REALLY moved outside and a symlink to it, a file, a FIFO or
    nothing is left at its name. Refused (link, file, FIFO): ONE `warn: skipping
    <where>/<site> (<the listing's reason>)`; gone: silent. Either way its draft is not
    discovered, the other system's is, and nothing in the moved folder is opened."""
    at = skills / site
    away = skills.parents[2] / f"away-{site.replace('/', '-')}"
    watched = [Path(d) for d, _dirs, _files in os.walk(at)]
    seam = SwapsOnStep(at.parent, at.name, away=away, plant=plant)
    with kernel_watch(opens=watched) as events:
        got = in_time(lambda: _discover(skills, seam), fifo=at if plant == "fifo" else None)
        seen = events()
    assert seam.fired, "the folder was never stepped into, so the row is void"
    assert seen == [], seen
    assert got == [skills / "elastic/_draft/a.md"]
    reason = SWAPPED_REASON[plant]
    warned = _warnings(caplog)
    assert warned == [GHOST] + ([] if reason is None else [f"warn: skipping {at} ({reason})"])


def test_an_absent_skills_folder_discovers_nothing_silently(tmp_path: Path, caplog):
    """A view whose folder is absent: `[]`, no warning."""
    root = tmp_path / "repo" / "defender" / "skills"
    root.mkdir(parents=True)
    with DrainTrees.open((root,)) as trees:
        got = lead_author.discover_system_drafts(
            skills=trees.mount(root).view().under("nothing-here"), where=root / "nothing-here",
            systems=SKILL_SYSTEMS)
    assert got == []
    assert _warnings(caplog) == []


DRAFT_B = "wazuh/_draft/b.md"


@pytest.mark.parametrize("site", ["wazuh", "wazuh/_draft", DRAFT_B, "ghost"])
@pytest.mark.parametrize("kind", ["link", "fifo", "file"])
def test_discover_never_enters_or_returns_a_non_plain_entry(
        skills: Path, site: str, kind: str, caplog):
    """A symlink (to where the real entry now lies, outside), a FIFO or a plain file at a
    declared `<sys>`, its `_draft`, a draft's name, or the undeclared top-level folder: never
    entered or returned, and nothing behind the link opened. Every other system is still read.
    The undeclared warning is for a directory, so a non-directory at `ghost` earns none. A plain
    file at the draft's own name is the plain draft: `file` at `b.md` is the control."""
    at = skills / site
    outside = skills.parents[2] / "outside"
    outside.mkdir(exist_ok=True)
    moved = outside / f"moved-{site.replace('/', '-')}"
    shutil.move(at, moved)
    if kind == "link":
        at.symlink_to(moved, target_is_directory=moved.is_dir())
    elif kind == "fifo":
        os.mkfifo(at)
    else:
        write(at, "---\nname: x\n---\na plain file\n")

    with kernel_watch(opens=[moved]) as events:
        got = in_time(lambda: _discover(skills), fifo=at if kind == "fifo" else None)
        seen = events()

    assert seen == [], seen
    a, b = skills / "elastic/_draft/a.md", skills / DRAFT_B
    assert got == ([a, b] if site == "ghost" or (site == DRAFT_B and kind == "file") else [a])
    assert _warnings(caplog) == ([] if site == "ghost" else [GHOST])


def _catalog_repo(tmp_path: Path) -> Path:
    """A stranded draft under `elastic` whose identity was taken over this batch, and another
    system (`wazuh`) holding a draft too."""
    repo = tmp_path / "repo"
    catalog = repo / CATALOG_REL
    write(catalog / "elastic" / "_draft" / "d1.md",
          query_template("elastic.d1", "draft", covers=["elastic.taken"]))
    write(catalog / "wazuh" / "_draft" / "d2.md",
          query_template("wazuh.d2", "draft", covers=["wazuh.taken"]))
    return repo


def _half_promote_under(repo: Path, taken: set[str], os_: Any | None = None) -> tuple:
    skills = repo / "defender" / "skills"
    with DrainTrees.open((skills,), **({"os_": os_} if os_ is not None else {})) as trees:
        return outcome(lambda: lead_author._refuse_half_promote(repo, taken,
                                                                tree_for=trees.tree_for))


@pytest.mark.parametrize("route", REFUSAL_ROUTES)
def test_half_promote_still_refuses_under_another_system_when_one_is_unlistable(
        tmp_path: Path, route: str, caplog):
    """`_refuse_half_promote`'s catalog listing (the step-4 selection): an unlistable `wazuh` is
    warned once and skipped; the stranded draft under `elastic` is still refused, named by its
    repo-relative path."""
    repo = _catalog_repo(tmp_path)
    refuser = RefusesFolder(repo / CATALOG_REL / "wazuh", route, errno.EACCES)
    got = _half_promote_under(repo, {"elastic.taken"}, refuser)
    assert raised(got, "LeadAuthorError",
                  "half-promote: draft defender/skills/gather/queries/elastic/_draft/d1.md"), got
    assert _warnings(caplog) == [f"warn: skipping {repo / CATALOG_REL / 'wazuh'} ({DENIED})"]


@pytest.mark.parametrize("route", REFUSAL_ROUTES)
def test_half_promote_under_the_unlistable_system_is_skipped_and_said(
        tmp_path: Path, route: str, caplog):
    repo = _catalog_repo(tmp_path)
    refuser = RefusesFolder(repo / CATALOG_REL / "wazuh", route, errno.EACCES)
    assert _half_promote_under(repo, {"wazuh.taken"}, refuser) == ("returned", None)
    assert _warnings(caplog) == [f"warn: skipping {repo / CATALOG_REL / 'wazuh'} ({DENIED})"]


def test_half_promote_control_reads_every_system(tmp_path: Path, caplog):
    repo = _catalog_repo(tmp_path)
    got = _half_promote_under(repo, {"wazuh.taken"})
    assert raised(got, "LeadAuthorError",
                  "half-promote: draft defender/skills/gather/queries/wazuh/_draft/d2.md"), got
    assert _warnings(caplog) == []


def test_half_promote_over_a_refused_catalog_walk_warns_once_and_refuses_nothing(
        tmp_path: Path, caplog):
    """The catalog folder itself refused (EIO reopening it): one warning naming the catalog,
    nothing refused (a refused folder reads as a missing one, O5.5)."""
    repo = _catalog_repo(tmp_path)
    refuser = RefusesFolder(repo / CATALOG_REL, "reopen", errno.EIO)
    assert _half_promote_under(repo, {"elastic.taken"}, refuser) == ("returned", None)
    said = _warnings(caplog)
    assert len(said) == 1, said
    assert said[0].startswith(f"warn: skipping {repo / CATALOG_REL} ("), said


def test_a_link_at_a_catalog_draft_is_passed_over_by_the_half_promote_walk(tmp_path, caplog):
    """A symlink at a catalog draft's name (to a draft outside recording the taken identity):
    selected by name, refused at read, passed over silently; nothing outside opened."""
    repo = _catalog_repo(tmp_path)
    outside = tmp_path / "outside"
    target = write(outside / "d3.md",
                   query_template("wazuh.d3", "draft", covers=["wazuh.outside-taken"]))
    (repo / CATALOG_REL / "wazuh/_draft/d3.md").symlink_to(target)
    with kernel_watch(opens=[target]) as events:
        got = _half_promote_under(repo, {"wazuh.outside-taken"})
        seen = events()
    assert seen == []
    assert got == ("returned", None)
    assert _warnings(caplog) == []
