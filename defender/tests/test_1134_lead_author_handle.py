"""#1134 step 6 (v3, addendum 2): the lead author and the pitfalls curator reach `skills/` only through the
drain's held mount, and the drain label that names that mount is consumed where the trees open.

The contract is the step-6 contract over #1134's design (D4 "Lead author" and "Pitfalls curator",
O3's catalog regression, O5.4, O5.5's draft-writer half, D7's rows for them), the 2026-10-01
addendum (A3: one `DrainTrees` per work-step seam call, opened inside the default seam with the
label bound in, closed when it returns or raises; A4: readers take a `Bound`, writers the `Held`)
and the owner decisions of 2026-09-29 (the label is required; functions that took
`catalog_dir` / `skills_dir` take the handle only, no `Path` form, no default). The shape it pins:

- `drains._invoke_lead_author(paths, run_dir, *, label, box, on_done)` and
  `drains._invoke_pitfalls(paths, *, label, box, on_curated, lock_wait_seconds)` require the label
  and open `open_drain_trees(paths, label)` AROUND the curator call. `lead_author.run(run_dir, *,
  label, ...)` requires it too. Below the open, the open `DrainTrees` flows:
  `run_under_held_queue_lock(..., trees)`, `run_pitfalls(*, paths, trees, ...)` and
  `build_lead_author_deps(paths, *, trees)` require it (`TypeError` without). The deps carry
  `skills` (the held mount, `trees.mount(paths.skills_dir)`) and `tree_for` (`trees.tree_for`).
- `synthesize_drafts(executed, *, skills: Held, where: Path, catalog=None, systems)` writes
  `gather/queries/<sys>/_draft/<hex>.md` through the `Held` (O5.4) and returns `where / name`.
- The readers take the mount's view and `where`: `collect_general_failures(..., skills=, where=,
  catalog=)`, `build_handoff(..., skills=, where=, catalog=)`, `discover_system_drafts(*, skills,
  where, systems)`, `_draft_contradicts_skill(skills, draft, *, where)`,
  `_minted_identities(skills, created, *, where)`, `render_query(source, name, params)`,
  `lead_neighbors.load_lane_catalog(skills, *, where)`, and `check_system_skill(source, system,
  name=None)` (a `Bound` with a name, or its unchanged `Path` form).
- Every post-agent rule (`_rules.py`, and the pitfalls curator's `_readable_pair` /
  `_pitfalls_content_rule` / `_pitfalls_rule` / `_verify_pitfalls_state`) takes a required
  `tree_for` and judges / reads through `lane_trees.kind_at` / `read_at` (a path inside the
  lane's mount through its handle; outside it, the plain path, D3).
- v3 (addendum 2): there is no `Bound.kind` / `Bound.walk`. Every "what stands here" goes on
  `_tree_listing.entry_kind` (one listing of the parent; a refused holding folder is a `reason`,
  which `kind_at` maps to `"other"`), and every listing on `_tree_listing.list_tree` with the
  tree's fixed depth. Neither raises: after the trees close they answer `Bad file descriptor`.

What the handle buys, per reader and rule (D7's guard plus positive control): an entry that is
not a plain file is never followed. The plants are real filesystem entries: a symlink at the
name to a file outside the repo carrying `OUT_MARK` (content a link-following reader would
accept, so following it changes the answer), a hard link at the name to such a file, and a
symlink or a plain file at each holding folder below `skills/` (the real folder moved outside).
Each guard asserts: the reader's "not read" answer; the kernel saw no read of the outside file
(and, for a symlink or a folder plant, no open of it either: `kernel_watch`, inotify, by any
route); the mark in neither the answer nor the log; the plant and everything outside unchanged.
Its positive control is the same bytes as a plain file at the same address: the "read" answer,
and the watch saw that read (it is not blind).

Sections: the reader/rule matrix; `_skills_content_rule`'s one verdict per link; `_departed_drafts`;
the draft writer (O3, O5.4, O5.5), through `synthesize_drafts`, `lead_author.run(label=, deps=)`,
`run_under_held_queue_lock(trees=)` and `drains.lead_author_drain` with its REAL default seams;
the existence-probe fault decision (an EACCES / EIO at a draft's holding folder refuses its
listing, the probe falls through to the write, which is refused and logged, and the claim goes
on); the trees' lifetime around each seam; and the label / trees plumbing.
`test_1134_lead_author_holes.py` carries the adversary-closing rows (v1's H1b-H8) and the
refused / gone folder handling of `discover_system_drafts` and the half-promote listing.

Faults that cannot be made for real as root (a refused listing, EACCES / EIO) go through the
`os_` seam of `DrainTrees.open` only; nothing is monkeypatched but the environment
(`monkeypatch.setenv("LEAD_AUTHOR_MODEL", ...)`, a tripwire that turns a reached agent spawn into
`FatalConfigError` instead of a model call). A FIFO plant runs under `in_time`'s deadline.

Red before step 6: the module imports names step 6 adds (`lane_trees.kind_at` / `read_at` /
`view_at`, `_lead_spine.lane_skills`, `lead_neighbors.load_lane_catalog`,
`path_validation.CATALOG_FOLDER`), so collection fails on the base.
"""
from __future__ import annotations

import dataclasses
import errno
import functools
import json
import logging
import os
import shutil
from collections.abc import Callable
from pathlib import Path, PurePosixPath
from typing import Any

import pytest

from defender import _git, _scaffold_rules
from defender._env import FatalConfigError
from defender._io import NotPlainEntry
from defender._tree_listing import entry_kind
from defender.learning.core import drains, markers
from defender.learning.core.config import AUTHOR_DRAIN_LABEL, LEAD_AUTHOR_DRAIN_LABEL, LoopPaths
from defender.learning.core.lane_trees import DrainTrees, kind_at, open_drain_trees, read_at, view_at
from defender.learning.leads import lead_author, lead_neighbors, lead_render, pitfalls_curator
from defender.learning.leads._lead_spine import lane_skills
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
from defender.learning.leads.path_validation import CATALOG_FOLDER, CATALOG_REL, SKILLS_REL
from defender.runtime.verbs import engine_for
from defender.tests._declared869 import LeadAuthorSpawn, head_files, seed_executed_query, seed_tree
from defender.tests._lead_author_1134 import (
    OUT_ID,
    OUT_MARK,
    Scene,
    ancestors,
    clear,
    errors,
    lead_trees,
    logged,
    opened,
    outcome,
    place,
    plant_folder,
    plant_state,
    raised,
    scene_over,
    write,
)
from defender.tests._repo import query_template, seed_skills_repo
from defender.tests._shared_readers_1134 import RefusesFolder, kernel_watch
from defender.tests._spec791 import (
    SpecBranch,
    author_markers,
    loop_paths,
    noop_scrub,
    noop_start_box,
    noop_stop_box,
)
from defender.tests._tree_listing_1134 import descriptors_under
from defender.tests.test_1111_rooted_io import census, in_time

LEAD = LEAD_AUTHOR_DRAIN_LABEL

#: `seed_skills_repo`'s declared systems (its two adapters).
DECLARED = frozenset({"elastic", "wazuh"})

#: The addresses the rows plant at, as names under the `skills/` mount.
TEMPLATE_NAME = "gather/queries/wazuh/probe.md"
DRAFT_NAME = "gather/queries/wazuh/_draft/probe.md"
MINTED_NAME = "gather/queries/wazuh/_draft/0a1b2c3d4e5f.md"
SKILL_DRAFT_NAME = "elastic/_draft/probe.md"
SKILL_MD_NAME = "elastic/SKILL.md"
REDUCER_NAME = "gather/defender-sql.md"
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
    outside it, and the lead drain's trees over it, open for the test."""
    with scene_over(tmp_path, seed_skills_repo(tmp_path / "repo")) as s:
        yield s


def resolver(s: Scene) -> _scaffold_rules.VerbResolver:
    return _scaffold_rules.VerbResolver(s.repo / "defender")


# ---------------------------------------------------------------------------------------
# The rows: every reader and rule step 6 moves onto the held mount
# ---------------------------------------------------------------------------------------


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
    """The reducer surface committed at HEAD with `REDUCER_TEXT`, so a working copy holding the
    same bytes is an unchanged document."""
    assert s.rel(REDUCER_NAME) == pitfalls_curator.REDUCER_REL
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
            s.repo, pitfalls_curator.REDUCER_REL, tree_for=s.tree_for),
        took=lambda s, got: got == ("returned", (REDUCER_TEXT, REDUCER_TEXT)),
        refused=lambda s, got: raised(got, "LeadAuthorError", "unreadable as a file"),
        hard=lambda s, got: raised(got, "LeadAuthorError", "unreadable as UTF-8 text"),
        prepare=_commit_reducer),
    Row("pitfalls_content_rule", REDUCER_NAME, REDUCER_TEXT,
        lambda s: pitfalls_curator._pitfalls_content_rule(
            s.repo, " M", pitfalls_curator.REDUCER_REL, tree_for=s.tree_for),
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
    # N-h: the `Path` form (`skills/connect/validate_scaffold.py`, unchanged) reads `path.name`
    # under `bind(path.parent)`, so a link AT the name is refused too. Its root is the path it
    # was given, followed by spelling, so no folder plant applies.
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
    """The positive control: the bytes every guard plants behind a link, as a plain file at the
    same address. The reader takes them (`took`), the rest of the tree is read as before, and
    the kernel watch saw the entry read (so the guards' empty watch is not a blind one)."""
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
    """A symlink at the name, to an outside file holding the control's bytes: the reader gives
    its "not read" answer, the kernel saw no open and no read of the target, none of it reaches
    the answer or the log, and the target and the link are as they were.

    Catches: any reader or rule still opening the name by a following spelling (`read_text`,
    `is_file()`, `exists()`), or a handle rooted below the mount."""
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
    """A hard link at the name to an outside file holding the control's bytes (H1). The kernel
    saw no read of the shared inode (by either name); the answer is the "not read" one (`hard`
    where an `entry_kind` gate calls the hard link a file, as it is one: the read then refuses it); no
    mark leaks; both names are left.

    Catches: a reader that asks `entry_kind` (which answers "file" for a hard link) and
    then opens the `Path`, instead of reading through the handle, which refuses it."""
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
    """The control's bytes at the same name, with one holding folder below the mount moved
    outside the repo and replaced by a symlink to it (`link`) or by a plain file (`file`): the
    reader neither descends the plant nor reaches the moved entry (no open, no read), gives its
    "not read" answer, leaks no mark, and leaves the plant.

    Catches: a reader rooted at a folder inside the mount (`catalog_dir`, a `bind` of
    `gather/queries`), which opens that folder by its spelling and so follows the link."""
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


# ---------------------------------------------------------------------------------------
# `_skills_content_rule`: its gates' answer on a link must not depend on the link's target
# ---------------------------------------------------------------------------------------
#
# The rule gates on "is there a file here" (the twin probe, the template and SKILL.md checks).
# A no-follow gate calls a link "other" whatever it points at, so the verdict cannot depend on
# the target: a good document, a bad one, or nothing. A follower's verdict does.


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
    """The control: plain good bytes pass, plain bad bytes are refused for what they say (the
    SKILL.md row through `check_system_skill`'s view form, the template row through
    `_check_promoted_template`)."""
    place(scene, case.name, case.good, "plain")
    assert content_verdict(scene, case.name) == ("returned", None)

    place(scene, case.name, case.bad, "plain")
    assert raised(content_verdict(scene, case.name), "LeadAuthorError", case.bad_says)


@pytest.mark.parametrize("case", CONTENT_CASES, ids=lambda c: c.id)
def test_the_content_rule_gives_a_link_one_verdict_whatever_it_points_at(scene: Scene, case):
    """A symlink at the name, to the good bytes, to the bad bytes, and to nothing: one verdict
    for all three, none naming what the bad bytes say, no target opened or read, the link left.

    Catches: a gate that follows (`is_file()`), whose verdict is pass / refuse / skip for the
    three, and a check that reads the target."""
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
    """`kind_at(twin) != "absent"` refuses: a live or dangling symlink, a folder, a FIFO or a
    hard link at the twin is a half-promote, the same verdict a plain twin gets; nothing is
    opened through it and the plant is left.

    Catches: the probe's `exists()`, which answers True for the live link and False for the
    dangling one (and would block on nothing, but a follower opening the FIFO would)."""
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


# ---------------------------------------------------------------------------------------
# `_departed_drafts`: departed means nothing at the name, not "not followable"
# ---------------------------------------------------------------------------------------

MINTED_IDS = ("wazuh.0a1b2c3d4e5f", OUT_ID)


@pytest.mark.parametrize(("state", "departed"), [
    ("plain", False), ("absent", True), ("link", False), ("dangling_link", False),
    ("hardlink", False),
])
def test_a_minted_draft_departs_only_when_nothing_stands_at_its_name(scene, state, departed):
    """`_departed_drafts` answers "departed" for a minted draft whose name holds nothing
    (`kind_at == "absent"`), and only then; `_covers_rule` refuses a departure nothing
    attributes. A link at the name (live or dangling) or a hard link is left for the scrub,
    not counted as a departure.

    Catches: `Path.exists()`, which follows: it calls a dangling link departed (the `absent`
    row is the positive control: the same identities, truly gone)."""
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


# ---------------------------------------------------------------------------------------
# The draft writer: rooted at the `skills/` mount (O5.4), never redirected outside it (O3),
# a refused write logged and the claim going on (O5.5)
# ---------------------------------------------------------------------------------------

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
    """The positive control for every writer row (O5.4): on a plain tree each lead's draft
    lands at `skills/gather/queries/<sys>/_draft/<hex>.md` with exactly `_draft_skeleton`'s
    bytes, `created` names exactly those, spelled `where / name` (`skills_dir / name`, today's
    spelling of the same file), and nothing else is written or logged."""
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


def test_a_draft_returns_the_path_where_spells_and_opens_nothing_by_it(tmp_path: Path):
    """`where` only spells: the drafts land below the HELD mount, and `created` is spelled
    `where / name` even when `where` names somewhere else entirely (never made, never opened).

    Catches: a writer that writes `where / name` by path, or derives the handle from `where`."""
    repo = bare_skills(tmp_path)
    skills_dir = repo / "defender" / "skills"
    elsewhere = tmp_path / "spelled-elsewhere"
    with opened(LoopPaths(repo_root=repo)) as trees:
        created = synthesize_drafts([ELASTIC_LEAD], skills=trees.mount(skills_dir),
                                    where=elsewhere, catalog=[], systems=SYSTEMS)
    name, text = draft_of(ELASTIC_LEAD)
    assert created == [elsewhere / name]
    assert (skills_dir / name).read_text(encoding="utf-8") == text
    assert not os.path.lexists(elsewhere), "where= was made or written through"


#: Every folder a draft's write passes below the mount. `gather` and `gather/queries` lie on
#: every system's path (O3: the old root, `catalog_dir`, was opened through them by spelling);
#: `wazuh` and `_draft` only on wazuh's (O5.4/O5.5: the other system's claim goes on).
WRITER_SITES = ("gather", "gather/queries", "gather/queries/wazuh", "gather/queries/wazuh/_draft")


@pytest.mark.parametrize("catalog", [None, []], ids=["catalog_none", "catalog_given"])
@pytest.mark.parametrize("kind", ["link", "file"])
@pytest.mark.parametrize("site", WRITER_SITES)
def test_a_planted_folder_on_the_drafts_path_refuses_the_write_and_the_claim_goes_on(
    bare: Scene, site: str, kind: str, catalog, caplog,
):
    """A folder on a draft's path moved outside the repo and replaced by a symlink to it, or
    by a plain file: no draft is written behind it, nothing outside the repo (or anywhere
    behind the link) changes or is opened, the refusal is logged at ERROR naming the draft and
    its query id, and the plant stays. A draft whose path does not cross the plant still lands,
    with its bytes (O5.5). With `catalog=None` the writer's own load reads through the same view.

    `site=gather/queries` and `site=gather` with `kind=link` are O3's regression: the old writer
    rooted at `catalog_dir` and so wrote the drafts into the link's target."""
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
    """The exists test and replace semantics at the draft's own name. A plain file, a hard link
    or a directory there is `kind` "file" / "dir": somebody's draft, skipped in silence, nothing
    opened. A symlink (live or dangling) or a FIFO is "other": it falls through to the write,
    which refuses it (`NotPlainEntry`): logged at ERROR, the target untouched, the plant left.
    Either way the name is not in `created`, and the other system's draft still lands.

    Catches: `exists()`, which follows and silently skips a live link (no log), and a write that
    replaces the link or writes through it."""
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


def test_a_refused_draft_write_raises_the_cores_not_plain_entry(bare: Scene):
    """The refusal the writer logs for a symlink at the draft's name is the core's own,
    exactly `NotPlainEntry` (so a writer that contained every OSError silently, or replaced the
    link, would not produce it): written through the same held mount the writer is handed."""
    w_name, w_text = draft_of(WAZUH_LEAD)
    bare.at(w_name).symlink_to(bare.outside / "no-such.md")
    with pytest.raises(OSError) as exc:  # noqa: PT011 — the exact type is asserted below
        bare.skills.write(w_name, w_text, mode="replace")
    assert type(exc.value) is NotPlainEntry
    assert bare.at(w_name).is_symlink()


# ---------------------------------------------------------------------------------------
# The existence-probe fault decision: an EACCES / EIO at a draft's holding folder refuses that
# folder's listing (`entry_kind`'s `reason`, never a raise); the probe falls through to the write,
# which is refused and logged, and the mint and the claim go on (today's `draft.exists()`
# re-raised it and unwound the claim)
# ---------------------------------------------------------------------------------------

#: The holding folders of the wazuh draft that only wazuh's path crosses.
WAZUH_FOLDERS = ("gather/queries/wazuh/_draft", "gather/queries/wazuh")


@pytest.mark.parametrize("err", [None, errno.EACCES, errno.EIO],
                         ids=["control", "EACCES", "EIO"])
@pytest.mark.parametrize("site", WAZUH_FOLDERS)
def test_a_kind_fault_at_a_drafts_holding_folder_is_logged_and_the_mint_goes_on(
        tmp_path: Path, site: str, err: int | None, caplog):
    """The trees held over an `os_` that refuses the open of one of the wazuh draft's holding
    folders with EACCES or EIO (as root, no permission bit can make that fault for real): the
    wazuh draft is not written, the fault is logged at ERROR naming the draft, its query id and
    the errno's words, and the elastic draft, minted after it in the same call, lands with its
    bytes. `control`: the same trees over the real `os` mint both.

    Catches: an existence test that unwinds the claim on one unreadable folder (today's
    `draft.exists()`), and one that reads a refused listing as "the draft is there" and skips
    in silence (the refusal is never logged)."""
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


def _run_dir(tmp_path: Path, *rows: tuple[str, str, str]) -> Path:
    """A run dir whose queries table holds `rows` (`(query_id, system, verb)`), in order,
    written through the production writer, one lead each."""
    run_dir = tmp_path / "runs" / "run-1"
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
        lead_author.build_lead_author_deps(paths, trees=trees),
        invoke_agent=spawn,
        extract=lambda _run_dir: ([], list(leads)),
        acquire_queue_lock=lambda: object(),
        release_queue_lock=lambda _fh: None,
    )


#: A model name no provider routes: an agent spawn the drive reaches raises `FatalConfigError`
#: at its key lookup instead of calling a model, so "reached the agent" is observable.
NO_MODEL = "no-such-model-1134"


@pytest.mark.parametrize("err", [None, errno.EACCES], ids=["control", "EACCES"])
def test_a_kind_fault_does_not_unwind_the_claim_through_run_under_held_queue_lock(
        tmp_path: Path, err: int | None, monkeypatch, caplog):
    """`run_under_held_queue_lock(trees=...)` with the trees held over an `os_` refusing the
    wazuh draft's `_draft` folder (EACCES): the run reads its real tables (a wazuh row, then an
    elastic row, both coined), logs the wazuh draft's fault, mints the elastic draft, and goes
    on to its agent: the spawn is reached (`FatalConfigError` from the unroutable model).
    `control`: over the real `os`, both drafts land and the agent is reached the same way."""
    monkeypatch.setenv("LEAD_AUTHOR_MODEL", NO_MODEL)
    repo = _worktree(tmp_path)
    paths = LoopPaths(repo_root=repo, state_dir=tmp_path / "state")
    run_dir = _run_dir(tmp_path, ("wazuh.hunt-creds", "wazuh", "esql"),
                       ("elastic.hunt-creds", "elastic", "esql"))
    site = paths.skills_dir / "gather/queries/wazuh/_draft"
    site.mkdir(parents=True, exist_ok=True)
    refuser = RefusesFolder(site, "step", err) if err is not None else None
    done: list[str | None] = []

    with DrainTrees.open((paths.skills_dir,), **({"os_": refuser} if refuser else {})) as trees, \
            pytest.raises(FatalConfigError, match=NO_MODEL):
        lead_author.run_under_held_queue_lock(run_dir, paths=paths, trees=trees,
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


def test_a_kind_fault_does_not_unwind_the_claim_through_run(tmp_path: Path, caplog):
    """`lead_author.run(label=, deps=)` with deps built under trees whose `os_` refuses the
    wazuh draft's `_draft` folder (EACCES): the elastic claim goes on to the agent, which is
    handed exactly the elastic draft's handoff (the fake fails, rc 1, so the run stops there,
    rc 2)."""
    repo = _worktree(tmp_path)
    paths = LoopPaths(repo_root=repo, state_dir=tmp_path / "state")
    run_dir = _run_dir(tmp_path)
    site = paths.skills_dir / "gather/queries/wazuh/_draft"
    site.mkdir(parents=True, exist_ok=True)
    refuser = RefusesFolder(site, "step", errno.EACCES)
    spawn = LeadAuthorSpawn(rc=1)

    with DrainTrees.open((paths.skills_dir,), os_=refuser) as trees:
        deps = _deps(paths, trees, spawn, [WAZUH_LEAD, ELASTIC_LEAD])
        rc = lead_author.run(run_dir, label=LEAD, paths=paths, deps=deps)

    assert rc == 2, "the run did not reach the (failing) agent"
    assert refuser.refused > 0
    e_name, e_text = draft_of(ELASTIC_LEAD)
    assert [h["executed_template_path"] for h in spawn.handoffs] == [f"{SKILLS_REL}{e_name}"]
    assert (paths.skills_dir / e_name).read_text(encoding="utf-8") == e_text
    assert len(said_for(caplog, WAZUH_LEAD, paths.skills_dir)) == 1, wrote_errors(caplog)


# ---------------------------------------------------------------------------------------
# Through the lead-author entry points: `run(label=, deps=)` and
# `run_under_held_queue_lock(trees=)` over a seeded worktree (O3, O5.4, O5.5)
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("site", [None, "gather", "gather/queries"])
def test_run_writes_no_draft_outside_skills_through_a_linked_catalog(
    tmp_path: Path, site: str | None, caplog,
):
    """O3 through `lead_author.run`. With `skills/gather` or `skills/gather/queries` replaced by
    a link to where the real folder now lies: both drafts are refused and logged, nothing outside
    the repo changes or is opened, the catalog reads as empty so no lead resolves, and the run is
    recorded done with no commit and no agent spawned.

    `site=None` is the control: both drafts land under `skills/` with their bytes, both are
    handed to the agent, and the commit carries them.

    No kernel watch on the moved folder here: the run's `git status` (its baseline) re-hashes
    the TRACKED files behind the link, which is git's read (N-a), not the lane's. The
    writer-level row above watches it with no git in the call."""
    repo = _worktree(tmp_path)
    paths = LoopPaths(repo_root=repo, state_dir=tmp_path / "state")
    run_dir = _run_dir(tmp_path)
    spawn = LeadAuthorSpawn()
    names = {lead.query_id: draft_of(lead) for lead in (WAZUH_LEAD, ELASTIC_LEAD)}
    with scene_over(tmp_path, repo) as s:
        if site is not None:
            plant_folder(s, site, "link")
        planted = plant_state(s.at(site)) if site is not None else None
        before = census(s.outside)
        deps = _deps(paths, s.trees, spawn, [WAZUH_LEAD, ELASTIC_LEAD])
        rc = lead_author.run(run_dir, label=LEAD, paths=paths, deps=deps)

    assert rc == 0
    if site is None:
        assert len(spawn.calls) == 1
        assert {h["executed_template_path"] for h in spawn.handoffs} == {
            f"{SKILLS_REL}{name}" for name, _ in names.values()}
        for name, text in names.values():
            assert (paths.skills_dir / name).read_text(encoding="utf-8") == text
        assert {f"{SKILLS_REL}{name}" for name, _ in names.values()} <= set(head_files(repo))
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
    """O5.5 through `lead_author.run`: `gather/queries/wazuh/_draft` is a plain file, or a link
    to an empty folder outside the repo. The wazuh draft is refused and logged; the elastic claim
    goes on: its draft lands with its bytes and is the one handoff the agent gets, with the plant
    still in place and nothing outside the repo changed.

    The agent fake fails (rc 1), so the run stops at the spawn (rc 2)."""
    repo = _worktree(tmp_path)
    paths = LoopPaths(repo_root=repo, state_dir=tmp_path / "state")
    run_dir = _run_dir(tmp_path)
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
        rc = lead_author.run(run_dir, label=LEAD, paths=paths,
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


@pytest.mark.parametrize("site", [None, "gather", "gather/queries"])
def test_run_under_held_queue_lock_writes_nothing_outside_skills_through_a_linked_catalog(
        tmp_path: Path, site: str | None, monkeypatch, caplog):
    """O3 through `run_under_held_queue_lock(trees=...)`, the drain's own entry, reading its
    real tables (one coined elastic row): with `skills/gather` or `skills/gather/queries` linked
    outside, the draft is refused and logged, nothing outside changes, no lead resolves, the
    agent is not reached and the run hands `on_done` no commit. `site=None` is the control: the
    draft lands with its frontmatter id and the run reaches its agent (`FatalConfigError` from
    the unroutable model)."""
    monkeypatch.setenv("LEAD_AUTHOR_MODEL", NO_MODEL)
    repo = _worktree(tmp_path)
    run_dir = _run_dir(tmp_path, ("elastic.newthing", "elastic", "esql"))
    hexname = _draft_basename("elastic.newthing")
    done: list[str | None] = []
    with scene_over(tmp_path, repo) as s:
        draft = s.at(f"gather/queries/elastic/_draft/{hexname}.md")
        if site is None:
            with pytest.raises(FatalConfigError, match=NO_MODEL):
                lead_author.run_under_held_queue_lock(run_dir, paths=s.paths, trees=s.trees,
                                                      on_done=done.append)
            assert f"id: elastic.{hexname}" in draft.read_text(encoding="utf-8")
            assert done == []
            return
        plant_folder(s, site, "link")
        before = census(s.outside)
        rc = lead_author.run_under_held_queue_lock(run_dir, paths=s.paths, trees=s.trees,
                                                   on_done=done.append)

    assert rc == 0
    assert done == [None]
    assert census(s.outside) == before
    assert any("synthesize_drafts: could not write" in m and str(draft) in m
               for m in errors(caplog)), errors(caplog)


# ---------------------------------------------------------------------------------------
# Through the drain, with its REAL default seams (the label bound into them)
# ---------------------------------------------------------------------------------------


class PlantingBranch(SpecBranch):
    """`SpecBranch` whose batch worktree is a seeded tree with `plant` applied to it: the state
    a box process running beside the lead author leaves before the claim's host work runs."""

    def __init__(self, base: Path, plant: Callable[[Path], None]) -> None:
        super().__init__(base)
        self._plant = plant
        self.worktrees: list[Path] = []

    def start_batch(self, batch_id: str) -> Path:
        self.events.append("start")
        wt = _worktree(self._base, name=f"wt-{batch_id}")
        self._plant(wt)
        self.worktrees.append(wt)
        return wt


def _failed(paths: LoopPaths) -> list[dict]:
    failed = paths.author_queue_dir / "failed"
    return [json.loads(p.read_text()) for p in sorted(failed.glob("*.json"))] \
        if failed.is_dir() else []


def test_the_drain_default_seams_carry_the_label_and_write_nothing_outside_skills(
    tmp_path: Path, monkeypatch, caplog,
):
    """O3 through `drains.lead_author_drain` with its production `run_lead_author` and
    `run_pitfalls` (neither injected): the batch worktree's `skills/gather/queries` is a link to
    a folder outside the repo, and the queued run holds one executed lead with a coined id.

    The draft for it is refused and logged, nothing outside the repo changes, and the marker is
    served: the run's `pitfalls_collected` and `done` (`commit: none`) are written and nothing is
    dead-lettered; the pitfalls leg runs clean. A default seam that bound no label (`TypeError`)
    or `author_drain`'s (its trees hold no `skills/`, or fail to open) fails the claim and
    dead-letters the marker, or fails the curation, which the drain logs as a pitfalls error.

    No positive control through the drain: with the catalog readable the lead would resolve and
    the production seam would spawn the real agent (`LEAD_AUTHOR_MODEL` is set to a name no
    provider routes, so a regression that reaches the spawn fails here rather than calling
    one)."""
    monkeypatch.setenv("LEAD_AUTHOR_MODEL", NO_MODEL)
    paths = loop_paths(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    planted: list[dict] = []

    def plant(wt: Path) -> None:
        queries = wt / CATALOG_REL
        os.replace(queries, outside / "elsewhere-queries")
        queries.symlink_to(outside / "elsewhere-queries", target_is_directory=True)
        planted.append(census(outside))

    branch = PlantingBranch(tmp_path / "worktrees", plant)
    run_dir = tmp_path / "runs" / "run-1"
    seed_executed_query(run_dir, query_id="elastic.newthing", system="elastic", verb="esql")
    markers.enqueue_case_for_curation("case-1", run_dir, paths)

    rc = drains.lead_author_drain(
        paths, branch=branch, start_box=noop_start_box, stop_box=noop_stop_box, scrub=noop_scrub,
    )

    assert rc == 0
    [before] = planted
    assert census(outside) == before, "a draft was written outside skills/"
    [wt] = branch.worktrees
    hexname = _draft_basename("elastic.newthing")
    assert any("synthesize_drafts: could not write" in m
               and str(wt / CATALOG_REL / "elastic" / "_draft" / f"{hexname}.md") in m
               for m in errors(caplog)), errors(caplog)
    assert (run_dir / "lead_author" / "pitfalls_collected").is_file()
    assert (run_dir / "lead_author" / "done").read_text().startswith("commit: none")
    assert author_markers(paths) == []
    assert _failed(paths) == [], "the claim was dead-lettered"
    assert [m for m in errors(caplog) if "pitfalls curation error" in m] == [], errors(caplog)


def test_a_seam_that_cannot_hold_skills_dead_letters_the_claim(tmp_path: Path, caplog):
    """The open's own fault routing (declared): the batch worktree has no `skills/`, so the
    lead-author seam's `open_drain_trees` fails to hold it (`FileNotFoundError`). That fault
    propagates out of the seam to the lane's dead-letter guard, which quarantines the claim
    naming it, rather than being swallowed into a transient retry (`_LeadAuthorRetry`, which
    would re-queue the marker with its attempts bumped)."""
    paths = loop_paths(tmp_path)

    def plant(wt: Path) -> None:
            shutil.rmtree(wt / "defender" / "skills")

    branch = PlantingBranch(tmp_path / "worktrees", plant)
    run_dir = tmp_path / "runs" / "run-1"
    seed_executed_query(run_dir, query_id="elastic.newthing", system="elastic", verb="esql")
    markers.enqueue_case_for_curation("case-1", run_dir, paths)

    drains.lead_author_drain(
        paths, branch=branch, start_box=noop_start_box, stop_box=noop_stop_box, scrub=noop_scrub,
    )

    failed = _failed(paths)
    assert len(failed) == 1, failed
    assert failed[0]["failed"].startswith("lead-author-error"), failed
    assert "FileNotFoundError" in failed[0]["failed"], failed
    assert author_markers(paths) == [], "the claim was re-queued as a transient"
    assert not (run_dir / "lead_author").exists()


# ---------------------------------------------------------------------------------------
# Lifetime (A3): one `DrainTrees` per seam call, open while the curator call runs, closed when
# the seam returns or raises; nothing below the seam keeps a handle
# ---------------------------------------------------------------------------------------


def _lifetime_paths(tmp_path: Path) -> tuple[LoopPaths, Path]:
    repo = _worktree(tmp_path)
    return LoopPaths(repo_root=repo, state_dir=tmp_path / "state"), repo


def _unresolved_run(tmp_path: Path) -> Path:
    """A run whose one executed row resolves to no catalog template and is no draft candidate
    (`wazuh.search`: its suffix is its verb), so the run reaches `on_done(None)` (nothing to
    hand the agent) through every reader of the claim, and never the agent."""
    return _run_dir(tmp_path, ("wazuh.search", "wazuh", "search"))


def test_the_lead_author_seam_holds_skills_only_while_its_call_runs(tmp_path: Path, caplog):
    """`drains._invoke_lead_author(..., label=LEAD)` over a worktree: while the curator call
    runs (seen from `on_done`, which the run calls inside it) this process holds exactly the
    worktree's `skills/` (one descriptor); once the seam returns it holds nothing under the
    worktree; and no handle was used after a close (no `Bad file descriptor` anywhere in the
    log of a normal claim, which reads the catalog, the drafts and the handoff through it)."""
    caplog.set_level(logging.DEBUG)
    paths, repo = _lifetime_paths(tmp_path)
    run_dir = _unresolved_run(tmp_path)
    during: list[tuple[str | None, list[str]]] = []
    assert descriptors_under(repo) == []

    drains._invoke_lead_author(
        paths, run_dir, label=LEAD,
        on_done=lambda sha: during.append((sha, sorted(descriptors_under(repo)))))

    assert during == [(None, [os.path.realpath(paths.skills_dir)])], during
    assert descriptors_under(repo) == [], "a handle on the leaf outlived the seam"
    assert (run_dir / "lead_author" / "pitfalls_collected").is_file()
    bad = [r.getMessage() for r in caplog.records if "Bad file descriptor" in r.getMessage()]
    assert bad == [], bad


@pytest.mark.parametrize("fault", ["RuntimeError", "OSError"])
def test_the_lead_author_seam_releases_skills_when_its_call_raises(tmp_path: Path, fault: str):
    """The curator call raises inside the seam (from `on_done`): a `RuntimeError` propagates
    out of the seam as itself, an `OSError` is the seam's swallowed transient
    (`_LeadAuthorRetry`). Either way the trees were held while it ran and are closed after."""
    paths, repo = _lifetime_paths(tmp_path)
    run_dir = _unresolved_run(tmp_path)
    during: list[list[str]] = []

    def on_done(_sha: str | None) -> None:
        during.append(sorted(descriptors_under(repo)))
        raise RuntimeError("on_done blew up") if fault == "RuntimeError" else OSError(
            errno.EIO, "on_done io fault")

    expected = RuntimeError if fault == "RuntimeError" else drains._LeadAuthorRetry
    with pytest.raises(expected):
        drains._invoke_lead_author(paths, run_dir, label=LEAD, on_done=on_done)

    assert during == [[os.path.realpath(paths.skills_dir)]], during
    assert descriptors_under(repo) == [], "a handle on the leaf outlived the raising seam"


def _queue_read_spy(repo: Path, state: Path, seen: list[list[str]],
                    fault: BaseException | None = None) -> LoopPaths:
    """A `LoopPaths` (the seam's injected `paths`) that records, each time the pitfalls queue's
    channel is asked for (the curator reads its queue right after taking the mount), what this
    process holds under the repo; with `fault`, raises it after recording. A class per call."""

    class QueueReadSpy(LoopPaths):
        @property
        def pitfalls(self):  # type: ignore[override]
            seen.append(sorted(descriptors_under(self.repo_root)))
            if fault is not None:
                raise fault
            return super().pitfalls

    return QueueReadSpy(repo_root=repo, state_dir=state)


@pytest.mark.parametrize("fault", [None, "RuntimeError"])
def test_the_pitfalls_seam_holds_skills_only_while_its_call_runs(tmp_path: Path, fault):
    """`drains._invoke_pitfalls(..., label=LEAD)` over a worktree with an empty queue: while the
    curator reads its queue the process holds exactly `skills/`; after the seam returns (rc 0)
    or raises (the queue read fails), it holds nothing under the worktree."""
    repo = _worktree(tmp_path)
    seen: list[list[str]] = []
    paths = _queue_read_spy(repo, tmp_path / "state", seen,
                            RuntimeError("queue read failed") if fault else None)
    assert descriptors_under(repo) == []

    if fault is None:
        assert drains._invoke_pitfalls(paths, label=LEAD, on_curated=lambda _d: None,
                                       lock_wait_seconds=0) == 0
    else:
        with pytest.raises(RuntimeError, match="queue read failed"):
            drains._invoke_pitfalls(paths, label=LEAD, on_curated=lambda _d: None,
                                    lock_wait_seconds=0)

    assert seen, "the curator never read its queue"
    assert all(held == [os.path.realpath(paths.skills_dir)] for held in seen), seen
    assert descriptors_under(repo) == [], "a handle on the leaf outlived the seam"


@pytest.mark.parametrize("seam", ["lead_author", "pitfalls"])
def test_a_hold_fault_at_the_open_propagates_out_of_the_seam(tmp_path: Path, seam: str):
    """A leaf with no `skills/`: the seam's `open_drain_trees` cannot hold it, and that
    `FileNotFoundError` propagates out of the seam unchanged (declared routing: the lane's
    dead-letter guard sees it), not swallowed into the curator call's `rc=None` and so not a
    `_LeadAuthorRetry`. Nothing is served and nothing is held after."""
    import shutil

    paths, repo = _lifetime_paths(tmp_path)
    shutil.rmtree(paths.skills_dir)
    run_dir = _unresolved_run(tmp_path)

    if seam == "lead_author":
        call = functools.partial(drains._invoke_lead_author, paths, run_dir, label=LEAD,
                                 on_done=lambda _s: None)
    else:
        call = functools.partial(drains._invoke_pitfalls, paths, label=LEAD,
                                 on_curated=lambda _d: None, lock_wait_seconds=0)
    with pytest.raises(FileNotFoundError):
        call()

    assert not (run_dir / "lead_author").exists()
    assert descriptors_under(repo) == []


# ---------------------------------------------------------------------------------------
# The label and the trees: required, and consulted (owner decision 1; the contract's Shape)
# ---------------------------------------------------------------------------------------


def _lessons(paths: LoopPaths) -> None:
    """The author drain's two corpora, made in the leaf, so its trees can be opened there (the
    refusal under test is then the lane's, not the open's)."""
    for tree in AUTHOR_DRAIN_LABEL.writable_trees(paths):
        tree.mkdir(parents=True, exist_ok=True)


def test_the_seams_and_entry_points_refuse_a_call_without_their_label_or_trees(tmp_path: Path):
    """No default: `_invoke_lead_author`, `_invoke_pitfalls` and `run` without `label`, and
    `run_under_held_queue_lock`, `run_pitfalls` and `build_lead_author_deps` without `trees`,
    are a `TypeError` (`run` even with deps, and even for a run dir that does not exist). Each
    is then driven with it, as the positive control: the empty run is served, the empty queue
    returns 0."""
    paths, _repo = _lifetime_paths(tmp_path)
    run_dir = _run_dir(tmp_path)

    with pytest.raises(TypeError):
        drains._invoke_lead_author(paths, run_dir, on_done=lambda _s: None)
    with pytest.raises(TypeError):
        drains._invoke_pitfalls(paths, on_curated=lambda _d: None, lock_wait_seconds=0)
    with pytest.raises(TypeError):
        lead_author.run(tmp_path / "no-such-run")
    with pytest.raises(TypeError):
        lead_author.build_lead_author_deps(paths)
    with opened(paths) as trees:
        deps = _deps(paths, trees, LeadAuthorSpawn(), [])
        with pytest.raises(TypeError):
            lead_author.run(run_dir, paths=paths, deps=deps)
        with pytest.raises(TypeError):
            lead_author.run_under_held_queue_lock(run_dir, paths=paths, on_done=lambda _s: None)
        with pytest.raises(TypeError):
            pitfalls_curator.run_pitfalls(paths=paths)

        assert lead_author.run(run_dir, label=LEAD, paths=paths, deps=deps) == 0
        assert lead_author.run_under_held_queue_lock(
            run_dir, paths=paths, trees=trees, on_done=lambda _s: None) == 0
        assert pitfalls_curator.run_pitfalls(paths=paths, trees=trees) == 0
    drains._invoke_lead_author(paths, run_dir, label=LEAD, on_done=lambda _s: None)
    assert (run_dir / "lead_author" / "pitfalls_collected").is_file()
    assert drains._invoke_pitfalls(paths, label=LEAD, on_curated=lambda _d: None,
                                   lock_wait_seconds=0) == 0


def test_the_deps_hold_the_trees_skills_mount_and_route_tree_for_through_the_trees(
        tmp_path: Path):
    """`build_lead_author_deps(paths, trees=trees)`: `deps.skills` IS `trees.mount(skills_dir)`
    (the held mount itself, no second hold), `deps.tree_for` answers with that same `Held` for a
    skills path and `None` for a path outside the lane's mount (a lessons path), and refuses a
    relative path as `DrainTrees.tree_for` does. The handoff and discovery partials read through
    the held view: a link at a pending skill draft is not discovered, the plain one is."""
    paths, _repo = _lifetime_paths(tmp_path)
    outside = tmp_path / "outside"
    write(paths.skills_dir / "elastic/_draft/plain.md",
          "---\nid: elastic.plain\nstatus: draft\n---\n")
    write(outside / "linked.md", f"---\nid: elastic.linked\nstatus: draft\n---\n# {OUT_MARK}\n")
    (paths.skills_dir / "elastic/_draft/linked.md").symlink_to(outside / "linked.md")

    with opened(paths) as trees:
        deps = lead_author.build_lead_author_deps(paths, trees=trees)
        held = trees.mount(paths.skills_dir)
        assert deps.skills is held
        hit = deps.tree_for(paths.skills_dir / "elastic/SKILL.md")
        assert hit is not None
        assert hit[0] is held
        assert hit[1] == "elastic/SKILL.md"
        assert deps.tree_for(paths.lessons_dir / "x.md") is None
        with pytest.raises(ValueError):  # noqa: PT011 — DrainTrees.tree_for's refusal of a relative path
            deps.tree_for("defender/skills/elastic/SKILL.md")
        found = deps.discover_system_drafts()

    assert paths.skills_dir / "elastic/_draft/plain.md" in found
    assert paths.skills_dir / "elastic/_draft/linked.md" not in found


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
    """`build_lead_author_deps` and `run_pitfalls` refuse trees that hold no mount at
    `paths.skills_dir` itself (`LeadAuthorError`): never a handle rooted elsewhere, above or
    below, and never a fallback to the plain path. `run_pitfalls` refuses up front, before it
    reads its queue, even a queue over the threshold, whose curator (`invoke`) is never called.

    Catches: a handle built at `paths.skills_dir` beside the trees (`hold(paths.skills_dir)`),
    and a `run_pitfalls` that takes the trees and ignores them until its commit gate, which a
    below-threshold queue (or one the curator declines) never reaches."""
    from defender.learning.core import persist
    from defender.tests._declared869 import Spawn, pitfall_row

    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "1")
    paths, trees = _refusing_trees(tmp_path)[how]()
    persist.append_pitfalls([pitfall_row("r:l-000:0", "elastic")], paths=paths)
    spawn = Spawn()
    with trees:
        with pytest.raises(LeadAuthorError):
            lead_author.build_lead_author_deps(paths, trees=trees)
        with pytest.raises(LeadAuthorError):
            pitfalls_curator.run_pitfalls(paths=paths, trees=trees, invoke=spawn)
    assert spawn.calls == []
    assert [r["pitfall_id"] for r in persist.read_pitfalls(paths)] == ["r:l-000:0"]


def test_trees_holding_skills_exactly_are_taken_whatever_opened_them(tmp_path: Path):
    """The control for the refusals: trees holding exactly `skills/`, opened directly
    (`DrainTrees.open`, not through the lead member), get deps whose `skills` is that trees'
    mount, and `run_pitfalls` serves its empty queue under them."""
    repo = _worktree(tmp_path)
    paths = LoopPaths(repo_root=repo, state_dir=tmp_path / "state")
    with DrainTrees.open((paths.skills_dir,)) as trees:
        deps = lead_author.build_lead_author_deps(paths, trees=trees)
        assert deps.skills is trees.mount(paths.skills_dir)
        assert pitfalls_curator.run_pitfalls(paths=paths, trees=trees) == 0


#: Non-members (#1179 O1'): the members' values and a name as strings, an unknown string. Each
#: raises `AttributeError` at its first use; the author member, which is a label, is refused
#: for holding no `skills/` (`LeadAuthorError`).
NON_MEMBERS = ["no_such_drain", "lead_author_drain", "author_drain", "LEAD_AUTHOR"]


def _refusal_for(label: object) -> type[Exception]:
    return LeadAuthorError if label is AUTHOR_DRAIN_LABEL else AttributeError


@pytest.mark.parametrize("label", [AUTHOR_DRAIN_LABEL, *NON_MEMBERS])
def test_run_consults_the_label_it_is_given(tmp_path: Path, label: object):
    """`run(label=...)` with deps: refused unless the label's trees hold the deps' `skills_dir`
    (the author member: `LeadAuthorError`), and a non-member raises at its first use
    (`AttributeError`), either way before the queue lock or any of the run; without deps it
    opens that label's trees, so the same label is refused there, again before any of the run
    is served. The control is the lead member, on the same deps."""
    paths, _repo = _lifetime_paths(tmp_path)
    _lessons(paths)
    run_dir = _run_dir(tmp_path)
    spawn = LeadAuthorSpawn()
    refusal = _refusal_for(label)
    with opened(paths) as trees:
        deps = _deps(paths, trees, spawn, [ELASTIC_LEAD])
        with pytest.raises(refusal):
            lead_author.run(run_dir, label=label, paths=paths, deps=deps)  # type: ignore[arg-type]
        assert not (run_dir / "lead_author").exists()
        with pytest.raises(refusal):
            lead_author.run(run_dir, label=label, paths=paths)  # type: ignore[arg-type]
        assert not (run_dir / "lead_author").exists()
        assert spawn.calls == []
        assert lead_author.run(run_dir, label=LEAD, paths=paths, deps=deps) == 0
    assert spawn.calls, "the control never reached the agent"


@pytest.mark.parametrize("label", [AUTHOR_DRAIN_LABEL, *NON_MEMBERS])
def test_the_drain_seams_consult_the_label(tmp_path: Path, label: object):
    """`_invoke_lead_author` / `_invoke_pitfalls` open the trees of the label they are handed:
    the author member's (its two corpora present in the leaf) hold no `skills/`, so each refuses
    with `LeadAuthorError`; a non-member raises at its first use (`AttributeError`). Either way
    nothing is served and nothing is left held. The lead member's control is in
    `test_the_seams_and_entry_points_refuse_...`."""
    paths, repo = _lifetime_paths(tmp_path)
    _lessons(paths)
    run_dir = _run_dir(tmp_path)
    refusal = _refusal_for(label)

    with pytest.raises(refusal):
        drains._invoke_lead_author(paths, run_dir, label=label,  # type: ignore[arg-type]
                                   on_done=lambda _s: None)
    assert not (run_dir / "lead_author").exists()
    with pytest.raises(refusal):
        drains._invoke_pitfalls(paths, label=label,  # type: ignore[arg-type]
                                on_curated=lambda _d: None, lock_wait_seconds=0)
    assert descriptors_under(repo) == []


def _rule_calls(s: Scene) -> dict[str, Callable[..., Any]]:
    """Each post-agent check with every argument but `tree_for`, passed as `**extra`."""
    rel = s.rel(TEMPLATE_NAME)
    return {
        "_frontmatter_id": lambda **extra: lead_author._frontmatter_id(s.repo, rel, **extra),
        "_check_promoted_template": lambda **extra: lead_author._check_promoted_template(
            s.repo, resolver(s), rel, **extra),
        "_skills_content_rule": lambda **extra: lead_author._skills_content_rule(
            s.repo, resolver(s), "A ", rel, **extra),
        "_skills_path_rule": lambda **extra: lead_author._skills_path_rule(
            s.repo, "A ", rel, systems=DECLARED, **extra),
        "_skills_rule": lambda **extra: lead_author._skills_rule(
            s.repo, resolver(s), "A ", rel, systems=DECLARED, **extra),
        "_answered_after_batch": lambda **extra: lead_author._answered_after_batch(
            s.repo, **extra),
        "_refuse_half_promote": lambda **extra: lead_author._refuse_half_promote(
            s.repo, {"wazuh.nothing"}, **extra),
        "_departed_drafts": lambda **extra: lead_author._departed_drafts(s.repo, {}, [], **extra),
        "_covers_rule": lambda **extra: lead_author._covers_rule(s.repo, {}, [], **extra),
        "_verify_skills_state": lambda **extra: lead_author._verify_skills_state(
            s.repo, [], systems=DECLARED, **extra),
        "_readable_pair": lambda **extra: pitfalls_curator._readable_pair(
            s.repo, pitfalls_curator.REDUCER_REL, **extra),
        "_pitfalls_content_rule": lambda **extra: pitfalls_curator._pitfalls_content_rule(
            s.repo, " M", pitfalls_curator.REDUCER_REL, **extra),
        "_pitfalls_rule": lambda **extra: pitfalls_curator._pitfalls_rule(
            s.repo, " M", pitfalls_curator.REDUCER_REL, systems=DECLARED, reducer_offered=True,
            **extra),
        "_verify_pitfalls_state": lambda **extra: pitfalls_curator._verify_pitfalls_state(
            s.repo, [], systems=DECLARED, reducer_offered=True, **extra),
    }


RULES = (
    "_frontmatter_id", "_check_promoted_template", "_skills_content_rule", "_skills_path_rule",
    "_skills_rule", "_answered_after_batch", "_refuse_half_promote", "_departed_drafts",
    "_covers_rule", "_verify_skills_state", "_readable_pair", "_pitfalls_content_rule",
    "_pitfalls_rule", "_verify_pitfalls_state",
)

#: Each check's answer through the lane's `tree_for` on the plain scene below (an unchanged
#: reducer surface, a well-formed established template the agent "wrote"): the control.
RULE_CONTROL: dict[str, Callable[[tuple], bool]] = {
    "_frontmatter_id": lambda got: got == ("returned", "wazuh.probe"),
    "_answered_after_batch": lambda got: got[0] == "returned" and "wazuh.probe" in got[1],
    "_departed_drafts": lambda got: got == ("returned", []),
    "_readable_pair": lambda got: got == ("returned", (REDUCER_TEXT, REDUCER_TEXT)),
    "_verify_skills_state": lambda got: got == ("returned", [f"{SKILLS_REL}{TEMPLATE_NAME}"]),
    "_verify_pitfalls_state": lambda got: raised(got, "LeadAuthorError", "probe.md"),
}


@pytest.mark.parametrize("rule", RULES)
def test_every_post_agent_check_requires_tree_for(scene: Scene, rule: str):
    """Each check reads the tree through the `tree_for` it is handed and has no default for it
    (a default would be a second way in, with no trees behind it): without it, `TypeError`.
    The control is the same call with the lane's `tree_for`, on a plain tree holding an
    unchanged reducer surface and a well-formed template."""
    _commit_reducer(scene)
    place(scene, TEMPLATE_NAME, marked_template("wazuh.probe"), "plain")
    call = _rule_calls(scene)[rule]

    with pytest.raises(TypeError):
        call()
    got = outcome(lambda: call(tree_for=scene.tree_for))
    assert RULE_CONTROL.get(rule, lambda g: g == ("returned", None))(got), got


def test_the_readers_and_the_writer_take_the_handle_and_nothing_else(scene: Scene):
    """Owner decision 2: `synthesize_drafts`, `collect_general_failures`, `build_handoff` and
    `discover_system_drafts` take `skills=` (the held mount or its view) with `where=`: the old
    `catalog_dir=` / `skills_dir=` spellings, and no tree at all, are `TypeError`.
    `collect_general_failures` with `catalog=None` needs BOTH `skills` and `where`; with a
    `catalog` it needs no tree. `render_query` takes `(source, name, params)`: its old
    `(template_path, params)` is a `TypeError`. `check_system_skill`: a `Bound` without the
    name, or a `Path` with one, is a `ValueError` before any read."""
    lead = _lead("wazuh.search", system="wazuh", verb="search", error_class="agent-fixable")
    catalog_dir = scene.skills_dir / "gather" / "queries"

    for call in (
        lambda: synthesize_drafts([lead], catalog_dir=catalog_dir, catalog=[], systems=DECLARED),
        lambda: synthesize_drafts([lead], catalog=[], systems=DECLARED),
        lambda: synthesize_drafts([lead], skills=scene.skills, catalog=[], systems=DECLARED),
        lambda: collect_general_failures([lead], scene.run_dir, catalog_dir=catalog_dir),
        lambda: collect_general_failures([lead], scene.run_dir),
        lambda: collect_general_failures([lead], scene.run_dir, skills=scene.view),
        lambda: collect_general_failures([lead], scene.run_dir, where=scene.skills_dir),
        lambda: lead_author.build_handoff(scene.run_dir, [lead], catalog_dir=catalog_dir),
        lambda: lead_author.build_handoff(scene.run_dir, [lead]),
        lambda: lead_author.discover_system_drafts(skills_dir=scene.skills_dir, systems=DECLARED),
        lambda: lead_author.discover_system_drafts(systems=DECLARED),
        lambda: lead_author.discover_system_drafts(skills=scene.view, systems=DECLARED),
        lambda: lead_render.render_query(scene.at(TEMPLATE_NAME), {"index": "x"}),
    ):
        with pytest.raises(TypeError):
            call()
    with pytest.raises(ValueError):  # noqa: PT011 — the call-shape refusal; the type is the contract
        _scaffold_rules.check_system_skill(scene.view, "elastic")
    with pytest.raises(ValueError):  # noqa: PT011 — the call-shape refusal; the type is the contract
        _scaffold_rules.check_system_skill(scene.at(SKILL_MD_NAME), "elastic", SKILL_MD_NAME)

    assert [r["query_id"] for r in collect_general_failures([lead], scene.run_dir, catalog=[])] \
        == ["wazuh.search"]
    assert [r["query_id"] for r in collect_general_failures(
        [lead], scene.run_dir, skills=scene.view, where=scene.skills_dir)] == ["wazuh.search"]


def test_render_query_raises_for_an_absent_template_naming_it(scene: Scene):
    """`render_query(source, name, params)` on a name with nothing at it raises `OSError` naming
    the name (`build_handoff` catches it and renders `""`); the plain template renders."""
    with pytest.raises(OSError, match="gather/queries/wazuh/absent.md"):
        lead_render.render_query(scene.view, "gather/queries/wazuh/absent.md", {})
    place(scene, TEMPLATE_NAME, marked_template("wazuh.probe"), "plain")
    assert "index: idx-7" in lead_render.render_query(
        scene.view.under("gather/queries"), "wazuh/probe.md", {"index": "idx-7"})


# ---------------------------------------------------------------------------------------
# The shared helpers: `kind_at` / `read_at` / `view_at`, `lane_skills`, `load_lane_catalog`
# ---------------------------------------------------------------------------------------


def test_kind_at_and_read_at_go_through_the_mount_and_keep_a_plain_path_outside_it(scene: Scene):
    """`lane_trees.kind_at` / `read_at`: a path inside the lane's mount (relative to the repo,
    as git status spells it, or absolute) is judged and read through its handle (a link there
    is "other" and refused; nothing is "absent" with a reason); a path outside every mount (the
    box's read-only area, D3) is judged and read by its plain path."""
    place(scene, TEMPLATE_NAME, marked_template("wazuh.probe"), "plain")
    rel = scene.rel(TEMPLATE_NAME)
    assert kind_at(scene.repo, scene.tree_for, rel) == "file"
    assert kind_at(scene.repo, scene.tree_for, scene.at(TEMPLATE_NAME)) == "file"
    assert read_at(scene.repo, scene.tree_for, rel) == (marked_template("wazuh.probe"), None)
    assert kind_at(scene.repo, scene.tree_for, scene.rel("gather/queries/wazuh")) == "dir"
    absent = scene.rel("gather/queries/wazuh/nothing.md")
    assert kind_at(scene.repo, scene.tree_for, absent) == "absent"
    text, reason = read_at(scene.repo, scene.tree_for, absent)
    assert text is None
    assert reason

    place(scene, TEMPLATE_NAME, marked_template("wazuh.probe"), "link")
    assert kind_at(scene.repo, scene.tree_for, rel) == "other"
    text, reason = read_at(scene.repo, scene.tree_for, rel)
    assert text is None
    assert reason
    assert OUT_MARK not in reason

    adapter = "defender/scripts/adapters/wazuh_adapter.py"
    assert kind_at(scene.repo, scene.tree_for, adapter) == "file"
    assert read_at(scene.repo, scene.tree_for, adapter) == (
        (scene.repo / adapter).read_text(encoding="utf-8"), None)
    assert kind_at(scene.repo, scene.tree_for, "defender/scripts/adapters") == "dir"
    assert kind_at(scene.repo, scene.tree_for, "defender/scripts/nothing.py") == "absent"
    (scene.repo / "defender/scripts/linked.py").symlink_to(scene.outside / "nowhere.py")
    assert kind_at(scene.repo, scene.tree_for, "defender/scripts/linked.py") == "other"


def test_kind_at_answers_other_for_a_refused_holding_folder_and_never_raises(tmp_path: Path):
    """`kind_at` through the handle goes on `entry_kind`, which has a reason channel: an EACCES
    at a holding folder is that folder's refused listing, which `kind_at` answers as `"other"`
    (O2: something stands in the way, and it is not the plain entry), never raised and never
    `"absent"`; so are a linked holding folder and a handle used after its trees closed (`Bad
    file descriptor`). The control answers `"file"`."""
    repo = bare_skills(tmp_path)
    skills_dir = repo / "defender" / "skills"
    refuser = RefusesFolder(skills_dir / "gather/queries/wazuh", "step", errno.EACCES)
    rel = "defender/skills/gather/queries/wazuh/auth-events.md"
    with DrainTrees.open((skills_dir,)) as trees:
        assert kind_at(repo, trees.tree_for, rel) == "file"
        tree_for = trees.tree_for
    held, name = tree_for(repo / rel)
    got = entry_kind(held.view(), name)
    assert (got.kind, got.absent, got.reason) == (None, False, os.strerror(errno.EBADF))
    assert kind_at(repo, tree_for, rel) == "other"
    with DrainTrees.open((skills_dir,), os_=refuser) as trees:
        held, name = trees.tree_for(repo / rel)
        assert entry_kind(held.view(), name).reason == os.strerror(errno.EACCES)
        assert kind_at(repo, trees.tree_for, rel) == "other"
    shutil.move(skills_dir / "gather/queries/wazuh", tmp_path / "moved-wazuh")
    (skills_dir / "gather/queries/wazuh").symlink_to(tmp_path / "moved-wazuh")
    with DrainTrees.open((skills_dir,)) as trees:
        assert kind_at(repo, trees.tree_for, rel) == "other"
        assert kind_at(repo, trees.tree_for, "defender/skills/gather/queries/wazuh") == "other"
        assert kind_at(repo, trees.tree_for, "defender/skills") == "dir"


def test_view_at_reads_the_mount_root_and_a_folder_below_it(scene: Scene):
    """`view_at(held, ".")` is the mount's own view; `view_at(held, name)` is the view of the
    folder `name` below it (the same handle: a read there walks from the held root)."""
    held = scene.skills
    assert view_at(held, ".").read(SKILL_MD_NAME).text == (
        scene.at(SKILL_MD_NAME).read_text(encoding="utf-8"))
    assert view_at(held, "gather/queries").read("wazuh/auth-events.md").text == (
        scene.at("gather/queries/wazuh/auth-events.md").read_text(encoding="utf-8"))
    assert entry_kind(view_at(held, "elastic"), "SKILL.md").kind == "file"


def test_lane_skills_is_the_trees_own_skills_mount_or_a_refusal(tmp_path: Path):
    """`lane_skills(trees, paths)` is `trees.mount(paths.skills_dir)` itself; trees without
    that exact mount point are a `LeadAuthorError` (not the `ValueError` of `mount`)."""
    paths, _repo = _lifetime_paths(tmp_path)
    with opened(paths) as trees:
        assert lane_skills(trees, paths) is trees.mount(paths.skills_dir)
    with DrainTrees.open((paths.defender_dir,)) as above, pytest.raises(LeadAuthorError):
        lane_skills(above, paths)


def test_load_lane_catalog_spells_each_template_as_today(scene: Scene):
    """`load_lane_catalog(view, where=skills_dir)` reads `gather/queries` under the mount and
    spells each template `skills_dir / gather/queries / <sys>/[_draft/]x.md`, exactly as
    today's `load_catalog(catalog_dir)` does (`created`, `minted` and `tpl.path` comparisons
    must not drift), in the same order."""
    got = lead_neighbors.load_lane_catalog(scene.view, where=scene.skills_dir)
    today = lead_neighbors.load_catalog(scene.skills_dir / CATALOG_FOLDER)
    assert [(t.id, t.path) for t in got] == [(t.id, t.path) for t in today]
    assert {t.path for t in got} == {scene.at("gather/queries/wazuh/auth-events.md"),
                                     scene.at("gather/queries/wazuh/_draft/newthing.md")}
    assert CATALOG_FOLDER == "gather/queries"
    assert f"{SKILLS_REL}{CATALOG_FOLDER}/" == CATALOG_REL


def test_the_path_form_of_check_system_skill_is_unchanged(scene: Scene):
    """N-h: `check_system_skill(path, system)` (`skills/connect/validate_scaffold.py`'s call)
    reads a plain SKILL.md as before, refuses a wrong name, and words an absent one
    `skill-unreadable`; no descriptor is left under the repo."""
    assert _scaffold_rules.check_system_skill(scene.at(SKILL_MD_NAME), "elastic") == []
    assert [f.code for f in _scaffold_rules.check_system_skill(
        scene.at(SKILL_MD_NAME), "wazuh")] == ["skill-name"]
    assert [f.code for f in _scaffold_rules.check_system_skill(
        scene.at("wazuh/SKILL.md"), "wazuh")] == ["skill-unreadable"]
    held = sorted(descriptors_under(scene.repo))
    assert held == [os.path.realpath(scene.skills_dir)], held  # the scene's own mount, only
