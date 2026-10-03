"""#1134 step 6 (v2, ported to v3): the holes the step-6 adversary found in the suite (E1-E10, R8), each pinned
by an observable a dishonest variant changes, beside a control on the same address. E1's rows
and E3's resolver pin live in `test_1134_lead_author_holes.py` (the spy `tree_for` table and the
label pins); the rest are here.

- E2a / E2b: a commit gate handed a plain `tree_for` (`lambda _p: None`) reads every path by its
  plain spelling, so a link or a hard link the agent / the curator left in the tree is followed
  (a symlink committed as mode 120000, an outside file's bytes read and quoted).
- E4: `where` stat'ed (a following probe) and trusted over the view it spells for.
- E5: the lift bypass's `contradicts_skill` read by the draft's plain path.
- E6: `_run_locked`'s reads re-resolving the mount by name (`bind(skills_dir)`), not the held
  `deps.skills` the trees hold.
- E7: the label compared to the lead constant instead of looked up in the mount list.
- E8: deps (the trees' `Held` and bound `tree_for`) cached past the seam's `with`.
- E9: the writer judging through the handle, then writing by path at the mount's spelling.
- E10: the stale vulture suppressions on the two entry points kept.
- R8: `run_pitfalls` reading its queue before it checks the trees.

Linux only in practice, like the files it extends: the read watch is inotify.
"""
from __future__ import annotations

import ast
import dataclasses
import errno
import inspect
import logging
import os
import re
from pathlib import Path
from typing import Any

import pytest

from defender import _git
from defender._env import FatalConfigError
from defender.learning.core import drains, lane_trees, persist
from defender.learning.core.config import LEAD_AUTHOR_DRAIN_LABEL, LoopPaths
from defender.learning.core.lane_trees import DrainTrees
from defender.learning.leads import lead_author, lead_neighbors, pitfalls_curator
from defender.learning.leads.draft_synthesis import synthesize_drafts
from defender.tests._tree_listing_1134 import RealOs, fd_path
from defender.tests._declared869 import LeadAuthorSpawn, pitfall_row
from defender.tests._declared870 import (
    REDUCER_REL,
    Spawn,
    commit_all,
    reducer_surface_text,
    seed_tree,
    shim_row,
    write_reducer_surface,
)
from defender.tests._lead_author_1134 import (
    OUT_MARK,
    Scene,
    clear,
    lead_trees,
    logged,
    outcome,
    place,
    plant_state,
    raised,
    scene_over,
    write,
)
from defender.tests._repo import query_template, seed_skills_repo
from defender.tests._shared_readers_1134 import RefusesFolder, kernel_watch
from defender.tests.test_1111_rooted_io import census, in_time
from defender.tests.test_1134_lead_author_handle import (
    CONTENT_CASES,
    DECLARED,
    ELASTIC_LEAD,
    MINTED_NAME,
    NO_MODEL,
    REFUSALS,
    SKILL_MD_NAME,
    TEMPLATE_NAME,
    WAZUH_LEAD,
    MovedMountPaths,
    OtherLanePaths,
    _deps,
    _lead,
    _refusing_trees,
    _run_dir,
    _unresolved_run,
    _worktree,
    bare_skills,
    content_verdict,
    draft_of,
    marked_template,
    said_for,
)

LEAD = LEAD_AUTHOR_DRAIN_LABEL
#: `OtherLanePaths`' label: a drain the mount list grants `skills/` to that is not the lead's.
OTHER = "other_lane"


def _head_mode(repo: Path, rel: str) -> str:
    """The git mode `rel` is committed with at HEAD (`100644` a file, `120000` a link)."""
    # The code under test (the pitfalls / lead commit) runs no `ls-tree`: the query shape this
    # shares is tenant.py's committed-id read (#1120), which no test here exercises.
    return _git.git(["ls-tree", "HEAD", "--", rel], cwd=repo).split(" ", 1)[0]  # lint-oracle: ok — not the code under test's query


# ---------------------------------------------------------------------------------------
# E2b: the pitfalls commit gate reads the reducer the curator left through the trees
# ---------------------------------------------------------------------------------------

#: The curator's edit: one pitfall appended under the reducer's `## Common pitfalls`, a
#: document the content rule accepts, carrying the mark.
EDITED_REDUCER = reducer_surface_text(bullets=(OUT_MARK,))
REDUCER_REFUSALS = {"link": "unreadable as a file", "hardlink": "unreadable as UTF-8 text"}


def _pitfalls_tree(tmp_path: Path) -> LoopPaths:
    """A committed tree carrying the reducer surface, and three queued reducer rows (a
    `defender-sql` mistake each), so the tick offers the reducer surface to its curator."""
    repo = seed_tree(tmp_path, adapters=("elastic", "cmdb"), markers=("elastic",),
                     skills=("elastic",), catalog=(), non_systems=("gather",))
    write_reducer_surface(repo)
    commit_all(repo, "seed the reducer surface")
    paths = LoopPaths(repo_root=repo, state_dir=tmp_path / "state")
    persist.append_pitfalls([shim_row(f"r:l-003:{i}") for i in range(3)], paths=paths)
    return paths


@pytest.mark.parametrize("left", ["plain", "link", "hardlink"])
def test_the_pitfalls_gate_reads_the_reducer_the_curator_left_through_the_trees(
        tmp_path: Path, monkeypatch, left: str):
    """E2b, through `run_pitfalls(trees=)`: the curator leaves the reducer surface as a symlink
    to an outside file holding a valid edit, or as a hard link to it. The commit gate refuses
    it as unreadable (`LeadAuthorError`), the kernel saw no open (link) or read (hard link) of
    the outside file, and HEAD is unchanged: no mode-120000 entry, nothing committed.

    `plain` is the control: the same bytes as a plain file are read and committed, a 100644
    blob, so the gate does read what the curator wrote.

    Catches: `_verify_pitfalls_state(..., tree_for=lambda _p: None)` in `run_pitfalls`: the
    plain-path fallback follows the link (`is_file()`, `read_text`), finds the frontmatter
    unchanged and commits the link itself (or the hard link's outside bytes)."""
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "1")
    paths = _pitfalls_tree(tmp_path)
    repo = paths.repo_root
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

    head = _git.git_head_sha(repo)
    watch = {"opens": [target]} if left == "link" else {"reads": [target]}
    with lead_trees(paths) as trees, kernel_watch(**watch) as events:
        got = outcome(lambda: pitfalls_curator.run_pitfalls(
            paths=paths, trees=trees, invoke=Spawn(curate)))
        seen = events()

    assert seen == [], f"the gate opened or read the outside file: {seen}"
    assert _head_mode(repo, REDUCER_REL) == "100644"
    if left == "plain":
        assert got == ("returned", 0), got
        assert _git.git_head_sha(repo) != head, "the control's edit was not committed"
        assert _git.git_show_file(repo, "HEAD", REDUCER_REL) == EDITED_REDUCER
        return
    assert raised(got, "LeadAuthorError", REDUCER_REFUSALS[left]), got
    assert _git.git_head_sha(repo) == head, "a link or a hard link was committed"


# ---------------------------------------------------------------------------------------
# E2a: the lead author's commit gate reads what the agent left through the trees
# ---------------------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class Left:
    """What the agent leaves below `skills/`: the name, the bytes, how the gate refuses the
    plain file (`None`: it passes and is committed), and how it refuses a link or a hard link
    to an outside file holding the same bytes."""

    id: str
    name: str
    text: str
    plain_refusal: str | None
    refusal: str


LEFTS = [
    # A well-formed template whose id names another system: a gate that reads it refuses it
    # for its id, quoting the mark.
    Left("template", "gather/queries/wazuh/left.md", marked_template(f"elastic.{OUT_MARK}"),
         plain_refusal="disagreeing with its directory",
         refusal="not a readable query template"),
    # A declared system's SKILL.md whose frontmatter is valid: read, it passes.
    Left("skill_md", "elastic/SKILL.md",
         f"---\nname: defender-elastic\n---\n# elastic\n\n- {OUT_MARK}\n",
         plain_refusal=None, refusal="could not be read"),
]


@pytest.mark.parametrize("left", ["plain", "link", "hardlink"])
@pytest.mark.parametrize("what", LEFTS, ids=lambda w: w.id)
def test_the_runs_commit_gate_reads_what_the_agent_left_through_the_trees(
        tmp_path: Path, what: Left, left: str, caplog):
    """E2a, through `run(label=, deps=)`: the agent (rc 0) leaves a catalog template under
    `skills/gather/queries/wazuh/`, or a declared system's `SKILL.md`, as a symlink to an
    outside file or a hard link to it. The commit gate refuses it unread: `LeadAuthorError`
    (the template is not a readable query template; the SKILL.md could not be read), no open
    (link) or read (hard link) of the outside file in the kernel watch, nothing it says quoting
    the outside bytes, and HEAD unchanged (no mode-120000 entry committed).

    `plain` is the control: the same bytes as a plain file are read, so the template is refused
    for the id it carries (quoted), and the valid SKILL.md passes and is committed as a file.

    Catches: `_run_locked` handing `_verify_skills_state` a plain `tree_for`, whose fallback
    follows the link (and reads the hard link) and quotes what it found; and a content rule
    that checks only a `"file"` at the name, so a link passes both halves unchecked and is
    committed as a link."""
    repo = _worktree(tmp_path)
    paths = LoopPaths(repo_root=repo, state_dir=tmp_path / "state")
    run_dir = _run_dir(tmp_path)
    target = write(tmp_path / "outside" / Path(what.name).name, what.text)
    at = paths.skills_dir / what.name

    def leave(_run_dir: Path) -> None:
        at.unlink(missing_ok=True)
        if left == "plain":
            write(at, what.text)
        elif left == "link":
            at.symlink_to(target)
        else:
            os.link(target, at)

    spawn = LeadAuthorSpawn(leave)
    head = _git.git_head_sha(repo)
    watch = {"opens": [target]} if left == "link" else {"reads": [target]}
    with lead_trees(paths) as trees, kernel_watch(**watch) as events:
        got = outcome(lambda: lead_author.run(
            run_dir, label=LEAD, paths=paths, deps=_deps(paths, trees, spawn, [ELASTIC_LEAD])))
        seen = events()

    assert spawn.calls, "the agent was never reached, so the gate never ran"
    assert seen == [], f"the commit gate opened or read the outside file: {seen}"
    rel = at.relative_to(repo).as_posix()
    if left == "plain" and what.plain_refusal is None:
        assert got == ("returned", 0), got
        assert _git.git_show_file(repo, "HEAD", rel) == what.text, "the control was not committed"
        assert _head_mode(repo, rel) == "100644"
        return
    assert _git.git_head_sha(repo) == head, "something was committed"
    if left == "plain":
        assert raised(got, "LeadAuthorError", what.plain_refusal), got
        assert OUT_MARK in got[2], "the control's file was not read"
        return
    assert raised(got, "LeadAuthorError", what.refusal), got
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
    """`_skills_content_rule(..., tree_for=)` at a promoted template's name and at a declared
    system's `SKILL.md`: a symlink to an outside file holding good bytes, a dangling symlink
    (`"other"`, not `"absent"`) or a FIFO is refused by the reading check (`LeadAuthorError`),
    without blocking, nothing behind the link opened, and the entry left as it was. `plain` is
    the control: the good bytes as a plain file pass.

    Catches: the content gates asking `kind_at(...) == "file"`, which lets anything else at a
    checked name through unchecked (to be committed as it stands)."""
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


# ---------------------------------------------------------------------------------------
# E9: the draft is created through the held mount
# ---------------------------------------------------------------------------------------


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
    """E9: the trees held over an `os_` whose disk is full under `gather/queries/elastic`. The
    elastic draft is not created (`created == []`, nothing at its name), and the refusal is
    logged naming the draft. `control`: over the same tree with room, the draft lands with
    its bytes.

    Catches: a writer that asks `entry_kind`, then writes by path at the mount's own
    spelling (`write_atomic(skills._where / name)`), which the held `os_` never sees."""
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


# ---------------------------------------------------------------------------------------
# E8: each claim reads and writes through its own trees
# ---------------------------------------------------------------------------------------


def test_two_claims_over_one_paths_each_mint_through_their_own_trees(
        tmp_path: Path, monkeypatch, caplog):
    """E8: two claims through `drains._invoke_lead_author` with the SAME `paths`, one wazuh row
    then one elastic row. Each mints its own draft and goes on to its agent (reached:
    `FatalConfigError` from the unroutable model), and no log line says `Bad file descriptor`.

    Catches: deps (the trees' `Held` and bound `tree_for`) kept past the seam's `with` and
    reused by a later claim over the same working copy: the second claim reads and writes
    through a closed handle, which answers EBADF as a refusal, so its draft is never minted."""
    caplog.set_level(logging.DEBUG)
    monkeypatch.setenv("LEAD_AUTHOR_MODEL", NO_MODEL)
    repo = _worktree(tmp_path)
    paths = LoopPaths(repo_root=repo, state_dir=tmp_path / "state")
    reached: list[str] = []
    for i, lead in enumerate((WAZUH_LEAD, ELASTIC_LEAD)):
        run_dir = _run_dir(tmp_path / f"claim-{i}", (lead.query_id, lead.system, lead.verb))
        try:
            drains._invoke_lead_author(paths, run_dir, label=LEAD, on_done=lambda _sha: None)
        except FatalConfigError:
            reached.append(lead.query_id)

    for lead in (WAZUH_LEAD, ELASTIC_LEAD):
        name, _ = draft_of(lead)
        assert (paths.skills_dir / name).is_file(), f"{lead.query_id}'s claim minted no draft"
    bad = [r.getMessage() for r in caplog.records if "Bad file descriptor" in r.getMessage()]
    assert bad == [], bad
    assert reached == [WAZUH_LEAD.query_id, ELASTIC_LEAD.query_id]


# ---------------------------------------------------------------------------------------
# E5: the lift bypass reads a pending draft through the trees
# ---------------------------------------------------------------------------------------

CONTRADICTING = (f"---\nid: elastic.contradicts\nstatus: draft\ncontradicts_skill: true\n---\n"
                 f"# {OUT_MARK}\n")


@pytest.mark.parametrize("left", ["plain", "hardlink"])
def test_the_lift_bypass_reads_a_pending_draft_through_the_trees(
        tmp_path: Path, monkeypatch, left: str):
    """E5, through `run(label=, deps=)` with no executed leads and the lift threshold at its
    default: one pending system-skill draft saying `contradicts_skill: true`. As a hard link to
    an outside file, its bytes are not read (no read in the kernel watch), so it does not
    bypass the threshold and the agent is never spawned. `plain` is the control: the same
    draft as a plain file bypasses the threshold and is handed to the agent.

    Catches: `_prepare_handoffs` reading `contradicts_skill` by the draft's plain path (the
    listing calls a hard link a file; only the read through the handle refuses it)."""
    monkeypatch.delenv("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", raising=False)
    repo = _worktree(tmp_path)
    paths = LoopPaths(repo_root=repo, state_dir=tmp_path / "state")
    run_dir = _run_dir(tmp_path)
    target = write(tmp_path / "outside" / "contradicts.md", CONTRADICTING)
    at = paths.skills_dir / "elastic/_draft/contradicts.md"
    if left == "plain":
        write(at, CONTRADICTING)
    else:
        at.parent.mkdir(parents=True, exist_ok=True)
        os.link(target, at)
    spawn = LeadAuthorSpawn()

    with lead_trees(paths) as trees, kernel_watch(reads=[target]) as events:
        got = outcome(lambda: lead_author.run(
            run_dir, label=LEAD, paths=paths, deps=_deps(paths, trees, spawn, [])))
        seen = events()

    assert seen == [], f"the hard link's outside file was read: {seen}"
    if left == "plain":
        assert [[d["draft_path"] for d in c["pending_drafts"]] for c in spawn.calls] == [
            [at.relative_to(repo).as_posix()]], "the control's draft did not bypass"
        return
    assert got == ("returned", 0), got
    assert spawn.calls == [], "a hard link's outside bytes bypassed the lift threshold"


# ---------------------------------------------------------------------------------------
# E6: the run's catalog loads go through the held mount it was handed
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("refused", [False, True], ids=["control", "EIO"])
def test_the_runs_catalog_loads_go_through_the_deps_held_mount(tmp_path: Path, refused: bool):
    """E6, through `run(label=, deps=)`: the trees are held over an `os_` that cannot list
    `skills/gather/queries` (EIO). The lead `wazuh.probe`, answered only by a template there,
    resolves to nothing: no handoff, the agent never spawned, the run done (rc 0).
    `control`: over the real `os` the template answers the lead and is handed to the agent
    (which fails, rc 1, so the run stops at the spawn, rc 2).

    Catches: `_run_locked` re-resolving the mount by name for its reads (`bind(skills_dir)`), a
    second handle the trees never held."""
    repo = _worktree(tmp_path)
    paths = LoopPaths(repo_root=repo, state_dir=tmp_path / "state")
    run_dir = _run_dir(tmp_path)
    write(paths.skills_dir / TEMPLATE_NAME, marked_template("wazuh.probe"))
    lead = _lead("wazuh.probe", system="wazuh", verb="noverb", params={"index": "idx-7"})
    spawn = LeadAuthorSpawn(rc=1)
    refuser = RefusesFolder(paths.skills_dir / "gather/queries", "reopen", errno.EIO)
    seam = {"os_": refuser} if refused else {}

    with DrainTrees.open((paths.skills_dir,), **seam) as trees:
        rc = lead_author.run(run_dir, label=LEAD, paths=paths,
                             deps=_deps(paths, trees, spawn, [lead]))

    if not refused:
        assert rc == 2
        assert [h["query_id"] for h in spawn.handoffs] == ["wazuh.probe"]
        return
    assert refuser.refused > 0
    assert spawn.calls == [], "a catalog the held mount refuses was read some other way"
    assert rc == 0


# ---------------------------------------------------------------------------------------
# E7: the label is looked up in the mount list, never compared to one constant
# ---------------------------------------------------------------------------------------


def test_run_with_deps_refuses_the_lead_label_when_its_mount_list_lacks_skills(tmp_path: Path):
    """E7, `run(label=LEAD_AUTHOR_DRAIN_LABEL, deps=...)` whose `deps.paths` is a `LoopPaths`
    whose lead drain mounts a tree that is not `skills/` (`MovedMountPaths`): refused
    (`LeadAuthorError` naming the `skills/` the label's lane does not mount) before any of the
    claim runs. The
    control, the same deps over the plain `LoopPaths`, serves the claim.

    Catches: `run` checking the label against the lead constant (a second label table)
    instead of asking `deps.paths.drain_writable_trees(label)` for `skills_dir`."""
    repo = _worktree(tmp_path)
    plain = LoopPaths(repo_root=repo, state_dir=tmp_path / "state")
    (repo / "moved-skills").mkdir()
    moved = MovedMountPaths(repo_root=repo, state_dir=tmp_path / "state")
    run_dir = _unresolved_run(tmp_path)
    collected = run_dir / "lead_author" / "pitfalls_collected"

    with lead_trees(plain) as trees:
        deps = _deps(plain, trees, LeadAuthorSpawn(), [])
        got = outcome(lambda: lead_author.run(
            run_dir, label=LEAD, paths=moved, deps=dataclasses.replace(deps, paths=moved)))
        assert raised(got, "LeadAuthorError", str(plain.skills_dir)), got
        assert not collected.exists(), "the refused claim ran"
        assert lead_author.run(run_dir, label=LEAD, paths=plain, deps=deps) == 0

    assert collected.is_file(), "the control's claim did not run"


def test_the_drain_seams_serve_a_label_the_mount_list_grants_skills_to(tmp_path: Path):
    """E7, the seams: `_invoke_lead_author` and `_invoke_pitfalls` with a label that is not the
    lead constant but whose mount list holds `skills/` (`OtherLanePaths`, `other_lane`) serve
    it: the lead claim runs to its done hook (nothing to hand the agent), and the pitfalls
    tick serves its empty queue (rc 0). (Their refusal of labels that mount no `skills/` is
    `test_the_drain_seams_consult_the_label`.)

    Catches: a seam that refuses every label but the lead constant, or opens the lead
    constant's mounts whatever label it was handed."""
    repo = _worktree(tmp_path)
    paths = OtherLanePaths(repo_root=repo, state_dir=tmp_path / "state")
    run_dir = _unresolved_run(tmp_path)
    done: list[str | None] = []

    drains._invoke_lead_author(paths, run_dir, label=OTHER, on_done=done.append)
    assert done == [None]
    assert (run_dir / "lead_author" / "pitfalls_collected").is_file()
    assert drains._invoke_pitfalls(paths, label=OTHER, on_curated=lambda _d: None,
                                   lock_wait_seconds=0) == 0


# ---------------------------------------------------------------------------------------
# E4: `where` only spells, for the readers too
# ---------------------------------------------------------------------------------------


@pytest.fixture
def scene(tmp_path: Path):
    with scene_over(tmp_path, seed_skills_repo(tmp_path / "repo")) as s:
        yield s


def _respelled(paths: list[Path], s: Scene, where: Path) -> list[Path]:
    return [where / p.relative_to(s.skills_dir) for p in paths]


def test_where_only_spells_for_the_readers(scene: Scene, tmp_path: Path):
    """E4: each reader handed the mount's view and a `where` that names somewhere that does not
    exist answers exactly what it answers with `where=skills_dir`, non-empty, spelled under
    the `where` it was given; and `where` is never made.

    Catches: a reader that stats `where` (or `where / gather/queries`), a following probe, and
    trusts it over the view: it answers nothing."""
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


# ---------------------------------------------------------------------------------------
# E10: the two entry points step 6 gives production callers keep no vulture suppression
# ---------------------------------------------------------------------------------------

_SUPPRESSION = re.compile(r"noqa:[^\n]*\bV1\d\d\b")


def _signature_lines(source: str, fn: ast.FunctionDef) -> str:
    """The source lines of `fn`'s `def` up to its body (decorators included)."""
    first = min([fn.lineno, *(d.lineno for d in fn.decorator_list)])
    return "\n".join(source.splitlines()[first - 1:fn.body[0].lineno - 1])


def test_the_lane_trees_entry_points_carry_no_vulture_suppression():
    """E10: `open_drain_trees` and `DrainTrees.tree_for` have production callers now (each
    lane's work step opens its trees; the lead author's rules and the curator's put-back look
    paths up), so neither `def` line keeps the `# noqa: V103` / `# noqa: V105` that stood in
    for a caller before step 6. A suppression left on a used name hides the day it is unused
    again."""
    source = inspect.getsource(lane_trees)
    tree = ast.parse(source)
    [opener] = [n for n in tree.body
                if isinstance(n, ast.FunctionDef) and n.name == "open_drain_trees"]
    [cls] = [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "DrainTrees"]
    [lookup] = [n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == "tree_for"]
    for fn in (opener, lookup):
        header = _signature_lines(source, fn)
        assert fn.name in header
        assert not _SUPPRESSION.search(header), (fn.name, header)


# ---------------------------------------------------------------------------------------
# R8: `run_pitfalls` checks its trees before it reads its queue
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("how", ["lane_trees", *REFUSALS])
def test_run_pitfalls_checks_its_trees_before_it_reads_its_queue(
        tmp_path: Path, monkeypatch, how: str):
    """R8: `run_pitfalls` over trees that do not hold `skills/` exactly (the author label's,
    an unknown label's, a moved or above lead mount, a mount below `skills/`) raises
    `LeadAuthorError` without opening its queue file: the kernel watch on the queue sees
    nothing. `lane_trees` is the control: under the lead drain's own trees the same tick does
    read the queue (and, below its threshold, stops there, rc 0).

    Catches: the queue read moved ahead of the trees check, which the row count alone cannot
    see (a read leaves the queue as it was)."""
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "99")
    if how == "lane_trees":
        paths = LoopPaths(repo_root=_worktree(tmp_path), state_dir=tmp_path / "state")
        trees = lead_trees(paths)
    else:
        paths, trees = _refusing_trees(tmp_path)[how]()
    persist.append_pitfalls([pitfall_row("r:l-000:0", "elastic")], paths=paths)
    queue = paths.pitfalls.file
    spawn = Spawn()

    with trees, kernel_watch(reads=[queue], opens=[queue]) as events:
        got = outcome(lambda: pitfalls_curator.run_pitfalls(paths=paths, trees=trees,
                                                            invoke=spawn))
        seen = events()

    assert spawn.calls == []
    if how == "lane_trees":
        assert got == ("returned", 0), got
        assert seen, "the control never read its queue, so the watch proves nothing"
        return
    assert raised(got, "LeadAuthorError", ""), got
    assert seen == [], f"the queue was read before the trees were checked: {seen}"
