from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

import dataclasses
import inspect
import json
import os
import shutil
import stat
import subprocess
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

import pytest

from defender.configuration._env import FatalConfigError
from defender._git import GitError
from defender.learning.author import _config
from defender.learning.core import drains, persist
from defender.learning.core.config import LEAD_AUTHOR_DRAIN_LABEL, LoopPaths
from defender.learning.core.faults import SYSTEMIC_FAULTS
from defender.learning.core.lane_trees import open_drain_trees
from defender.learning.leads import lead_author, pitfalls_curator
from defender.learning.leads.draft_synthesis import _draft_basename
from defender.learning.leads.lead_extraction import ExecutedLead, LeadAuthorError
from defender.learning.leads.pitfalls_curator import PitfallsDisposition
from defender import box as box_mod
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.learning.curation._curator1134 import plant_fifo
from defender.tests.support.learning.core._state1135 import curation_row, curation_run_dir, enqueue_case, state_for_paths
from defender.tests.support.runtime.engine._declared869 import (
    Spawn,
    commit_all,
    git,
    pitfall_row,
    seed_executed_query,
    seed_tree,
    write,
)
from defender.tests.support.learning.core._declared870 import consumed_by_id, curate_execution_md, graveyard_by_id
from defender.tests.support.sandbox._spec791 import (
    SpecBranch,
    author_markers,
    loop_paths,
    marker_body,
    noop_start_box,
    noop_stop_box,
)
from defender.tests.learning.curation.test_1134_curator_git_bounds import _Shim, _within
from defender.learning.core.state import PITFALLS

LEAD = LEAD_AUTHOR_DRAIN_LABEL

BOUND = 1.5
#: How long a stalled shim git sleeps: past `_within`'s 40-second deadline, so an unbounded call
#: fails the test at the deadline rather than answering late.
STALL_SECONDS = 60

#: Repo-relative spellings the commits and refusals are checked against.
SKILLS_REL = "defender/skills/"
#: A committed system-skill draft: the pending draft the lead-author agent is handed (lift
#: threshold 1), which it may edit or remove (no `covers:`, so a removal is admitted).
LIFT = "defender/skills/elastic/_draft/lift.md"
#: A new system-skill draft the agent writes.
NEW = "defender/skills/elastic/_draft/new.md"
#: The pitfalls surface the curator edits.
EXEC = "defender/skills/elastic/execution.md"
#: A new non-`.md` file under `skills/`: out of the lanes' scope.
STRAY = "defender/skills/elastic/stray.py"
#: A non-`.md` file already under `skills/` before the claim's baseline: tolerated by the scope
#: check (it is in the baseline), never admitted.
NOTES = "defender/skills/elastic/notes.txt"

LIFT_TEXT = "# lift\n\nA pending elastic skill draft.\n"
EDITED_LIFT = "# lift\n\nA pending elastic skill draft, edited by the agent.\n"

#: The rows the pitfalls scenes queue (threshold 1): one elastic mistake.
PID = "p:elastic:0"

#: The lead a mint-route claim executes: coined, so the lane mints a draft for it under the
#: catalog before its baseline, and that new `.md` is what the claim admits.
MINT_LEAD = ExecutedLead(
    lead_id="l-001", query_index=0, is_multi_query=False, entry_index=0,
    query_id="elastic.hunt-creds", system="elastic", verb="esql", params={"query": "FROM logs"},
    raw_command="cli", goal_text="probe the thing", what_to_summarize=(), raw_ref=None,
    payload_status="ok", payload_digest="2 bytes", error_class=None,
)
MINTED = f"defender/skills/gather/queries/elastic/_draft/{_draft_basename('elastic.hunt-creds')}.md"

#: A model name no provider routes: a scene through the DEFAULT seams that reaches the real agent
#: spawn raises `FatalConfigError` at its key lookup instead of calling a model.
NO_MODEL = "no-such-model-1175"

#: Subcommands that read what changed in the worktree (the baseline / scope-check reader,
#: however it is spelled), and those that write the index or the commit.
READS = frozenset({"status", "ls-files", "diff", "diff-files", "diff-index"})
WRITES = frozenset({"add", "commit", "rm", "update-index"})


def _worktree(base: Path, name: str = "wt-1", *, committed: dict[str, str] | None = None) -> Path:
    """A committed git repo standing in for the batch's `lead-author/<id>` worktree: elastic and
    wazuh declared (adapter + committed `execution.md`), the catalog, `LIFT` committed, and
    `skills/invlang` / `skills/connect` as the Python packages they are in the real tree. Its
    root `.gitignore` carries the real repo's Python rules (`__pycache__/`, `*.py[cod]`).
    `committed` adds more committed files, by repo-relative path."""
    repo = seed_tree(base, adapters=("elastic", "wazuh"), markers=("elastic", "wazuh"),
                     skills=("elastic",), catalog=("elastic", "wazuh"), name=name, commit=False)
    ignore = repo / ".gitignore"
    ignore.write_text(ignore.read_text(encoding="utf-8") + "__pycache__/\n*.py[cod]\n",
                      encoding="utf-8")
    write(repo / LIFT, LIFT_TEXT)
    write(repo / "defender/skills/invlang/__init__.py", "")
    write(repo / "defender/skills/connect/__init__.py", "")
    for rel, text in (committed or {}).items():
        write(repo / rel, text)
    commit_all(repo, "seed")
    return repo


class _Branch(SpecBranch):
    """The drain's batch lifecycle over worktrees built BEFORE the tick (so no fixture git meets a
    shim on `PATH`): `start_batch` hands out the next; `finish_batch` and `cleanup` are recorded
    (`cleanup` deletes nothing, so the tree can be read after the tick); `quarantine_dir` is where
    a tainted tree is archived."""

    def __init__(self, base: Path, *trees: Path) -> None:
        super().__init__(base)
        self._trees = list(trees)

    @property
    def quarantine_dir(self) -> Path:
        return self._base / "quarantine"

    def start_batch(self, batch_id: str) -> Path:
        self.events.append("start")
        return self._trees.pop(0)


class _LeadLane:
    """The lead-author work step handed to the drain as `run_lead_author`: the REAL lane
    (`lead_author.run(label=, deps=)`) under the lane's held trees, with only the agent spawn
    and `extract` (it hands back `leads`) replaced, run under the queue lock the drain holds for
    the tick. `replaced` swaps further deps fields in. The agent fake runs `edit(worktree)`
    and returns 0; `reached` records each spawn's handoffs and pending drafts."""

    def __init__(self, edit: Callable[[Path], None], *, leads: Iterable[ExecutedLead] = (),
                 **replaced: Any) -> None:
        self.edit = edit
        self.leads = list(leads)
        self.replaced = replaced
        self.reached: list[dict] = []

    def __call__(self, paths: LoopPaths, state: Any, run: Any, *, box: Any = None,
                 on_done: Callable[[str | None], None]) -> None:
        worktree = paths.repo_root
        run_dir = run.run_dir  # the drain hands the run it opened from the claim (#1105 PR 2)

        def agent(_run_dir, handoffs, pending_drafts=None, *, box=None, **_kw) -> int:
            self.reached.append({"handoffs": list(handoffs or []),
                                 "pending": [d["draft_path"] for d in pending_drafts or []]})
            self.edit(worktree)
            return 0

        with open_drain_trees(paths, LEAD) as trees:
            deps = dataclasses.replace(
                lead_author.build_lead_author_deps(paths, state=state, trees=trees),
                invoke_agent=agent,
                extract=lambda _run_dir: ([], list(self.leads)),
                **self.replaced,
            )
            # The drain holds the queue lock for the whole tick, so the lane runs under it, as
            # the drain's own default seam does (`run(deps=)` would take it again and skip).
            rc = lead_author._run_locked(run_dir, deps, box=box, on_done=on_done)
        if rc != 0:
            raise LeadAuthorError(f"lead-author for {run_dir.name} returned rc={rc}")


class _PitfallsLane:
    """The pitfalls work step handed to the drain as `run_pitfalls`: the REAL curation
    (`pitfalls_curator.run_pitfalls`) under the lane's held trees, with only the agent spawn
    replaced (`Spawn(edit)`, which runs `edit(worktree)` and records its handoffs). `kwargs` are
    passed to `run_pitfalls`."""

    def __init__(self, edit: Callable[[Path], None], **kwargs: Any) -> None:
        self.spawn = Spawn(edit)
        self.kwargs = kwargs

    def __call__(self, paths: LoopPaths, state: Any, *, box: Any = None,
                 on_curated: Callable[[PitfallsDisposition], None]) -> int:
        with open_drain_trees(paths, LEAD) as trees:
            return pitfalls_curator.run_pitfalls(paths=paths, state=state, trees=trees, invoke=self.spawn,
                                                 box=box, on_curated=on_curated, **self.kwargs)


def _no_curation(*_a: Any, **_kw: Any) -> int:
    return 0


def _no_claim(*_a: Any, **_kw: Any) -> None:
    raise AssertionError("no lead-author claim was queued, yet one was served")


def _edits(*fns: Callable[[Path], None]) -> Callable[[Path], None]:
    def edit(root: Path) -> None:
        for fn in fns:
            fn(root)

    return edit


def _put(rel: str, text: str) -> Callable[[Path], None]:
    return lambda root: write(root / rel, text)


def _remove(rel: str) -> Callable[[Path], None]:
    return lambda root: (root / rel).unlink()


def _fifo(rel: str) -> Callable[[Path], None]:
    return lambda root: plant_fifo(root / rel)


def _put_bytes(rel: str, data: bytes) -> Callable[[Path], None]:
    def edit(root: Path) -> None:
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_bytes(data)

    return edit


EDIT_LIFT = _put(LIFT, EDITED_LIFT)
CURATE = curate_execution_md("elastic")


@dataclasses.dataclass
class _Scene:
    tmp: Path
    paths: LoopPaths
    wt: Path
    branch: _Branch
    run_dirs: list[Path]
    queue_before: bytes | None

    @property
    def run_dir(self) -> Path:
        [only] = self.run_dirs
        return only


def _lead_scene(tmp: Path, monkeypatch: pytest.MonkeyPatch, *, cases: Iterable[str] = ("case-1",),
                committed: dict[str, str] | None = None, lift_threshold: bool = True) -> _Scene:
    """One lead-author claim per case queued (its run dir bare: the lane's `extract` is the
    fake's), over a fresh worktree. With `lift_threshold`, a single pending system draft (`LIFT`)
    is enough for the lane to hand it to the agent, so the claim reaches the agent."""
    if lift_threshold:
        monkeypatch.setenv("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", "1")
    paths = loop_paths(tmp)
    state = state_for_paths(paths)
    wt = _worktree(tmp / "worktrees", committed=committed)
    run_dirs = []
    for case in cases:
        # Where a natural run lives, so the drain can open the row's address (#1105 PR 2).
        run_dir = curation_run_dir(case)
        (run_dir / "gather_raw").mkdir(parents=True)
        enqueue_case(state, case, run_dir)
        run_dirs.append(run_dir)
    return _Scene(tmp, paths, wt, _Branch(tmp / "worktrees", wt), run_dirs, None)


def _pitfalls_scene(tmp: Path, monkeypatch: pytest.MonkeyPatch, *,
                    committed: dict[str, str] | None = None) -> _Scene:
    """One queued elastic pitfall at threshold 1, no lead-author claim, over a fresh worktree."""
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "1")
    paths = loop_paths(tmp)
    wt = _worktree(tmp / "worktrees", committed=committed)
    persist.append_pitfalls([pitfall_row(PID, "elastic")], state=state_for_paths(paths))
    return _Scene(tmp, paths, wt, _Branch(tmp / "worktrees", wt), [],
                  (location_path(paths.state_root) / PITFALLS.queue).read_bytes())


def _tick(sc: _Scene, *, run_lead_author: Any = None, run_pitfalls: Any = None,
          fifos: Iterable[Path] = (), shim: _Shim | None = None, what: str = "",
          **drain_kw: Any) -> tuple[str, Any]:
    """`drains.lead_author_drain` over the scene with the real scrub, under `_within`'s
    deadline: `("value", rc)` or `("raised", exc)`. A seam left `None` is the drain's default."""
    kw: dict[str, Any] = dict(branch=sc.branch, start_box=noop_start_box, stop_box=noop_stop_box,
                              scrub=box_mod.scrub, **drain_kw)
    if run_lead_author is not None:
        kw["run_lead_author"] = run_lead_author
    if run_pitfalls is not None:
        kw["run_pitfalls"] = run_pitfalls
    return _within(lambda: drains.lead_author_drain(sc.paths, **kw), fifos=list(fifos),
                   shim=shim, what=what)


def _stall_git(at: Path, patch: pytest.MonkeyPatch, stall: Iterable[str] = (), *,
               flag: Path | None = None) -> _Shim:
    """Put a `git` first on `PATH` that logs every invocation (in `_Shim`'s format) and runs the
    real git, except that an invocation whose SUBCOMMAND (its first non-option argument, `-c` /
    `-C` values skipped) is in `stall` stalls instead: `exec sleep STALL_SECONDS` in its own
    process, so a timeout's kill ends it, its pid recorded for `_Shim.kill_stalls` and its
    subcommand in `<at>/stalled`. With `flag`, only once that file exists (the agent fake writes
    it): the calls after the agent ran."""
    real = shutil.which("git")
    assert real is not None
    bin_dir = at / "bin"
    bin_dir.mkdir(parents=True)
    log, pids, count, stalled = at / "calls.log", at / "stalls.pids", at / "count", at / "stalled"
    gate = f"[ -e '{flag}' ] && ran=1" if flag is not None else "ran=1"
    words = " ".join(sorted(stall))
    script = f"""#!/bin/sh
n=$(( $(cat '{count}' 2>/dev/null || echo 0) + 1 ))
echo "$n" > '{count}'
ran=0; {gate}
printf '%s %s %s\\n' "$n" "$ran" "$*" >> '{log}'
sub=""; skip=0
for a in "$@"; do
  if [ "$skip" = 1 ]; then skip=0; continue; fi
  case "$a" in
    -c|-C) skip=1 ;;
    -*) ;;
    *) sub="$a"; break ;;
  esac
done
case " {words} " in
  *" $sub "*)
    if [ -n "$sub" ] && [ "$ran" = 1 ]; then
      echo "$$" >> '{pids}'; echo "$sub" >> '{stalled}'; exec sleep {STALL_SECONDS}
    fi ;;
esac
exec "{real}" "$@"
"""
    shim = bin_dir / "git"
    shim.write_text(script, encoding="utf-8")
    shim.chmod(0o755)
    patch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")
    return _Shim(log=log, pids=pids)


def _stalled(shim: _Shim) -> list[str]:
    """The subcommands the shim stalled, in order."""
    at = shim.log.parent / "stalled"
    return at.read_text(encoding="utf-8").split() if at.is_file() else []


def _inflight(paths: LoopPaths) -> dict[str, dict]:
    d = location_path(paths.state_root) / "author-queue" / "inflight"
    return {p.name: marker_body(p) for p in sorted(d.glob("*.json"))} if d.is_dir() else {}


def _failed(paths: LoopPaths) -> list[dict]:
    d = location_path(paths.state_root) / "author-queue" / "failed"
    return [json.loads(p.read_text(encoding="utf-8")) for p in sorted(d.glob("*.json"))] \
        if d.is_dir() else []


def _is_fifo(at: Path) -> bool:
    return os.path.lexists(at) and stat.S_ISFIFO(os.lstat(at).st_mode)


def _commits(wt: Path) -> int:
    return int(git(wt, "rev-list", "--count", "HEAD").stdout)


def _head_changes(wt: Path) -> set[str]:
    """HEAD's own changes as `"<status>\\t<path>"` (no rename pairing)."""
    out = git(wt, "show", "--no-renames", "--name-status", "--format=", "HEAD").stdout
    return {line for line in out.splitlines() if line}


def _done_sha(run_dir: Path) -> str | None:
    done = run_dir / "lead_author" / "done"
    if not done.is_file():
        return None
    first = done.read_text(encoding="utf-8").splitlines()[0]
    assert first.startswith("commit: "), first
    return first[len("commit: "):]


def _head_sha(wt: Path) -> str:
    return git(wt, "rev-parse", "HEAD").stdout.strip()


def _is_systemic_git_fault(e: BaseException) -> bool:
    """A git fault the drains route as systemic: a `GitError`, never a `SubprocessError` (which
    `_run_curator_module` swallows into a retry / rc 0)."""
    return isinstance(e, GitError) and not isinstance(e, subprocess.SubprocessError)


def _assert_lead_claim_held(sc: _Scene, case: str = "case-1") -> None:
    """The claim was served once and not consumed, dead-lettered or re-queued: it waits in
    `inflight/` with its one attempt for the next tick's reclaim, its run not recorded done."""
    [run_dir] = [d for d in sc.run_dirs if d.name == fixture_uuid(case)]
    assert _inflight(sc.paths) == {f"{case}.json": {
        **curation_row(case, run_dir), "attempts": 1}}, _inflight(sc.paths)
    assert _failed(sc.paths) == [], "the claim was dead-lettered"
    assert author_markers(sc.paths) == [], "the claim was re-queued"
    assert _done_sha(run_dir) is None


def _assert_lead_served(sc: _Scene, changes: set[str]) -> None:
    """The tick landed: the claim consumed, its run recorded done with the batch's one new
    commit, which carries exactly `changes`."""
    assert _inflight(sc.paths) == {}
    assert _failed(sc.paths) == []
    assert author_markers(sc.paths) == []
    assert _commits(sc.wt) == 2, "the claim did not commit exactly once"
    assert _done_sha(sc.run_dir) == _head_sha(sc.wt)
    assert _head_changes(sc.wt) == changes
    assert "finish" in sc.branch.events


def _assert_rows_untouched(sc: _Scene) -> None:
    assert sc.queue_before is not None
    assert (location_path(sc.paths.state_root) / PITFALLS.queue).read_bytes() == sc.queue_before, "a queued row was rewritten"
    assert consumed_by_id(sc.paths) == {}
    assert graveyard_by_id(sc.paths) == {}


def _assert_rows_consumed(sc: _Scene, changes: set[str]) -> None:
    assert _commits(sc.wt) == 2, "the curation did not commit exactly once"
    assert _head_changes(sc.wt) == changes
    consumed = consumed_by_id(sc.paths)
    assert consumed[PID]["consumed_category"] == "consumed_committed"
    assert consumed[PID]["consumed_commit"] == _head_sha(sc.wt)
    assert persist.read_pitfalls(state_for_paths(sc.paths)) == []
    assert "finish" in sc.branch.events


def _assert_tainted_by(got: tuple[str, Any], fifo: Path) -> None:
    """The tick ended in the scrub's refusal of the FIFO, and in nothing else: the claim's own
    work raised nothing (the taint carries no context) and the FIFO still stands."""
    result, exc = got
    assert result == "raised", got
    assert isinstance(exc, box_mod.RunTainted), repr(exc)
    assert exc.__context__ is None, f"the claim's work failed before the scrub: {exc.__context__!r}"
    assert [(f.path, f.filemode) for f in exc.findings] == [(fifo, "p")], exc.findings
    assert _is_fifo(fifo), "the FIFO was removed"


#: Where the agent leaves a FIFO: at the mount's root, and in the system folder every edited
#: path of these scenes lies under (so the FIFO is on each path git walks or hashes).
FIFO_SITES = [
    pytest.param(f"{SKILLS_REL}{where}{name}", id=f"skills/{where}{name}")
    for name in (".gitignore", ".gitattributes")
    for where in ("", "elastic/")
]


@pytest.mark.parametrize("site", FIFO_SITES)
def test_t1_t2_a_fifo_the_lead_author_agent_leaves_hangs_nothing_and_the_scrub_refuses_it(
    tmp_path, monkeypatch, site,
):
    sc = _lead_scene(tmp_path, monkeypatch)
    fifo = sc.wt / site
    lane = _LeadLane(_edits(EDIT_LIFT, _fifo(site)))

    got = _tick(sc, run_lead_author=lane, run_pitfalls=_no_curation, fifos=[fifo], what=site)

    assert [r["pending"] for r in lane.reached] == [[LIFT]], "the claim never reached the agent"
    _assert_tainted_by(got, fifo)
    _assert_lead_claim_held(sc)
    assert "finish" not in sc.branch.events
    fifo.unlink()  # observed; the test's own git reads below must not meet it
    assert _commits(sc.wt) == 2
    assert _head_changes(sc.wt) == {f"M\t{LIFT}"}


@pytest.mark.parametrize("site", FIFO_SITES)
def test_t1_t2_a_fifo_the_pitfalls_agent_leaves_hangs_nothing_and_the_scrub_refuses_it(
    tmp_path, monkeypatch, site,
):
    sc = _pitfalls_scene(tmp_path, monkeypatch)
    fifo = sc.wt / site
    lane = _PitfallsLane(_edits(CURATE, _fifo(site)))

    got = _tick(sc, run_lead_author=_no_claim, run_pitfalls=lane, fifos=[fifo], what=site)

    assert len(lane.spawn.calls) == 1, "the curation never reached the agent"
    _assert_tainted_by(got, fifo)
    _assert_rows_untouched(sc)
    assert "finish" not in sc.branch.events
    fifo.unlink()
    assert _commits(sc.wt) == 2
    assert _head_changes(sc.wt) == {f"M\t{EXEC}"}


def test_t1_control_the_same_lead_author_claim_without_a_plant_lands(tmp_path, monkeypatch):
    """T1's positive control at the same address: the same edit, no FIFO. The tick lands (rc 0):
    the claim consumed and its run recorded done with the commit carrying exactly `M LIFT`."""
    sc = _lead_scene(tmp_path, monkeypatch)

    got = _tick(sc, run_lead_author=_LeadLane(EDIT_LIFT), run_pitfalls=_no_curation)

    assert got == ("value", 0), got
    _assert_lead_served(sc, {f"M\t{LIFT}"})


def test_t1_control_the_same_curation_without_a_plant_lands(tmp_path, monkeypatch):
    """T1's positive control, pitfalls: the same edit, no FIFO. The row is consumed as
    `consumed_committed` against the commit, which carries exactly `M EXEC`."""
    sc = _pitfalls_scene(tmp_path, monkeypatch)

    got = _tick(sc, run_lead_author=_no_claim, run_pitfalls=_PitfallsLane(CURATE))

    assert got == ("value", 0), got
    _assert_rows_consumed(sc, {f"M\t{EXEC}"})


@pytest.mark.parametrize("site", FIFO_SITES)
def test_t1b_a_new_draft_commits_past_a_fifo_on_its_path(tmp_path, monkeypatch, site):
    sc = _lead_scene(tmp_path, monkeypatch)
    fifo = sc.wt / site
    lane = _LeadLane(_edits(_put(NEW, "# new\n\nA new elastic skill draft.\n"), _fifo(site)))

    got = _tick(sc, run_lead_author=lane, run_pitfalls=_no_curation, fifos=[fifo], what=site)

    assert len(lane.reached) == 1
    _assert_tainted_by(got, fifo)
    _assert_lead_claim_held(sc)
    fifo.unlink()
    assert _commits(sc.wt) == 2
    assert _head_changes(sc.wt) == {f"A\t{NEW}"}


def test_t1b_the_minted_draft_commits_past_a_fifo_at_the_mount_root(tmp_path, monkeypatch):
    sc = _lead_scene(tmp_path, monkeypatch, lift_threshold=False)
    site = f"{SKILLS_REL}.gitignore"
    fifo = sc.wt / site
    lane = _LeadLane(_fifo(site), leads=[MINT_LEAD])

    got = _tick(sc, run_lead_author=lane, run_pitfalls=_no_curation, fifos=[fifo], what=site)

    assert len(lane.reached) == 1
    _assert_tainted_by(got, fifo)
    _assert_lead_claim_held(sc)
    fifo.unlink()
    assert _commits(sc.wt) == 2
    assert _head_changes(sc.wt) == {f"A\t{MINTED}"}


STAR = "*\n"
PLAINS = {
    # name: (the agent's extra writes, the non-`.md` new paths the refusal must name)
    "none": ({}, ()),
    "stray": ({STRAY: "print('x')\n"}, (STRAY,)),
    "star": ({f"{SKILLS_REL}.gitignore": STAR}, (f"{SKILLS_REL}.gitignore",)),
    "star+stray": ({f"{SKILLS_REL}.gitignore": STAR, STRAY: "print('x')\n"},
                   (f"{SKILLS_REL}.gitignore", STRAY)),
    "nested-star+stray": ({f"{SKILLS_REL}elastic/.gitignore": STAR, STRAY: "print('x')\n"},
                          (f"{SKILLS_REL}elastic/.gitignore", STRAY)),
}


@pytest.mark.parametrize("plant", list(PLAINS))
def test_t3_a_plain_star_gitignore_hides_nothing_from_the_lead_author_scope_check(
    tmp_path, monkeypatch, plant,
):
    writes, named = PLAINS[plant]
    sc = _lead_scene(tmp_path, monkeypatch)
    lane = _LeadLane(_edits(EDIT_LIFT, *(_put(rel, text) for rel, text in writes.items())))

    got = _tick(sc, run_lead_author=lane, run_pitfalls=_no_curation)

    assert got == ("value", 0), got
    assert len(lane.reached) == 1
    if not named:
        _assert_lead_served(sc, {f"M\t{LIFT}"})
        return
    [failed] = _failed(sc.paths)
    reason = failed["failed"]
    assert reason.startswith("lead-author-error: LeadAuthorError("), reason
    for rel in named:
        assert rel in reason, (rel, reason)
    assert _commits(sc.wt) == 1, "the refused claim committed"
    assert _inflight(sc.paths) == {}
    assert author_markers(sc.paths) == []
    assert _done_sha(sc.run_dir) is None


@pytest.mark.parametrize("plant", ["none", "stray", "star+stray"])
def test_t3_a_plain_star_gitignore_hides_nothing_from_the_pitfalls_scope_check(
    tmp_path, monkeypatch, plant,
):
    monkeypatch.setenv("LEARNING_AUTHOR_MAX_ATTEMPTS", "1")
    writes, named = PLAINS[plant]
    sc = _pitfalls_scene(tmp_path, monkeypatch)
    lane = _PitfallsLane(_edits(CURATE, *(_put(rel, text) for rel, text in writes.items())))

    got = _tick(sc, run_lead_author=_no_claim, run_pitfalls=lane)

    assert got == ("value", 0), got
    assert len(lane.spawn.calls) == 1
    if not named:
        _assert_rows_consumed(sc, {f"M\t{EXEC}"})
        return
    graveyard = graveyard_by_id(sc.paths)
    assert PID in graveyard, f"the batch was not retired; consumed: {consumed_by_id(sc.paths)}"
    reason = graveyard[PID]["deadletter_reason"]
    assert reason.startswith("batch-error:LeadAuthorError"), reason
    for rel in named:
        assert rel in reason, (rel, reason)
    assert _commits(sc.wt) == 1, "the refused curation committed"
    assert persist.read_pitfalls(state_for_paths(sc.paths)) == []


PYC = b"\x00\x0d\x0d\x0a not really bytecode"


@pytest.mark.parametrize("package", ["invlang", "connect"])
def test_t4_a_pycache_made_during_the_lead_author_claim_is_no_stray(
    tmp_path, monkeypatch, package,
):
    sc = _lead_scene(tmp_path, monkeypatch)
    pyc = f"{SKILLS_REL}{package}/__pycache__/__init__.cpython-312.pyc"

    got = _tick(sc, run_lead_author=_LeadLane(_edits(EDIT_LIFT, _put_bytes(pyc, PYC))),
                run_pitfalls=_no_curation)

    assert got == ("value", 0), got
    _assert_lead_served(sc, {f"M\t{LIFT}"})


def test_t4_a_pycache_made_during_the_curation_is_no_stray(tmp_path, monkeypatch):
    """T4 (O5), pitfalls: the same `.pyc` under `skills/invlang` during the curation; the row is
    consumed against a commit of exactly `M EXEC`."""
    sc = _pitfalls_scene(tmp_path, monkeypatch)
    pyc = f"{SKILLS_REL}invlang/__pycache__/__init__.cpython-312.pyc"

    got = _tick(sc, run_lead_author=_no_claim,
                run_pitfalls=_PitfallsLane(_edits(CURATE, _put_bytes(pyc, PYC))))

    assert got == ("value", 0), got
    _assert_rows_consumed(sc, {f"M\t{EXEC}"})


ON_PATH = ["defender/.gitignore", "defender/skills/.gitignore",
           "defender/skills/elastic/.gitignore"]
#: Off the path to `skills/`, as the real repo commits several (`evaluations/.gitignore`).
OFF_PATH = "evaluations/.gitignore"


@pytest.mark.parametrize("committed", [*ON_PATH, OFF_PATH])
def test_a_gitignore_committed_on_the_path_to_skills_is_a_systemic_refusal(
    tmp_path, monkeypatch, committed,
):
    sc = _lead_scene(tmp_path, monkeypatch, committed={committed: "*.tmp\n"})

    got = _tick(sc, run_lead_author=_LeadLane(EDIT_LIFT), run_pitfalls=_no_curation)

    if committed == OFF_PATH:
        assert got == ("value", 0), got
        _assert_lead_served(sc, {f"M\t{LIFT}"})
        return
    result, exc = got
    assert result == "raised", got
    assert isinstance(exc, SYSTEMIC_FAULTS), repr(exc)
    assert not isinstance(exc, box_mod.RunTainted), repr(exc)
    _assert_lead_claim_held(sc)
    assert _commits(sc.wt) == 1
    assert "finish" not in sc.branch.events


@pytest.mark.parametrize("committed", ["defender/skills/.gitignore", OFF_PATH])
def test_a_gitignore_committed_inside_skills_is_a_systemic_refusal_for_the_curation(
    tmp_path, monkeypatch, committed,
):
    sc = _pitfalls_scene(tmp_path, monkeypatch, committed={committed: "*.tmp\n"})

    got = _tick(sc, run_lead_author=_no_claim, run_pitfalls=_PitfallsLane(CURATE))

    if committed == OFF_PATH:
        assert got == ("value", 0), got
        _assert_rows_consumed(sc, {f"M\t{EXEC}"})
        return
    result, exc = got
    assert result == "raised", got
    assert isinstance(exc, SYSTEMIC_FAULTS), repr(exc)
    assert not isinstance(exc, box_mod.RunTainted), repr(exc)
    _assert_rows_untouched(sc)
    assert _commits(sc.wt) == 1
    assert "finish" not in sc.branch.events


@pytest.mark.parametrize("stall", [True, False], ids=["stalled", "control"])
def test_t5_an_overrun_through_the_default_lead_author_seam_is_systemic(
    tmp_path, monkeypatch, stall,
):
    monkeypatch.setenv("LEAD_AUTHOR_MODEL", NO_MODEL)
    monkeypatch.delenv("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", raising=False)
    sc = _lead_scene(tmp_path, monkeypatch, lift_threshold=False)
    seed_executed_query(sc.run_dir, query_id="wazuh.search", system="wazuh", verb="search")

    with monkeypatch.context() as patch:
        shim = _stall_git(tmp_path / "git-shim", patch, READS if stall else ())
        got = _tick(sc, shim=shim, git_timeout=BOUND)

    if not stall:
        assert got == ("value", 0), got
        assert _done_sha(sc.run_dir) == "none"
        assert _inflight(sc.paths) == {}
        assert _failed(sc.paths) == []
        assert "finish" in sc.branch.events
        return
    result, exc = got
    assert result == "raised", got
    assert _is_systemic_git_fault(exc), repr(exc)
    assert _stalled(shim), "nothing was stalled: the overrun under test never happened"
    _assert_lead_claim_held(sc)
    assert "finish" not in sc.branch.events


@pytest.mark.parametrize("stall", [True, False], ids=["stalled", "control"])
def test_t5_an_overrun_through_the_default_pitfalls_seam_is_systemic(
    tmp_path, monkeypatch, stall,
):
    monkeypatch.setenv("LEAD_AUTHOR_MODEL", NO_MODEL)
    sc = _pitfalls_scene(tmp_path, monkeypatch)

    with monkeypatch.context() as patch:
        shim = _stall_git(tmp_path / "git-shim", patch, READS if stall else ())
        got = _tick(sc, shim=shim, git_timeout=BOUND)

    result, exc = got
    assert result == "raised", got
    if stall:
        assert _is_systemic_git_fault(exc), repr(exc)
        assert _stalled(shim), "nothing was stalled: the overrun under test never happened"
    else:
        assert isinstance(exc, FatalConfigError), repr(exc)
        assert NO_MODEL in str(exc), repr(exc)
    _assert_rows_untouched(sc)
    assert "finish" not in sc.branch.events


AFTER_AGENT = {"scope-check": READS, "commit": WRITES}


@pytest.mark.parametrize("stall", [*AFTER_AGENT, None], ids=[*AFTER_AGENT, "control"])
def test_t5_an_overrun_after_the_lead_author_agent_is_systemic(tmp_path, monkeypatch, stall):
    sc = _lead_scene(tmp_path, monkeypatch)
    flag = tmp_path / "agent-ran"
    lane = _LeadLane(_edits(EDIT_LIFT, lambda _root: flag.write_text("")), git_timeout=BOUND)

    with monkeypatch.context() as patch:
        shim = _stall_git(tmp_path / "git-shim", patch, AFTER_AGENT.get(stall or "", ()),
                          flag=flag)
        got = _tick(sc, run_lead_author=lane, run_pitfalls=_no_curation, shim=shim)

    assert len(lane.reached) == 1
    if stall is None:
        assert got == ("value", 0), got
        _assert_lead_served(sc, {f"M\t{LIFT}"})
        return
    result, exc = got
    assert result == "raised", got
    assert _is_systemic_git_fault(exc), repr(exc)
    assert _stalled(shim), "nothing was stalled: the overrun under test never happened"
    _assert_lead_claim_held(sc)
    assert _commits(sc.wt) == 1


@pytest.mark.parametrize("stall", [*AFTER_AGENT, None], ids=[*AFTER_AGENT, "control"])
def test_t5_an_overrun_after_the_pitfalls_agent_is_systemic(tmp_path, monkeypatch, stall):
    sc = _pitfalls_scene(tmp_path, monkeypatch)
    flag = tmp_path / "agent-ran"
    lane = _PitfallsLane(_edits(CURATE, lambda _root: flag.write_text("")), git_timeout=BOUND)

    with monkeypatch.context() as patch:
        shim = _stall_git(tmp_path / "git-shim", patch, AFTER_AGENT.get(stall or "", ()),
                          flag=flag)
        got = _tick(sc, run_lead_author=_no_claim, run_pitfalls=lane, shim=shim)

    assert len(lane.spawn.calls) == 1
    if stall is None:
        assert got == ("value", 0), got
        _assert_rows_consumed(sc, {f"M\t{EXEC}"})
        return
    result, exc = got
    assert result == "raised", got
    assert _is_systemic_git_fault(exc), repr(exc)
    assert _stalled(shim), "nothing was stalled: the overrun under test never happened"
    _assert_rows_untouched(sc)
    assert _commits(sc.wt) == 1


CLEANUP = ["reset", "clean"]


def _raising(fault: BaseException) -> Callable[..., Any]:
    def step(*_a: Any, **_kw: Any) -> Any:
        raise fault

    return step


def _serving(served: list[Path]) -> Callable[..., None]:
    """A `run_lead_author` that serves a claim cleanly with no git of its own: recorded done,
    no commit."""

    def serve(_paths, _state, run, *, box=None, on_done):
        served.append(run.run_dir)
        on_done(None)

    return serve


def _curating(_paths, _state, *, box=None, on_curated) -> int:
    """A `run_pitfalls` that curates cleanly with no git of its own: the queued row committed
    (as a stand-in sha), handed to the drain to consume after the scrub."""
    on_curated(PitfallsDisposition(committed_ids=(PID,), sha="abc1175", held_ids=()))
    return 0


@pytest.mark.parametrize("stall", [*CLEANUP, None], ids=[*CLEANUP, "control"])
def test_t5b_a_cleanup_overrun_under_a_lead_author_fault_keeps_that_fault(
    tmp_path, monkeypatch, stall,
):
    sc = _lead_scene(tmp_path, monkeypatch)
    fault = GitError(["status"], 128, "the claim's own git fault")

    with monkeypatch.context() as patch:
        shim = _stall_git(tmp_path / "git-shim", patch, [stall] if stall else ())
        got = _tick(sc, run_lead_author=_raising(fault), run_pitfalls=_no_curation, shim=shim,
                    git_timeout=BOUND)

    assert got[0] == "raised", got
    assert got[1] is fault, got
    assert _stalled(shim) == ([stall] if stall else []), _stalled(shim)
    _assert_lead_claim_held(sc)


@pytest.mark.parametrize("stall", [*CLEANUP, None], ids=[*CLEANUP, "control"])
def test_t5b_a_cleanup_overrun_after_a_clean_claim_ends_the_tick(tmp_path, monkeypatch, stall):
    sc = _lead_scene(tmp_path, monkeypatch, cases=("case-a", "case-b"))
    served: list[Path] = []

    with monkeypatch.context() as patch:
        shim = _stall_git(tmp_path / "git-shim", patch, [stall] if stall else ())
        got = _tick(sc, run_lead_author=_serving(served), run_pitfalls=_no_curation, shim=shim,
                    git_timeout=BOUND)

    run_a, run_b = sc.run_dirs
    if stall is None:
        assert got == ("value", 0), got
        assert served == [run_a, run_b]
        assert _inflight(sc.paths) == {}
        assert author_markers(sc.paths) == []
        assert _done_sha(run_a) == "none"
        assert _done_sha(run_b) == "none"
        return
    result, exc = got
    assert result == "raised", got
    assert _is_systemic_git_fault(exc), repr(exc)
    assert _stalled(shim) == [stall], _stalled(shim)
    assert served == [run_a], "the next claim was served over the first one's leftovers"
    assert _inflight(sc.paths) == {"case-a.json": {
        **curation_row("case-a", run_a), "attempts": 1}}, _inflight(sc.paths)
    assert author_markers(sc.paths) == ["case-b.json"]
    assert marker_body(location_path(sc.paths.state_root) / "author-queue" / "case-b.json") == \
        curation_row("case-b", run_b)
    assert _failed(sc.paths) == []
    assert _done_sha(run_a) is None
    assert "finish" not in sc.branch.events


@pytest.mark.parametrize("stall", [*CLEANUP, None], ids=[*CLEANUP, "control"])
def test_t5b_a_cleanup_overrun_after_a_clean_curation_ends_the_tick(
    tmp_path, monkeypatch, stall,
):
    sc = _pitfalls_scene(tmp_path, monkeypatch)

    with monkeypatch.context() as patch:
        shim = _stall_git(tmp_path / "git-shim", patch, [stall] if stall else ())
        got = _tick(sc, run_lead_author=_no_claim, run_pitfalls=_curating, shim=shim,
                    git_timeout=BOUND)

    if stall is None:
        assert got == ("value", 0), got
        assert consumed_by_id(sc.paths)[PID]["consumed_commit"] == "abc1175"
        assert "finish" in sc.branch.events
        return
    result, exc = got
    assert result == "raised", got
    assert _is_systemic_git_fault(exc), repr(exc)
    assert _stalled(shim) == [stall], _stalled(shim)
    _assert_rows_untouched(sc)
    assert "finish" not in sc.branch.events


@pytest.mark.parametrize("stall", ["clean", None], ids=["clean", "control"])
def test_t5b_a_cleanup_overrun_under_a_curation_fault_keeps_that_fault(
    tmp_path, monkeypatch, stall,
):
    sc = _pitfalls_scene(tmp_path, monkeypatch)
    fault = GitError(["status"], 128, "the curation's own git fault")

    with monkeypatch.context() as patch:
        shim = _stall_git(tmp_path / "git-shim", patch, [stall] if stall else ())
        got = _tick(sc, run_lead_author=_no_claim, run_pitfalls=_raising(fault), shim=shim,
                    git_timeout=BOUND)

    assert got[0] == "raised", got
    assert got[1] is fault, got
    assert _stalled(shim) == ([stall] if stall else []), _stalled(shim)
    _assert_rows_untouched(sc)


@pytest.mark.parametrize("stray", [False, True], ids=["control", "baseline-stray"])
def test_t6_the_lead_author_commit_is_exactly_what_the_check_admitted(
    tmp_path, monkeypatch, stray,
):
    sc = _lead_scene(tmp_path, monkeypatch)
    if stray:
        write(sc.wt / NOTES, "left here before the claim\n")
    lane = _LeadLane(_edits(_remove(LIFT), _put(NEW, "# new\n\nA new elastic skill draft.\n")))

    got = _tick(sc, run_lead_author=lane, run_pitfalls=_no_curation)

    assert got == ("value", 0), got
    assert [r["pending"] for r in lane.reached] == [[LIFT]]
    _assert_lead_served(sc, {f"D\t{LIFT}", f"A\t{NEW}"})


@pytest.mark.parametrize("stray", [False, True], ids=["control", "baseline-stray"])
def test_t6_the_curation_commit_is_exactly_what_the_check_admitted(
    tmp_path, monkeypatch, stray,
):
    """T6 (O4, M2), pitfalls: with `NOTES` standing under `skills/` before the curation's
    baseline (`baseline-stray`), the commit still carries exactly `M EXEC`."""
    sc = _pitfalls_scene(tmp_path, monkeypatch)
    if stray:
        write(sc.wt / NOTES, "left here before the curation\n")

    got = _tick(sc, run_lead_author=_no_claim, run_pitfalls=_PitfallsLane(CURATE))

    assert got == ("value", 0), got
    _assert_rows_consumed(sc, {f"M\t{EXEC}"})


def test_the_lanes_default_bound_is_the_curators_sixty_seconds(tmp_path):
    assert _config.GIT_TIMEOUT_SECONDS == 60.0
    assert inspect.signature(drains.lead_author_drain).parameters["git_timeout"].default \
        == _config.GIT_TIMEOUT_SECONDS
    assert inspect.signature(pitfalls_curator.run_pitfalls).parameters["git_timeout"].default \
        == _config.GIT_TIMEOUT_SECONDS
    wt = _worktree(tmp_path)
    paths = LoopPaths(repo_root=wt, state_dir=tmp_path / "state")
    state = state_for_paths(paths)
    with open_drain_trees(paths, LEAD) as trees:
        assert lead_author.build_lead_author_deps(paths, state=state, trees=trees).git_timeout \
            == _config.GIT_TIMEOUT_SECONDS
