"""#1175 scene helpers for the lead-author lane's per-claim worktree commits (`ClaimGit`).

Its own cases were removed by #1108 P4 (slice S-D): they pinned `ClaimGit`'s worktree
commit/cleanup over the product repo, which P4 replaces with P3's git-free draft and
commit-maker. The helpers stay only because `test_1175_claim_session.py` and
`test_1175_adversary_holes.py` import them."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

import dataclasses
import json
import os
import shutil
import stat
import subprocess
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

import pytest

from defender._git import GitError
from defender.learning.core import drains, persist
from defender.learning.core.config import LEAD_AUTHOR_DRAIN_LABEL, LoopPaths
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


PYC = b"\x00\x0d\x0d\x0a not really bytecode"


ON_PATH = ["defender/.gitignore", "defender/skills/.gitignore",
           "defender/skills/elastic/.gitignore"]
#: Off the path to `skills/`, as the real repo commits several (`evaluations/.gitignore`).
OFF_PATH = "evaluations/.gitignore"


AFTER_AGENT = {"scope-check": READS, "commit": WRITES}


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


