"""#1178: the lead-author lane commits exactly what its gate judged.

Today both committers of the lane (the per-claim lead-author commit and the pitfalls commit) run
their gate over the working tree, then `commit_corpus` runs `git add -- defender/skills` and
`git commit -- defender/skills`, which re-reads the working tree at commit time (C3). The box is
still up, so anything a box process writes under `skills/` after the gate read it lands unvetted:
a new path, a rewrite of a vetted file, a swap to a link. The design (the issue's "Intent +
design" comment) closes it: the gate runs as today (first pass), exactly its candidates are
staged, the staged set is checked against them (paths, kinds, regular-file modes only), the
staged `skills/` tree is copied to a host-private snapshot, the same rules run again over the
snapshot (second pass, binding), and the index is committed with no pathspec (C2), every git call
under `_git.committed_view_env()`.

The seam this file drives: `_lead_spine.commit_judged(..., step=)`, reached through
`LeadAuthorDeps.gate_step` and `pitfalls_curator.run_pitfalls(gate_step=)`. It is called with
"judged", "staged", "snapshotted" and "rejudged", in that order; a test plays "a box process is
still writing" by mutating the worktree inside it at a named step.

- O1: at every step, every mutation (bad bytes into the vetted file, a new `.md` and a new non-`.md`,
  a symlink swap, a UTF-7 `.gitattributes`, a FIFO `.gitattributes`, a FIFO `.gitignore` in
  `skills/` or in the candidate's folder): the commit holds exactly the vetted bytes at 100644
  and no other path, or the run refuses with HEAD unchanged. Never the mutated content. Positive
  control: no mutation, so the commit holds the plain bytes. The same holds with no hook at all
  (production's deps), git's own `post-index-change` hook playing the box; and for writes the
  second pass must see (staged bad bytes, then the disk restored), for an embedded repository at
  a candidate's name (a gitlink), for a judged delete re-created before staging, and for a
  folded template whose identity or `covers:` is rewritten after the first pass (the batch
  rules run on the second pass too). The snapshot never appears under the worktree.
- O2: a symlink at a catalog draft, a system-skill draft or a `queries/<sys>/README.md`, left by
  the agent, is refused (each commits as mode 120000 today, C1); a plain file there commits, and
  an executable one commits as 100755 (C8).
- O3: staging that does not match the candidates (a candidate gone, now a FIFO, now a folder,
  or something else already staged) is refused; a vanished candidate is a claim refusal
  (`LeadAuthorError`, dead-lettered), never a `GitError` (which halts the whole drain).
- O4: a link present before the gate gets today's message, from the first pass, before anything
  is staged; a second-pass refusal names the path as the worktree spells it; a draft discard an
  untouched template covers still commits (the snapshot holds the whole catalog).
- Renames: a promote (draft deleted, near-identical established file added) still commits, as a
  delete plus an add (C14).
- `commit_judged` alone: the commit holds the bytes the second pass read, whatever is on disk
  by then (C2/C3, D1).
- D4 census: neither committer references a pathspec committer; both reference `commit_judged`;
  `commit_judged` itself (and what it calls) references none, and its `git commit` carries no
  pathspec.

Faults enter through injection seams (`deps`, `invoke=`, the hook); git, the filesystem, links
and FIFOs are real. Linux only in practice (FIFOs, the inotify watch).
"""
from __future__ import annotations

import ast
import contextlib
import dataclasses
import os
import shlex
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from defender import _git
from defender.learning.core import faults, persist
from defender.learning.core.config import LEAD_AUTHOR_DRAIN_LABEL, LoopPaths
from defender.learning.core.lane_trees import read_at
from defender.learning.leads import _lead_spine, lead_author, pitfalls_curator
from defender.learning.leads.lead_extraction import ExecutedLead, LeadAuthorError
from defender.tests._by_path import import_lint_lib
from defender.tests._declared869 import LeadAuthorSpawn, Spawn
from defender.tests._declared870 import (
    REDUCER_REL,
    reducer_surface_text,
    shim_row,
    write_reducer_surface,
)
from defender.tests._lead_author_1134 import clear, lead_trees, write
from defender.tests._repo import build_once_copy, query_template, seed_skills_repo
from defender.tests._shared_readers_1134 import kernel_watch

LEAD = LEAD_AUTHOR_DRAIN_LABEL

#: The gate-step hook's names, in the order the pinned interface calls them.
STEPS = ("judged", "staged", "snapshotted", "rejudged")

#: A hung git call (a FIFO opened as `.gitattributes`) fails the row after this long.
DEADLINE = 20.0

ATTRS_REL = "defender/skills/.gitattributes"
IGNORE_REL = "defender/skills/.gitignore"

#: `${evil}` spelled in UTF-7 (C13's probe): a literal string as raw bytes, the undeclared
#: placeholder `${evil}` once decoded under a `working-tree-encoding=UTF-7` attribute.
U7_EVIL = "+ACQAew-evil+AH0-"
#: `"\n## "` in UTF-7, then `Evil`: raw, part of one bullet; decoded, a new `## Evil` section the
#: pitfalls content rule refuses (an added line outside `## Common pitfalls`).
U7_SECTION = "+AAoAIwAj- Evil"

#: A lead whose `query_id` the seeded catalog answers (`wazuh/auth-events.md`): the handoff
#: resolves, so the agent is reached, and no draft is minted, so the agent's own edit is the
#: whole candidate set.
CATALOGUED_LEAD = ExecutedLead(
    lead_id="l-001", query_index=0, is_multi_query=False, entry_index=0,
    query_id="wazuh.auth-events", system="wazuh", verb="search", params={"index": "x"},
    raw_command="cli", goal_text="probe the thing", what_to_summarize=(), raw_ref=None,
    payload_status="ok", payload_digest="2 bytes", error_class=None,
)


@pytest.fixture(autouse=True)
def _pitfalls_lane_opens(monkeypatch):
    """One queued mistake opens the pitfalls lane (three identical reducer rows merge into one)."""
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "1")


# ---------------------------------------------------------------------------------------
# The tree, the hook, and the two lanes driven through their real entry points
# ---------------------------------------------------------------------------------------


def _build_seed(repo: Path) -> None:
    """`seed_skills_repo` (a wazuh adapter with real verbs, a catalog with an established
    template and a draft, an elastic SKILL.md and skill draft), plus the reducer surface the
    pitfalls lane amends, committed."""
    seed_skills_repo(repo)
    write_reducer_surface(repo)
    _git.git(["add", "-A"], cwd=repo)
    _git.git(["commit", "-q", "-m", "seed the reducer surface"], cwd=repo)


def _seeded(tmp_path: Path) -> Path:
    """The seed at `tmp_path / "repo"`, built once per process and copied."""
    return build_once_copy("seed_1178", _build_seed, tmp_path / "repo")


def _g(repo: Path, *args: str) -> str:
    """A read-only git question about `repo`, asked as the committed tree has it (no worktree
    `.gitattributes`, which may be a planted FIFO) and bounded."""
    return _git.git(list(args), cwd=repo, env=_git.committed_view_env(), timeout=10)


def _staged_names(repo: Path) -> list[str]:
    """What the index holds that HEAD does not, by name."""
    out = _g(repo, "diff-index", "--cached", "--name-only", "-z", "HEAD")
    return sorted(p for p in out.split("\0") if p)


class GateSteps:
    """The `gate_step` hook: records each step name and, at step `at`, runs `mutate` (the box
    process writing); `actions` maps further steps to further writes. With `index_of`, it also
    records the index's staged names at each step."""

    def __init__(self, at: str | None = None, mutate: Callable[[], None] | None = None, *,
                 index_of: Path | None = None,
                 actions: dict[str, Callable[[], None]] | None = None) -> None:
        self.actions = dict(actions or {})
        if at is not None and mutate is not None:
            self.actions[at] = mutate
        self.index_of = index_of
        self.seen: list[str] = []
        self.staged: dict[str, list[str]] = {}

    def __call__(self, step: str) -> None:
        self.seen.append(step)
        if self.index_of is not None:
            self.staged[step] = _staged_names(self.index_of)
        if (act := self.actions.get(step)) is not None:
            act()


def _release(fifo: Path) -> None:
    """Open the FIFO's other end, so a call stuck opening it returns."""
    with contextlib.suppress(OSError):
        os.close(os.open(fifo, os.O_RDWR | os.O_NONBLOCK))


def _bounded(fn: Callable[[], Any], *, fifos: tuple[Path, ...] = ()) -> Any:
    """`fn()`'s value (its exception re-raised), failing the test if it has not returned within
    `DEADLINE`. A call stuck on one of `fifos` is released (each git child that opens it, in
    turn), so a regression costs one failed row, not a wedged run."""
    out: dict[str, Any] = {}

    def body() -> None:
        try:
            out["value"] = fn()
        except BaseException as e:  # noqa: BLE001 — handed back to the caller's thread
            out["error"] = e

    worker = threading.Thread(target=body, daemon=True)
    worker.start()
    worker.join(DEADLINE)
    hung = worker.is_alive()
    for _ in range(200):
        if not worker.is_alive():
            break
        for fifo in fifos:
            _release(fifo)
        worker.join(0.1)
    if hung:
        pytest.fail(f"the run did not return within {DEADLINE}s: a git call blocked opening a "
                    "FIFO in the worktree (a `.gitattributes` read outside `committed_view_env`, "
                    "or a `.gitignore` read by a staging call that applies ignore rules)")
    if "error" in out:
        raise out["error"]
    return out.get("value")


@dataclasses.dataclass
class Drive:
    """One run of a lane's entry point: the repo, HEAD before it, and what it returned or the
    refusal it raised (`LeadAuthorError` or `GitError`; anything else propagates)."""

    repo: Path
    head: str
    rc: int | None
    error: Exception | None


def _caught(repo: Path, head: str, fn: Callable[[], int]) -> Drive:
    try:
        return Drive(repo, head, fn(), None)
    except (LeadAuthorError, _git.GitError) as e:
        return Drive(repo, head, None, e)


def _gate(hook: GateSteps | None) -> dict[str, Any]:
    """The hook as the entry points take it, or nothing at all: the rows that need no hook
    (O2) run against today's signatures."""
    return {} if hook is None else {"gate_step": hook}


def _drive_lead(tmp_path: Path, repo: Path, leave: Callable[[Path], None], *,
                hook: GateSteps | None = None, fifos: tuple[Path, ...] = ()) -> Drive:
    """`lead_author.run(label=, deps=)` over `repo`: the agent (rc 0) runs `leave(repo)`; only the
    spawn, the two tables and the queue lock are replaced."""
    paths = LoopPaths(repo_root=repo, state_dir=tmp_path / "state")
    run_dir = tmp_path / "runs" / "run-1"
    (run_dir / "gather_raw").mkdir(parents=True, exist_ok=True)
    spawn = LeadAuthorSpawn(lambda _run_dir: leave(repo))
    head = _git.git_head_sha(repo)
    with lead_trees(paths) as trees:
        deps = dataclasses.replace(
            lead_author.build_lead_author_deps(paths, trees=trees),
            invoke_agent=spawn,
            extract=lambda _run_dir: ([], [CATALOGUED_LEAD]),
            acquire_queue_lock=lambda: object(),
            release_queue_lock=lambda _fh: None,
            **_gate(hook),
        )
        got = _caught(repo, head, lambda: _bounded(
            lambda: lead_author.run(run_dir, label=LEAD, paths=paths, deps=deps), fifos=fifos))
    assert spawn.calls, "the agent was never reached, so the gate never ran"
    return got


def _drive_pitfalls(tmp_path: Path, repo: Path, leave: Callable[[Path], None], *,
                    hook: GateSteps | None = None, fifos: tuple[Path, ...] = ()) -> Drive:
    """`pitfalls_curator.run_pitfalls(trees=, invoke=)` over `repo`, with three queued reducer
    rows (one mistake), so the reducer surface is offered: the curator (rc 0) runs
    `leave(repo)`."""
    paths = LoopPaths(repo_root=repo, state_dir=tmp_path / "state")
    persist.append_pitfalls([shim_row(f"r:l-003:{i}") for i in range(3)], paths=paths)
    spawn = Spawn(leave)
    head = _git.git_head_sha(repo)
    with lead_trees(paths) as trees:
        got = _caught(repo, head, lambda: _bounded(
            lambda: pitfalls_curator.run_pitfalls(
                paths=paths, trees=trees, invoke=spawn, **_gate(hook)),
            fifos=fifos))
    assert spawn.calls, "the curator was never reached, so the gate never ran"
    return got


@dataclasses.dataclass(frozen=True)
class Lane:
    """One committer of the lane, and what its agent leaves.

    `vetted` is the one file the agent leaves at `vetted_rel` (status `status` in the commit):
    the first pass admits it as raw bytes, and it carries a UTF-7 escape whose decoded text the
    gate refuses (row (d)). `refused` is bytes the gate refuses at the same path. `smuggled` is a
    new `.md` the gate WOULD admit if it judged it, and a new non-`.md`."""

    id: str
    vetted_rel: str
    status: str
    vetted: str
    refused: str
    refusal: str
    smuggled: tuple[tuple[str, str], ...]
    drive: Callable[..., Drive]

    def leave(self, repo: Path) -> None:
        write(repo / self.vetted_rel, self.vetted)


def _query(note: str) -> str:
    return f"```query\nverb: search\nparams:\n  index: ${{index}}\n  note: {note}\n```"


LEAD_LANE = Lane(
    id="lead",
    vetted_rel="defender/skills/gather/queries/wazuh/probe.md",
    status="A",
    vetted=query_template("wazuh.probe", "established", body=_query(U7_EVIL)),
    refused=query_template("wazuh.probe", "established", body=_query("${evil}")),
    refusal="${evil}",
    smuggled=(
        ("defender/skills/gather/queries/wazuh/smuggled.md",
         query_template("wazuh.smuggled", "established")),
        ("defender/skills/gather/queries/wazuh/smuggled.sh", "#!/bin/sh\necho smuggled\n"),
    ),
    drive=_drive_lead,
)

PITFALLS_LANE = Lane(
    id="pitfalls",
    vetted_rel=REDUCER_REL,
    status="M",
    vetted=reducer_surface_text(bullets=(f"keep the unnest argument a LIST{U7_SECTION}",)),
    refused=reducer_surface_text(bullets=("keep the unnest argument a LIST",)).replace(
        "description: The defender-sql quirks that cost a query.",
        "description: rewritten by a box process.",
    ),
    refusal="frontmatter",
    smuggled=(
        ("defender/skills/elastic/execution.md",
         "# elastic\n\n## Common pitfalls\n\n- smuggled past the gate\n"),
        ("defender/skills/elastic/smuggled.sh", "#!/bin/sh\necho smuggled\n"),
    ),
    drive=_drive_pitfalls,
)

LANES = [pytest.param(LEAD_LANE, id="lead"), pytest.param(PITFALLS_LANE, id="pitfalls")]


def _parent(repo: Path) -> str:
    return _g(repo, "rev-parse", "HEAD^")


def _committed(repo: Path) -> list[tuple[str, str, str, str]]:
    """HEAD against its parent, renames off: `(status, new mode, path, new blob)` per entry."""
    out = _g(repo, "diff-tree", "--no-commit-id", "-r", "--no-renames", "--raw", "-z",
             "HEAD^", "HEAD")
    fields = [f for f in out.split("\0") if f]
    rows = []
    for meta, path in zip(fields[::2], fields[1::2], strict=True):
        _old_mode, new_mode, _old_blob, new_blob, status = meta.lstrip(":").split(" ")
        rows.append((status, new_mode, path, new_blob))
    return rows


def _blob(repo: Path, sha: str) -> bytes:
    return _git.git_blob_bytes(repo, sha, env=_git.committed_view_env(), timeout=10)


def _assert_committed(d: Drive, entries: list[tuple[str, str, str]], *,
                      mode: str = "100644") -> None:
    """The run returned 0 and made one commit on top of the HEAD it started from, holding
    exactly `entries` (`(status, path, text)`, text `""` for a delete) at `mode`."""
    assert d.error is None, f"the run refused: {d.error!r}"
    assert d.rc == 0, d.rc
    assert _git.git_head_sha(d.repo) != d.head, "nothing was committed"
    assert _parent(d.repo) == d.head, "the run made more than one commit"
    got = _committed(d.repo)
    assert [(s, p) for s, _m, p, _b in got] == [(s, p) for s, p, _t in entries], got
    for (status, got_mode, _path, blob), (_s, _p, text) in zip(got, entries, strict=True):
        if status == "D":
            continue
        assert got_mode == mode, got
        assert _blob(d.repo, blob) == text.encode("utf-8"), f"{_path} holds other bytes"


def _assert_refused(d: Drive, says: str = "") -> None:
    """The run refused as a claim refusal (`LeadAuthorError`, never `GitError`) and committed
    nothing."""
    assert d.error is not None, "the run was not refused"
    assert isinstance(d.error, LeadAuthorError), f"refused as {type(d.error).__name__}: {d.error}"
    assert not isinstance(d.error, _git.GitError), d.error
    assert says in str(d.error), d.error
    assert _git.git_head_sha(d.repo) == d.head, "a refused run moved HEAD"


def _assert_judged_or_refused(d: Drive, lane: Lane) -> None:
    """O1's one verdict: the commit holds the vetted bytes at 100644 and no other path, or the
    run refused with HEAD unchanged."""
    if d.error is not None:
        _assert_refused(d)
        return
    _assert_committed(d, [(lane.status, lane.vetted_rel, lane.vetted)])


# ---------------------------------------------------------------------------------------
# O1: what a box process writes after the gate read the tree never reaches the commit
# ---------------------------------------------------------------------------------------


def _rewrite(lane: Lane, repo: Path, _target: Path) -> None:
    """(a) The vetted file rewritten with bytes the gate refuses."""
    write(repo / lane.vetted_rel, lane.refused)


def _add_new(lane: Lane, repo: Path, _target: Path) -> None:
    """(b) A new `.md` the gate would admit, and a new non-`.md`, under `skills/`."""
    for rel, text in lane.smuggled:
        write(repo / rel, text)


def _swap_link(lane: Lane, repo: Path, target: Path) -> None:
    """(c) The vetted file swapped for a symlink to an outside file holding refused bytes."""
    at = repo / lane.vetted_rel
    clear(at)
    at.symlink_to(target)


def _utf7(lane: Lane, repo: Path, _target: Path) -> None:
    """(d) `skills/.gitattributes` re-encoding every `.md` as UTF-7, and the vetted file written
    again: its raw bytes are what the first pass admitted, its UTF-7-decoded text is refused."""
    write(repo / ATTRS_REL, "*.md working-tree-encoding=UTF-7\n")
    write(repo / lane.vetted_rel, lane.vetted)


def _fifo_attrs(_lane: Lane, repo: Path, _target: Path) -> None:
    """(e) `skills/.gitattributes` made a FIFO: a git call that reads worktree attributes blocks."""
    at = repo / ATTRS_REL
    clear(at)
    os.mkfifo(at)


def _folder_ignore(lane: Lane, repo: Path) -> Path:
    return (repo / lane.vetted_rel).parent / ".gitignore"


def _fifo_ignore_skills(_lane: Lane, repo: Path, _target: Path) -> None:
    """(f) `skills/.gitignore` made a FIFO: a git call that reads ignore rules (`git add`, `git
    status`) blocks opening it, whatever `committed_view_env` says."""
    at = repo / IGNORE_REL
    clear(at)
    os.mkfifo(at)


def _fifo_ignore_folder(lane: Lane, repo: Path, _target: Path) -> None:
    """(f) The same FIFO `.gitignore`, in the candidate's own folder."""
    at = _folder_ignore(lane, repo)
    clear(at)
    os.mkfifo(at)


def _fifo_sites(lane: Lane, repo: Path) -> tuple[Path, ...]:
    """Every name a row may plant a FIFO at, for `_bounded` to release."""
    return (repo / ATTRS_REL, repo / IGNORE_REL, _folder_ignore(lane, repo))


MUTATIONS = [
    pytest.param(_rewrite, id="bad_bytes"),
    pytest.param(_add_new, id="new_paths"),
    pytest.param(_swap_link, id="symlink_swap"),
    pytest.param(_utf7, id="utf7_gitattributes"),
    pytest.param(_fifo_attrs, id="fifo_gitattributes"),
    pytest.param(_fifo_ignore_skills, id="fifo_gitignore_skills"),
    pytest.param(_fifo_ignore_folder, id="fifo_gitignore_folder"),
]


@pytest.mark.parametrize("mutate", MUTATIONS)
@pytest.mark.parametrize("step", STEPS)
@pytest.mark.parametrize("lane", LANES)
def test_a_box_write_at_any_gate_step_never_reaches_the_commit(
        tmp_path: Path, lane: Lane, step: str, mutate):
    """O1, through each committer's real entry point: the agent leaves one vetted file, the
    first pass admits it, and at `step` a box process (the hook) writes under `skills/`. The
    commit holds exactly the vetted bytes at 100644 and no other path, or the run refuses
    (`LeadAuthorError`) with HEAD unchanged: never the rewritten bytes, the new paths, a mode
    120000 entry, the UTF-7-decoded text, and never a hang. The swapped link's outside target is
    never opened (A4).

    Catches: committing with a pathspec (re-reads the disk, C3), staging the whole folder
    (sweeps the new paths in), judging the disk instead of the staged snapshot, any git call
    in steps 2-6 outside `committed_view_env()` (re-encodes the staged bytes, or blocks opening
    the FIFO `.gitattributes`), and staging through a git call that reads ignore rules (`git
    add` opens every `.gitignore` on the way to a candidate, so a FIFO one blocks it)."""
    repo = _seeded(tmp_path)
    target = write(tmp_path / "outside" / "swapped.md", lane.refused)
    hook = GateSteps(at=step, mutate=lambda: mutate(lane, repo, target))
    with kernel_watch(opens=[target]) as events:
        d = lane.drive(tmp_path, repo, lane.leave, hook=hook, fifos=_fifo_sites(lane, repo))
        seen = events()
    assert step in hook.seen, f"the hook never fired at {step!r}: the box write never happened"
    assert hook.seen == list(STEPS[:len(hook.seen)]), hook.seen
    assert seen == [], f"the host opened the swapped link's outside target: {seen}"
    _assert_judged_or_refused(d, lane)


@pytest.mark.parametrize("lane", LANES)
def test_with_no_box_write_the_commit_holds_the_plain_vetted_bytes(tmp_path: Path, lane: Lane):
    """O1's positive control, and the hook's contract: no mutation at any step, so the commit
    holds the vetted bytes at 100644, the only path; the hook fires at all four steps in order,
    with nothing staged at "judged" and exactly the candidate staged from "staged" on.

    Catches: a gate that refuses whenever a hook is present (every negative row would pass), and
    a hook fired out of its moment (the matrix would mutate where it says it does not)."""
    repo = _seeded(tmp_path)
    hook = GateSteps(index_of=repo)
    d = lane.drive(tmp_path, repo, lane.leave, hook=hook)
    _assert_committed(d, [(lane.status, lane.vetted_rel, lane.vetted)])
    assert hook.seen == list(STEPS), hook.seen
    assert hook.staged == {"judged": [], "staged": [lane.vetted_rel],
                           "snapshotted": [lane.vetted_rel], "rejudged": [lane.vetted_rel]}


@pytest.mark.parametrize("lane", LANES)
def test_a_rewrite_before_staging_is_refused_by_the_second_pass_in_the_worktrees_spelling(
        tmp_path: Path, lane: Lane):
    """O1 / O4 / D1: the vetted file rewritten with refused bytes right after the first pass is
    staged, snapshotted and judged by the second pass, which refuses it with today's rule and
    message, the path spelled as the worktree spells it (`defender/skills/...`), never the
    snapshot's. HEAD unchanged. (The positive control above is this address unmutated.)"""
    repo = _seeded(tmp_path)
    hook = GateSteps(at="judged", mutate=lambda: _rewrite(lane, repo, repo))
    d = lane.drive(tmp_path, repo, lane.leave, hook=hook)
    _assert_refused(d, lane.refusal)
    assert lane.vetted_rel in str(d.error), d.error
    assert str(tmp_path) not in str(d.error), f"the refusal names a host path: {d.error}"


def _post_index_change_box(tmp_path: Path, repo: Path, lane: Lane) -> Path:
    """git itself as the box process, for a run with no `gate_step`: a `post-index-change` hook
    (`core.hooksPath` on the repo) that, the first time the index is written with the vetted
    path staged, overwrites that path on disk with refused bytes. git runs it synchronously
    after every index write (`add`, `update-index`, `commit`), so the write lands after staging
    and before the commit, deterministically. Returns the marker it leaves once it has fired."""
    hooks = tmp_path / "githooks"
    hooks.mkdir()
    marker = tmp_path / "box-wrote"
    refused = write(tmp_path / "refused-bytes", lane.refused)
    script = hooks / "post-index-change"
    script.write_text(
        "#!/bin/sh\n"
        f"[ -e {shlex.quote(str(marker))} ] && exit 0\n"
        f"git diff --cached --name-only | grep -qxF {shlex.quote(lane.vetted_rel)} || exit 0\n"
        f": > {shlex.quote(str(marker))}\n"
        f"cp {shlex.quote(str(refused))} {shlex.quote(lane.vetted_rel)}\n",
        encoding="utf-8",
    )
    script.chmod(0o755)
    _git.git(["config", "core.hooksPath", str(hooks)], cwd=repo)
    return marker


@pytest.mark.parametrize("lane", LANES)
def test_with_no_hook_a_box_write_after_staging_never_reaches_the_commit(
        tmp_path: Path, lane: Lane):
    """O1 on production's own path: no `gate_step` at all (the deps and `run_pitfalls` as the
    drain builds them). git's `post-index-change` hook plays the box: once the vetted path is
    staged it rewrites it on disk with refused bytes. The commit holds the vetted bytes (or the
    run refuses with HEAD unchanged); the disk is left holding the box's bytes, so the race did
    happen.

    Catches: a fix taken only when a hook is passed, production keeping today's pathspec commit
    (`git commit -- skills` re-reads the disk, C3)."""
    repo = _seeded(tmp_path)
    marker = _post_index_change_box(tmp_path, repo, lane)
    d = lane.drive(tmp_path, repo, lane.leave)
    assert marker.exists(), "the vetted path was never staged with the hook live: no race ran"
    assert (repo / lane.vetted_rel).read_text(encoding="utf-8") == lane.refused
    _assert_judged_or_refused(d, lane)


@pytest.mark.parametrize("restored_at", ["staged", "snapshotted"])
@pytest.mark.parametrize("lane", LANES)
def test_bad_bytes_staged_then_restored_on_disk_are_still_refused(
        tmp_path: Path, lane: Lane, restored_at: str):
    """O1 / D1: refused bytes written right after the first pass are what gets staged; the box
    then puts the vetted bytes back on disk (after staging, or after the snapshot). The second
    pass judges the staged bytes, through the snapshot, so the run refuses with today's message
    and HEAD unchanged, though the disk now holds bytes the gate admits.

    Catches: a second pass that reads the disk (the held mount) rather than the snapshot of the
    index: it would admit the restored bytes and commit the staged refused ones."""
    repo = _seeded(tmp_path)
    hook = GateSteps(actions={
        "judged": lambda: _rewrite(lane, repo, repo),
        restored_at: lambda: lane.leave(repo),
    })
    d = lane.drive(tmp_path, repo, lane.leave, hook=hook)
    assert restored_at in hook.seen, hook.seen
    _assert_refused(d, lane.refusal)
    assert (repo / lane.vetted_rel).read_text(encoding="utf-8") == lane.vetted


def _listing(root: Path) -> set[str]:
    """Every entry below `root`, hidden ones included, judged without following a link."""
    out: set[str] = set()
    for dirpath, dirnames, filenames in os.walk(root):
        for name in (*dirnames, *filenames):
            out.add((Path(dirpath) / name).relative_to(root).as_posix())
    return out


@pytest.mark.parametrize("lane", LANES)
def test_the_snapshot_never_appears_under_the_worktree(tmp_path: Path, lane: Lane):
    """The snapshot is host-private (design step 4: a fresh temp dir, never under the worktree,
    which the box mounts). Between "staged" and "snapshotted" nothing new appears anywhere
    under the worktree, hidden folders included; the run commits the vetted bytes.

    Catches: a snapshot made under `skills/` (or anywhere in the worktree), where a box process
    could rewrite what the second pass reads."""
    repo = _seeded(tmp_path)
    seen: dict[str, set[str]] = {}
    hook = GateSteps(actions={
        "staged": lambda: seen.__setitem__("staged", _listing(repo)),
        "snapshotted": lambda: seen.__setitem__("snapshotted", _listing(repo)),
    })
    d = lane.drive(tmp_path, repo, lane.leave, hook=hook)
    _assert_committed(d, [(lane.status, lane.vetted_rel, lane.vetted)])
    assert set(seen) == {"staged", "snapshotted"}, hook.seen
    assert lane.vetted_rel in seen["staged"], "the listing does not see the worktree"
    assert sorted(seen["snapshotted"] - seen["staged"]) == [], "the snapshot is in the worktree"


SKILL_DRAFT_REL = "defender/skills/elastic/_draft/falco-na.md"
#: What a box process writes back at the deleted skill draft's name: a draft the gate admits.
BOXED_DRAFT = "---\nid: elastic.boxed\nstatus: draft\n---\n# written by a box process\n"


@pytest.mark.parametrize("box", ["none", "recreated"])
def test_a_judged_delete_recreated_before_staging_is_refused(tmp_path: Path, box: str):
    """Design step 3 (each candidate staged "added/modified or deleted as its record says"): the
    agent deletes the seeded, committed system-skill draft (a delete the gate allows); right
    after the first pass a box process writes the name back with other bytes the gate would
    admit. Staged, it is a modification where the first pass judged a deletion: refused, HEAD
    unchanged. `none` is the control: the delete commits.

    Catches: a staged-set check by names only, which hands the second pass the staged status
    ("M") and so judges and commits bytes the first pass never saw."""
    repo = _seeded(tmp_path)
    hook = GateSteps(at="judged", mutate=(
        (lambda: write(repo / SKILL_DRAFT_REL, BOXED_DRAFT)) if box == "recreated" else None))
    d = _drive_lead(tmp_path, repo, lambda root: (root / SKILL_DRAFT_REL).unlink(), hook=hook)
    if box == "none":
        _assert_committed(d, [("D", SKILL_DRAFT_REL, "")])
        return
    _assert_refused(d)


def _embedded_repo(at: Path) -> None:
    """`at` replaced by a git repository with one commit: `git add` stages it as a gitlink."""
    clear(at)
    at.mkdir(parents=True)
    _git.git(["init", "-q"], cwd=at)
    write(at / "inner.md", "a nested repository's file\n")
    ident = ["-c", "user.email=box@example.com", "-c", "user.name=box"]
    _git.git([*ident, "add", "inner.md"], cwd=at)
    _git.git([*ident, "commit", "-q", "-m", "nested"], cwd=at)


@pytest.mark.parametrize("lane", LANES)
def test_a_candidate_swapped_for_an_embedded_repository_is_refused(tmp_path: Path, lane: Lane):
    """O2 (no gitlink, 160000): right after the first pass the box replaces the candidate with an
    embedded git repository at the same name, which git stages as a gitlink. Refused, HEAD
    unchanged, nothing at mode 160000 in it. (The O1 positive control is this address
    unmutated.)

    Catches: a mode check that refuses only symlinks (120000)."""
    repo = _seeded(tmp_path)
    hook = GateSteps(at="judged", mutate=lambda: _embedded_repo(repo / lane.vetted_rel))
    d = lane.drive(tmp_path, repo, lane.leave, hook=hook)
    assert "judged" in hook.seen, hook.seen
    _assert_refused(d)
    listing = _g(repo, "ls-tree", "-r", "-z", "HEAD").split("\0")
    modes = {entry.split(" ", 1)[0] for entry in listing if entry}
    assert "160000" not in modes, modes


AUTH_REL = "defender/skills/gather/queries/wazuh/auth-events.md"
#: The seeded established template folded with one more identity: the first pass admits it.
FOLDED = query_template("wazuh.auth-events", "established",
                        covers=("wazuh.auth-old", "wazuh.auth-extra"))


@pytest.mark.parametrize(("box", "says"), [
    pytest.param(None, None, id="none"),
    pytest.param(query_template("wazuh.clobbered", "established",
                                covers=("wazuh.auth-old", "wazuh.auth-extra")),
                 "rewrote the identity of an established template", id="identity_rewritten"),
    pytest.param(query_template("wazuh.auth-events", "established", covers=("wazuh.auth-extra",)),
                 "dropped `covers:` entries", id="covers_dropped"),
])
def test_a_folded_template_rewritten_after_the_first_pass_meets_the_batch_rules(
        tmp_path: Path, box: str | None, says: str | None):
    """The second pass runs every rule, the whole-batch ones included (`_covers_rule`'s
    monotonicity: an established template keeps its `id:` and every `covers:` entry it had at
    HEAD). HEAD's `auth-events.md` covers `wazuh.auth-old`; the agent folds `wazuh.auth-extra` in
    (admitted). Right after the first pass the box rewrites the file with another `id:`, or
    without `wazuh.auth-old`: the staged bytes are refused with today's message, HEAD unchanged.
    `none` is the control: the fold commits.

    Catches: a second pass that runs only the per-path rules (both rewrites pass those)."""
    repo = _seeded(tmp_path)
    write(repo / AUTH_REL, query_template("wazuh.auth-events", "established",
                                          covers=("wazuh.auth-old",)))
    _git.git(["commit", "-q", "-a", "-m", "auth-events covers wazuh.auth-old"], cwd=repo)
    hook = GateSteps(at="judged", mutate=(lambda: write(repo / AUTH_REL, box)) if box else None)
    d = _drive_lead(tmp_path, repo, lambda root: write(root / AUTH_REL, FOLDED), hook=hook)
    if box is None:
        _assert_committed(d, [("M", AUTH_REL, FOLDED)])
        return
    _assert_refused(d, says)


# ---------------------------------------------------------------------------------------
# O2: only regular files reach a lead-author commit
# ---------------------------------------------------------------------------------------

O2_SITES = [
    pytest.param("defender/skills/gather/queries/wazuh/_draft/x.md",
                 query_template("wazuh.x", "draft"), id="catalog_draft"),
    pytest.param("defender/skills/elastic/_draft/x.md",
                 "---\nid: elastic.x\nstatus: draft\n---\n# pending\n", id="skill_draft"),
    pytest.param("defender/skills/gather/queries/wazuh/README.md",
                 "# wazuh catalog notes\n", id="catalog_readme"),
]


@pytest.mark.parametrize("left", ["plain", "symlink"])
@pytest.mark.parametrize(("rel", "text"), O2_SITES)
def test_a_symlink_the_agent_leaves_where_no_content_rule_reads_is_refused(
        tmp_path: Path, rel: str, text: str, left: str):
    """O2, through `lead_author.run`: the agent leaves a symlink to an outside file at a catalog
    draft, a system-skill draft or a catalog `README.md`, names no content rule reads, so today
    it passes the gate and commits as mode 120000 (C1). Now: refused (`LeadAuthorError`), HEAD
    unchanged, the outside file never opened. `plain` is the control: the same bytes as a plain
    file commit, 100644."""
    repo = _seeded(tmp_path)
    target = write(tmp_path / "outside" / "target.md", text)

    def leave(root: Path) -> None:
        at = root / rel
        if left == "plain":
            write(at, text)
            return
        at.parent.mkdir(parents=True, exist_ok=True)
        at.symlink_to(target)

    with kernel_watch(opens=[target]) as events:
        d = _drive_lead(tmp_path, repo, leave)
        seen = events()
    assert seen == [], f"the host opened the link's outside target: {seen}"
    if left == "plain":
        _assert_committed(d, [("A", rel, text)])
        return
    _assert_refused(d)


def test_an_executable_file_the_agent_leaves_commits_as_100755(tmp_path: Path):
    """O2's other regular mode (C8: `skills/` holds 100755 files today): the agent leaves an
    executable `queries/wazuh/README.md`. It commits, at 100755, through production's deps (no
    hook). The 100644 form at this address is O2's `catalog_readme-plain` row.

    Catches: a mode check that admits only 100644."""
    repo = _seeded(tmp_path)
    rel = "defender/skills/gather/queries/wazuh/README.md"
    text = "# wazuh catalog notes\n"

    def leave(root: Path) -> None:
        write(root / rel, text)
        os.chmod(root / rel, 0o755)

    d = _drive_lead(tmp_path, repo, leave)
    _assert_committed(d, [("A", rel, text)], mode="100755")


# ---------------------------------------------------------------------------------------
# O3: staging that does not match the candidates refuses the commit
# ---------------------------------------------------------------------------------------


def _staging_fault(kind: str, lane: Lane, repo: Path) -> None:
    at = repo / lane.vetted_rel
    if kind == "vanished":
        at.unlink()
    elif kind == "fifo":
        at.unlink()
        os.mkfifo(at)
    elif kind == "folder":
        at.unlink()
        write(at / "inner.md", lane.vetted)
    elif kind == "prestaged_outside_skills":
        rel = "defender/scripts/adapters/elastic_adapter.py"
        write(repo / rel, "VERBS = {}  # staged by a box process\n")
        _git.git(["add", "--", rel], cwd=repo)
    elif kind == "prestaged_in_skills":
        rel, text = lane.smuggled[0]
        write(repo / rel, text)
        _git.git(["add", "--", rel], cwd=repo)
    elif kind != "none":
        raise ValueError(kind)


O3_KINDS = ["none", "vanished", "fifo", "folder", "prestaged_outside_skills",
            "prestaged_in_skills"]


@pytest.mark.parametrize("kind", O3_KINDS)
@pytest.mark.parametrize("lane", LANES)
def test_staging_that_does_not_match_the_candidates_refuses_the_commit(
        tmp_path: Path, lane: Lane, kind: str):
    """O3, at "judged" (after the first pass, before staging): the candidate gone (an untracked
    one makes `git add` exit 128, C6; a tracked one stages a delete), a FIFO (git stages nothing,
    C5), a folder holding a file (git stages other names, C4), or another path already staged
    (outside `skills/`, or a new template inside it: a pathspec-less commit would carry either).
    Each refuses with `LeadAuthorError` and HEAD unchanged. `none` is the control on the same
    address: the commit is made."""
    repo = _seeded(tmp_path)
    hook = GateSteps(at="judged", mutate=lambda: _staging_fault(kind, lane, repo))
    at = repo / lane.vetted_rel
    d = lane.drive(tmp_path, repo, lane.leave, hook=hook, fifos=(at,))
    assert hook.seen[:1] == ["judged"], hook.seen
    if kind == "none":
        _assert_committed(d, [(lane.status, lane.vetted_rel, lane.vetted)])
        return
    _assert_refused(d)


def test_a_vanished_candidate_dead_letters_the_claim_and_does_not_halt_the_drain(
        tmp_path: Path):
    """The staging failure's class (C16): the agent's new file removed between the first pass and
    `git add` makes git fail (rc 128). Raised as `GitError`, a systemic fault, it would halt the
    whole drain (`faults.run_or_dead_letter` re-raises it), so a box process could stop the lane
    by deleting a file; raised as `LeadAuthorError` the claim dead-letters like every other
    refusal. Driven through the drain's own guard: it returns False with the refusal handed to
    the dead-letter sink, nothing raised, HEAD unchanged."""
    repo = _seeded(tmp_path)
    head = _git.git_head_sha(repo)
    lane = LEAD_LANE
    hook = GateSteps(at="judged", mutate=lambda: _staging_fault("vanished", lane, repo))
    dead: list[Exception] = []

    def claim() -> None:
        d = _drive_lead(tmp_path, repo, lane.leave, hook=hook)
        if d.error is not None:
            raise d.error

    served = faults.run_or_dead_letter(claim, dead.append)

    assert served is False, "the vanished candidate was committed"
    assert [type(e) for e in dead] == [LeadAuthorError], dead
    assert _git.git_head_sha(repo) == head


# ---------------------------------------------------------------------------------------
# Renames, and O4: what the gate said before still holds
# ---------------------------------------------------------------------------------------

DRAFT_REL = "defender/skills/gather/queries/wazuh/_draft/newthing.md"
PROMOTED_REL = "defender/skills/gather/queries/wazuh/newthing.md"
PROMOTED = query_template("wazuh.newthing", "established", covers=("wazuh.newthing",))


def test_a_promote_commits_as_a_delete_and_an_add(tmp_path: Path):
    """C14: the agent promotes the seeded draft (deletes `_draft/newthing.md`, adds a
    near-identical established `newthing.md` carrying its identity in `covers:`). Staged, git
    would report the pair as one rename record by default; the staged-set check must read it as
    the delete and the add the first pass judged. The commit is made through all four steps and
    holds exactly the delete and the add, the new file's bytes at 100644."""
    repo = _seeded(tmp_path)

    def promote(root: Path) -> None:
        (root / DRAFT_REL).unlink()
        write(root / PROMOTED_REL, PROMOTED)

    hook = GateSteps()
    d = _drive_lead(tmp_path, repo, promote, hook=hook)
    _assert_committed(d, [("D", DRAFT_REL, ""), ("A", PROMOTED_REL, PROMOTED)])
    assert hook.seen == list(STEPS), hook.seen


@pytest.mark.parametrize("kind", ["symlink", "hardlink"])
def test_a_link_present_before_the_gate_gets_todays_refusal_before_anything_is_staged(
        tmp_path: Path, kind: str):
    """O4: the agent leaves an established template as a symlink (or a hard link) to an outside
    file holding a valid template. The first pass, unchanged, refuses it with today's message
    ("not a readable query template") before anything is staged: the hook never fires, the index
    holds nothing, HEAD is unchanged, and the outside file is never opened or read (`git add`
    of a hard link would read it, N1). The positive control is the O1 control at this address
    (a plain file there commits)."""
    repo = _seeded(tmp_path)
    target = write(tmp_path / "outside" / "probe.md", query_template("wazuh.probe", "established"))
    at = repo / LEAD_LANE.vetted_rel

    def leave(_root: Path) -> None:
        at.parent.mkdir(parents=True, exist_ok=True)
        if kind == "symlink":
            at.symlink_to(target)
        else:
            os.link(target, at)

    hook = GateSteps()
    watch = {"opens": [target]} if kind == "symlink" else {"reads": [target]}
    with kernel_watch(**watch) as events:
        d = _drive_lead(tmp_path, repo, leave, hook=hook)
        seen = events()
    _assert_refused(d, "not a readable query template")
    assert hook.seen == [], f"the gate went on past the first pass: {hook.seen}"
    assert _staged_names(repo) == [], "something was staged before the first pass refused"
    assert seen == [], f"the host opened or read the outside file: {seen}"


DUP_REL = "defender/skills/gather/queries/wazuh/_draft/dup.md"


@pytest.mark.parametrize(("covers", "says"), [
    pytest.param("wazuh.auth-events", None, id="covered_by_an_untouched_template"),
    pytest.param("wazuh.orphan", "without attributing it", id="covered_by_nothing"),
])
def test_a_draft_discard_is_judged_against_the_whole_catalog_on_both_passes(
        tmp_path: Path, covers: str, says: str | None):
    """O4 with no concurrent writer: the agent deletes a committed draft recording one identity.
    When an established template the agent never touched (`auth-events.md`) answers it, the
    discard is attributed and commits as a delete, through all four steps: the second pass's
    snapshot holds the whole `skills/` tree, not just the staged paths (D2: the batch rules read
    the whole catalog). When nothing answers it, today's refusal ("without attributing it")
    stands, HEAD unchanged: the rule is live on this address.

    Catches: a snapshot of the candidates only, whose second pass finds the identity orphaned and
    refuses a batch the first pass admitted."""
    repo = _seeded(tmp_path)
    write(repo / DUP_REL, query_template("wazuh.dup", "draft", covers=(covers,)))
    _git.git(["add", "--", DUP_REL], cwd=repo)
    _git.git(["commit", "-q", "-m", "a draft recording one identity"], cwd=repo)
    hook = GateSteps()
    d = _drive_lead(tmp_path, repo, lambda root: (root / DUP_REL).unlink(), hook=hook)
    if says is not None:
        _assert_refused(d, says)
        return
    _assert_committed(d, [("D", DUP_REL, "")])
    assert hook.seen == list(STEPS), hook.seen


# ---------------------------------------------------------------------------------------
# `commit_judged` alone: the commit holds what the second pass read (C2/C3, D1)
# ---------------------------------------------------------------------------------------

VETTED_REL = LEAD_LANE.vetted_rel
VETTED = query_template("wazuh.probe", "established")


class ReadingJudge:
    """A trivial gate: admits `VETTED_REL` on both passes, recording on each the records it was
    handed and the text it read through the `tree_for` it was handed (the held mount on the
    first pass, the snapshot on the second), as the real rules read (`read_at`)."""

    def __init__(self, repo: Path) -> None:
        self.repo = repo
        self.calls: list[tuple[list[tuple[str, str]] | None, str | None]] = []

    def __call__(self, tree_for, records):
        text, _reason = read_at(self.repo, tree_for, VETTED_REL)
        self.calls.append((None if records is None else list(records), text))
        return [VETTED_REL]


@pytest.mark.parametrize("step", ["staged", "snapshotted", "rejudged"])
def test_the_commit_holds_the_bytes_the_second_pass_read_not_the_disk(tmp_path: Path, step):
    """`commit_judged` with a trivial judge: the vetted file is rewritten on disk at `step`,
    after it was staged. The second pass reads the staged bytes through the snapshot's
    `tree_for` (D1), and HEAD holds exactly those bytes: the index is committed, not the disk
    (C2; a pathspec commit re-reads the disk, C3). Returns `([VETTED_REL], HEAD)`; the second
    pass gets the first pass's records, naming the path."""
    from defender.learning.leads._lead_spine import commit_judged

    repo = _seeded(tmp_path)
    write(repo / VETTED_REL, VETTED)
    head = _git.git_head_sha(repo)
    judge = ReadingJudge(repo)
    hook = GateSteps(at=step, mutate=lambda: write(repo / VETTED_REL, LEAD_LANE.refused))
    with lead_trees(LoopPaths(repo_root=repo, state_dir=tmp_path / "state")) as trees:
        changed, sha = _bounded(lambda: commit_judged(
            repo, judge, trees.tree_for, lambda paths: f"test(#1178): {paths}\n", step=hook))

    assert hook.seen == list(STEPS), hook.seen
    assert (changed, sha) == ([VETTED_REL], _git.git_head_sha(repo))
    assert _parent(repo) == head
    first, second = judge.calls
    assert first == (None, VETTED), first
    assert second[1] == VETTED, "the second pass did not read the staged bytes"
    assert VETTED_REL in [p for _xy, p in second[0]], second[0]
    got = _committed(repo)
    assert [(s, m, p) for s, m, p, _b in got] == [("A", "100644", VETTED_REL)], got
    assert _blob(repo, got[0][3]) == VETTED.encode("utf-8")


def test_nothing_to_commit_returns_no_sha_and_leaves_head(tmp_path: Path):
    """`commit_judged` whose first pass admits nothing (a valid no-edit tick): `([], None)`, HEAD
    unchanged, nothing staged."""
    from defender.learning.leads._lead_spine import commit_judged

    repo = _seeded(tmp_path)
    head = _git.git_head_sha(repo)
    with lead_trees(LoopPaths(repo_root=repo, state_dir=tmp_path / "state")) as trees:
        got = _bounded(lambda: commit_judged(
            repo, lambda _tree_for, _records: [], trees.tree_for, lambda paths: "unused\n"))
    assert got == ([], None)
    assert _git.git_head_sha(repo) == head
    assert _staged_names(repo) == []


# ---------------------------------------------------------------------------------------
# D4 census: both committers go through `commit_judged`, neither through a pathspec commit
# ---------------------------------------------------------------------------------------

#: Every helper that commits with a pathspec, so re-reads the working tree at commit time (C3).
PATHSPEC_COMMITTERS = frozenset({"commit_corpus", "commit_corpus_paths", "git_commit",
                                 "git_commit_paths"})


def _references(module) -> set[str]:
    """The dotted origin of every name and attribute chain the module's source loads, resolved
    through its imports (aliases and `from` imports included) by the lint gates' resolver."""
    astlib = import_lint_lib("_astlib")
    tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
    env = astlib.module_env(tree)
    found: set[str] = set()
    for node in ast.walk(tree):
        if (isinstance(node, ast.Name | ast.Attribute) and isinstance(node.ctx, ast.Load)
                and (origin := astlib.origin(node, env)) is not None):
            found.add(origin)
    return found


@pytest.mark.parametrize("module", [lead_author, pitfalls_curator],
                         ids=["lead_author", "pitfalls_curator"])
def test_each_committer_commits_through_commit_judged_and_never_a_pathspec_commit(module):
    """D4: the lead author (`lead_author/__init__.py`) and the pitfalls curator reference
    `_lead_spine.commit_judged`, and no pathspec committer (`commit_corpus`, `git_commit`, or
    their path-list forms), called or passed along. Today both call `commit_corpus`."""
    refs = _references(module)
    pathspec = sorted(r for r in refs if r.rsplit(".", 1)[-1] in PATHSPEC_COMMITTERS)
    assert pathspec == [], f"{module.__name__} still commits with a pathspec: {pathspec}"
    assert any(r.endswith("_lead_spine.commit_judged") for r in refs), (
        f"{module.__name__} does not commit through _lead_spine.commit_judged"
    )


#: `git commit` options whose next argv element is their value (a message, a file, an author).
_COMMIT_VALUE_OPTIONS = frozenset({
    "-m", "--message", "-F", "--file", "-C", "--reuse-message", "-c", "--reedit-message",
    "-t", "--template", "--author", "--date", "--trailer", "--cleanup",
})


def _defs_reached(tree: ast.Module, start: set[str]) -> list[ast.FunctionDef]:
    """The module-level defs named in `start` and every module-level def they name, transitively
    (a call, or a reference such as a `partial` or a context manager)."""
    defs = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}
    todo, reached = list(start), {}
    while todo:
        name = todo.pop()
        if name in reached or name not in defs:
            continue
        reached[name] = defs[name]
        todo.extend(n.id for n in ast.walk(defs[name]) if isinstance(n, ast.Name))
    return list(reached.values())


def _commit_judged_code() -> list[tuple[ast.FunctionDef, Any]]:
    """`_lead_spine.commit_judged`, every `_lead_spine` def it reaches, and every `defender._git`
    function those reference (with the `_git` defs they reach in turn), each with its module's
    resolver env."""
    astlib = import_lint_lib("_astlib")
    out: list[tuple[ast.FunctionDef, Any]] = []
    git_names: set[str] = set()
    for module in (_lead_spine, _git):
        tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
        env = astlib.module_env(tree)
        start = {"commit_judged"} if module is _lead_spine else git_names
        for fn in _defs_reached(tree, start):
            out.append((fn, env))
            if module is not _lead_spine:
                continue
            for node in ast.walk(fn):
                if (isinstance(node, ast.Name | ast.Attribute) and isinstance(node.ctx, ast.Load)
                        and (origin := astlib.origin(node, env)) is not None
                        and origin.startswith("defender._git.")):
                    git_names.add(origin.rsplit(".", 1)[-1])
    return out


def _commit_argvs(fn: ast.FunctionDef) -> list[ast.List | ast.Tuple]:
    """Every git argv literal in `fn` that runs `commit`: a list or tuple holding the string
    `"commit"`, every element before it a string (git's own options)."""
    found = []
    for node in ast.walk(fn):
        if not isinstance(node, ast.List | ast.Tuple):
            continue
        consts = [e.value if isinstance(e, ast.Constant) else None for e in node.elts]
        if "commit" in consts and all(isinstance(c, str) for c in consts[:consts.index("commit")]):
            found.append(node)
    return found


def _pathspec_of(argv: ast.List | ast.Tuple) -> list[str]:
    """What follows `commit` in `argv` that is not an option or an option's value: a `--`, a
    starred list, a path or any other value would be a pathspec (C3)."""
    elts = argv.elts[[getattr(e, "value", None) for e in argv.elts].index("commit") + 1:]
    stray, takes_value = [], False
    for e in elts:
        if takes_value:
            takes_value = False
            continue
        if isinstance(e, ast.Constant) and isinstance(e.value, str) and e.value != "--" \
                and e.value.startswith("-"):
            takes_value = e.value in _COMMIT_VALUE_OPTIONS
            continue
        stray.append(ast.unparse(e))
    return stray


def test_commit_judged_commits_the_index_with_no_pathspec_and_no_pathspec_committer():
    """D4 / C2, of `commit_judged` itself: the code it runs (its own def, the `_lead_spine` defs
    it reaches, and the `_git` functions those use) references no pathspec committer
    (`commit_corpus`, `git_commit`, their path-list forms), and runs `git commit` with options
    only: no `--`, no path, no list spliced in. So whichever caller, hook or none, the commit is
    the index the second pass judged.

    Catches: a `commit_judged` that keeps today's `git commit -- defender/skills` on some branch
    (production's hookless one, say): the D4 census of the two callers cannot see past the call."""
    astlib = import_lint_lib("_astlib")
    code = _commit_judged_code()
    assert any(fn.name == "commit_judged" for fn, _env in code), "no commit_judged in _lead_spine"
    refs = sorted(
        origin for fn, env in code for node in ast.walk(fn)
        if isinstance(node, ast.Name | ast.Attribute) and isinstance(node.ctx, ast.Load)
        and (origin := astlib.origin(node, env)) is not None
        and origin.rsplit(".", 1)[-1] in PATHSPEC_COMMITTERS
    )
    assert refs == [], f"commit_judged reaches a pathspec committer: {refs}"
    argvs = [(fn.name, argv) for fn, _env in code for argv in _commit_argvs(fn)]
    assert argvs, "commit_judged runs no `git commit` this census can read"
    stray = {f"{name}: {ast.unparse(argv)}": _pathspec_of(argv) for name, argv in argvs}
    assert all(not s for s in stray.values()), f"a `git commit` with a pathspec: {stray}"
