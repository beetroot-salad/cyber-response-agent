#!/usr/bin/env python3
from __future__ import annotations

import contextlib
import logging
import shutil
import sys
import tempfile
from collections.abc import Callable, Iterator
from pathlib import Path

if (_root := str(Path(__file__).resolve().parents[3])) not in sys.path:
    sys.path.insert(0, _root)

from defender import _git
from defender._io import Held, guarded_mkdir
from defender.learning.core import config as _loop_config
from defender.learning.core.lane_trees import DrainTrees, TreeFor
from defender.learning.leads.lead_extraction import LeadAuthorError
from defender.learning.leads.path_validation import SKILLS_REL, _porcelain_records


PENDING_DIR = _loop_config.DEFAULT_PATHS.lead_pending_dir

_logger = logging.getLogger(__name__)


def _spawn_author_agent(
    *,
    system_prompt_file: Path,
    batch_id: str,
    user_prompt: str,
    repo_root: Path,
    learning_run_dir: Path,
    log_label: str,
    salt: str,
    box=None,
) -> int:
    PENDING_DIR.mkdir(parents=True, exist_ok=True)
    from defender.learning.leads import lead_author_engine
    # Every knob is read at spawn: each is env-backed, and a default would freeze it at import.
    return lead_author_engine.run_author_stage(
        wiring=_loop_config.StageWiring.for_batch(
            system_prompt_file,
            _loop_config.lead_author_model(),
            _loop_config.lead_author_effort(),
            batch_id=batch_id, label=log_label,
        ),
        ctx=_loop_config.StageContext(
            learning_run_dir=learning_run_dir,
            user=user_prompt,
            request_limit=_loop_config.lead_author_request_limit(),
            wall_clock_timeout=_loop_config.lead_author_timeout(),
            repo_root=repo_root,
            box=box,
            salt=salt,
        ),
        log_label=log_label,
        log=_logger,
    )


def _verify_corpus_scope(
    repo_root: Path,
    baseline_stray: list[str],
    *,
    actor: str,
    rule: Callable[[str, str], None],
    batch_rule: Callable[[list[tuple[str, str]]], None] | None = None,
    records: list[tuple[str, str]] | None = None,
) -> list[str]:
    """Per-path `rule` over every in-corpus change, then an optional whole-batch `batch_rule`.

    `batch_rule` is for invariants only decidable across the batch (e.g. whether a deleted
    draft's identity was taken over by another file in the same commit). It runs last, on
    records `rule` already admitted.

    `records` are the `(xy, path)` changes to judge; `None` reads `git status` (the first pass).
    `commit_judged`'s second pass hands in the staged records instead (#1178)."""
    if records is None:
        records = _porcelain_records(repo_root)

    def _in_corpus(p: str) -> bool:
        return p.startswith(SKILLS_REL) and p.endswith(".md")

    new_stray = sorted({p for _, p in records if not _in_corpus(p)} - set(baseline_stray))
    if new_stray:
        raise LeadAuthorError(
            f"{actor} changed files outside {SKILLS_REL}*.md: {new_stray}; refusing to commit"
        )
    in_corpus: list[tuple[str, str]] = []
    for xy, path in records:
        if not _in_corpus(path):
            continue
        rule(xy, path)
        in_corpus.append((xy, path))
    if batch_rule is not None:
        batch_rule(in_corpus)
    return sorted(path for _, path in in_corpus)


#: A gate-step hook, called with each step of `commit_judged` in order: "judged" (the first pass
#: admitted the candidates), "staged" (they are staged and the staged set checked), "snapshotted"
#: (the staged `skills/` tree is copied to the private snapshot) and "rejudged" (the second pass
#: admitted the same paths; the commit is next). The seam a test plays a still-writing box through.
GateStep = Callable[[str], None]

#: Every git call of `commit_judged` is bounded: a box process can make one block for good (a FIFO
#: where git opens a file), and a hung gate would hold the lane's locks forever.
_GATE_GIT_TIMEOUT = 120.0

#: The index modes of a regular file: the only entries a lead-lane commit may carry (#1178 O2).
_REGULAR_MODES = frozenset({"100644", "100755"})


def _gate_git(repo_root: Path, args: list[str], *, input: str | None = None) -> list[str]:
    """One `-z` git call of the gate, as its NUL-separated fields: attributes from HEAD's tree,
    never a worktree `.gitattributes` the box may have written (`committed_view_env`), and
    bounded."""
    return _git.git_z(args, cwd=repo_root, env=_git.committed_view_env(),
                      timeout=_GATE_GIT_TIMEOUT, input=input)


def _staged_records(repo_root: Path) -> dict[str, tuple[str, str]]:
    """`{path: (status, new mode)}` for everything the index holds that HEAD does not: the whole
    index, no pathspec, renames off so a promote reads as a delete plus an add (C14)."""
    fields = _gate_git(repo_root, ["diff", "--cached", "--raw", "--no-renames", "-z", "HEAD"])
    staged: dict[str, tuple[str, str]] = {}
    for meta, path in zip(fields[0::2], fields[1::2], strict=False):
        if not meta:
            continue
        # `:<old mode> <new mode> <old sha> <new sha> <status>`
        _old_mode, new_mode, _old, _new, status = meta.lstrip(":").split(" ")
        staged[path] = (status[:1], new_mode)
    return staged


def _judged_deletions(repo_root: Path, candidates: list[str]) -> set[str]:
    """Which `candidates` the first pass judged as deletions, asked of `git status` the moment it
    returns: a judged delete the box re-creates must not be staged as content (#1178 step 3)."""
    wanted = set(candidates)
    records = _git.git_status(repo_root, pathspec=SKILLS_REL, no_renames=True,
                              timeout=_GATE_GIT_TIMEOUT, env=_git.committed_view_env())
    return {path for xy, path in records if path in wanted and "D" in xy}


def _stage_candidates(
    repo_root: Path, candidates: list[str], deletions: set[str],
) -> list[tuple[str, str]]:
    """Stage exactly `candidates` and check the index holds exactly them: each staged as a
    deletion exactly when the first pass judged one (`deletions`), and as a regular file
    otherwise (#1178 O2, O3). Answers the staged records, `(xy, path)` with xy `"<status> "`,
    for the second pass.

    `update-index`, not `add`: it takes each name literally, reads no `.gitignore` (one the box
    makes a FIFO would hang `add`), and fails on a folder or a FIFO at a name rather than staging
    something else there. Every refusal is a `LeadAuthorError`, never a `GitError`: a box process
    that deletes a candidate must cost this claim, not halt the drain (GitError is systemic)."""
    try:
        _gate_git(repo_root, ["update-index", "--add", "--remove", "-z", "--stdin"],
                  input="".join(f"{p}\0" for p in candidates))
        staged = _staged_records(repo_root)
    except (_git.GitError, _git.GitTimeout) as e:
        raise LeadAuthorError(
            f"staging the judged paths failed ({e}); refusing to commit"
        ) from e
    if sorted(staged) != sorted(candidates):
        raise LeadAuthorError(
            f"the staged paths {sorted(staged)} are not the judged paths {sorted(candidates)}; "
            "refusing to commit (the tree changed under the gate)"
        )
    flipped = sorted(p for p, (status, _mode) in staged.items()
                     if (status == "D") != (p in deletions))
    if flipped:
        raise LeadAuthorError(
            f"staged {flipped} as {'deleted' if flipped[0] not in deletions else 'present'}, "
            "not as the gate judged it; refusing to commit (the tree changed under the gate)"
        )
    odd = sorted(p for p, (status, mode) in staged.items()
                 if status != "D" and mode not in _REGULAR_MODES)
    if odd:
        raise LeadAuthorError(
            f"staged {odd} as something other than a regular file; refusing to commit"
        )
    return [(f"{status} ", path) for path, (status, _mode) in sorted(staged.items())]


@contextlib.contextmanager
def _staged_snapshot(repo_root: Path, tree_for: TreeFor) -> Iterator[TreeFor]:
    """The index's `skills/` tree copied into a fresh host-private folder (never under the
    worktree, so no box mount covers it), held, and a `TreeFor` over it: a worktree path under
    `skills/` answers with the snapshot's held root and its name there; any other path answers
    as `tree_for` does (the box's read-only area). Removed on exit."""
    snap = Path(tempfile.mkdtemp(prefix="lead-gate-"))
    try:
        names = _gate_git(repo_root, ["ls-files", "-z", "--", SKILLS_REL])
        if names:
            _gate_git(repo_root, ["checkout-index", "-z", "--stdin", f"--prefix={snap}/"],
                      input="".join(f"{n}\0" for n in names))
        skills = repo_root / SKILLS_REL
        snap_skills = snap / SKILLS_REL
        guarded_mkdir(snap_skills, base=snap)
        with DrainTrees.open((snap_skills,)) as held:
            def snapshot_tree_for(path: Path | str) -> tuple[Held, str] | None:
                p = Path(path)
                if p.is_absolute() and p.is_relative_to(skills):
                    return held.tree_for(snap_skills / p.relative_to(skills))
                return tree_for(path)
            yield snapshot_tree_for
    finally:
        shutil.rmtree(snap, ignore_errors=True)


def _no_step(_name: str) -> None:
    return None


def commit_judged(
    repo_root: Path,
    judge: Callable[[TreeFor, list[tuple[str, str]] | None], list[str]],
    tree_for: TreeFor,
    message: Callable[[list[str]], str],
    *,
    step: GateStep | None = None,
) -> tuple[list[str], str | None]:
    """Run the gate twice and commit exactly what it judged (#1178).

    `judge(tree_for, None)` is the first pass: today's gate (git status, stray check, rules) over
    the held mount, returning the admitted paths, so today's verdicts and messages stand and a
    link is refused before git reads it. Then exactly those paths are staged and the index is
    checked to hold exactly them, each a deletion exactly when the first pass judged one and a
    regular file otherwise; the staged `skills/` tree is
    copied to a host-private snapshot, and `judge(snapshot_tree_for, records)` judges it again
    with the staged records; it must admit the same paths. The index is committed with no
    pathspec, so the commit is the bytes the second pass read, whatever a still-running box writes
    meanwhile (a pathspec commit re-reads the disk). Every git call is under
    `committed_view_env` and bounded.

    Returns `(changed, sha)`; `sha` is None when the first pass admits nothing. Refusals raise
    `LeadAuthorError`, staging failures among them (what a box process can provoke); a git fault
    after staging (the snapshot, the commit) reads only the index and stays a `GitError`. The
    drain's reset discards whatever a refusal left staged."""
    fire = step or _no_step
    changed = judge(tree_for, None)
    try:
        deletions = _judged_deletions(repo_root, changed) if changed else set()
    except (_git.GitError, _git.GitTimeout) as e:
        raise LeadAuthorError(f"reading the judged paths' state failed ({e}); refusing to commit") from e
    fire("judged")
    if not changed:
        return [], None
    records = _stage_candidates(repo_root, changed, deletions)
    fire("staged")
    with _staged_snapshot(repo_root, tree_for) as snapshot_tree_for:
        fire("snapshotted")
        again = judge(snapshot_tree_for, records)
    if sorted(again) != sorted(changed):
        raise LeadAuthorError(
            f"the second pass admitted {sorted(again)}, not the first pass's {sorted(changed)}; "
            "refusing to commit"
        )
    fire("rejudged")
    _git.git(["commit", "-q", "-F", "-"], cwd=repo_root, env=_git.committed_view_env(),
             timeout=_GATE_GIT_TIMEOUT, input=message(changed))
    return changed, _git.git_head_sha(repo_root)


def lane_skills(trees: DrainTrees, paths: _loop_config.LoopPaths) -> Held:
    """The held `skills/` mount of the lane's trees, `trees.mount(paths.skills_dir)`: never a
    handle built here. The lane's trees must hold `paths.skills_dir` itself as a mount point; trees
    opened for a label that grants no such mount (another lane's, an unknown one, a mount list that
    moved it or holds a folder above it) are refused rather than left to fall back on plain paths
    (#1134)."""
    try:
        return trees.mount(paths.skills_dir)
    except ValueError:
        raise LeadAuthorError(
            f"refused: the lane's held trees {[str(m) for m in trees.mounts]} hold no mount at "
            f"{paths.skills_dir}"
        ) from None


def _loop_commit_body(
    title: str, summary: str, changed: list[str], *, trailer: str = "",
) -> str:
    body_paths = "\n".join(f"- {p}" for p in changed)
    return f"{title}\n\n{summary}\n\nPaths:\n{body_paths}\n{trailer}"
