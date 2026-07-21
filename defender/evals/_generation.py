from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path

from defender import _git

_EVALS_DIR = Path(__file__).resolve().parent
if str(_EVALS_DIR) not in sys.path:
    sys.path.insert(0, str(_EVALS_DIR))

from _secondary_config import WORKTREES_DIR  # noqa: E402



_TRAILER_GEN_RE = re.compile(r"^Generation:\s*(\d+)\s*$", re.MULTILINE)
_TRAILER_MODEL_RE = re.compile(r"^Actor-Model:\s*(\S.*?)\s*$", re.MULTILINE)


@dataclass
class GenerationPin:
    generation: int
    sha: str
    actor_model: str


def parse_trailers(commit_msg: str) -> tuple[int | None, str | None]:
    gm = _TRAILER_GEN_RE.search(commit_msg)
    mm = _TRAILER_MODEL_RE.search(commit_msg)
    gen = int(gm.group(1)) if gm else None
    model = mm.group(1) if mm else None
    return gen, model


def list_actor_commits(repo_root: Path) -> list[GenerationPin]:
    log_out = _git.git(
        ["log", "--grep=^Actor-Model: ", "--format=__SHA__%H%n%B%n__END__", "HEAD"],
        cwd=repo_root,
    )
    out: list[GenerationPin] = []
    for chunk in log_out.split("__SHA__"):
        chunk = chunk.strip()
        if not chunk:
            continue
        sha, _, rest = chunk.partition("\n")
        body = rest.split("__END__", 1)[0]
        gen, model = parse_trailers(body)
        if gen is None or model is None:
            print(
                f"warning: actor-author commit {sha[:8]} missing trailer "
                f"(gen={gen!r}, model={model!r}) — skipping",
                file=sys.stderr,
            )
            continue
        out.append(GenerationPin(generation=gen, sha=sha, actor_model=model))
    return out


def resolve_target_pin(repo_root: Path, k: int) -> GenerationPin | None:
    commits = list_actor_commits(repo_root)
    if not commits:
        return None
    latest_gen = max(c.generation for c in commits)
    target_gen = latest_gen - k
    if target_gen < 1:
        return None
    for c in commits:
        if c.generation == target_gen:
            return c
    return None



def worktree_path_for(pin: GenerationPin, worktrees_dir: Path | None = None) -> Path:
    worktrees_dir = worktrees_dir or WORKTREES_DIR
    return worktrees_dir / f"replay-gen-{pin.generation}"


def _worktree_head_sha(path: Path) -> str | None:
    return _git.git(["rev-parse", "HEAD"], cwd=path, check=False) or None


def ensure_worktree(pin: GenerationPin, repo_root: Path, worktrees_dir: Path | None = None) -> Path:
    path = worktree_path_for(pin, worktrees_dir=worktrees_dir)
    if path.is_dir() and (path / ".git").exists():
        head = _worktree_head_sha(path)
        if head == pin.sha:
            return path
        print(
            f"warning: worktree {path} at {head} != pin {pin.sha}; recreating",
            file=sys.stderr,
        )
        _git.git_worktree_remove(repo_root, path, force=True)
    path.parent.mkdir(parents=True, exist_ok=True)
    _git.git_worktree_add(repo_root, path, pin.sha, detach=True)
    return path


def replay_script_path(worktree: Path) -> Path:
    new = worktree / "defender" / "learning" / "ops" / "replay_actor.py"
    legacy = worktree / "defender" / "learning" / "replay_actor.py"
    return new if new.is_file() else legacy


def worktree_has_replay_script(worktree: Path) -> bool:
    return replay_script_path(worktree).is_file()
