from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from defender import _git  # noqa: E402 — needs REPO_ROOT on sys.path


def run(cmd: list[str], cwd: Path, env: dict | None = None,
        input_: str | None = None, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd, cwd=cwd, env=env, input=input_,
        capture_output=True, text=True, check=check, encoding="utf-8"
    )


def init_git(tmp: Path) -> None:
    _git.git(["init", "-q", "-b", "main"], cwd=tmp)
    _git.git(["config", "user.email", "eval@local"], cwd=tmp)
    _git.git(["config", "user.name", "eval"], cwd=tmp)
    _git.git(["add", "-A"], cwd=tmp)
    _git.git(["commit", "-q", "-m", "scenario baseline"], cwd=tmp)


def find_venv_py(repo_root: Path) -> Path:
    env = os.environ.get("LEARNING_VERIFIER_PYTHON")
    if env:
        return Path(env).resolve()
    candidates = [repo_root / "defender" / ".venv" / "bin" / "python3"]
    p = repo_root.parent
    for _ in range(6):
        candidates.append(p / "defender" / ".venv" / "bin" / "python3")
        candidates.append(p / "workspace" / "defender" / ".venv" / "bin" / "python3")
        if p.parent == p:
            break
        p = p.parent
    for c in candidates:
        if c.is_file():
            return c
    sys.exit(f"no defender venv found; tried {candidates}")
