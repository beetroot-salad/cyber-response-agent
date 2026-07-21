
from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from defender._git import REPO_ROOT, GitError, git
from defender._io import read_text_soft


def _read_env_key(env_file: Path, var: str = "ANTHROPIC_API_KEY") -> str | None:
    text, _err = read_text_soft(env_file)
    if text is None:
        return None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):]
        k, sep, v = line.partition("=")
        if sep and k.strip() == var:
            return v.strip().strip('"').strip("'") or None
    return None


@lru_cache(maxsize=1)
def _main_repo_root() -> Path:
    try:
        out = git(["rev-parse", "--git-common-dir"], cwd=REPO_ROOT)
    except (OSError, GitError):
        return REPO_ROOT
    if not out:
        return REPO_ROOT
    common = Path(out)
    if not common.is_absolute():
        common = (REPO_ROOT / common).resolve()
    return common.parent


def resolve_first_party_key(
    *, root: Path | None = None, main_repo_root: Path | None = None,
    var: str = "ANTHROPIC_API_KEY",
) -> tuple[str | None, Path | None]:
    if root is None:
        root = REPO_ROOT
    if main_repo_root is None:
        main_repo_root = _main_repo_root()
    candidates: list[Path] = []
    explicit = os.environ.get("DEFENDER_ENV_FILE")
    if explicit:
        candidates.append(Path(explicit))
    candidates += [
        root / ".env",
        main_repo_root / ".env",
    ]
    seen: set[Path] = set()
    for path in candidates:
        if path in seen:
            continue
        seen.add(path)
        if path.is_file():
            key = _read_env_key(path, var)
            if key:
                return key, path
    return None, None
