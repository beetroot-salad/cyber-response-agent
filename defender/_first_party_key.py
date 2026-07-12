"""First-party (metered) API-key sourcing from a `.env` file.

The in-process PydanticAI engine calls a provider's first-party REST API, so it
needs a real *billable* key — not the ambient subscription credential a Claude
Code session exports (which 401s against the first-party API). This module reads
that key from a `.env` file, precedence-ordered, without a full dotenv load.

Neutral by design: it depends only on `defender._git` (REPO_ROOT + git), no
runtime/pydantic graph, so BOTH the runtime entrypoint (`run.py`) and the
learning loop (the judge's metered-key sourcing) can import it. `run.py`
re-exports these names for its historical surface.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from defender._git import REPO_ROOT, GitError, git
from defender._io import read_text_soft


def _read_env_key(env_file: Path, var: str = "ANTHROPIC_API_KEY") -> str | None:
    """Extract a single var from a `.env` file. Deliberately *not* a full dotenv
    load — we only want the API key, not to clobber adapter config (data-source creds,
    docker-context vars) that also live in these files. Returns the value or None."""
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
    """The main worktree's root, where shared config like `.env` lives.

    Under a linked git worktree `REPO_ROOT` is the *worktree* root, not the main
    checkout, so `<repo_root>/.env` misses the canonical file. Git's common dir
    (`.../.git`) is shared by every worktree; its parent is the main root. Falls back
    to `REPO_ROOT` outside a git tree.

    `@lru_cache`d: the value is a function of `REPO_ROOT` + the on-disk `.git` layout, both
    process-invariant, so the `git rev-parse` fork runs once per process instead of once
    per key-sourcing. A learn drain sources a metered key per run (N runs, one process),
    which without the cache is N identical forks — and more, since `_prepare_engines_for`
    sources one key per distinct model. The error-fallback is therefore sticky for the
    process; a test exercising it must `_main_repo_root.cache_clear()`.
    """
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
    """The billable provider API key for the PydanticAI engine, sourced from a
    `.env` file rather than the ambient environment. Defaults to the first-party
    ANTHROPIC_API_KEY; pass ``var="FIREWORKS_API_KEY"`` for the Fireworks/GLM path.

    Inside a Claude Code session the ambient ANTHROPIC key is the *subscription*
    credential (the session's nested `claude -p` rides it; it 401s against the
    first-party REST API this engine calls), so the `.env` key takes precedence.
    First existing file that defines ``var`` wins:

      1. ``$DEFENDER_ENV_FILE``        — explicit override
      2. ``<repo_root>/.env``
      3. ``<main_worktree_root>/.env`` — repo_root points at the *worktree* root
                                         under a linked git worktree; shared config
                                         like .env lives in the main checkout

    Returns ``(key, source_path)`` or ``(None, None)``.
    """
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
