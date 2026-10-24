"""Where published views (run pages, learning pages) go: the one tenant-free owner (#1279 A4).

The deployment rule is stated here and nowhere else (O4): only a `dev` deployment has a publish
root, until blob serving exists. The publisher lays tenant areas over this root, and box start
compares what it mounts against it, so neither resolves a destination on its own.
"""
from __future__ import annotations

import os
from pathlib import Path

from defender._io import read_text_utf8
from defender.configuration import _env

#: The override for where views are published. Host configuration, like `DEFENDER_DATA_ROOT`:
#: read at call time so a test's `setenv` reaches an already-imported module.
PUBLISH_DIR_ENV = "DEFENDER_RUN_VISUALIZATIONS_DIR"
PUBLISH_DIR_NAME = "run-visualizations"

_DEFENDER_DIR = Path(__file__).resolve().parents[1]


class PublishRootRefused(Exception):
    """The publish root cannot be determined safely: under pytest it was about to resolve to a
    real checkout, or a worktree's main checkout cannot be found (A7)."""


def publish_root(start: Path | None = None) -> Path | None:
    """The publish root, or `None` outside `dev`.

    Order: the deployment rule, applied first so no checkout is read outside `dev`; the
    `PUBLISH_DIR_ENV` override; else `<main checkout>/run-visualizations/`, the main checkout
    reached from `start` (by default this package's checkout), so a worktree publishes into the
    one folder the operator opens. Found by reading `.git` rather than running git, which as root
    in a user-owned repo depends on `safe.directory` and inherited `GIT_DIR`.

    Raises `PublishRootRefused` when a worktree's main checkout cannot be determined: falling back
    to `start` would judge mounts, and publish pages, against the wrong folder.
    """
    if _env.deployment() != "dev":
        return None
    override = os.environ.get(PUBLISH_DIR_ENV)
    if override:
        return Path(override)
    if start is None:
        if "PYTEST_CURRENT_TEST" in os.environ:
            raise PublishRootRefused(
                f"{PUBLISH_DIR_ENV} is unset under pytest; refusing the real checkout's "
                f"{PUBLISH_DIR_NAME}/")
        start = _DEFENDER_DIR.parent
    return _main_checkout(start) / PUBLISH_DIR_NAME


def _main_checkout(start: Path) -> Path:
    """`start`, or the main checkout its `.git` file points back to. No `.git` at all (an image
    build) or a `.git` directory is `start` itself; a pointer that cannot be followed, or that
    lands somewhere without `defender/`, is refused."""
    dot_git = start / ".git"
    if dot_git.is_dir() or not dot_git.exists():
        return start
    try:
        pointer = read_text_utf8(dot_git).strip()
        if not pointer.startswith("gitdir:"):
            raise ValueError(f"{dot_git} is not a gitdir pointer")
        admin = (start / pointer[len("gitdir:"):].strip()).resolve()
        common = (admin / read_text_utf8(admin / "commondir").strip()).resolve()
        main = common.parent
        if not (main / "defender").is_dir():
            raise ValueError(f"{main} (from {dot_git}) holds no defender/")
    except (OSError, ValueError) as exc:
        raise PublishRootRefused(f"main checkout of {start} undeterminable: {exc}") from exc
    return main
