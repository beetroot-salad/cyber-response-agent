"""Where published views (run pages, learning pages) go: the one tenant-free owner (#1279 A4).

The deployment rule is stated here and nowhere else (O4): only a `dev` deployment has a publish
root, until blob serving exists. The publisher lays tenant areas over this root, and box start
compares what it mounts against it, so neither resolves a destination on its own.

The owner never raises (#1279 rev 4, A9): it answers a root, or `NoRoot` saying why. Every
caller asks the same question, with no start, so box start judges mounts against exactly the
folder this process publishes into (A8).
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from defender._io import read_text_utf8
from defender.configuration import _env

#: The override for where views are published. Host configuration, like `DEFENDER_DATA_ROOT`:
#: read at call time so a test's `setenv` reaches an already-imported module.
PUBLISH_DIR_ENV = "DEFENDER_RUN_VISUALIZATIONS_DIR"
PUBLISH_DIR_NAME = "run-visualizations"

_DEFENDER_DIR = Path(__file__).resolve().parents[1]


class CheckoutUndeterminable(Exception):
    """A worktree's main checkout cannot be found: its `.git` pointer cannot be followed, or it
    leads somewhere without `defender/`."""


@dataclass(frozen=True)
class NoRoot:
    """There is nowhere to publish: `not-dev` (the deployment rule), or `undeterminable` (dev,
    but the default root cannot be found; `reason` names the cause)."""

    kind: Literal["not-dev", "undeterminable"]
    reason: str


def publish_root() -> Path | NoRoot:
    """The publish root of this process, or `NoRoot`.

    Order: the deployment rule, applied first so no checkout is read outside `dev`; the
    `PUBLISH_DIR_ENV` override; else `<main checkout>/run-visualizations/` of this package's
    checkout, so a worktree publishes into the one folder the operator opens. Under pytest the
    default is never used: a test that reaches it would write into the real checkout."""
    deployment = _env.deployment()
    if deployment != "dev":
        return NoRoot("not-dev", f"this deployment counts as {deployment!r}, and only "
                                 f"{_env.DEPLOYMENT_ENV}=dev has a publish destination")
    override = os.environ.get(PUBLISH_DIR_ENV)
    if override:
        return Path(override)
    if "PYTEST_CURRENT_TEST" in os.environ:
        return NoRoot("undeterminable", f"{PUBLISH_DIR_ENV} is unset under pytest; refusing the "
                                        f"real checkout's {PUBLISH_DIR_NAME}/")
    try:
        return main_checkout(_DEFENDER_DIR.parent) / PUBLISH_DIR_NAME
    except CheckoutUndeterminable as e:
        return NoRoot("undeterminable", str(e))


def main_checkout(start: Path) -> Path:
    """`start`, or the main checkout its `.git` file points back to. No `.git` at all (an image
    build) or a `.git` directory is `start` itself. Found by reading `.git` rather than running
    git, which as root in a user-owned repo depends on `safe.directory` and inherited `GIT_DIR`.
    Raises `CheckoutUndeterminable` rather than fall back to `start`, which would publish where
    the operator is not looking."""
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
        raise CheckoutUndeterminable(f"main checkout of {start} undeterminable: {exc}") from exc
    return main
