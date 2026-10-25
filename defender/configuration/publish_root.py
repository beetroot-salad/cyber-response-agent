"""Where published views (run pages, learning pages) go: the one tenant-free owner (#1279 A4).

The deployment rule is stated here and nowhere else (O4): only a `dev` deployment has a publish
root, until blob serving exists. The publisher lays tenant areas over this root, and box start
compares what it mounts against it, so neither resolves a destination on its own.

The root is host configuration that `dev` must name (#1279 rev 5, A11): there is no default
worked out from a checkout, so every process on a host that shares the setting publishes into,
and judges box mounts against, the same folder. The owner never raises (A9): it answers a root,
or `NoRoot` saying why.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from defender.configuration import _env

#: Where views are published on `dev`. Host configuration, like `DEFENDER_DATA_ROOT`: read at
#: call time so a test's `setenv` reaches an already-imported module.
PUBLISH_DIR_ENV = "DEFENDER_RUN_VISUALIZATIONS_DIR"


@dataclass(frozen=True)
class NoRoot:
    """There is nowhere to publish: `not-dev` (the deployment rule), or `unset` (`dev`, but
    `PUBLISH_DIR_ENV` names no folder); `reason` says which, for the operator."""

    kind: Literal["not-dev", "unset"]
    reason: str


def publish_root() -> Path | NoRoot:
    """The publish root, or `NoRoot`. The deployment rule is applied first, so outside `dev`
    the setting is never read."""
    deployment = _env.deployment()
    if deployment != "dev":
        return NoRoot("not-dev", f"this deployment counts as {deployment!r}, and only "
                                 f"{_env.DEPLOYMENT_ENV}=dev has a publish destination")
    configured = os.environ.get(PUBLISH_DIR_ENV)
    if not configured:
        return NoRoot("unset", f"{PUBLISH_DIR_ENV} is unset; a dev deployment names its publish "
                               "folder (no folder is assumed)")
    return Path(configured)
