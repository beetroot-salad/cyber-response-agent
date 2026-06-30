"""The forge port — the PR/host provider the author drains open PRs against.

``gh`` (GitHub) is the *one* injected seam in the author git layer: unlike ``git``
(local, deterministic, exercised against a real tmp repo), the forge crosses a
network/auth boundary that can't be hit hermetically, and the provider could change
(GitLab/Gitea). So it sits behind a small ``Forge`` protocol with a ``GhForge`` adapter;
``AuthorBranch`` takes a ``Forge`` and tests inject a fake instead of shelling out to
``gh``. ``git`` is *not* injected — it goes through ``defender._git`` directly.

``GhForge`` raises ``ForgeError`` on a ``gh`` failure; ``AuthorBranch`` translates that to
its lifecycle-level ``BranchError`` (the union spanning git *and* forge faults) so the
worktree-batch envelope's ``except BranchError`` retry path is unchanged.
"""
from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

# The repo root — sourced from the git facade this seam is paired with, rather than
# re-deriving a hand-counted parents[N] that drifts if the module moves.
from defender._git import REPO_ROOT


class ForgeError(Exception):
    """A forge (``gh``) command failed — the PR list/create couldn't complete."""


class Forge(Protocol):
    """The PR-host operations the author drains need: confirm the per-prefix writer
    lease (any open PR under a branch prefix) and open one PR for a pushed branch."""

    def list_open_prs(self, head_prefix: str) -> list[dict]:
        """Open PRs whose head branch matches ``head_prefix`` (a substring search the
        caller prefix-confirms). Each row carries at least ``number`` + ``headRefName``."""
        ...

    def open_pr(self, *, base: str, head: str, title: str, body: str) -> str:
        """Open a PR from ``head`` into ``base``; return the forge's ref (URL/number)."""
        ...


@dataclass(frozen=True)
class GhForge:
    """The production ``gh`` adapter. ``cwd`` is where ``gh`` runs (the repo root)."""

    cwd: Path = REPO_ROOT

    def list_open_prs(self, head_prefix: str) -> list[dict]:
        proc = subprocess.run(
            ["gh", "pr", "list", "--search", f"head:{head_prefix}", "--state", "open",
             "--json", "number,headRefName"],
            cwd=self.cwd, capture_output=True, text=True,
        )
        if proc.returncode != 0:
            raise ForgeError(f"gh pr list failed: {proc.stderr.strip()}")
        try:
            rows = json.loads(proc.stdout or "[]")
        except json.JSONDecodeError as e:
            raise ForgeError(f"gh pr list returned non-JSON: {e}") from e
        return [r for r in rows if isinstance(r, dict)]

    def open_pr(self, *, base: str, head: str, title: str, body: str) -> str:
        proc = subprocess.run(
            ["gh", "pr", "create", "--base", base, "--head", head,
             "--title", title, "--body", body],
            cwd=self.cwd, capture_output=True, text=True,
        )
        if proc.returncode != 0:
            raise ForgeError(f"gh pr create failed: {proc.stderr.strip()}")
        return proc.stdout.strip()
