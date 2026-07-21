from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from defender._git import REPO_ROOT


class ForgeError(Exception):
    pass


class Forge(Protocol):

    def list_open_prs(self, head_prefix: str) -> list[dict]:
        ...

    def list_prs_for_head(self, head: str) -> list[dict]:
        ...

    def open_pr(self, *, base: str, head: str, title: str, body: str) -> str:
        ...


@dataclass(frozen=True)
class GhForge:

    cwd: Path = REPO_ROOT

    def _list_prs(self, *match_args: str) -> list[dict]:
        proc = subprocess.run(
            ["gh", "pr", "list", *match_args, "--state", "open",
             "--json", "number,headRefName,url"],
            cwd=self.cwd, capture_output=True, text=True, encoding="utf-8"
        )
        if proc.returncode != 0:
            raise ForgeError(f"gh pr list failed: {proc.stderr.strip()}")
        try:
            rows = json.loads(proc.stdout or "[]")
        except json.JSONDecodeError as e:
            raise ForgeError(f"gh pr list returned non-JSON: {e}") from e
        return [r for r in rows if isinstance(r, dict)]

    def list_open_prs(self, head_prefix: str) -> list[dict]:
        return self._list_prs("--search", f"head:{head_prefix}")

    def list_prs_for_head(self, head: str) -> list[dict]:
        return self._list_prs("--head", head)

    def open_pr(self, *, base: str, head: str, title: str, body: str) -> str:
        proc = subprocess.run(
            ["gh", "pr", "create", "--base", base, "--head", head,
             "--title", title, "--body", body],
            cwd=self.cwd, capture_output=True, text=True, encoding="utf-8"
        )
        if proc.returncode != 0:
            raise ForgeError(f"gh pr create failed: {proc.stderr.strip()}")
        return proc.stdout.strip()
