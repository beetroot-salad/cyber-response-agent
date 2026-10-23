"""Fixture harness for the check_calls and check_stub suites.

Every test drives the REAL script via subprocess (the scripts have no injection seam) against a
throwaway git repo built on the fly, and asserts on the exit code and the identity of the test
named in a finding, never exact wording. Exit codes: 0 clean, 1 the check looked and found
something, 2 it could not look (never a silent pass). Fixture layout is NAMESPACE-PACKAGE (no
`__init__.py`), as `defender` requires.
"""
from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parent.parent


def run_script(
    script: str,
    *argv: str,
    cwd: Path,
    env_extra: dict[str, str] | None = None,
    timeout: int = 120,
) -> subprocess.CompletedProcess[str]:
    """Drive a real script via subprocess. `$PYTHONPATH` carries the scripts dir so its
    shared helpers import; `env_extra` overrides process env for the child."""
    env = dict(os.environ)
    env["PYTHONPATH"] = str(SCRIPTS_DIR) + os.pathsep + env.get("PYTHONPATH", "")
    env.update(env_extra or {})
    return subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / script), *argv],
        cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout,
    )


class Repo:
    """A throwaway git repo standing in for a target project's checkout."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self._git("init", "-q")
        self._git("config", "user.email", "harness@example.test")
        self._git("config", "user.name", "harness")
        self._git("config", "commit.gpgsign", "false")

    def _git(self, *args: str) -> str:
        return subprocess.run(
            ["git", *args], cwd=self.root, check=True, capture_output=True, text=True
        ).stdout

    def write(self, rel: str, text: str) -> Path:
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(text).lstrip("\n"))
        return p

    def commit(self, msg: str = "c") -> str:
        self._git("add", "-A")
        self._git("commit", "-q", "-m", msg)
        return self._git("rev-parse", "HEAD").strip()


@pytest.fixture
def make_repo(tmp_path: Path):
    counter = {"n": 0}

    def _factory() -> Repo:
        counter["n"] += 1
        d = tmp_path / f"repo{counter['n']}"
        d.mkdir()
        return Repo(d)

    return _factory
