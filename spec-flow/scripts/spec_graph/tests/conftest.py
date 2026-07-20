"""Fixture harness for the #643 check_actors suite.

Every test here drives the REAL entry point (`check_actors.py`, via subprocess) against a
throwaway git repo built on the fly. There is no injection seam: `check()` computes both the
changed set (`git diff base...HEAD` at the repo root) and the source census (over codeRoots)
internally, so a fixture must be an actual git repo with a `.claude/spec-flow.json` and a real
import graph on disk. Layout is NAMESPACE-PACKAGE (no `__init__.py`) — the resolver the fix adds
must map `a.b.c` to `<repo_root>/a/b/c.py` directly, exactly as `defender` (a namespace package)
requires; an `__init__.py` layout would not exercise the real condition.

The path to the check_actors under test is overridable via `$CHECK_ACTORS_PATH` — the mandatory
null-stub discrimination run points it at a no-op stub. `$PYTHONPATH` always carries the spec_graph
dir so the script's `import _config` resolves regardless of which script file is invoked.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

SPEC_GRAPH_DIR = Path(__file__).resolve().parent.parent
DEFAULT_CHECK_ACTORS = SPEC_GRAPH_DIR / "check_actors.py"


def run_script(
    script: str,
    *argv: str,
    cwd: Path,
    env_extra: dict[str, str] | None = None,
    timeout: int = 120,
) -> subprocess.CompletedProcess[str]:
    """Drive a real spec_graph script via subprocess — the house style; the scripts have
    no injection seam. `$PYTHONPATH` carries the spec_graph dir so `import _config`
    resolves whichever script file is invoked; `script` may be a bare filename (resolved
    against that dir) or an absolute path (the `$CHECK_*_PATH` null-stub overrides).
    `env_extra` overrides process env for the child — e.g. forcing a non-utf-8 locale,
    exactly the environment that makes an unpinned read/print raise."""
    env = dict(os.environ)
    env["PYTHONPATH"] = str(SPEC_GRAPH_DIR) + os.pathsep + env.get("PYTHONPATH", "")
    env.update(env_extra or {})
    return subprocess.run(
        [sys.executable, str(SPEC_GRAPH_DIR / script), *argv],
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

    def config(
        self,
        *,
        code_roots: list[str],
        entrypoint_stems: tuple[str, ...] = (),
        context_aliases: dict[str, str] | None = None,
        artifacts: str = "**/spec_graph_*.yaml",
    ) -> None:
        self.write(
            ".claude/spec-flow.json",
            json.dumps(
                {
                    "specGraph": {
                        "artifacts": artifacts,
                        "codeRoots": list(code_roots),
                        "entrypointStems": list(entrypoint_stems),
                        "contextAliases": dict(context_aliases or {}),
                        "conceptAliases": {},
                    }
                }
            ),
        )

    def graph(
        self, text: str = "schema_version: 1\ndemands: []\n", name: str = "spec_graph_x.yaml"
    ) -> str:
        self.write(name, text)
        return name

    def commit(self, msg: str = "c") -> str:
        self._git("add", "-A")
        self._git("commit", "-q", "-m", msg)
        return self._git("rev-parse", "HEAD").strip()

    def run(
        self,
        graph_name: str,
        base: str,
        subdir: str | None = None,
        env_extra: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        env = dict(os.environ)
        check = os.environ.get("CHECK_ACTORS_PATH", str(DEFAULT_CHECK_ACTORS))
        env["PYTHONPATH"] = str(SPEC_GRAPH_DIR) + os.pathsep + env.get("PYTHONPATH", "")
        # `env_extra` overrides process env for the child — used to force a non-utf-8 locale (see the
        # ascii-locale test), which is exactly the environment that makes an unpinned read/print raise.
        env.update(env_extra or {})
        # `subdir` runs the tool from a subdirectory of the fixture (not the repo root), exactly as
        # this project's gate does (`cd defender && spec-graph …`). git resolves paths against the
        # process CWD, so the graph arg is made absolute here to stay readable from the subdir —
        # what is under test is that check_actors ANCHORS its own git diff at the repo root anyway.
        cwd = self.root / subdir if subdir else self.root
        graph_arg = str(self.root / graph_name) if subdir else graph_name
        return subprocess.run(
            [sys.executable, check, graph_arg, "--base", base],
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )


@pytest.fixture
def make_repo(tmp_path: Path):
    counter = {"n": 0}

    def _factory() -> Repo:
        counter["n"] += 1
        d = tmp_path / f"repo{counter['n']}"
        d.mkdir()
        return Repo(d)

    return _factory
