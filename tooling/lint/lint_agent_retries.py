#!/usr/bin/env python3
"""Agent retries fence (#631): every pydantic_ai `Agent(...)` built in production passes `retries=`.

The framework's default is no retry budget, which turns a single denied tool call into a dead
run. A construction is any call whose callee resolves to pydantic_ai's `Agent`, however it is
imported or aliased. A `**mapping` argument does not count as passing `retries=`, because the
check cannot see inside it.

There is no baseline and no suppression: pass `retries=`. A file that does not parse or decode
is a finding of exit 2, never skipped.

Run from anywhere:  python tooling/lint/lint_agent_retries.py [--root DIR]
Exit 0 = clean, 1 = a finding, 2 = could not scan.
"""
from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

import _astlib

#: The checkout's own `defender/`, so a run from any directory or worktree sweeps itself.
DEFENDER = Path(__file__).resolve().parents[2] / "defender"

EXCLUDED_DIRS = ("tests", ".venv", "__pycache__")
_AGENT_ORIGINS = frozenset({"pydantic_ai.Agent", "pydantic_ai.agent.Agent"})


def scan(root: Path) -> list[str]:
    root = Path(root).resolve()
    if not root.is_dir():
        raise _astlib.ScanBlind(f"{root} is not a directory")
    findings: list[str] = []
    for rel in _astlib.source_files(root, EXCLUDED_DIRS):
        _text, tree = _astlib.read_and_parse(root / rel, rel)
        env = _astlib.module_env(tree)
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and _astlib.callee(node, env) in _AGENT_ORIGINS
                    and not _astlib.has_kw(node, "retries")):
                findings.append(f"{rel}:{node.lineno}: `Agent(...)` omits `retries=`: the "
                                "framework default gives a denied tool call no second try")
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=DEFENDER,
                        help="a defender/-shaped tree to sweep (default: this checkout's)")
    args = parser.parse_args(argv)
    try:
        found = scan(args.root)
    except _astlib.ScanBlind as exc:
        print(f"[lint_agent_retries] {exc}", file=sys.stderr)
        return 2
    for line in found:
        print(line)
    print(f"[lint_agent_retries] {len(found)} finding(s).")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
