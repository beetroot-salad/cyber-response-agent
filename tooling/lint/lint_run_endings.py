#!/usr/bin/env python3
"""One owner for run-ending precedence (#1465): only `investigation/run_endings.py` orders endings.

Which ending a run takes when several are raised (bare or inside an exception group) is decided by
the table in `defender/investigation/run_endings.py`. A site that ends a run, or stamps a lead,
asks `ending_in` there. A second place that calls `carried_unless_overridden` (the group reader
that says "this failure, unless a kill or abort beside it wins") is deciding precedence itself, so
the next ending would have to be added there too, in a matching place.

A call resolving to `defender._exception_groups.carried_unless_overridden` outside the table's
module is a finding. There is no baseline and no suppression: add a row to the table.

Run from anywhere:  python tooling/lint/lint_run_endings.py [--root DIR]
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
#: The only module that orders endings (and the reader it uses, which defines the function).
OWNERS = frozenset({"investigation/run_endings.py", "_exception_groups.py"})
_ORDERING_READER = "defender._exception_groups.carried_unless_overridden"


def scan(root: Path) -> list[str]:
    root = Path(root).resolve()
    if not root.is_dir():
        raise _astlib.ScanBlind(f"{root} is not a directory")
    findings: list[str] = []
    for rel in _astlib.source_files(root, EXCLUDED_DIRS):
        if rel in OWNERS:
            continue
        _text, tree = _astlib.read_and_parse(root / rel, rel)
        env = _astlib.module_env(tree)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and _astlib.callee(node, env) == _ORDERING_READER:
                findings.append(f"{rel}:{node.lineno}: orders endings itself; add a row to the "
                                "table in investigation/run_endings.py and ask `ending_in`")
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=DEFENDER,
                        help="a defender/-shaped tree to sweep (default: this checkout's)")
    args = parser.parse_args(argv)
    try:
        found = scan(args.root)
    except _astlib.ScanBlind as exc:
        print(f"[lint_run_endings] {exc}", file=sys.stderr)
        return 2
    for line in found:
        print(line)
    print(f"[lint_run_endings] {len(found)} finding(s).")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
