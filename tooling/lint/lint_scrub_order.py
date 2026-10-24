#!/usr/bin/env python3
"""Scrub-order fence (#540): three rules over the entrypoint and the bash tool.

* In `run.py`'s `main`, the call to the box lifecycle (which scrubs the run folder) comes
  before every reader of that folder: listing it, the table cross-check, the curation enqueue,
  the case ticket and the page render.
* Neither `main` nor `_run_investigation_lifecycle` has an `except` that would swallow the
  taint signal: none names `RunTainted`, `Exception` or `BaseException`, and none is bare.
* The bash tool never calls `run_parsed` on the in-process executor `bash_exec`: a box failure
  has no in-process fallback.

Order is source position inside the one function; attribute calls read as their attribute
name. A file or function that is missing, or a named call that is gone, is a finding (the rule
must be re-sited, never silently pass). A file that does not parse or decode is exit 2.

There is no baseline and no suppression: fix the code.

Run from anywhere:  python tooling/lint/lint_scrub_order.py [--root DIR]
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

_RUN = "run.py"
_BASH = "runtime/tools/_bash.py"
_CONSUMERS = ("iterdir", "cross_check_tables", "enqueue_curation", "record_case_ticket",
              "visualize")
_SWALLOWERS = ("RunTainted", "Exception", "BaseException")


def _function(root: Path, rel: str, name: str, findings: list[str]) -> ast.AST | None:
    path = root / rel
    if not path.is_file():
        findings.append(f"{rel}: missing; the scrub-order rules have nothing to hold")
        return None
    _text, tree = _astlib.read_and_parse(path, rel)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    findings.append(f"{rel}: defines no `{name}`; re-site the scrub-order rule")
    return None


def _call_order(fn: ast.AST) -> list[str]:
    hits = []
    for node in ast.walk(fn):
        if isinstance(node, ast.Call):
            f = node.func
            name = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", None)
            if name:
                hits.append(((node.lineno, node.col_offset), name))
    return [name for _pos, name in sorted(hits)]


def _caught(fn: ast.AST) -> list[tuple[int, str]]:
    out = []
    for node in ast.walk(fn):
        if isinstance(node, ast.ExceptHandler):
            if node.type is None:
                out.append((node.lineno, "(bare except)"))
                continue
            for sub in ast.walk(node.type):
                if isinstance(sub, ast.Name):
                    out.append((node.lineno, sub.id))
                elif isinstance(sub, ast.Attribute):
                    out.append((node.lineno, sub.attr))
    return out


def scan(root: Path) -> list[str]:
    root = Path(root).resolve()
    if not root.is_dir():
        raise _astlib.ScanBlind(f"{root} is not a directory")
    findings: list[str] = []

    main = _function(root, _RUN, "main", findings)
    if main is not None:
        order = _call_order(main)
        if "lifecycle" not in order:
            findings.append(f"{_RUN}: `main` no longer drives the lifecycle through its "
                            "`lifecycle` seam; re-site the scrub-order rule")
        else:
            reap = order.index("lifecycle")
            for consumer in _CONSUMERS:
                if consumer not in order:
                    findings.append(f"{_RUN}: `main` no longer calls `{consumer}`; re-site the "
                                    "scrub-order rule")
                elif order.index(consumer) < reap:
                    findings.append(f"{_RUN}: `main` calls `{consumer}` before the lifecycle "
                                    "has scrubbed the run folder")

    for name, fn in (("main", main),
                     ("_run_investigation_lifecycle",
                      _function(root, _RUN, "_run_investigation_lifecycle", findings))):
        if fn is None:
            continue
        for lineno, caught in _caught(fn):
            if caught == "(bare except)" or caught in _SWALLOWERS:
                findings.append(f"{_RUN}:{lineno}: `{name}` has an `except` naming {caught} "
                                "that would swallow the run-tainted signal")

    bash = _function(root, _BASH, "_tool_bash", findings)
    if bash is not None:
        if "run_parsed" not in _call_order(bash):
            findings.append(f"{_BASH}: `_tool_bash` no longer calls `run_parsed`; re-site the "
                            "no-in-process-fallback rule")
        for node in ast.walk(bash):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "run_parsed"
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "bash_exec"):
                findings.append(f"{_BASH}:{node.lineno}: the bash tool reaches the in-process "
                                "executor directly; a box failure must not fall back to it")
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=DEFENDER,
                        help="a defender/-shaped tree to sweep (default: this checkout's)")
    args = parser.parse_args(argv)
    try:
        found = scan(args.root)
    except _astlib.ScanBlind as exc:
        print(f"[lint_scrub_order] {exc}", file=sys.stderr)
        return 2
    for line in found:
        print(line)
    print(f"[lint_scrub_order] {len(found)} finding(s).")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
