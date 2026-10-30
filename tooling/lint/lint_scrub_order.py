#!/usr/bin/env python3
"""Scrub-order fence (#540, re-sited by #1342): three rules over the entrypoint and the bash tool.

* `run.py` has two compositions, the operator's `main` and the job entry's `job_main`. Each
  calls the box lifecycle (which scrubs the run folder) and then the shared `_post_steps`, in
  that order. The readers of the run folder — listing it, the table cross-check and the page
  render — live only in `_post_steps`; a composition calling one itself is a finding. The
  operator's own readers, the case ticket and the curation enqueue, come after its lifecycle.
* None of `main`, `job_main`, `_post_steps` or `_run_investigation_lifecycle` has an `except`
  that would swallow the taint signal: none names `RunTainted`, `Exception` or `BaseException`,
  and none is bare.
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
_BASH = "investigation/tools/_bash.py"
#: The readers of the scrubbed folder that live only in the shared post-steps.
_READERS = ("iterdir", "cross_check_tables", "visualize")
#: The operator composition's own readers, after its lifecycle.
_OPERATOR_READERS = ("record_case_ticket", "enqueue_curation")
_COMPOSITIONS = ("main", "job_main")
_LIFECYCLE = "lifecycle"
_POST_STEPS = "_post_steps"
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


def _composition_findings(name: str, order: list[str]) -> list[str]:
    """One composition's order: the lifecycle, then the post-steps (and, for `main`, its own
    readers) after it; no reader of the folder called here instead of in the post-steps."""
    if _LIFECYCLE not in order:
        return [f"{_RUN}: `{name}` no longer drives the lifecycle through its `{_LIFECYCLE}` seam; "
                "re-site the scrub-order rule"]
    reap = order.index(_LIFECYCLE)
    found = []
    after = (_POST_STEPS, *(_OPERATOR_READERS if name == "main" else ()))
    for call in after:
        if call not in order:
            found.append(f"{_RUN}: `{name}` no longer calls `{call}`; re-site the scrub-order rule")
        elif order.index(call) < reap:
            found.append(f"{_RUN}: `{name}` calls `{call}` before the lifecycle has scrubbed the "
                         "run folder")
    for reader in _READERS:
        if reader in order:
            found.append(f"{_RUN}: `{name}` calls `{reader}` itself; the readers of the scrubbed "
                         f"folder live only in `{_POST_STEPS}`")
    return found


def _readers_elsewhere(root: Path) -> list[str]:
    """A reader called from a `run.py` function that is neither `_post_steps` nor a composition (those are
    checked by order above): a helper the compositions
    reach would read the folder before the scrub whatever order the compositions show."""
    path = root / _RUN
    if not path.is_file():
        return []
    _text, tree = _astlib.read_and_parse(path, _RUN)
    found: list[str] = []

    def visit(node: ast.AST, owner: str | None) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                visit(child, child.name)
                continue
            if isinstance(child, ast.Call) and owner not in (None, _POST_STEPS, *_COMPOSITIONS):
                f = child.func
                name = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", None)
                if name in _READERS:
                    found.append(f"{_RUN}:{child.lineno}: `{owner}` calls `{name}`; the readers of the "
                                 f"run folder live only in `{_POST_STEPS}`")
            visit(child, owner)

    visit(tree, None)
    return found


def scan(root: Path) -> list[str]:
    root = Path(root).resolve()
    if not root.is_dir():
        raise _astlib.ScanBlind(f"{root} is not a directory")
    findings: list[str] = []

    functions = {name: _function(root, _RUN, name, findings)
                 for name in (*_COMPOSITIONS, _POST_STEPS, "_run_investigation_lifecycle")}

    for name in _COMPOSITIONS:
        fn = functions[name]
        if fn is not None:
            findings.extend(_composition_findings(name, _call_order(fn)))

    steps = functions[_POST_STEPS]
    if steps is not None:
        order = _call_order(steps)
        for reader in _READERS:
            if reader not in order:
                findings.append(f"{_RUN}: `{_POST_STEPS}` no longer calls `{reader}`; re-site the "
                                "scrub-order rule")

    findings.extend(_readers_elsewhere(root))

    for name, fn in functions.items():
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
    # One finding per fault: a missing `run.py` is found once, not once per function.
    return list(dict.fromkeys(findings))


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
