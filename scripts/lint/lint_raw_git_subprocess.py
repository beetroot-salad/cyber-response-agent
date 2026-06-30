#!/usr/bin/env python3
"""Raw git-subprocess smell — flag hand-rolled ``git`` subprocess calls under
``defender/`` that bypass the shared ``defender._git`` facade.

The "run a git argv, check rc, return stdout" primitive (plus ``git status
--porcelain`` parsing and worktree add/remove/prune) was reinvented ~8× across
``learning/``, ``evals/``, ``scripts/`` and ``run.py`` (#460). Each copy re-derived
the rc check, the error message, and (for status) the porcelain parsing — and the
non-``-z`` copies mis-handled spaced paths. The single surface is
``defender/_git.py`` (``git`` / ``git_status`` / ``git_commit`` / ``git_worktree_*`` /
``GitError``); route every git invocation through it.

What this flags: any call whose first positional argument is a **list literal
starting with the string** ``"git"`` — e.g. ``subprocess.run(["git", "status", …])``,
``subprocess.check_output(["git", …])``, or a local wrapper ``run(["git", …])`` /
``_run(["git", …])``. The list-first-element shape catches the wrapper indirections
too, and never matches the facade's own ``_git.git(["status", …])`` (those lists start
with the *subcommand*, not ``"git"``).

What it does NOT flag: calls through ``defender._git`` (the facade itself, which is
out of scope below); a git argv built in a variable rather than an inline list (rare;
not statically matchable); and **test modules** — ``tests/`` fixtures legitimately
build throwaway repos with raw ``git init``/``commit`` (the sanctioned real-tmp-repo
testing pattern, #389/#460), so the whole test category is exempt.

The one sanctioned subprocess site is ``defender/_git.py`` itself (excluded from
scope). Mark any other deliberate exception with ``# lint-git: ok — <reason>`` on the
call's line span. Pre-existing sites are ratcheted via
``lint_raw_git_subprocess_baseline.json`` (see scripts/lint/_baseline.py); the gate
fails only on a NEW file+function pair.

Run from repo root:  python scripts/lint/lint_raw_git_subprocess.py
Regenerate the baseline:  python scripts/lint/lint_raw_git_subprocess.py --update-baseline
Exit 0 = clean (no new sites), 1 = new sites.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

from _baseline import Finding, gate

REPO_ROOT = Path(__file__).resolve().parents[2]
SCOPE = REPO_ROOT / "defender"
BASELINE_PATH = Path(__file__).with_name("lint_raw_git_subprocess_baseline.json")

EXCLUDED_DIRS = (".venv", "__pycache__", "run-visualizations", "run-transcripts")
# The facade itself is the one sanctioned git-subprocess site.
EXCLUDED_FILES = ("defender/_git.py",)
SUPPRESS_MARKER = "lint-git: ok"


def _in_scope(path: Path) -> bool:
    return not any(part in EXCLUDED_DIRS for part in path.parts)


def _is_test_module(rel: str) -> bool:
    """A ``tests/`` dir or a flat ``test_*.py`` / ``*_test.py`` / ``conftest.py``.
    Test fixtures build throwaway repos with raw git on purpose (the sanctioned
    real-tmp-repo pattern), so the whole category is exempt."""
    p = Path(rel)
    return (
        "tests" in p.parts
        or p.name == "conftest.py"
        or (p.name.startswith("test_") and p.suffix == ".py")
        or p.name.endswith("_test.py")
    )


def _is_git_argv_call(node: ast.AST) -> bool:
    """True if ``node`` is a call whose first positional arg is a list literal whose
    first element is the constant string ``"git"`` (``["git", …]`` / ``["git", *a]``)."""
    if not isinstance(node, ast.Call) or not node.args:
        return False
    first = node.args[0]
    if not isinstance(first, ast.List) or not first.elts:
        return False
    head = first.elts[0]
    return isinstance(head, ast.Constant) and head.value == "git"


def _suppressed(node: ast.AST, lines: list[str]) -> bool:
    start = node.lineno
    end = getattr(node, "end_lineno", start) or start
    return any(
        SUPPRESS_MARKER in lines[i - 1]
        for i in range(start, end + 1)
        if 0 < i <= len(lines)
    )


def _scan_file(rel: str, tree: ast.AST, lines: list[str]) -> list[Finding]:
    if _is_test_module(rel):
        return []
    findings: list[Finding] = []
    seen: set[str] = set()

    def visit(node: ast.AST, func_name: str) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            func_name = node.name
        if _is_git_argv_call(node) and not _suppressed(node, lines):
            fp = f"{rel}:{func_name}"
            if fp not in seen:
                seen.add(fp)
                findings.append(
                    Finding(
                        fingerprint=fp,
                        display=(
                            f"{rel}:{node.lineno}: raw git subprocess in "
                            f"{func_name}() — use the defender._git facade"
                        ),
                    )
                )
        for child in ast.iter_child_nodes(node):
            visit(child, func_name)

    visit(tree, "<module>")
    return findings


def _scan() -> list[Finding]:
    findings: list[Finding] = []
    for path in sorted(SCOPE.rglob("*.py")):
        if not _in_scope(path):
            continue
        rel = path.relative_to(REPO_ROOT).as_posix()
        if rel in EXCLUDED_FILES:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(text)
        except (OSError, SyntaxError):
            continue
        findings.extend(_scan_file(rel, tree, text.splitlines()))
    return findings


HEADER = (
    "lint_raw_git_subprocess baseline — hand-rolled git subprocess calls under "
    "defender/ that bypass the defender._git facade (a ~8× dedup smell + the "
    "spaced-path porcelain bug, #460). Fingerprint is file:function (no line "
    "number). CI fails on a fingerprint absent here. Regenerate: python "
    "scripts/lint/lint_raw_git_subprocess.py --update-baseline. Annotate "
    'intentional entries; "" = un-triaged debt to route through defender._git.'
)


def main(argv: list[str]) -> int:
    if not SCOPE.is_dir():
        print(f"defender/ not found at {SCOPE}", file=sys.stderr)
        return 2
    findings = _scan()
    print(
        "Route git invocations through the defender._git facade (git / git_status / "
        "git_commit / git_worktree_* / GitError), not a hand-rolled subprocess call."
    )
    print("Mark a sanctioned git subprocess with `# lint-git: ok — <reason>`.")
    return gate(
        findings, BASELINE_PATH, argv,
        label="lint_raw_git_subprocess", header=HEADER,
    )


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
