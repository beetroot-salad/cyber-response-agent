#!/usr/bin/env python3
"""Inline API path smell (#1440): a Forgejo API path written anywhere but the forge adapter, or an
OpenBao path written in the lifecycle.

Every Forgejo call the product makes is named in ``defender/_forgejo_api.py``, and every OpenBao
call the lifecycle makes in ``defender/_openbao_api.py``. Callers send what those answer. A path
written at the point of use makes a second, unnamed call shape: "who deletes a forge user?" turns
back into a grep.

What this flags, outside test modules: a string literal (or a constant part of an f-string)
containing ``/api/v1`` in any file but ``_forgejo_api.py``; and one containing ``/v1/`` in a file
under ``lifecycle/``. Docstrings are prose and are not read. Not seen: a path assembled from
pieces none of which holds the marker.

The credential proxy and the tenancy's AppRole login still write their own OpenBao paths: they
are outside this rule's OpenBao scope, not exempt from it.

Mark a deliberate exception with ``# lint-api-path: ok — <reason>`` on the literal's lines. The
baseline ships EMPTY.

Run from repo root:  python tooling/lint/lint_inline_api_paths.py
Exit 0 = clean, 1 = new sites, 2 = scan-blind.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

from _astlib import ScanBlind, read_and_parse, source_files
from _baseline import Finding, gate

REPO_ROOT = Path(__file__).resolve().parents[2]
SCOPE = REPO_ROOT / "defender"
BASELINE_PATH = Path(__file__).with_name("lint_inline_api_paths_baseline.json")

EXCLUDED_DIRS = (".venv", "__pycache__")
SUPPRESS_MARKER = "lint-api-path: ok"
#: The one file a Forgejo path may be written in, relative to the scan scope.
FORGEJO_ADAPTER = "_forgejo_api.py"
#: Where an OpenBao path may not be written: the lifecycle sends `_openbao_api`'s calls.
OPENBAO_SCOPE = "lifecycle/"

_ADVICE = {
    "forgejo": "Forgejo API path written inline — name the call in defender/_forgejo_api.py",
    "openbao": "OpenBao path written in the lifecycle — name the call in defender/_openbao_api.py",
}


def _is_test_module(rel: str) -> bool:
    p = Path(rel)
    return (
        "tests" in p.parts
        or p.name == "conftest.py"
        or (p.name.startswith("test_") and p.suffix == ".py")
        or p.name.endswith("_test.py")
    )


def _docstrings(tree: ast.AST) -> set[int]:
    """The ids of every module, class and function docstring node."""
    found: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
                found.add(id(first.value))
    return found


def _kind(text: str, rel: str) -> str | None:
    if "/api/v1" in text and rel != FORGEJO_ADAPTER:
        return "forgejo"
    if "/v1/" in text and rel.startswith(OPENBAO_SCOPE):
        return "openbao"
    return None


def _suppressed(node: ast.AST, lines: list[str]) -> bool:
    start = getattr(node, "lineno", 0)
    end = getattr(node, "end_lineno", start) or start
    return any(SUPPRESS_MARKER in lines[i - 1] for i in range(start, end + 1) if 0 < i <= len(lines))


def _scan_file(rel: str, tree: ast.AST, lines: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()
    prose = _docstrings(tree)

    def visit(node: ast.AST, func_name: str, literal: ast.AST | None) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            func_name = node.name
        if isinstance(node, ast.JoinedStr):
            literal = node
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in prose:
            site = literal or node
            kind = _kind(node.value, rel)
            if kind is not None and not _suppressed(site, lines):
                fingerprint = f"{rel}:{func_name}:{kind}"
                if fingerprint not in seen:
                    seen.add(fingerprint)
                    findings.append(Finding(
                        fingerprint=fingerprint,
                        display=f"{rel}:{getattr(site, 'lineno', '?')}: {_ADVICE[kind]} (in {func_name}())",
                    ))
        for child in ast.iter_child_nodes(node):
            visit(child, func_name, literal)

    visit(tree, "<module>", None)
    return findings


def _scan(root: Path) -> list[Finding]:
    """Findings under ``root``, fingerprints relative to it (drivable on a tmp tree)."""
    findings: list[Finding] = []
    for rel in source_files(root, EXCLUDED_DIRS):
        if _is_test_module(rel):
            continue
        text, tree = read_and_parse(root / rel, rel)
        findings.extend(_scan_file(rel, tree, text.splitlines()))
    return findings


HEADER = (
    "lint_inline_api_paths baseline — Forgejo API paths written outside defender/_forgejo_api.py, "
    "and OpenBao paths written in defender/lifecycle/ rather than defender/_openbao_api.py (#1440). "
    "Fingerprint is file:function:kind (forgejo|openbao), file relative to the scan scope. This "
    "baseline ships EMPTY — every site was moved onto the adapters when the gate landed, so an "
    "entry in it is a regression someone chose. Regenerate: "
    "python tooling/lint/lint_inline_api_paths.py --update-baseline."
)


def main(
    argv: list[str] | None = None,
    *,
    scope: Path | None = None,
    baseline_path: Path | None = None,
) -> int:
    # DI/test seams: the tests drive injected tmp trees and baselines.
    args = sys.argv[1:] if argv is None else argv
    root = SCOPE if scope is None else scope
    baseline = BASELINE_PATH if baseline_path is None else baseline_path
    if not root.is_dir():
        print(f"scan scope not found at {root}", file=sys.stderr)
        return 2
    try:
        findings = _scan(root)
    except ScanBlind as exc:
        print(f"lint_inline_api_paths: {exc}", file=sys.stderr)
        return 2
    print(
        "Name every Forgejo call in defender/_forgejo_api.py, and every OpenBao call the "
        "lifecycle makes in defender/_openbao_api.py; send what they answer (#1440)."
    )
    print("Mark a deliberate site with `# lint-api-path: ok — <reason>`.")
    return gate(findings, baseline, args, label="lint_inline_api_paths", header=HEADER)


if __name__ == "__main__":
    sys.exit(main())
