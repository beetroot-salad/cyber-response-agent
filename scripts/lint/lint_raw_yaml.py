#!/usr/bin/env python3
"""Raw PyYAML: flag a YAML load or dump under ``defender/`` that bypasses ``defender/_yaml.py``.

No YAML the tree reads may reuse a node by alias (#1127). Loading an alias is cheap — PyYAML
shares the node rather than copying it — so the cost lands on whatever walks the result as a
tree: a few hundred bytes of aliases stand for billions of values to an encoder, a comparison
or a cleaner, and an alias can close a cycle that crashes the first recursive walker.
``_yaml.safe_load`` (and ``compose``, ``safe_load_typed_and_spelled``) refuse any alias, and
``_yaml.safe_dump`` never writes one. A raw ``yaml.safe_load`` accepts aliases again, and a raw
``yaml.safe_dump`` writes ``&id001``/``*id001`` the tree's own readers then refuse — so either
one reopens the class the module closed.

What it flags — a **Call** whose resolved origin is a PyYAML load or dump function
(``yaml.load``, ``yaml.safe_load``, ``yaml.compose``, ``yaml.dump``, ``yaml.safe_dump``, their
``_all`` forms, ``full_load`` and ``unsafe_load``), in defender/ production code. The callee is
resolved (``scripts/lint/_astlib.py``), so an aliased module or a from-import counts.

Tests are excluded (fixtures build YAML with PyYAML to probe the readers, aliases included), and
``defender/_yaml.py`` is exempt as the canonical module.

Mark a deliberate site with ``# lint-yaml: ok — <reason>`` on the call's line span. The
baseline ships EMPTY, so an entry in it is a chosen regression.

Run from repo root:  python scripts/lint/lint_raw_yaml.py
Regenerate the baseline:  python scripts/lint/lint_raw_yaml.py --update-baseline
Exit 0 = clean (no new sites), 1 = new sites, 2 = scan scope missing.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

from _astlib import ScanBlind, callee, module_env, read_and_parse, source_files
from _baseline import Finding, gate

REPO_ROOT = Path(__file__).resolve().parents[2]
SCOPE = REPO_ROOT / "defender"
BASELINE_PATH = Path(__file__).with_name("lint_raw_yaml_baseline.json")

EXCLUDED_DIRS = (".venv", "__pycache__")
SUPPRESS_MARKERS = ("lint-yaml: ok",)
CANONICAL_MODULE = "_yaml.py"

_LOADS = ("load", "safe_load", "full_load", "unsafe_load", "load_all", "safe_load_all",
          "full_load_all", "unsafe_load_all", "compose", "compose_all")
_DUMPS = ("dump", "safe_dump", "dump_all", "safe_dump_all")
_KIND = {**{f"yaml.{n}": "load" for n in _LOADS}, **{f"yaml.{n}": "dump" for n in _DUMPS}}
_ADVICE = {
    "load": "raw PyYAML load (accepts aliases) — use defender._yaml.safe_load",
    "dump": "raw PyYAML dump (writes aliases) — use defender._yaml.safe_dump",
}


def _is_test_module(rel: str) -> bool:
    p = Path(rel)
    return (
        "tests" in p.parts
        or p.name == "conftest.py"
        or (p.name.startswith("test_") and p.suffix == ".py")
        or p.name.endswith("_test.py")
    )


def _suppressed(node: ast.AST, lines: list[str]) -> bool:
    start = node.lineno  # type: ignore[attr-defined]
    end = getattr(node, "end_lineno", start) or start
    return any(
        any(m in lines[i - 1] for m in SUPPRESS_MARKERS)
        for i in range(start, end + 1)
        if 0 < i <= len(lines)
    )


def _scan_file(rel: str, tree: ast.AST, lines: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()
    env = module_env(tree)

    def visit(node: ast.AST, func_name: str) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            func_name = node.name
        if isinstance(node, ast.Call):
            kind = _KIND.get(callee(node, env) or "")
            if kind is not None and not _suppressed(node, lines):
                fingerprint = f"{rel}:{func_name}:{kind}"
                if fingerprint not in seen:
                    seen.add(fingerprint)
                    findings.append(Finding(
                        fingerprint=fingerprint,
                        display=f"{rel}:{node.lineno}: {_ADVICE[kind]} (in {func_name}())",
                    ))
        for child in ast.iter_child_nodes(node):
            visit(child, func_name)

    visit(tree, "<module>")
    return findings


def _scan(root: Path) -> list[Finding]:
    """Findings under ``root``, fingerprints relative to it (drivable on a tmp tree)."""
    findings: list[Finding] = []
    for rel in source_files(root, EXCLUDED_DIRS):
        path = root / rel
        # By path, not basename: a second module named `_yaml.py` is not the canonical one.
        if rel == CANONICAL_MODULE or _is_test_module(rel):
            continue
        text, tree = read_and_parse(path, rel)
        findings.extend(_scan_file(rel, tree, text.splitlines()))
    return findings


HEADER = (
    "lint_raw_yaml baseline — PyYAML load/dump calls under defender/ that bypass "
    "defender/_yaml.py, whose readers refuse aliases and whose writer never emits one "
    "(#1127). Fingerprint is file:function:kind (load|dump; no line number), file relative "
    "to the scan scope. CI fails on a fingerprint absent here. This baseline ships EMPTY — "
    "every site was moved onto _yaml when the gate landed, so an entry in it is a regression "
    "someone chose. Regenerate: python scripts/lint/lint_raw_yaml.py --update-baseline."
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
        print(f"lint_raw_yaml: {exc}", file=sys.stderr)
        return 2
    print(
        "Read and write YAML through defender/_yaml.py — safe_load / safe_dump — never "
        "PyYAML directly: its loader accepts aliases and its dumper writes them (#1127)."
    )
    print("Mark a deliberate site with `# lint-yaml: ok — <reason>`.")
    return gate(findings, baseline, args, label="lint_raw_yaml", header=HEADER)


if __name__ == "__main__":
    sys.exit(main())
