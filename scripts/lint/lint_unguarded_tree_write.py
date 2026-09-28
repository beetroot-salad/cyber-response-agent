#!/usr/bin/env python3
"""Unguarded shared-tree write: flag a write into a box-writable tree (a run dir, the drain
worktree's corpus) that bypasses the alias-refusing primitives (``defender._io.write_guarded``
/ ``guarded_mkdir`` / ``open_guarded``).

A grep over write idioms cannot see a wrapper, so this gate resolves the callee, not the
spelling: ``from defender._io import write_atomic as wa; wa(...)`` is the same finding as the
unaliased form.

What it flags, inside `SCOPE` (``defender/``): a call to ``defender._io.write_atomic`` or
``defender._io.append_jsonl`` (``write_atomic`` delegates to ``write_guarded`` and is fine for
callers outside every box mount, but inside a hard-gated module it is still a finding because
those modules' artifacts are inside the tree), and the duck-typed ``<x>.write_text(...)`` /
``<x>.write_bytes(...)`` / ``<x>.mkdir(...)`` shapes (matched like ``opener_slot`` matches
``<p>.open(...)``).

What it does not flag: ``write_guarded`` / ``guarded_mkdir`` / ``open_guarded`` themselves.
The modules implementing them get no blanket exemption (``_io.py`` is itself hard-gated):
the raw idioms they need carry per-line ``# lint-unguarded-tree-write: ok`` markers naming
why, so a new unguarded write there is still a finding.

Ratcheted via ``lint_unguarded_tree_write_baseline.json``, except for the writer-census modules
(``LINT_HARD_GATED_MODULES``, kept set-equal to ``defender/tests/e2e/_spec771.py``'s census):
those are hard-gated, never ratcheted, so a converted writer that regresses fails CI.

Run from repo root:  python scripts/lint/lint_unguarded_tree_write.py
Regenerate the baseline:  python scripts/lint/lint_unguarded_tree_write.py --update-baseline
Exit 0 = clean, 1 = new (non-hard-gated) sites or a hard-gated-module site at all, 2 = scan blind.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

from _astlib import ScanBlind, ModuleEnv, callee, module_env, read_and_parse
from _baseline import Finding, gate

REPO_ROOT = Path(__file__).resolve().parents[2]
SCOPE = REPO_ROOT / "defender"
BASELINE_PATH = Path(__file__).with_name("lint_unguarded_tree_write_baseline.json")

EXCLUDED_DIRS = (".venv", "__pycache__")

#: Whole-file idioms that bypass the canonical seam. `write_atomic` delegates to
#: `write_guarded` and is safe, but stays flagged: `write_guarded` is the one seam every
#: shared-tree writer uses, and going quiet on a wrapper because the wrapped call became safe
#: recreates the blind spot wrappers cause. A caller that keeps `write_atomic` because it also
#: serves callers outside every box mount marks the line `# lint-unguarded-tree-write: ok`.
#: `append_jsonl` is still literally unguarded (`"a"`, no `O_NOFOLLOW`). Both resolved by callee.
_UNSAFE_CALLEES = frozenset({"defender._io.write_atomic", "defender._io.append_jsonl"})

#: Duck-typed method shapes that write/create without the guarded primitive (the receiver is
#: a Path value, so there is no import origin to resolve).
_UNSAFE_METHODS = frozenset({"write_text", "write_bytes", "mkdir"})

#: The writer census: a copy of `defender/tests/e2e/_spec771.py`'s
#: `CENSUS_MODULES | DRAIN_MODULES`, not a derivation, because a repo-root lint may not import
#: the test package (it drags in pydantic_ai and the whole runtime). Kept in step only by
#: `test_the_write_lint_hard_gates_the_census_rows_and_ratchets_only_new_ones` (set-for-set);
#: a census row added there and not here is a module the gate stops covering.
LINT_HARD_GATED_MODULES: frozenset[str] = frozenset({
    "runtime/observe.py",
    "runtime/driver/",
    "runtime/session_store.py",
    "hooks/budget_enforcer.py",
    "runtime/circuit_breaker.py",
    "runtime/query_tool.py",
    "runtime/tools_gather.py",
    "hooks/record_lead.py",
    "_io.py",
    "runtime/tools/",
    "runtime/box/",
    "learning/author/drain.py",
    "_tenant.py",
})


def _hard_gated(rel: str) -> bool:
    """Is this file one the census hard-gates?

    An entry ending in `/` names a package and covers every file under it, so a census
    module that became a package (`runtime/driver.py` -> `runtime/driver/`) stays covered
    across all its files.
    """
    return rel in LINT_HARD_GATED_MODULES or any(
        entry.endswith("/") and rel.startswith(entry) for entry in LINT_HARD_GATED_MODULES
    )


SUPPRESS_MARKERS = ("lint-unguarded-tree-write: ok",)


def _in_scope(path: Path) -> bool:
    return not any(part in EXCLUDED_DIRS for part in path.parts)


def _is_test_module(rel: str) -> bool:
    p = Path(rel)
    return (
        "tests" in p.parts
        or p.name == "conftest.py"
        or (p.name.startswith("test_") and p.suffix == ".py")
        or p.name.endswith("_test.py")
    )


def _suppressed(node: ast.AST, lines: list[str]) -> bool:
    start = node.lineno
    end = getattr(node, "end_lineno", start) or start
    return any(
        any(m in lines[i - 1] for m in SUPPRESS_MARKERS)
        for i in range(start, end + 1)
        if 0 < i <= len(lines)
    )


def _unsafe_reason(call: ast.Call, env: ModuleEnv) -> str | None:
    origin = callee(call, env)
    if origin in _UNSAFE_CALLEES:
        return origin
    func = call.func
    if isinstance(func, ast.Attribute) and func.attr in _UNSAFE_METHODS:
        # Duck-typed: a same-named method on an unrelated object would match too — the
        # tradeoff `opener_slot` makes for `.open(...)`.
        return f"<value>.{func.attr}"
    return None


def _scan_file(rel: str, tree: ast.AST, lines: list[str]) -> list[Finding]:
    if _is_test_module(rel):
        return []
    findings: list[Finding] = []
    seen: set[str] = set()
    env = module_env(tree)

    def report(fingerprint: str, finding: Finding) -> None:
        if fingerprint not in seen:
            seen.add(fingerprint)
            findings.append(finding)

    def visit(node: ast.AST, func_name: str) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            func_name = node.name
        if isinstance(node, ast.Call) and not _suppressed(node, lines):
            reason = _unsafe_reason(node, env)
            if reason is not None:
                fp = f"{rel}:{func_name}"
                report(
                    fp,
                    Finding(
                        fingerprint=fp,
                        display=(
                            f"{rel}:{node.lineno}: unguarded shared-tree write ({reason}) in "
                            f"{func_name}() — route through defender._io.write_guarded / "
                            f"guarded_mkdir"
                        ),
                    ),
                )
        for child in ast.iter_child_nodes(node):
            visit(child, func_name)

    visit(tree, "<module>")
    return findings


def _scan(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in sorted(root.rglob("*.py")):
        if not _in_scope(path):
            continue
        text, tree = read_and_parse(path, path.relative_to(root).as_posix())
        rel = path.relative_to(root).as_posix()
        findings.extend(_scan_file(rel, tree, text.splitlines()))
    return findings


HEADER = (
    "lint_unguarded_tree_write baseline — a shared-tree write reachable while a box is alive "
    "that bypasses #771's alias-refusing primitives (write_guarded/guarded_mkdir/open_guarded). "
    "Fingerprint is file:function, file relative to the scan scope. Modules named in the "
    "writer census (LINT_HARD_GATED_MODULES, derived from _spec771.py's CENSUS) are HARD-gated "
    "— a finding there fails regardless of the baseline. Regenerate: python "
    "scripts/lint/lint_unguarded_tree_write.py --update-baseline."
)


def main(
    argv: list[str] | None = None,
    *,
    scope: Path | None = None,
    baseline_path: Path | None = None,
) -> int:
    args = sys.argv[1:] if argv is None else argv
    root = SCOPE if scope is None else scope
    baseline = BASELINE_PATH if baseline_path is None else baseline_path
    if not root.is_dir():
        print(f"scan scope not found at {root}", file=sys.stderr)
        return 2
    try:
        findings = _scan(root)
    except ScanBlind as exc:
        print(f"lint_unguarded_tree_write: {exc}", file=sys.stderr)
        return 2

    hard_gated = [
        f for f in findings
        if _hard_gated(f.fingerprint.split(":")[0])
    ]
    if hard_gated:
        # A census-module finding ends the run before the ratchet.
        for f in hard_gated:
            print(f"HARD-GATED (never ratcheted): {f.display}", file=sys.stderr)
        return 1

    print(
        "Route shared-tree writes through defender._io.write_guarded / guarded_mkdir "
        "(#771 M3) rather than write_atomic/append_jsonl/write_text/write_bytes/mkdir directly."
    )
    print("Mark a sanctioned exception with `# lint-unguarded-tree-write: ok — <reason>`.")
    return gate(findings, baseline, args, label="lint_unguarded_tree_write", header=HEADER)


if __name__ == "__main__":
    sys.exit(main())
