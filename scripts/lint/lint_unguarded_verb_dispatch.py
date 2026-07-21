#!/usr/bin/env python3
"""Unguarded verb-dispatch smell — flag a data-source verb dispatch that resolves a verb
function from an injected registry OUTSIDE a fault seam.

The mechanical shape of the #672/#678 escape. A data-source tool promises "any unmapped fault
-> the fault-class envelope; write a row, never unwind out of ``agent.iter()``" and delivers
that promise through a single fault-mapping ``try``. The registry dispatch —
``registry.verbs(system)[verb]`` — resolves the verb function to call, and in the production
``ModuleVerbRegistry`` that call LAZILY IMPORTS the adapter, so it can raise
``KeyError``/``ImportError``/``SystemExit`` on a broken or malformed adapter. If that dispatch
sits OUTSIDE the seam, a broken adapter unwinds the stage with no row and no breaker outcome —
exactly the invariant the module documents, silently unmet. The whole suite stayed green because
every injected fake resolves cleanly, so no test ever drove the resolution seam
(``spec_graph_672``'s ``d7`` was discharged with the fault injected inside the verb body only).

What this flags: a subscripted verb dispatch — an ``ast.Subscript`` whose ``.value`` is a call
to ``<anything>.verbs(...)``, i.e. ``X.verbs(...)[...]`` — that is not lexically inside a ``try``
in its own function. The subscript is the discriminator: ``X.verbs(system)[verb]`` RESOLVES A
VERB FN TO EXECUTE (must be fault-guarded so a broken adapter faults-and-continues), whereas a
bare ``X.verbs(system)`` (no subscript) reads the roster mapping for validation / skill
description and is out of scope.

What it does NOT flag:
  - a module that installs a pydantic-ai capability catch-all (a ``ClassDef`` based on
    ``AbstractCapability``, or a ``wrap_tool_execute`` method): its tool body's dispatch is
    guarded by the hook's ``except BaseException`` one seam out, not by a lexical ``try``
    (``runtime/query_tool.py`` — its ``registry.verbs(system)[verb]`` rides the ``wrap_tool_execute``
    catch-all). The whole such module is exempt.
  - a dispatch entering a nested function/closure is judged by ITS OWN function's ``try`` state,
    not the enclosing one — a ``try`` in the outer function does not dynamically guard a callee.
  - test modules — fakes resolve cleanly by construction; this smell is a production-code shape.

Mark a deliberate exception with ``# lint-verb-dispatch: ok — <reason>`` on the dispatch's line
span. Pre-existing sites are ratcheted via ``lint_unguarded_verb_dispatch_baseline.json`` (see
scripts/lint/_baseline.py); the gate fails only on a NEW file+function pair.

Run from repo root:  python scripts/lint/lint_unguarded_verb_dispatch.py
Regenerate the baseline:  python scripts/lint/lint_unguarded_verb_dispatch.py --update-baseline
Exit 0 = clean (no new sites), 1 = new sites.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

from _astlib import read_and_parse
from _baseline import Finding, gate

REPO_ROOT = Path(__file__).resolve().parents[2]
SCOPE = REPO_ROOT / "defender"
BASELINE_PATH = Path(__file__).with_name("lint_unguarded_verb_dispatch_baseline.json")

EXCLUDED_DIRS = (".venv", "__pycache__", "run-visualizations", "run-transcripts")
SUPPRESS_MARKER = "lint-verb-dispatch: ok"


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


def _module_installs_capability_catchall(tree: ast.AST) -> bool:
    """True iff the module defines a pydantic-ai capability whose ``wrap_tool_execute`` hook is
    the ``except BaseException`` catch-all for its tool bodies — so a lexical ``try`` around the
    dispatch is not the seam here (``query_tool``'s shape)."""
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and (
            node.name == "wrap_tool_execute"
        ):
            return True
        if isinstance(node, ast.ClassDef) and any(
            isinstance(b, ast.Name) and b.id == "AbstractCapability"
            or isinstance(b, ast.Attribute) and b.attr == "AbstractCapability"
            for b in node.bases
        ):
            return True
    return False


def _is_verb_dispatch(node: ast.AST) -> bool:
    """True iff ``node`` is ``<expr>.verbs(...)[...]`` — a subscripted call to a ``.verbs``
    attribute, i.e. resolving one verb fn from the registry to execute it."""
    if not isinstance(node, ast.Subscript):
        return False
    call = node.value
    return (
        isinstance(call, ast.Call)
        and isinstance(call.func, ast.Attribute)
        and call.func.attr == "verbs"
    )


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
    if _module_installs_capability_catchall(tree):
        return []
    findings: list[Finding] = []
    seen: set[str] = set()

    def visit(node: ast.AST, func_name: str, guarded: bool) -> None:
        if _is_verb_dispatch(node) and not guarded and not _suppressed(node, lines):
            fp = f"{rel}:{func_name}"
            if fp not in seen:
                seen.add(fp)
                findings.append(
                    Finding(
                        fingerprint=fp,
                        display=(
                            f"{rel}:{node.lineno}: unguarded verb dispatch in {func_name}() — "
                            "`registry.verbs(system)[verb]` resolves a verb fn (a lazy adapter "
                            "import that can raise) OUTSIDE a fault `try`; move it inside the "
                            "seam so a broken adapter faults-and-continues (writes a row), "
                            "never unwinds."
                        ),
                    )
                )
        for field, child in ast.iter_fields(node):
            _visit_field(node, field, child, func_name, guarded, visit)

    visit(tree, "<module>", False)
    return findings


def _visit_field(node, field, child, func_name, guarded, visit) -> None:  # noqa: ANN001
    """Recurse into one AST field, tracking two things the flat walk cannot: the ENCLOSING
    function (a nested def resets the ``try`` guard — an outer ``try`` never dynamically guards a
    callee) and whether we are inside a ``Try.body`` (the only region an ``except`` protects; a
    dispatch in ``orelse``/a handler is unguarded)."""
    items = child if isinstance(child, list) else [child]
    for item in items:
        if not isinstance(item, ast.AST):
            continue
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            name = getattr(item, "name", func_name)
            visit(item, name, False)  # a nested scope resets the guard
        else:
            child_guarded = guarded or (isinstance(node, ast.Try) and field == "body")
            visit(item, func_name, child_guarded)


HEADER = (
    "lint_unguarded_verb_dispatch baseline — a data-source verb dispatch "
    "`registry.verbs(system)[verb]` (a lazy adapter import that can raise) resolved OUTSIDE a "
    "fault `try`, so a broken adapter unwinds the stage with no row/no breaker (the #672/#678 "
    "escape). Fingerprint is file:function (no line number); modules with a pydantic-ai "
    "capability catch-all are exempt. CI fails on a fingerprint absent here. Regenerate: "
    "python scripts/lint/lint_unguarded_verb_dispatch.py --update-baseline"
)


def _scan() -> list[Finding]:
    findings: list[Finding] = []
    for path in sorted(SCOPE.rglob("*.py")):
        if not _in_scope(path):
            continue
        rel = path.relative_to(REPO_ROOT).as_posix()
        try:
            text, tree = read_and_parse(path, rel)
        except SyntaxError:
            continue
        findings.extend(_scan_file(rel, tree, text.splitlines()))
    return findings


def main() -> int:
    return gate(
        _scan(),
        BASELINE_PATH,
        sys.argv,
        label="lint_unguarded_verb_dispatch",
        header=HEADER,
    )


if __name__ == "__main__":
    raise SystemExit(main())
