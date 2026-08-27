#!/usr/bin/env python3
"""``__dataclass_fields__`` where ``dataclasses.fields()`` is meant — the pseudo-field hole.

The two look interchangeable and are not. ``fields(obj)`` returns the REAL fields: the ones the
generated ``__init__`` accepts. ``__dataclass_fields__`` is the raw mapping, and it also holds
the ``ClassVar`` and ``InitVar`` PSEUDO-fields, which ``fields()`` filters out precisely because
they are not constructor parameters. So::

    @dataclass
    class Ctx:
        run_id: str
        as_of: ClassVar[Any] = None

    [f.name for f in fields(Ctx)]      -> ["run_id"]
    list(Ctx.__dataclass_fields__)     -> ["run_id", "as_of"]     <- the hole

Feed the second list to ``replace()`` (or to any ``Cls(**kwargs)`` splat) and it raises
``TypeError: __init__() got an unexpected keyword argument`` — an ``init=False`` field raises
``ValueError`` the same way. This is not theoretical: `#965` swapped one for the other in the
estate registry's context-carrying helper, on a line whose own comment asserted it could not
raise and which sat OUTSIDE the handler that converts a fault into a ledger row. The result was
the one state that table exists to make visible — a served response with no row — plus an exit
code that read as infrastructure and tripped the circuit breaker for one sibling and not its
base.

There is no legitimate production use of the raw mapping in this tree. Reading a field's
metadata, iterating fields, building a kwargs dict, checking a name: ``fields()`` answers all
of them and answers them correctly. So this gate is a flat ban rather than a heuristic, and its
baseline ships EMPTY.

What it flags, inside `SCOPE` (``defender/``): any attribute access named
``__dataclass_fields__``, plus the string spelling reached through ``getattr(x,
"__dataclass_fields__")`` — the same attribute by a different door.

What it does NOT flag: test modules. Three tests assert a retired field is ABSENT from a class
(``assert "bindable" not in AgentDefinition.__dataclass_fields__``), which is a membership
question about the class rather than field iteration, and is the stricter of the two checks
there — the pseudo-fields it also sees are extra names the assertion wants to cover. Tests are
skipped by the same rule ``lint_unguarded_tree_write`` uses.

Ratcheted (``lint_dataclass_fields_baseline.json``) with ``require_reasons`` ON, so the empty
baseline can only grow by someone writing down why.

Run from repo root:  python scripts/lint/lint_dataclass_fields.py
Regenerate the baseline:  python scripts/lint/lint_dataclass_fields.py --update-baseline
Exit 0 = clean, 1 = new sites or an un-triaged baseline entry, 2 = scan blind.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

from _astlib import ScanBlind, read_and_parse
from _baseline import Finding, gate

REPO_ROOT = Path(__file__).resolve().parents[2]
SCOPE = REPO_ROOT / "defender"
BASELINE_PATH = Path(__file__).with_name("lint_dataclass_fields_baseline.json")

EXCLUDED_DIRS = (".venv", "__pycache__", "run-visualizations", "run-transcripts")

ATTR = "__dataclass_fields__"
SUPPRESS_MARKERS = ("lint-dataclass-fields: ok",)


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
    start = getattr(node, "lineno", 0)
    end = getattr(node, "end_lineno", start) or start
    return any(
        any(m in lines[i - 1] for m in SUPPRESS_MARKERS)
        for i in range(start, end + 1)
        if 0 < i <= len(lines)
    )


def _hits(node: ast.AST) -> bool:
    """The attribute by either door: spelled, or named as a string to ``getattr``/``hasattr``.

    The string form is checked against the CALL's arguments rather than against every string
    literal in the file, so a docstring or a comment naming the attribute — this gate's own
    explanation of why not to use it, for one — is not a finding.
    """
    if isinstance(node, ast.Attribute) and node.attr == ATTR:
        return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
        if node.func.id in ("getattr", "hasattr"):
            return any(
                isinstance(a, ast.Constant) and a.value == ATTR for a in node.args
            )
    return False


def _scan_file(rel: str, tree: ast.AST, lines: list[str]) -> list[Finding]:
    if _is_test_module(rel):
        return []
    findings: list[Finding] = []
    seen: set[str] = set()

    def visit(node: ast.AST, func_name: str) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            func_name = node.name
        if _hits(node) and not _suppressed(node, lines):
            fp = f"{rel}:{func_name}"
            if fp not in seen:
                seen.add(fp)
                findings.append(Finding(
                    fingerprint=fp,
                    display=(
                        f"{rel}:{getattr(node, 'lineno', 0)}: {ATTR} in {func_name}() — use "
                        f"dataclasses.fields(); the raw mapping also holds ClassVar/InitVar "
                        f"pseudo-fields, which are not constructor parameters"
                    ),
                ))
        for child in ast.iter_child_nodes(node):
            visit(child, func_name)

    visit(tree, "<module>")
    return findings


def _scan(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in sorted(root.rglob("*.py")):
        if not _in_scope(path):
            continue
        rel = path.relative_to(root).as_posix()
        text, tree = read_and_parse(path, rel)
        findings.extend(_scan_file(rel, tree, text.splitlines()))
    return findings


HEADER = (
    "lint_dataclass_fields baseline — reads of __dataclass_fields__ under defender/ outside "
    "tests. The raw mapping also holds ClassVar/InitVar pseudo-fields, so splatting it into "
    "replace()/__init__ raises; dataclasses.fields() is the answer to every use in this tree. "
    "Ships EMPTY. Fingerprint is file:function. Every entry needs a reason. Regenerate: "
    "python scripts/lint/lint_dataclass_fields.py --update-baseline."
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
        print(f"lint_dataclass_fields: {exc}", file=sys.stderr)
        return 2

    print(
        "Use dataclasses.fields(obj) rather than type(obj).__dataclass_fields__ — the raw "
        "mapping also holds ClassVar/InitVar pseudo-fields, which the generated __init__ does "
        "not accept."
    )
    print("Mark a sanctioned exception with `# lint-dataclass-fields: ok — <reason>`.")
    return gate(
        findings, baseline, args,
        label="lint_dataclass_fields", header=HEADER, require_reasons=True,
    )


if __name__ == "__main__":
    sys.exit(main())
