#!/usr/bin/env python3
"""``__dataclass_fields__`` where ``dataclasses.fields()`` is meant — the pseudo-field hole.

The two look interchangeable and are not. ``fields(obj)`` returns the real fields, the ones
the generated ``__init__`` accepts. ``__dataclass_fields__`` is the raw mapping, which also
holds the ``ClassVar`` and ``InitVar`` pseudo-fields that ``fields()`` filters out. So::

    @dataclass
    class Ctx:
        run_id: str
        as_of: ClassVar[Any] = None

    [f.name for f in fields(Ctx)]      -> ["run_id"]
    list(Ctx.__dataclass_fields__)     -> ["run_id", "as_of"]     <- the hole

Feed the second list to ``replace()`` (or any ``Cls(**kwargs)`` splat) and it raises
``TypeError: __init__() got an unexpected keyword argument`` (an ``init=False`` field raises
``ValueError`` likewise) — from code that looks like it cannot raise, possibly outside the
handler meant to record the fault.

There is no legitimate production use of the raw mapping in this tree: ``fields()`` answers
metadata reads, iteration, kwargs building and name checks correctly. So this gate is a flat
ban, and its baseline ships empty.

What it flags, inside `SCOPE` (``defender/``): any attribute access named
``__dataclass_fields__``, plus the string spelling reached through ``getattr(x,
"__dataclass_fields__")`` — the same attribute by a different door.

What it does not flag: test modules. Tests assert a retired field is absent
(``assert "bindable" not in AgentDefinition.__dataclass_fields__``), a membership question
where seeing the pseudo-fields too makes the check stricter.

Ratcheted (``lint_dataclass_fields_baseline.json``) with ``require_reasons`` on, so the empty
baseline can only grow with a written reason.

Run from repo root:  python scripts/lint/lint_dataclass_fields.py
Regenerate the baseline:  python scripts/lint/lint_dataclass_fields.py --update-baseline
Exit 0 = clean, 1 = new sites or an un-triaged baseline entry, 2 = scan blind.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

from _astlib import ScanBlind, read_and_parse, source_files
from _baseline import Finding, gate

REPO_ROOT = Path(__file__).resolve().parents[2]
SCOPE = REPO_ROOT / "defender"
BASELINE_PATH = Path(__file__).with_name("lint_dataclass_fields_baseline.json")

EXCLUDED_DIRS = (".venv", "__pycache__")

ATTR = "__dataclass_fields__"
SUPPRESS_MARKERS = ("lint-dataclass-fields: ok",)


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

    The string form is checked only against the call's arguments, so a docstring or comment
    naming the attribute is not a finding.
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
    for path in (root / _r for _r in source_files(root, EXCLUDED_DIRS)):
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
