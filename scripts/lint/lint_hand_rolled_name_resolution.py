#!/usr/bin/env python3
"""Hand-rolled name resolution: flag an AST check that decides which function, class or import
a piece of source refers to by comparing a name against a literal, instead of asking
``_astlib``'s scope-aware resolver.

``node.func.id == "run_stage"`` matches a call spelled ``run_stage``, not the call to
``run_stage``. Python resolves names in ways the string cannot see:

  * ``import ... as`` — ``from x import run_stage as _rs`` then ``_rs(...)`` is the same
    function under a name the check does not match.
  * the attribute form — ``stage_mod.run_stage(...)`` has no ``.func.id`` at all.
  * shadowing — a module-level ``from a.b import JudgeDeps`` plus a function-local
    ``from c.d import Other as JudgeDeps``: Python resolves at the site, while "is there an
    honest import anywhere in this file" says yes.
  * rebinding that is not an import — ``for JudgeDeps in (Other,):``, ``with ... as``, a
    tuple unpack, a walrus.

Each of these has caused a live policy miss with tests green. The name is not the binding, so
stop hand-writing it: ``scripts/lint/_astlib.py`` builds the real scope tree and answers with
the resolved dotted origin (``callee``, ``origin``, ``owner_derived``). It is the declared
owner of this question.

What this flags — one exact, two-part condition:

  a module that parses source it read off disk (``ast.parse`` over a ``.read_text()``, i.e.
  a claim about a real shipped file), decides what a name refers to by matching the spelling,
  and does not go through ``_astlib`` at all.

The three spellings it looks for:

  - callee-by-name    a comparison against ``<...>.func.id`` / ``<...>.func.attr``, including
                      ``getattr(node.func, "id", None) == X``. Use ``_astlib.callee``.
  - alias-by-hand     a read of ``.asname``; the only reason to read an alias is to decide
                      what a name is bound to. Use ``_astlib.origin``.
  - import-module     a comparison against ``<...>.module`` where the module mentions
                      ``ast.ImportFrom``. Same question at the import site.

Why "does not reach the resolver" is part of the condition: the resolver returns ``None`` for
a duck-typed method on a value (``registry.verbs(system)``, ``p.open()``), and gates
legitimately match those by name. So the question is whether the module asked the owner, not
whether it compared a name.

What it does not flag — none of these is name resolution:

  - definitions by name: ``FunctionDef.name``, ``ClassDef.name``, ``arg.arg``.
  - keyword arguments: ``keyword.arg == "tools"`` is part of the callee's signature.
  - synthetic source: a module that only parses string literals it wrote itself, where the
    spelling is the fact.
  - ``scripts/lint/_astlib.py``, which is the resolver.

Mark a deliberate exception with ``# lint-ast-resolve: ok — <reason>`` on the flagged line.
The reason must name what makes the lexical answer sufficient ("the source is synthetic and
declared inline", "this reports a spelling, and the binding is asserted separately").

Pre-existing sites are ratcheted via ``lint_hand_rolled_name_resolution_baseline.json``; the
gate fails only on a new file+shape+function fingerprint. ``require_reasons`` is off, unlike
``lint_unowned_field``: this baseline opened with untriaged pre-existing debt, and the ratchet's
job is that the next entry gets looked at.

Run from repo root:  python scripts/lint/lint_hand_rolled_name_resolution.py
Regenerate the baseline:  python scripts/lint/lint_hand_rolled_name_resolution.py --update-baseline
Exit 0 = clean, 1 = new findings, 2 = a file could not be scanned.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

from _astlib import ScanBlind, read_and_parse, source_files
from _baseline import Finding, gate

REPO_ROOT = Path(__file__).resolve().parents[2]
SCOPES = (REPO_ROOT / "defender", REPO_ROOT / "scripts" / "lint")
BASELINE_PATH = Path(__file__).with_name("lint_hand_rolled_name_resolution_baseline.json")
HEADER = ("Hand-rolled AST name resolution. See "
          "scripts/lint/lint_hand_rolled_name_resolution.py.")
LABEL = "lint_hand_rolled_name_resolution"

EXCLUDED_DIRS = (".venv", "__pycache__", "node_modules")
SUPPRESS_MARKER = "lint-ast-resolve: ok"

#: The resolver itself, which must read `.func.id`, `.asname` and `.module`.
OWNER = REPO_ROOT / "scripts" / "lint" / "_astlib.py"


def _reaches_the_resolver(text: str) -> bool:
    """Whether this module goes through `_astlib` at all — directly, or via the test helper
    `tests/_by_path.import_lint_lib`. This half makes the gate an ownership check rather than
    a name-comparison ban."""
    return "_astlib" in text


def _parses_real_source(tree: ast.AST) -> bool:
    """Whether the module parses source it read off disk, rather than a string it wrote.

    A claim about a real module must survive how that module actually spells things; a claim
    about synthetic source written three lines up need not.
    """
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and _attr_chain(node.func) is not None):
            continue
        chain = _attr_chain(node.func)
        if chain and chain[-1] == "parse" and "ast" in chain:
            if any(isinstance(sub, ast.Attribute) and sub.attr in ("read_text", "read_bytes")
                   for arg in node.args for sub in ast.walk(arg)):
                return True
        # `_astlib.read_and_parse(path, rel)` is the same act through the owner's helper.
        if chain and chain[-1] == "read_and_parse":
            return True
    return False


def _attr_chain(node: ast.expr) -> list[str] | None:
    """`a.b.c` -> ['a','b','c'] for a pure Name.attr chain, else None."""
    parts: list[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if not isinstance(cur, ast.Name):
        return None
    parts.append(cur.id)
    return list(reversed(parts))


def _reads_callee_name(node: ast.expr) -> bool:
    """`x.func.id`, `x.func.attr`, or `getattr(x.func, "id"|"attr", ...)`."""
    chain = _attr_chain(node)
    if chain and len(chain) >= 3 and chain[-1] in ("id", "attr") and chain[-2] == "func":
        return True
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id == "getattr" and len(node.args) >= 2):
        target, attr = node.args[0], node.args[1]
        tchain = _attr_chain(target)
        return bool(
            tchain and tchain[-1] == "func"
            and isinstance(attr, ast.Constant) and attr.value in ("id", "attr")
        )
    return False


def _reads_attr(node: ast.expr, name: str) -> bool:
    chain = _attr_chain(node)
    return bool(chain and len(chain) >= 2 and chain[-1] == name)


def _enclosing_name(tree: ast.AST, target: ast.AST) -> str:
    """The nearest enclosing def/class name, for a fingerprint that survives a line move."""
    best = "<module>"
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            start, end = node.lineno, getattr(node, "end_lineno", node.lineno)
            if start <= getattr(target, "lineno", 0) <= end:
                best = node.name
    return best


def _suppressed(node: ast.AST, lines: list[str]) -> bool:
    start = getattr(node, "lineno", 1)
    end = getattr(node, "end_lineno", start) or start
    return any(SUPPRESS_MARKER in lines[i - 1] for i in range(start, end + 1)
               if 0 < i <= len(lines))


def _findings_for(tree: ast.Module, text: str, rel: str) -> list[Finding]:
    """The sites, but only for a module that both parses real source and skips the resolver
    (so duck-typed method matches and synthetic-source suites are never flagged).
    """
    if _reaches_the_resolver(text) or not _parses_real_source(tree):
        return []

    lines = text.splitlines()
    mentions_importfrom = "ImportFrom" in text
    out: list[Finding] = []

    def report(node: ast.AST, shape: str, hint: str) -> None:
        if _suppressed(node, lines):
            return
        where = _enclosing_name(tree, node)
        out.append(Finding(
            fingerprint=f"{shape} {rel}::{where}",
            display=f"{shape} at {rel}:{getattr(node, 'lineno', 0)} in {where}() — {hint}",
        ))

    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr == "asname":
            report(node, "alias-by-hand",
                   "reads an import's alias to decide what a name is bound to, in a module "
                   "that never reaches `_astlib` — `origin(node, env)` answers that after "
                   "real scoping, including a function-local shadow")
            continue
        if not isinstance(node, ast.Compare):
            continue
        sides = [node.left, *node.comparators]
        if any(_reads_callee_name(s) for s in sides):
            report(node, "callee-by-name",
                   "matches a call by the SPELLING of its callee, in a module that never "
                   "reaches `_astlib` — an alias or the attribute form is the same function "
                   "under another name; `callee(call, env)` returns the dotted origin")
        elif mentions_importfrom and any(_reads_attr(s, "module") for s in sides):
            report(node, "import-module-by-name",
                   "decides an import by its written module path, in a module that never "
                   "reaches `_astlib` — `origin` resolves the binding the site actually sees")
    return out


def main(argv: list[str]) -> int:
    findings: list[Finding] = []
    for scope in SCOPES:
        if not scope.exists():
            continue
        try:
            rels = source_files(scope, EXCLUDED_DIRS)
        except ScanBlind as blind:
            print(f"[{LABEL}] could not list {scope}: {blind}", file=sys.stderr)
            return 2
        for path in (scope / _r for _r in rels):
            if path.resolve() == OWNER.resolve():
                continue
            rel = path.relative_to(REPO_ROOT).as_posix()
            try:
                text, tree = read_and_parse(path, rel)
            except ScanBlind as blind:
                print(f"[{LABEL}] could not scan {rel}: {blind}", file=sys.stderr)
                return 2
            if "import ast" not in text:
                continue
            findings.extend(_findings_for(tree, text, rel))
    return gate(findings, BASELINE_PATH, argv, label=LABEL, header=HEADER)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
