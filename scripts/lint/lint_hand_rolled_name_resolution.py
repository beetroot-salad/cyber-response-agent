#!/usr/bin/env python3
"""Hand-rolled name resolution — flag an AST check that decides WHICH function, class or
import a piece of source refers to by comparing a name against a literal, instead of asking
``_astlib``'s scope-aware resolver.

THE BUG CLASS, and it is one this repo has now shipped four times in three rounds of review
on a single PR (#1008). A check reads ``node.func.id == "run_stage"`` and calls that "the
call to run_stage". It is not. It is *a call spelled* ``run_stage``, and Python resolves
names in a way the string cannot see:

  * ``import ... as`` — ``from x import run_stage as _rs`` then ``_rs(...)`` is the same
    function under a name the check does not match. SHIPPED: a module-level helper handed
    every production judge draw a read AND bash lane while the census that existed to count
    exactly those calls reported 1 of 2, with 225 tests green.
  * the ATTRIBUTE form — ``stage_mod.run_stage(...)`` is the same call with ``.func.id``
    absent entirely. SHIPPED: the module under test spells every cross-module call this way,
    so the widening call written like its neighbours was invisible.
  * SHADOWING — an honest module-level ``from a.b import JudgeDeps`` plus a function-local
    ``from c.d import Other as JudgeDeps`` at the line that constructs it. Python resolves at
    the SITE; a walk that asks "is there an honest import anywhere in this file" says yes.
    SHIPPED, and it put every draw back under the wrong compiled policy.
  * REBINDING that is not an import at all — ``for JudgeDeps in (Other,):``, a ``with ... as``,
    a tuple unpack, a walrus. A hand-written binding sweep enumerated ImportFrom and Assign
    and saw none of these.

Each miss looked like a one-line oversight and each was the same mistake: THE NAME IS NOT THE
BINDING. That is not a thing to remember harder — it is a thing to stop hand-writing.
``scripts/lint/_astlib.py`` builds the real scope tree and answers with the resolved dotted
origin, so all four shapes above give a different answer than the expected one; it is the
declared owner of this question (see its module docstring) and six gates and seven suites
already go through it.

WHAT THIS FLAGS — one exact, two-part condition, not a similarity search:

  a module that PARSES SOURCE IT READ OFF DISK (``ast.parse`` over a ``.read_text()``, i.e. it
  is making a claim about a real shipped file), that decides what a name REFERS TO by matching
  the spelling, and that does not go through ``_astlib`` at all.

The three spellings it looks for, each a shape that has shipped a live miss:

  - callee-by-name    a comparison against ``<...>.func.id`` / ``<...>.func.attr``, including
                      ``getattr(node.func, "id", None) == X``. Use ``_astlib.callee``.
  - alias-by-hand     a read of ``.asname``. The only reason to look at an import's alias is to
                      decide what a name is bound to. Use ``_astlib.origin``.
  - import-module     a comparison against ``<...>.module`` where the module mentions
                      ``ast.ImportFrom``. Same question at the import site.

WHY THE "DOES NOT REACH THE RESOLVER" HALF IS THE GATE, rather than flagging every site. The
resolver answers for names ROOTED AT AN IMPORT and returns ``None`` for a duck-typed method on
a value — ``registry.verbs(system)``, ``p.open()``. Several gates here legitimately match such
a method by name because there is nothing to resolve, and flagging those would be a gate that
fails for a reason other than the one it names. So the exact question is not "did you compare
a name" but "did you ASK THE OWNER" — and a module that never imports the resolver has not.
That mirrors the ``@owns`` gate: the machine-checkable half of an ownership decision, with the
judgment left where a human can see it.

WHAT IT DOES NOT FLAG, deliberately — none of these is name resolution:

  - DEFINITIONS by name: ``FunctionDef.name``, ``ClassDef.name``, ``arg.arg``. Finding the
    function called ``foo`` in a file is a lexical question with a lexical answer.
  - keyword arguments: ``keyword.arg == "tools"`` is part of the callee's signature.
  - synthetic source: a module that only ever parses string literals it wrote itself is making
    a claim about its own fixture, where the spelling IS the fact.
  - ``scripts/lint/_astlib.py``, which IS the resolver and must read these fields.

Mark a deliberate exception with ``# lint-ast-resolve: ok — <reason>`` on the flagged line.
The reason must NAME WHAT MAKES THE LEXICAL ANSWER SUFFICIENT here ("the source is synthetic
and declared inline", "this reports a spelling, and the binding is asserted separately") —
a destination the next reader can check, not an assertion that this case is fine. That
mirrors the ``@owns`` gate's suppression rule and the invlang fence rule.

Pre-existing sites are ratcheted via ``lint_hand_rolled_name_resolution_baseline.json``; the
gate fails only on a NEW file+shape+function fingerprint. ``require_reasons`` is OFF here, and
that is a deliberate difference from ``lint_unowned_field``: that gate's baseline starts empty,
so every entry is a decision someone made, whereas this one opens with real pre-existing debt
that nobody has triaged yet. Demanding a sentence per entry up front would buy a wall of
identical prose. The entries ARE annotated with what they are; the point of the ratchet here is
that the NEXT one has to be looked at.

Run from repo root:  python scripts/lint/lint_hand_rolled_name_resolution.py
Regenerate the baseline:  python scripts/lint/lint_hand_rolled_name_resolution.py --update-baseline
Exit 0 = clean, 1 = new findings, 2 = a file could not be scanned.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

from _astlib import ScanBlind, read_and_parse
from _baseline import Finding, gate

REPO_ROOT = Path(__file__).resolve().parents[2]
SCOPES = (REPO_ROOT / "defender", REPO_ROOT / "scripts" / "lint")
BASELINE_PATH = Path(__file__).with_name("lint_hand_rolled_name_resolution_baseline.json")
HEADER = ("Hand-rolled AST name resolution. See "
          "scripts/lint/lint_hand_rolled_name_resolution.py.")
LABEL = "lint_hand_rolled_name_resolution"

EXCLUDED_DIRS = (".venv", "__pycache__", "run-visualizations", "run-transcripts", "node_modules")
SUPPRESS_MARKER = "lint-ast-resolve: ok"

#: The resolver itself. It must read `.func.id`, `.asname` and `.module` — that is what it is
#: for — so it is the one module this gate cannot apply to.
OWNER = REPO_ROOT / "scripts" / "lint" / "_astlib.py"


def _in_scope(path: Path) -> bool:
    return not any(part in EXCLUDED_DIRS for part in path.parts)


def _reaches_the_resolver(text: str) -> bool:
    """Whether this module goes through `_astlib` at all — directly, or via the test helper
    (`tests/_by_path.import_lint_lib`) that is the only sanctioned way to reach it from a
    suite. This is the half of the condition that makes the gate an OWNERSHIP check rather
    than a name-comparison ban."""
    return "_astlib" in text


def _parses_real_source(tree: ast.AST) -> bool:
    """Whether the module parses source it READ OFF DISK, rather than a string it wrote itself.

    The discriminator between "asserting something about a shipped file" and "checking a
    fixture". A claim about a real module's behaviour has to survive how that module actually
    spells things; a claim about synthetic source written three lines up does not.
    """
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and _attr_chain(node.func) is not None):
            continue
        chain = _attr_chain(node.func)
        if chain and chain[-1] == "parse" and "ast" in chain:
            if any(isinstance(sub, ast.Attribute) and sub.attr in ("read_text", "read_bytes")
                   for arg in node.args for sub in ast.walk(arg)):
                return True
        # `_astlib.read_and_parse(path, rel)` is the same act through the owner's own helper;
        # a module using it already reaches the resolver, so this only matters for the report.
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
    """The sites, but only for a module that both parses real source and skips the resolver.

    Both halves are checked before any site is reported, so a gate that legitimately matches a
    duck-typed method by name — the resolver returns None for those, there is nothing to ask —
    is never flagged for it, and neither is a suite checking synthetic source it wrote itself.
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
        for path in sorted(scope.rglob("*.py")):
            if not _in_scope(path) or path.resolve() == OWNER.resolve():
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
