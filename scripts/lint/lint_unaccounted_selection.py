#!/usr/bin/env python3
"""Unaccounted selection — flag code under ``defender/`` that selects a subset of an
invlang document by grammar and drops the rest in silence.

ONE RULE, TWO ARMS. Whenever a reader splits invlang bytes into "the part I want" and "the
rest", the rest has to go somewhere a reader can name — another rule that owns it, a
diagnostic, or an answer that changes because the selection came back empty. Discarding it
is not neutral; it makes content that was WRITTEN indistinguishable from content that was
never there, and every downstream rule is universally quantified, so what vanishes is not
merely unchecked — it is un-refusable.

Both arms exist because the same defect shipped twice at different scales (#932).

ARM 1 — THE DOCUMENT. ``INVLANG_FENCE_RE`` matches ```invlang…``` pairs and three readers
walked its matches while dropping the complement: the tokenizer, the frontier's prefix
rebuild, and the turn-N seed slicer. A run closed its ORIENT fence, wrote prose, then
continued with ``## PLAN`` and all its ``:H`` rows without reopening one. Rows outside a
fence never reach the tokenizer, so they cannot even raise a ``ParseWarning``; the companion
came back with no hypotheses and every hypothesis-side rule passed over an empty collection.
``parser.scan_fences`` is now the one reader of the pattern and returns what the fences
ORPHAN alongside what they hold.

ARM 2 — THE CELL. The same shape one level down. ``:L findings``' ``tests`` column is mixed
(hypotheses and the commitments a lead was run for), and both readers of it SELECTED their
kind with ``[t for t in tested if SOME_ID_RE.fullmatch(t)]``. A token in neither namespace
was skipped by both and validated clean — including ``h-001.ac1``, the qualified spelling
spec rule #7 blesses, which a live run wrote as its ENTIRE tests cell. That lead's whole
column reached no rule at all. The fix was to classify exhaustively and report the residue.

WHAT ARM 2 FLAGS: a call to a ``*_RE``-suffixed regex — ``match`` / ``fullmatch`` /
``search`` — inside a comprehension's ``if``, where the call is NOT under a ``not``.
Non-negated is the whole distinction and it is load-bearing:

    [t for t in xs if ID_RE.fullmatch(t)]          # KEEPS matches, drops the rest  -> flagged
    [err(t) for t in xs if not ID_RE.fullmatch(t)] # REPORTS non-matches            -> clean

The second shape is how the four id rules in ``validate.py`` are written and it is correct;
without the negation test this gate would flag all of them and read as noise.

The ``*_RE`` suffix is a CONVENTION, not a resolved type — every regex in this package
follows it, and one that does not is invisible here. That is the arm's known hole and it is
the price of not requiring type inference.

WHAT NEITHER ARM SEES — read before treating a green run as proof:

- ``getattr(parser, "INVLANG_" + "FENCE_RE")`` and other computed access; the gate reads
  names, not values.
- A split done with ``str.split`` or ``find``/``index`` arithmetic rather than a regex.
- A filter written as a ``for`` loop with a bare ``continue`` rather than a comprehension.
  ``lint_silent_row_drop`` covers that shape where a ``ParseWarning`` is owed.
- Whether a caller that DOES use ``scan_fences`` reads ``orphaned_headers`` at all, or
  whether a residue rule someone adds actually reports. Nothing structural can ask that.

So a clean run means "no reader selects by grammar without saying where the rest went, in
the two shapes mechanized here" — not "every complement is accounted for".

THE BASELINE SHIPS EMPTY. Arm 1's five sites were folded into ``scan_fences``; arm 2's four
surviving sites are correct and carry an inline marker SAYING SO, which is the documentation
this gate exists to force. Mark a deliberate site with ``# lint-selection: ok — <reason>``
on the flagged line or anywhere in the flagged node's span.
"""


from __future__ import annotations

import ast
import sys
from pathlib import Path

from _astlib import ModuleEnv, ScanBlind, callee, module_env, read_and_parse, str_args
from _baseline import Finding, gate

REPO_ROOT = Path(__file__).resolve().parents[2]
SCOPE = REPO_ROOT / "defender"
BASELINE_PATH = Path(__file__).with_name("lint_unaccounted_selection_baseline.json")

EXCLUDED_DIRS = (".venv", "__pycache__", "run-visualizations", "run-transcripts")
SUPPRESS_MARKERS = ("lint-selection: ok",)

#: The modules that OWN the split. `_tokenize` holds the fence grammar and must use the
#: regex; `parser` is the facade that re-exports the name, which reads as an `import`
#: finding but adds no second reader. Exempted by full relative path, not basename: a
#: basename match would wave through any new `parser.py` anywhere under the scope — i.e. a
#: verbatim second copy of the grammar, which is the one thing this gate exists to stop.
CANONICAL_MODULES = (
    "skills/invlang/parser/_tokenize.py",
    "skills/invlang/parser/__init__.py",
)

FENCE_CONST = "INVLANG_FENCE_RE"
FENCE_LITERAL = "```invlang"

_RE_FUNCTIONS = (
    "compile", "search", "match", "fullmatch", "finditer", "findall", "split", "sub", "subn",
)

#: Arm 2. The regex methods that ANSWER a shape question, and so can stand as a
#: comprehension's filter. `sub`/`split`/`findall` transform rather than test and cannot
#: appear in an `if` position meaningfully, so they are not listed.
_PREDICATE_METHODS = ("match", "fullmatch", "search")

_ADVICE = {
    "import": f"imports {FENCE_CONST}",
    "attribute": f"reaches for {FENCE_CONST}",
    "regex": f"re-derives the {FENCE_LITERAL} fence pattern",
    "filter": "selects by grammar in a comprehension and drops the non-matches",
}

_FIX = {
    "import": "read the document through skills/invlang/parser.scan_fences, which returns "
              "what the fences ORPHAN alongside what they hold",
    "attribute": "read the document through skills/invlang/parser.scan_fences, which returns "
                 "what the fences ORPHAN alongside what they hold",
    "regex": "read the document through skills/invlang/parser.scan_fences, which returns "
             "what the fences ORPHAN alongside what they hold",
    "filter": "classify every token exhaustively and report the residue, or say in a "
              "`# lint-selection: ok — <reason>` marker which rule owns what this drops",
}


def _negated_within(cond: ast.expr, call: ast.Call) -> bool:
    """True when `call` sits under a `not` inside the comprehension condition `cond`.

    THE DISTINCTION ARM 2 RESTS ON. `if RE.fullmatch(t)` keeps the matches and discards
    everything else; `if not RE.fullmatch(t)` turns every non-match into the finding. The
    second is how `validate.py`'s four id-structure rules are written, and flagging them
    would make this gate noise."""
    for sub in ast.walk(cond):
        if isinstance(sub, ast.UnaryOp) and isinstance(sub.op, ast.Not):
            if any(inner is call for inner in ast.walk(sub.operand)):
                return True
    return False


def _grammar_filter_calls(node: ast.AST) -> list[ast.Call]:
    """Non-negated `*_RE` predicate calls sitting in this node's comprehension filters."""
    out: list[ast.Call] = []
    for gen in getattr(node, "generators", []) or []:
        for cond in gen.ifs:
            for sub in ast.walk(cond):
                if not (isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute)):
                    continue
                if sub.func.attr not in _PREDICATE_METHODS:
                    continue
                base = sub.func.value
                # `ID_RE.fullmatch(...)` and `parser.ID_RE.fullmatch(...)` alike — the name
                # carrying the convention is the one immediately left of the method.
                name = getattr(base, "id", None) or getattr(base, "attr", None)
                if not (isinstance(name, str) and name.endswith("_RE")):
                    continue
                if not _negated_within(cond, sub):
                    out.append(sub)
    return out


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


def _kind(node: ast.AST, env: ModuleEnv) -> str | None:
    if isinstance(node, (ast.Import, ast.ImportFrom)):
        # `as` name is irrelevant — what is bound is the same object under another label.
        if any(alias.name == FENCE_CONST for alias in node.names):
            return "import"
        return None
    if isinstance(node, ast.Attribute) and node.attr == FENCE_CONST:
        return "attribute"
    if _grammar_filter_calls(node):
        return "filter"
    if isinstance(node, ast.Call):
        target = callee(node, env)
        if target and target.split(".")[0] == "re" and target.split(".")[-1] in _RE_FUNCTIONS:
            if any(FENCE_LITERAL in value for value in str_args(node, env)):
                return "regex"
    return None


def _scan_file(rel: str, tree: ast.AST, lines: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()
    env = module_env(tree)

    def visit(node: ast.AST, func_name: str) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            func_name = node.name
        kind = _kind(node, env)
        # Arm 1 exempts the module that OWNS the fence split — it must use the regex. Arm 2
        # does not: a silent grammar filter inside the parser is the same defect it is
        # anywhere else, and three of the four sites this gate documents live there.
        if kind in ("import", "attribute", "regex") and rel in CANONICAL_MODULES:
            kind = None
        if kind and not _suppressed(node, lines):
            # Fingerprint carries no line number, so moving the offending call within its
            # function does not read as a new finding — same convention as the sibling gates.
            fingerprint = f"{rel}:{func_name}:{kind}"
            if fingerprint not in seen:
                seen.add(fingerprint)
                findings.append(Finding(
                    fingerprint=fingerprint,
                    display=(
                        f"{rel}:{getattr(node, 'lineno', 0)}: {_ADVICE[kind]} — "
                        f"{_FIX[kind]} (in {func_name}())"
                    ),
                ))
        for child in ast.iter_child_nodes(node):
            visit(child, func_name)

    visit(tree, "<module>")
    return findings


def _scan(root: Path) -> list[Finding]:
    """Findings under ``root``, fingerprints relative to it — so the gate is drivable on an
    injected tmp tree, not just the repo checkout."""
    findings: list[Finding] = []
    for path in sorted(root.rglob("*.py")):
        if not _in_scope(path):
            continue
        rel = path.relative_to(root).as_posix()
        if _is_test_module(rel):
            continue
        text, tree = read_and_parse(path, rel)
        findings.extend(_scan_file(rel, tree, text.splitlines()))
    return findings


HEADER = (
    "lint_unaccounted_selection baseline — readers under defender/ that split a document "
    "on its ```invlang fences without going through skills/invlang/parser.scan_fences "
    "(#932). Fingerprint is file:function:kind (import|attribute|regex; no line number), "
    "file relative to the scan scope. CI fails on a fingerprint absent here. This baseline "
    "ships EMPTY — all five sites were folded into scan_fences when the gate landed, so an "
    "entry in it is a regression someone chose. Regenerate: python scripts/lint/"
    "lint_unaccounted_selection.py --update-baseline."
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
    # A file inside the scan scope that could not be read or parsed never entered the corpus,
    # so a violation could sit in it and this gate would still print 0 findings. Exit 2 — the
    # gate could not run, which is categorically not "clean".
    try:
        findings = _scan(root)
    except ScanBlind as exc:
        print(f"lint_unaccounted_selection: {exc}", file=sys.stderr)
        return 2
    print(
        "Read invlang fences through skills/invlang/parser.scan_fences — never by walking "
        "INVLANG_FENCE_RE or re-deriving the pattern (#932: three readers each dropped what "
        "the fences left out, and a run's whole PLAN section went unvalidated)."
    )
    print("Mark a deliberate site with `# lint-selection: ok — <reason>`.")
    return gate(
        findings, baseline, args,
        label="lint_unaccounted_selection", header=HEADER,
    )


if __name__ == "__main__":
    sys.exit(main())
