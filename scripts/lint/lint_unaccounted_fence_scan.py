#!/usr/bin/env python3
"""Unaccounted fence scan — flag any reader under ``defender/`` that splits an
investigation document on its ```invlang fences without going through
``skills/invlang/parser.scan_fences``.

WHAT WENT WRONG.  ``INVLANG_FENCE_RE`` matches ```invlang…``` pairs, and every reader that
walked its matches took the content and dropped the complement on the floor. Dropping it is
correct — prose between blocks is not invlang. Dropping it *silently* is not: a run closed
its ORIENT fence, wrote three paragraphs, and continued with ``## PLAN`` and all its ``:H``
rows without reopening one. Those rows were not malformed, they were ABSENT — the tokenizer
is fed fence bodies, so nothing outside a fence can even raise a ``ParseWarning``. The
companion came back with zero hypotheses, and every hypothesis-side rule is universally
quantified, so all of them passed over an empty collection. A whole PLAN section went
unvalidated and the write landed clean (#932).

Three readers had derived the same split independently — the tokenizer, the frontier's
prefix rebuild, and the turn-N seed slicer — each restating in a comment that fences are the
content and the rest is ignored, and each blind in the same way. ``scan_fences`` is now the
one place that knows it, and it returns the complement (``orphaned_headers``) alongside the
content so a caller cannot take one without being handed the other. This gate keeps a fourth
copy from growing back.

WHAT IT FLAGS — under ``defender/``, production code only:

- **Binding the regex.** An ``import``/``from … import`` whose alias binds
  ``INVLANG_FENCE_RE``, under any ``as`` name, and any attribute access spelled
  ``<x>.INVLANG_FENCE_RE``. You cannot use a module-level constant without one of the two,
  so this is the load-bearing arm.
- **Re-deriving the pattern.** Any ``re`` call — ``compile``/``search``/``match``/
  ``fullmatch``/``finditer``/``findall``/``split``/``sub``/``subn`` — whose pattern
  argument contains the literal ```` ```invlang ````, inline or via a module-level constant.
  This is the arm that matters more than it looks: importing the shared regex at least
  reuses one grammar, whereas a second ``re.compile(r"```invlang\\n(.*?)\\n```")`` is a
  second grammar that will drift from the first. The ``re`` callee is resolved by ORIGIN
  (``scripts/lint/_astlib.py``), so ``import re as regex`` and ``from re import findall``
  are the same case as the dotted form.

WHAT IT DOES *NOT* SEE — read this before treating a green run as proof:

- ``getattr(parser, "INVLANG_" + "FENCE_RE")`` and other computed access. The gate reads
  names, not values.
- A fence split done with ``str.split("```invlang")`` or ``find``/``index`` arithmetic
  rather than a regex. The frontmatter gate (``lint_hand_rolled_frontmatter``) covers that
  family for ``---`` fences and the same arms could be added here if a site ever appears;
  none does today, and arms are added against real sites, not imagined ones.
- Whether a caller that DOES use ``scan_fences`` actually reads ``orphaned_headers``.
  Nothing structural can ask that — the point of returning the complement on the same value
  is that ignoring it is a visible choice at the call site rather than an invisible default.

So a clean run means "no reader re-derives the fence split", not "every reader accounts for
what it drops". The second is what review and `tests/test_932_unfenced_surface.py` are for.

THE BASELINE SHIPS EMPTY. All five call sites were folded into ``scan_fences`` in the change
that added this gate, so an entry appearing here is a regression someone chose, not debt
inherited. Mark a deliberate site with ``# lint-fence-scan: ok — <reason>`` on the flagged
line or anywhere in the flagged node's span.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

from _astlib import ModuleEnv, ScanBlind, callee, module_env, read_and_parse, str_args
from _baseline import Finding, gate

REPO_ROOT = Path(__file__).resolve().parents[2]
SCOPE = REPO_ROOT / "defender"
BASELINE_PATH = Path(__file__).with_name("lint_unaccounted_fence_scan_baseline.json")

EXCLUDED_DIRS = (".venv", "__pycache__", "run-visualizations", "run-transcripts")
SUPPRESS_MARKERS = ("lint-fence-scan: ok",)

#: The module that OWNS the split. Exempted by full relative path, not basename: a basename
#: match would wave through any new `parser.py` anywhere under the scope — i.e. a verbatim
#: second copy of the grammar, which is the one thing this gate exists to stop.
CANONICAL_MODULE = "skills/invlang/parser.py"

FENCE_CONST = "INVLANG_FENCE_RE"
FENCE_LITERAL = "```invlang"

_RE_FUNCTIONS = (
    "compile", "search", "match", "fullmatch", "finditer", "findall", "split", "sub", "subn",
)

_ADVICE = {
    "import": f"imports {FENCE_CONST}",
    "attribute": f"reaches for {FENCE_CONST}",
    "regex": f"re-derives the {FENCE_LITERAL} fence pattern",
}


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
        if kind and not _suppressed(node, lines):
            # Fingerprint carries no line number, so moving the offending call within its
            # function does not read as a new finding — same convention as the sibling gates.
            fingerprint = f"{rel}:{func_name}:{kind}"
            if fingerprint not in seen:
                seen.add(fingerprint)
                findings.append(Finding(
                    fingerprint=fingerprint,
                    display=(
                        f"{rel}:{getattr(node, 'lineno', 0)}: {_ADVICE[kind]} — read the "
                        f"document through skills/invlang/parser.scan_fences, which returns "
                        f"what the fences ORPHAN alongside what they hold "
                        f"(in {func_name}())"
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
        if rel == CANONICAL_MODULE or _is_test_module(rel):
            continue
        text, tree = read_and_parse(path, rel)
        findings.extend(_scan_file(rel, tree, text.splitlines()))
    return findings


HEADER = (
    "lint_unaccounted_fence_scan baseline — readers under defender/ that split a document "
    "on its ```invlang fences without going through skills/invlang/parser.scan_fences "
    "(#932). Fingerprint is file:function:kind (import|attribute|regex; no line number), "
    "file relative to the scan scope. CI fails on a fingerprint absent here. This baseline "
    "ships EMPTY — all five sites were folded into scan_fences when the gate landed, so an "
    "entry in it is a regression someone chose. Regenerate: python scripts/lint/"
    "lint_unaccounted_fence_scan.py --update-baseline."
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
        print(f"lint_unaccounted_fence_scan: {exc}", file=sys.stderr)
        return 2
    print(
        "Read invlang fences through skills/invlang/parser.scan_fences — never by walking "
        "INVLANG_FENCE_RE or re-deriving the pattern (#932: three readers each dropped what "
        "the fences left out, and a run's whole PLAN section went unvalidated)."
    )
    print("Mark a deliberate site with `# lint-fence-scan: ok — <reason>`.")
    return gate(
        findings, baseline, args,
        label="lint_unaccounted_fence_scan", header=HEADER,
    )


if __name__ == "__main__":
    sys.exit(main())
