#!/usr/bin/env python3
"""Hand-rolled frontmatter parsing: flag fence arithmetic under ``defender/`` that bypasses the
canonical grammar in ``defender/_frontmatter.py``.

There is one contract for parsing YAML frontmatter out of a markdown doc:
``split_frontmatter`` / ``parse_frontmatter`` / ``parse_frontmatter_or_none``. Readers that
re-derive the fence offsets each get a subtly different grammar (a loose leading fence, an
unanchored regex, a ``text[3:]`` slice), so the same document parses differently depending on
who reads it — a parser differential that can, e.g., let a linter accept a SKILL.md ``name:``
the runtime rejects.

What it flags — parse-shaped **Call** nodes in defender/ production code:

- ``<x>.find/rfind/index("…---…")`` — fence-offset arithmetic
- ``<x>.split/rsplit/partition/rpartition("---…" | "\\n---…")`` — a fence separator. Both
  halves of the grammar count: ``"\\n---"`` is the closing fence ``split_frontmatter``
  itself searches for.
- ``<x>.startswith/removeprefix/removesuffix("---…" | "\\n---…")`` — a hand-rolled
  opening/closing-fence check or strip
- ``re.compile/search/match/fullmatch/sub/subn/finditer/findall/split`` with a
  fence pattern (``^---`` / ``\\A---`` / ``\\n---`` / a ``---``-leading literal).
  A closing-fence pattern is matched in both spellings — the raw ``r"\\n---"`` (constant
  holds ``\\`` + ``n``) and the non-raw ``"\\n---"`` (constant holds a real newline);
  they are different strings in the AST. (This docstring is not raw, so both render as
  ``\\n`` here; the difference is the ``r`` prefix on the source literal.)

The ``re`` call is identified by resolved origin (``scripts/lint/_astlib.py``), so aliases and
from-imports count. String args are read inline and through module-level constants:
``FENCE = "---\\n"`` then ``text.startswith(FENCE)`` is flagged, so hoisting a literal is not
an evasion.

What it does not flag: constants and writer f-strings that merely emit fences and are never
passed into a parse-shaped call (``f"---\\nid: …"``, a ``"--- stdout ---"`` separator,
docstrings) — the detector keys on Call nodes. Also waived: ``"\\n---" in text`` containment
Compare nodes (false-positive risk on separator checks). Tests are excluded (fixtures
hand-build fence documents), and ``defender/_frontmatter.py`` is exempt as the canonical
module.

Known limitation — a call-free parser is out of reach by construction: a slice-compare
(``if text[:4] == "---\\n":``) or a line loop (``lines = text.split("\\n")`` then
``if lines[0] == "---":``) makes no fence-shaped call. Widening to ``Compare`` nodes would drag
in every ``x[:n] == "…"`` in the tree. The gate stops the idiomatic copy, which is the shape
people actually reach for.

Mark a deliberate site with ``# lint-frontmatter: ok — <reason>`` on the call's line span.
Pre-existing sites are ratcheted via ``lint_hand_rolled_frontmatter_baseline.json``; the gate
fails only on a new file+function+kind. The baseline ships empty, so an entry is a chosen
regression.

Run from repo root:  python scripts/lint/lint_hand_rolled_frontmatter.py
Regenerate the baseline:  python scripts/lint/lint_hand_rolled_frontmatter.py --update-baseline
Exit 0 = clean (no new sites), 1 = new sites, 2 = scan scope missing.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

from _astlib import ScanBlind, read_and_parse, ModuleEnv, callee, module_env, str_args
from _baseline import Finding, gate

REPO_ROOT = Path(__file__).resolve().parents[2]
SCOPE = REPO_ROOT / "defender"
BASELINE_PATH = Path(__file__).with_name("lint_hand_rolled_frontmatter_baseline.json")

EXCLUDED_DIRS = (".venv", "__pycache__")
SUPPRESS_MARKERS = ("lint-frontmatter: ok",)
CANONICAL_MODULE = "_frontmatter.py"

_FIND_METHODS = ("find", "rfind", "index")
_SPLIT_METHODS = ("split", "rsplit", "partition", "rpartition")
_PREFIX_METHODS = ("startswith", "removeprefix", "removesuffix")
_RE_FUNCS = (
    "compile", "search", "match", "fullmatch",
    "sub", "subn", "finditer", "findall", "split",
)
# A regex arg is fence-shaped when it anchors or searches for a '---' fence line. Matched
# against the constant, so escapes have two spellings: `"\\A---"` / `"\\n---"` are what a raw
# `r"\A---"` / `r"\n---"` contains, while `"\n---"` is a real newline (non-raw). Both needed.
_FENCE_PATTERN_MARKS = ("^---", "\\A---", "\\n---", "\n---")


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


def _is_fence_pattern(value: str) -> bool:
    return value.startswith("---") or any(m in value for m in _FENCE_PATTERN_MARKS)


def _is_fence_literal(value: str) -> bool:
    """A fence-shaped separator/opener: the opening fence (``---\\n…``) or the closing one
    (``\\n---``, what ``split_frontmatter`` itself searches for)."""
    return value.startswith("---") or value.startswith("\n---")


def _kind(call: ast.Call, env: ModuleEnv) -> str | None:
    """Which hand-rolled fence-parse shape this call is, or None.

    The regex branch resolves the callee, so ``re.search`` / aliased / bare from-imported
    ``search`` are one case. It must run before the ast.Attribute guard below, since a
    from-import callee is an ``ast.Name``.
    """
    args = str_args(call, env)
    if not args:
        return None

    o = callee(call, env)
    if o is not None and o.startswith("re.") and o.rpartition(".")[2] in _RE_FUNCS:
        # Early return: `re.split(p, t)` on a non-fence pattern must not fall through into
        # the str `.split` branch below.
        return "regex" if any(_is_fence_pattern(v) for v in args) else None

    # The remaining shapes are str methods, duck-typed (the receiver is a value): key on
    # the attribute name.
    func = call.func
    if not isinstance(func, ast.Attribute):
        return None
    attr = func.attr
    if attr in _FIND_METHODS and any("---" in v for v in args):
        return "find"
    if attr in _SPLIT_METHODS and any(_is_fence_literal(v) for v in args):
        return "split"
    if attr in _PREFIX_METHODS and any(_is_fence_literal(v) for v in args):
        return "startswith"
    return None


def _suppressed(node: ast.AST, lines: list[str]) -> bool:
    start = node.lineno  # type: ignore[attr-defined]
    end = getattr(node, "end_lineno", start) or start
    return any(
        any(m in lines[i - 1] for m in SUPPRESS_MARKERS)
        for i in range(start, end + 1)
        if 0 < i <= len(lines)
    )


_ADVICE = {
    "find": "hand-rolled fence-offset find/rfind/index('…---…')",
    "split": "hand-rolled split/rsplit/partition('---…')",
    "startswith": "hand-rolled opening-fence startswith('---…')",
    "regex": "hand-rolled fence regex",
}


def _scan_file(rel: str, tree: ast.AST, lines: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()
    env = module_env(tree)

    def visit(node: ast.AST, func_name: str) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            func_name = node.name
        if isinstance(node, ast.Call) and (kind := _kind(node, env)) and not _suppressed(node, lines):
            fingerprint = f"{rel}:{func_name}:{kind}"
            if fingerprint not in seen:
                seen.add(fingerprint)
                findings.append(Finding(
                    fingerprint=fingerprint,
                    display=(
                        f"{rel}:{node.lineno}: {_ADVICE[kind]} — route through "
                        f"defender/_frontmatter.py (in {func_name}())"
                    ),
                ))
        for child in ast.iter_child_nodes(node):
            visit(child, func_name)

    visit(tree, "<module>")
    return findings


def _scan(root: Path) -> list[Finding]:
    """Findings under ``root``, fingerprints relative to it (drivable on a tmp tree)."""
    findings: list[Finding] = []
    for path in sorted(root.rglob("*.py")):
        if not _in_scope(path):
            continue
        rel = path.relative_to(root).as_posix()
        # Exempt the canonical module by path, not basename: a basename match would wave
        # through a verbatim second copy of the grammar named after the module it duplicates.
        if rel == CANONICAL_MODULE:
            continue
        if _is_test_module(rel):
            continue
        text, tree = read_and_parse(path, rel)
        findings.extend(_scan_file(rel, tree, text.splitlines()))
    return findings


HEADER = (
    "lint_hand_rolled_frontmatter baseline — fence arithmetic under defender/ that "
    "bypasses the canonical grammar in defender/_frontmatter.py (#591). Fingerprint is "
    "file:function:kind (find|split|startswith|regex; no line number), file relative to "
    "the scan scope. CI fails on a fingerprint absent here. This baseline ships EMPTY — "
    "the five hand-rolled sites were folded when the gate landed, so an entry in it is a "
    "regression someone chose. Regenerate: python scripts/lint/"
    "lint_hand_rolled_frontmatter.py --update-baseline."
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
    # An unreadable file never entered the corpus. Exit 2: the gate could not run, which is
    # not "clean".
    try:
        findings = _scan(root)
    except ScanBlind as exc:
        print(f"lint_hand_rolled_frontmatter: {exc}", file=sys.stderr)
        return 2
    print(
        "Parse frontmatter through defender/_frontmatter.py — split_frontmatter / "
        "parse_frontmatter / parse_frontmatter_or_none — never by re-deriving the "
        "fence offsets (#591: five copies, five grammars, one parser differential "
        "in the eval metric)."
    )
    print("Mark a deliberate site with `# lint-frontmatter: ok — <reason>`.")
    return gate(
        findings, baseline, args,
        label="lint_hand_rolled_frontmatter", header=HEADER,
    )


if __name__ == "__main__":
    sys.exit(main())
