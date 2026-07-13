#!/usr/bin/env python3
"""Hand-rolled frontmatter parsing — flag fence arithmetic under ``defender/`` that
bypasses the canonical grammar in ``defender/_frontmatter.py``.

There is ONE contract for "parse the YAML frontmatter out of a markdown doc":
``split_frontmatter`` / ``parse_frontmatter`` / ``parse_frontmatter_or_none``. Before
#591, five readers re-derived the fence offsets themselves, each with a subtly
different grammar — a loose leading fence, an unanchored regex, a ``text[3:]``
slice — so the same document parsed differently depending on who read it. The
worst of it: the secondary eval metric and the learning loop read the same
``report.md`` through DIFFERENT grammars (parser differential injected into
exactly the divergence signal secondary exists to measure), and a scaffold
linter greenlit a SKILL.md whose real ``name:`` the runtime would reject. This
gate keeps a sixth copy from growing back.

What it flags — parse-shaped **Call** nodes in defender/ production code:

- ``<x>.find/rfind/index("…---…")`` — fence-offset arithmetic
- ``<x>.split/rsplit/partition/rpartition("---…")`` — a ``---``-leading separator
- ``<x>.startswith("---…")`` — a hand-rolled opening-fence check
- ``re.compile/search/match/fullmatch/sub/subn/finditer/findall/split`` with a
  fence pattern (``^---`` / ``\\A---`` / ``\\n---`` / a ``---``-leading literal)

What it does NOT flag: string **constants** and writer f-strings that merely EMIT
fences (``f"---\\nid: …"``, a ``"--- stdout ---"`` separator, docstrings) — the
detector keys on Call nodes, never on Constant/JoinedStr content. Also waived by
design (spec_graph_591 ``w_containment_detector``): ``"\\n---" in text``
in-containment Compare nodes — flagging them risks false positives on separator
checks. Tests are excluded (fixtures legitimately hand-build fence documents),
and ``defender/_frontmatter.py`` itself is exempt by name — the canonical module
is where the fence arithmetic is SUPPOSED to live.

Mark a deliberate site with ``# lint-frontmatter: ok — <reason>`` on the call's
line span. Pre-existing sites are ratcheted via
``lint_hand_rolled_frontmatter_baseline.json``; the gate fails only on a NEW
file+function+kind. The baseline ships EMPTY — the five sites were folded when
the gate landed, so an entry appearing in it is a regression someone chose.

Run from repo root:  python scripts/lint/lint_hand_rolled_frontmatter.py
Regenerate the baseline:  python scripts/lint/lint_hand_rolled_frontmatter.py --update-baseline
Exit 0 = clean (no new sites), 1 = new sites, 2 = scan scope missing.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

from _baseline import Finding, gate

REPO_ROOT = Path(__file__).resolve().parents[2]
SCOPE = REPO_ROOT / "defender"
BASELINE_PATH = Path(__file__).with_name("lint_hand_rolled_frontmatter_baseline.json")

EXCLUDED_DIRS = (".venv", "__pycache__", "run-visualizations", "run-transcripts")
SUPPRESS_MARKERS = ("lint-frontmatter: ok",)
CANONICAL_MODULE = "_frontmatter.py"

_FIND_METHODS = ("find", "rfind", "index")
_SPLIT_METHODS = ("split", "rsplit", "partition", "rpartition")
_RE_FUNCS = (
    "compile", "search", "match", "fullmatch",
    "sub", "subn", "finditer", "findall", "split",
)
# A regex arg is fence-shaped when it anchors or searches for a '---' fence line.
_FENCE_PATTERN_MARKS = ("^---", "\\A---", "\n---")


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


def _str_args(call: ast.Call) -> list[str]:
    """The string-literal args of a call — positional and keyword (so
    ``re.compile(pattern=r"^---…")`` is seen), tuple elements flattened (so
    ``startswith(("---", "…"))`` is)."""
    out: list[str] = []
    for arg in [*call.args, *(kw.value for kw in call.keywords)]:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            out.append(arg.value)
        elif isinstance(arg, ast.Tuple):
            out.extend(
                el.value for el in arg.elts
                if isinstance(el, ast.Constant) and isinstance(el.value, str)
            )
    return out


def _receiver_root(call: ast.Call) -> str | None:
    """For ``<root>.….attr(...)``, the root Name id (so ``re.search`` can be told
    from ``text.split``). None for an unnamable receiver."""
    func = call.func
    if not isinstance(func, ast.Attribute):
        return None
    cur: ast.expr = func.value
    while isinstance(cur, (ast.Attribute, ast.Subscript, ast.Call)):
        cur = cur.value if not isinstance(cur, ast.Call) else cur.func
    return cur.id if isinstance(cur, ast.Name) else None


def _is_fence_pattern(value: str) -> bool:
    return value.startswith("---") or any(m in value for m in _FENCE_PATTERN_MARKS)


def _kind(call: ast.Call) -> str | None:
    """Which hand-rolled fence-parse shape this call is, or None."""
    func = call.func
    if not isinstance(func, ast.Attribute):
        return None
    attr = func.attr
    args = _str_args(call)
    if not args:
        return None
    if _receiver_root(call) == "re" and attr in _RE_FUNCS:
        if any(_is_fence_pattern(v) for v in args):
            return "regex"
        return None
    if attr in _FIND_METHODS and any("---" in v for v in args):
        return "find"
    if attr in _SPLIT_METHODS and args[0].startswith("---"):
        return "split"
    if attr == "startswith" and any(v.startswith("---") for v in args):
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

    def visit(node: ast.AST, func_name: str) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            func_name = node.name
        if isinstance(node, ast.Call) and (kind := _kind(node)) and not _suppressed(node, lines):
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
    """Findings under ``root``, fingerprints relative to it — so the gate is
    drivable on an injected tmp tree, not just the repo checkout."""
    findings: list[Finding] = []
    for path in sorted(root.rglob("*.py")):
        if not _in_scope(path):
            continue
        if path.name == CANONICAL_MODULE:
            continue
        rel = path.relative_to(root).as_posix()
        if _is_test_module(rel):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(text)
        except (OSError, SyntaxError):
            continue
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
    findings = _scan(root)
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
