#!/usr/bin/env python3
"""Shared-oracle smell: a test that computes its expected value with the same git query the
code under test runs.

A test whose oracle re-runs production's own command cannot disagree with the code about how
the tree is read. Every input on which the shared primitive is wrong is invisible to the suite
by construction: assertion and implementation fail together and the run stays green.

Example: production lists skill markers with
``git ls-tree -r --name-only HEAD -- <dir>`` then ``listing.split()`` and a
``count("/") == 3`` filter, and the test computes its expected set the same way. Neither
notices that ``--name-only`` C-quotes non-ASCII paths, ``.split()`` tears paths containing a
space, or ``ls-tree`` output is cwd-relative. Routing the call through the ``defender._git``
facade satisfies ``lint_raw_git_subprocess``; hand-rolling the parse of its output re-opens the
same hole one layer up.

What this flags: a git query argv shape that appears in both a production module and a test
module under `defender/`. The shape is the run of literal tokens up to `--` (the pathspec is
variable), with a leading `git` and `-C <path>` stripped, so the facade's
`_git.git(["ls-tree", ...])` and a test's `subprocess.run(["git", "-C", str(repo), "ls-tree",
...])` normalize to the same string. Only read subcommands count (`_READ_SUBCOMMANDS`): a
fixture that plants a tree already knows what it planted. A one-token shape is too generic and
is skipped.

What it cannot flag: an oracle that duplicates production's logic without its argv. And a
shared shape can be benign — an identity read like `rev-parse HEAD` to learn which commit was
just made — hence the baseline with `require_reasons`. The fix for a true positive is to
assert against the tree the test planted, not to change the argv.

Suppress a deliberate site with `# lint-oracle: ok — <reason>` on the call's line span.

Run from repo root:  python scripts/lint/lint_shared_oracle.py
Regenerate the baseline:  python scripts/lint/lint_shared_oracle.py --update-baseline
Exit 0 = clean, 1 = a new shared shape or an un-triaged baseline entry, 2 = could not run.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

from _baseline import Finding, gate
from _astlib import ScanBlind, module_env, read_and_parse, str_value, source_files

REPO_ROOT = Path(__file__).resolve().parents[2]
SCOPE = REPO_ROOT / "defender"
BASELINE_PATH = Path(__file__).with_name("lint_shared_oracle_baseline.json")

EXCLUDED_DIRS = (".venv", "__pycache__")
SUPPRESS_MARKER = "lint-oracle: ok"

#: git subcommands that answer a question about the tree rather than change it; only these
#: can rig an oracle. A closed positive table: "not obviously a write" would sweep in every
#: future subcommand unread.
_READ_SUBCOMMANDS = frozenset({
    "blame", "cat-file", "count-objects", "describe", "diff", "for-each-ref", "grep",
    "log", "ls-files", "ls-remote", "ls-tree", "merge-base", "name-rev", "rev-list",
    "rev-parse", "shortlog", "show", "show-ref", "status", "symbolic-ref", "var",
    "whatchanged",
})

#: Below this many literal tokens (a bare `show`) the shape says nothing about how the answer
#: was derived and would pair unrelated calls.
_MIN_SHAPE_TOKENS = 2


def _is_test_module(rel: str) -> bool:
    """A ``tests/`` dir, or a flat ``test_*.py`` / ``*_test.py`` / ``conftest.py``. Matches
    ``lint_raw_git_subprocess._is_test_module``: that gate exempts tests, this one is about
    them."""
    p = Path(rel)
    return (
        "tests" in p.parts
        or p.name == "conftest.py"
        or (p.name.startswith("test_") and p.suffix == ".py")
        or p.name.endswith("_test.py")
    )


def _shape(elts: list[ast.expr], env) -> str | None:
    """The normalized git-query shape of an argv list literal, or None if it is not one.

    Non-literal elements (``str(repo)``, a ``*flags`` splat) are dropped rather than ending
    the shape: they are the parts that legitimately differ between production and test.
    `str_value` resolves module-level string constants, so hoisting a literal does not evade
    the match.

    Truncated at ``--``: the pathspec after it is spelled differently on the two sides for
    reasons unrelated to whether they ask git the same question.
    """
    toks = [v for e in elts if (v := str_value(e, env)) is not None]
    if toks[:1] == ["git"]:
        toks = toks[1:]
    if toks[:1] == ["-C"]:      # `-C <path>`; the path was already dropped as non-literal
        toks = toks[1:]
    if "--" in toks:
        toks = toks[: toks.index("--")]
    if len(toks) < _MIN_SHAPE_TOKENS or toks[0] not in _READ_SUBCOMMANDS:
        return None
    return "|".join(toks)


def _suppressed(node: ast.AST, lines: list[str]) -> bool:
    start = node.lineno
    end = getattr(node, "end_lineno", start) or start
    return any(
        SUPPRESS_MARKER in lines[i - 1]
        for i in range(start, end + 1)
        if 0 < i <= len(lines)
    )


def _raised(tree: ast.Module) -> set[ast.AST]:
    """Every node under a ``raise`` statement.

    An argv can be data: `raise GitError(["rev-parse", "HEAD"], 128, ...)` names the failed
    call and executes nothing, so it cannot rig an oracle.
    """
    out: set[ast.AST] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Raise):
            out.update(ast.walk(node))
    return out


def _shapes_in(rel: str, tree: ast.Module, lines: list[str]) -> dict[str, int]:
    """Every git-query shape this module runs -> the first line it runs it on."""
    env = module_env(tree)
    raised = _raised(tree)
    found: dict[str, int] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not node.args or node in raised:
            continue
        first = node.args[0]
        if not isinstance(first, ast.List) or not first.elts:
            continue
        shape = _shape(first.elts, env)
        if shape is None or _suppressed(node, lines):
            continue
        found.setdefault(shape, node.lineno)
    return found


def _scan() -> list[Finding]:
    prod: dict[str, str] = {}                       # shape -> "file:line" of a producer
    tests: dict[str, dict[str, int]] = {}           # test rel -> {shape: line}
    for name in source_files(SCOPE, EXCLUDED_DIRS):
        path = SCOPE / name
        rel = path.relative_to(REPO_ROOT).as_posix()
        text, tree = read_and_parse(path, rel)
        shapes = _shapes_in(rel, tree, text.splitlines())
        if not shapes:
            continue
        if _is_test_module(rel):
            tests[rel] = shapes
        else:
            for shape, line in shapes.items():
                prod.setdefault(shape, f"{rel}:{line}")

    findings: list[Finding] = []
    for rel in sorted(tests):
        for shape, line in sorted(tests[rel].items()):
            if shape not in prod:
                continue
            findings.append(
                Finding(
                    fingerprint=f"{rel}:{shape}",
                    display=(
                        f"{rel}:{line}: oracle runs `git {shape.replace('|', ' ')}` — the "
                        f"same query as {prod[shape]}. Assert against the tree the test "
                        f"planted, not against a second copy of the code's own read."
                    ),
                )
            )
    return findings


HEADER = (
    "lint_shared_oracle baseline — git QUERY argv shapes run by both a production module "
    "and a test module under defender/: a test whose expected value comes from the code's "
    "own command cannot disagree with it, so the shared primitive's blind spots are "
    "invisible to the suite (#869/#908 — ls-tree C-quoting, .split() on spaced paths, and "
    "cwd-relative output, all asserted green by an oracle running the same argv). "
    "Fingerprint is file:argv-shape (no line number). CI fails on a fingerprint absent "
    "here AND on any entry left un-triaged. Regenerate: python "
    "scripts/lint/lint_shared_oracle.py --update-baseline. Say why the shared query is "
    "not an oracle (an identity read, a facade contract test) or fix it."
)


def main(argv: list[str]) -> int:
    if not SCOPE.is_dir():
        print(f"defender/ not found at {SCOPE}", file=sys.stderr)
        return 2
    # An unreadable file never entered the corpus; an unread production file also shrinks
    # what every test is matched against. Exit 2: the gate could not run, which is not "clean".
    try:
        findings = _scan()
    except ScanBlind as exc:
        print(f"lint_shared_oracle: {exc}", file=sys.stderr)
        return 2
    print(
        "A test's expected value must not come from the same git query the code under "
        "test runs — assert against the tree the test planted."
    )
    print("Suppress a deliberate site with `# lint-oracle: ok — <reason>`.")
    return gate(
        findings, BASELINE_PATH, argv,
        label="lint_shared_oracle", header=HEADER, require_reasons=True,
    )


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
