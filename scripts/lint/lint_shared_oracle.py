#!/usr/bin/env python3
"""Shared-oracle smell — a test that computes its EXPECTED value with the same git
query the code under test runs.

A test whose oracle re-runs production's own command is not a test of that command.
It cannot disagree with the code about how the tree is read; it can only confirm the
code does what the test's own copy does. Every input on which the shared primitive is
wrong is invisible to the suite BY CONSTRUCTION — the assertion and the implementation
fail together, in the same direction, and the run stays green.

THE SHIPPED CASE (#869/#908). `declared_systems._marker_names` read the committed tree
with::

    _git.git(["ls-tree", "-r", "--name-only", "HEAD", "--", SKILLS_REL], cwd=repo_root)
    ... for rel in listing.split(): if rel.count("/") != 3: continue

and `test_869_resolver.py` computed the set it asserted against with the SAME argv and
the SAME `count("/") == 3`. Both were transcribed from an executed probe recorded in the
spec, run over ASCII fixtures at the repo root. Three preconditions travelled with that
probe unstated and unnoticed by 57 tests: `--name-only` C-QUOTES a non-ASCII path (so it
no longer ends in `/execution.md`), `.split()` TEARS a path containing a space, and
`ls-tree`'s output is CWD-relative while the `cat-file -e HEAD:<path>` probe beside it is
project-root-relative. Each silently un-declared a real system — the exact failure #869
existed to prevent. The `-z`/spaced-path half of this is a REPLAY: `lint_raw_git_subprocess`'s
own docstring records "the non-`-z` copies mis-handled spaced paths" from #460. Routing the
call through the `defender._git` facade satisfied that gate; hand-rolling the PARSE of what
it returned re-opened the same hole one layer up.

WHAT THIS FLAGS: a git QUERY argv shape that appears in both a production module and a
test module under `defender/`. The shape is the run of literal tokens up to `--` (the
pathspec after it is variable by construction), with a leading `git` and `-C <path>`
stripped, so the facade's `_git.git(["ls-tree", ...])` and a test's raw
`subprocess.run(["git", "-C", str(repo), "ls-tree", ...])` normalize to the same string.
Only READ subcommands count (`_READ_SUBCOMMANDS`): a fixture builds its tree with
`init`/`add`/`commit`, and planting a tree is never how an oracle gets rigged — you know
what you planted. A shape of one token (a bare `show`) is too generic to mean anything and
is skipped.

WHAT IT DOES NOT FLAG, and cannot: an oracle that duplicates production's LOGIC without
duplicating its argv, and a shared shape whose test use is an identity read rather than a
derived expectation (`rev-parse HEAD` to learn which commit was just made). The second is
why this gate is baseline-ratcheted with `require_reasons`: the benign sites are real, and
the ratchet costs them one sentence each while making a NEW shared query unmergeable.
The remedy for a true positive is never to change the argv — it is to assert against the
tree the test PLANTED (it already knows the answer), so the oracle and the implementation
can disagree.

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
from _astlib import ScanBlind, module_env, read_and_parse, str_value

REPO_ROOT = Path(__file__).resolve().parents[2]
SCOPE = REPO_ROOT / "defender"
BASELINE_PATH = Path(__file__).with_name("lint_shared_oracle_baseline.json")

EXCLUDED_DIRS = (".venv", "__pycache__", "run-visualizations", "run-transcripts")
SUPPRESS_MARKER = "lint-oracle: ok"

#: git subcommands that ANSWER a question about the tree, as opposed to changing it. Only
#: these can rig an oracle: a fixture's `init`/`add`/`commit`/`checkout` builds the state
#: the test planted, and a test that plants a tree already knows what is in it. Kept as a
#: closed positive table — "not obviously a write" would sweep in every future subcommand
#: unread, which is the direction that produces false alarms nobody triages.
_READ_SUBCOMMANDS = frozenset({
    "blame", "cat-file", "count-objects", "describe", "diff", "for-each-ref", "grep",
    "log", "ls-files", "ls-remote", "ls-tree", "merge-base", "name-rev", "rev-list",
    "rev-parse", "shortlog", "show", "show-ref", "status", "symbolic-ref", "var",
    "whatchanged",
})

#: Below this many literal tokens the shape carries no information — a bare `show` or
#: `status` says nothing about HOW the answer was derived, and matching on it would pair
#: unrelated calls.
_MIN_SHAPE_TOKENS = 2


def _in_scope(path: Path) -> bool:
    return not any(part in EXCLUDED_DIRS for part in path.parts)


def _is_test_module(rel: str) -> bool:
    """A ``tests/`` dir, or a flat ``test_*.py`` / ``*_test.py`` / ``conftest.py``. Matches
    ``lint_raw_git_subprocess._is_test_module`` — the same partition of this tree, read
    from the other side: that gate exempts tests, this one is about them."""
    p = Path(rel)
    return (
        "tests" in p.parts
        or p.name == "conftest.py"
        or (p.name.startswith("test_") and p.suffix == ".py")
        or p.name.endswith("_test.py")
    )


def _shape(elts: list[ast.expr], env) -> str | None:
    """The normalized git-query shape of an argv list literal, or None if it is not one.

    Non-literal elements (``str(repo)``, a ``*flags`` splat, a Path expression) are DROPPED
    rather than ending the shape: they are the parts that legitimately differ between a
    production call and a test's, and stopping at the first one would make every shape a
    one-token prefix. `str_value` resolves module-level string constants too, so hoisting a
    literal into a named constant — which this repo asks for — does not evade the match.

    Truncated at ``--``: everything after it is a pathspec, which the two sides spell
    differently (a module constant on one, an imported name the resolver cannot see on the
    other) for reasons that have nothing to do with whether they ask git the same question.
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

    An argv can be DATA as well as a command: `raise GitError(["rev-parse", "HEAD"], 128,
    ...)` names the call that failed so the error can report it, and executes nothing. A
    shape reached only by raising cannot rig an oracle, and reading it as one puts an
    entry in the baseline whose honest annotation is "this is not a git call" — which is a
    detector bug wearing a reason. Cheap and sound: raising is not running.
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
    for path in sorted(SCOPE.rglob("*.py")):
        if not _in_scope(path):
            continue
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
    # A file inside the scan scope that could not be read or parsed never entered the corpus,
    # so a violation could sit in it and this gate would still print 0 findings. Exit 2 — the
    # gate could not run, which is categorically not "clean" (#618/#621/#652). It is doubly
    # wrong here: an unread PRODUCTION file also shrinks the corpus every test is matched
    # against, so a blind scan under-reports the tests it did read.
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
