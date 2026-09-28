#!/usr/bin/env python3
"""Duplicate-helper lint: catches the "same helper hand-copied across modules" smell that the
jscpd gate (ci.yml) is structurally blind to.

jscpd is a block-level token-clone detector (`--min-tokens 60`, repo-wide % threshold), tuned
for large mirrored blocks. It cannot see a 1-5 line utility (`_now_iso`, `_log`) copied into
many modules, nor divergent copies (same concept, drifted body) with no long identical run.

This lint uses a cheap signal: the same module-level function name `def`'d in two or more
modules. For each group it normalizes the AST body (docstrings stripped) and classifies:

  - identical-duplicate   every copy's body is identical after normalization → pure
                          copy-paste; extract to a shared module.

  - divergent-duplicate   same name, drifted bodies → unify the contract or rename. The
                          higher-value flag: divergent copies silently diverge in behavior.

Ratchet model (mirrors jscpd): today's duplicate names are recorded in
`lint_duplicate_helpers_baseline.json`, and the lint fails (exit 1) only on a name not in it.
Regenerate after a deliberate change with `--update-baseline`.

Scope: `defender/` only, module-level defs only. Excluded: `.venv`, `runs/`, test modules
(a `tests/` dir or a flat `test_*.py` / `*_test.py`), and `skills/connect/examples/`
(scaffold templates meant to be copied). A few polymorphic entry-point names are allowlisted.

Also skipped: thin same-name delegators, whose whole body is `return <mod>.<same_name>(...)`
(see `_is_delegator`); the real body lives once in the target.

Limitation: name-based, so a copy under a different name is not surfaced. Block-level dup is
jscpd's job; this is the small-helper complement.

Run from repo root:  python scripts/lint/lint_duplicate_helpers.py
Regenerate the baseline:  python scripts/lint/lint_duplicate_helpers.py --update-baseline
Exit 0 = clean (no new dup names), 1 = new dup names.
"""
from __future__ import annotations

import ast
import sys
from collections import defaultdict
from pathlib import Path

from _baseline import Finding, gate
from _astlib import ScanBlind, read_and_parse

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFENDER = REPO_ROOT / "defender"
BASELINE_PATH = Path(__file__).with_name("lint_duplicate_helpers_baseline.json")

# Directory names (any path segment, relative to defender/) excluded from scope. Flat
# test_*.py files are handled in `_in_scope`.
EXCLUDED_DIRS = (".venv", "tests", "runs")

# Accepted-boilerplate excludes (by path substring):
#   connect/examples/   — adapter scaffold templates, meant to be copied
#
# No filename-suffix exclusion: adapter duplication under `scripts/adapters/` gets fixed or
# carries a written `# lint-dup: ok`.
EXCLUDED_PATH_PARTS = ("skills/connect/examples/",)

# Module-level names legitimately defined in many modules (entry points). Never reported.
ALLOWLIST_NAMES = frozenset(
    {
        "main",  # every script's entry point
        "run",  # generic per-module driver entry
    }
)

# Inline suppression: put this on the `def` line of an intentional copy.
SUPPRESS = "lint-dup: ok"


def _in_scope(path: Path) -> bool:
    rel = path.relative_to(DEFENDER)
    if any(part in EXCLUDED_DIRS for part in rel.parts):
        return False
    # Flat pytest modules outside a tests/ dir are fixture helpers too.
    if path.name.startswith("test_") or path.name.endswith("_test.py"):
        return False
    rel_posix = rel.as_posix()
    return not any(part in rel_posix for part in EXCLUDED_PATH_PARTS)


def _strip_docstring(body: list[ast.stmt]) -> list[ast.stmt]:
    """Drop a leading docstring so copies differing only in their docstring normalize as
    identical."""
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        return body[1:]
    return body


def _body_fingerprint(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    """AST dump of the body (docstring stripped, positions excluded) — identical
    fingerprints mean copy-paste regardless of name/annotations."""
    return "".join(ast.dump(node) for node in _strip_docstring(fn.body))


def _is_delegator(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """True if the body is just `return <mod>.<same_name>(...)` (optionally awaited) — a
    thin re-export adapter kept for import-locality, not a copy. A def that calls a
    differently-named shared helper is a real body."""
    body = _strip_docstring(fn.body)
    if len(body) != 1 or not isinstance(body[0], ast.Return):
        return False
    value = body[0].value
    if isinstance(value, ast.Await):
        value = value.value
    return (
        isinstance(value, ast.Call)
        and isinstance(value.func, ast.Attribute)
        and value.func.attr == fn.name
    )


def _suppressed(fn: ast.FunctionDef | ast.AsyncFunctionDef, lines: list[str]) -> bool:
    """True if the SUPPRESS marker sits anywhere in the def's header, from the first
    decorator through the last line of a multi-line signature."""
    start = fn.decorator_list[0].lineno if fn.decorator_list else fn.lineno
    end = max(fn.lineno, fn.body[0].lineno - 1) if fn.body else fn.lineno
    return any(
        SUPPRESS in lines[i - 1] for i in range(start, end + 1) if 0 < i <= len(lines)
    )


def _collect() -> dict[str, list[tuple[str, int, str]]]:
    """name -> list of (rel_path, lineno, body_fingerprint) for every
    module-level def across in-scope defender/ source."""
    table: dict[str, list[tuple[str, int, str]]] = defaultdict(list)
    for path in sorted(DEFENDER.rglob("*.py")):
        if not _in_scope(path):
            continue
        text, tree = read_and_parse(path, path.relative_to(REPO_ROOT).as_posix())
        lines = text.splitlines()
        rel = path.relative_to(REPO_ROOT).as_posix()
        for node in tree.body:  # module level only
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if node.name in ALLOWLIST_NAMES:
                continue
            if _is_delegator(node):
                continue
            if _suppressed(node, lines):
                continue
            table[node.name].append((rel, node.lineno, _body_fingerprint(node)))
    return table


def _dup_groups(
    table: dict[str, list[tuple[str, int, str]]],
) -> tuple[list[tuple[str, list]], list[tuple[str, list]]]:
    """Split duplicated names (defined in >=2 modules) into (identical, divergent)."""
    identical: list[tuple[str, list]] = []
    divergent: list[tuple[str, list]] = []
    for name, sites in sorted(table.items()):
        if len({rel for rel, _, _ in sites}) < 2:
            continue
        fingerprints = {fp for _, _, fp in sites}
        (identical if len(fingerprints) == 1 else divergent).append((name, sites))
    return identical, divergent


def _print_section(title: str, groups: list[tuple[str, list]]) -> None:
    print(f"\n=== {title} ({len(groups)} name{'' if len(groups) == 1 else 's'}) ===")
    for name, sites in groups:
        locs = ", ".join(f"{rel}:{lineno}" for rel, lineno, _ in sites)
        print(f"  {name}() x{len(sites)}: {locs}")


HEADER = (
    "lint_duplicate_helpers baseline — module-level helper names defined in >=2 "
    "in-scope defender/ modules. Fingerprint is the bare name. CI fails on a dup "
    "name absent here. Regenerate: "
    "python scripts/lint/lint_duplicate_helpers.py --update-baseline. "
    'Shrink as dups are consolidated; annotate intentional entries, "" = un-triaged. '
    "Never hand-add to silence a new dup — fix it or use `# lint-dup: ok — <reason>`."
)


def main(argv: list[str]) -> int:
    # An unreadable file never entered the corpus. Exit 2: the gate could not run, which is
    # not "clean".
    try:
        table = _collect()
    except ScanBlind as exc:
        print(f"lint_duplicate_helpers: {exc}", file=sys.stderr)
        return 2
    identical, divergent = _dup_groups(table)

    _print_section("identical-duplicate (extract to a shared module)", identical)
    _print_section("divergent-duplicate (unify the contract or rename)", divergent)

    findings = [
        Finding(
            fingerprint=name,
            display=f"{kind} {name}() x{len(sites)}: "
            + ", ".join(f"{rel}:{lineno}" for rel, lineno, _ in sites),
        )
        for kind, groups in (("identical", identical), ("divergent", divergent))
        for name, sites in groups
    ]
    return gate(
        findings, BASELINE_PATH, argv,
        label="lint_duplicate_helpers", header=HEADER,
    )


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
