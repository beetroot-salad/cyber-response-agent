#!/usr/bin/env python3
"""Duplicate-helper lint — catches the recurring "same helper hand-copied across
modules" smell that the jscpd gate (ci.yml) is structurally blind to.

Why this exists alongside jscpd: jscpd is a block-level token-clone detector
(`--min-tokens 60`, repo-wide % threshold). It is correctly tuned for *large*
hand-mirrored blocks (the #330 class) but cannot see the *scattered small
helper* class — a 1-5 line utility (`_now_iso`, `_log`, `_subscription_env`)
copied into many modules is far under 60 tokens, and a dozen tiny copies barely
move a percentage. It is also blind to *divergent* copies (same concept, drifted
body/return type — the #359 `_parse_frontmatter` class), since there is no long
identical token run to match. Issues #357/#358/#359/#360 are exactly these.

This lint works on a different, cheap signal: the same module-level function
name `def`'d in two or more modules. For each such group it normalizes the AST
body (docstrings stripped) and classifies:

  - identical-duplicate   every copy's body is byte-identical after
                          normalization → pure copy-paste; extract to a shared
                          module (`_loop_config.py` / `_author_shared.py`).
                          (#357 `_subscription_env`, #358 `_now_iso`/`_log`.)

  - divergent-duplicate   same name, bodies have drifted → unify the contract
                          or rename. The higher-value flag: divergent copies
                          silently diverge in behavior. (#359 `_parse_frontmatter`.)

Ratchet model (mirrors the jscpd gate): the duplicate names that exist *today*
are recorded in `lint_duplicate_helpers_baseline.json`. The lint fails (exit 1)
only on a duplicate name *not* in the baseline — i.e. newly-introduced drift —
so it blocks growth without forcing a big-bang cleanup of the existing set.
Regenerate the baseline after a deliberate change with `--update-baseline`.

Scope: `defender/` only, module-level defs only (nested defs and methods are
not counted). Excluded as the jscpd gate's `--ignore` does: `.venv`, the
transient run-output dirs (`runs/`, `run-visualizations/`), and `**/*_cli.py`
(per-system adapter shims share argparse scaffolding by design). Excluded
additionally (fixture/scaffold code that re-implements helpers by design):
test modules — a `tests/` dir or a flat `test_*.py` / `*_test.py` file — and
`skills/connect/examples/` (adapter scaffold templates meant to be copied). A
few legitimately-polymorphic names (entry points) are allowlisted below.

Limitation: name-based, so a dup split across *different* names (e.g. #360's
`acquire_queue_lock` vs `acquire_lock`) is only partially surfaced — the
same-named copies fire, the renamed sibling does not. Block-level dup is jscpd's
job; this is the small-helper complement.

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

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFENDER = REPO_ROOT / "defender"
BASELINE_PATH = Path(__file__).with_name("lint_duplicate_helpers_baseline.json")

# Directory names (any path segment, relative to defender/) excluded from scope.
# `.venv` + the transient run-output dirs mirror the jscpd gate's --ignore;
# `tests` drops fixture-helper modules (flat test_*.py files handled below).
EXCLUDED_DIRS = (".venv", "tests", "runs", "run-visualizations")

# Accepted-boilerplate excludes (by filename suffix / path substring):
#   *_cli.py            — per-system adapter shims share argparse scaffolding by
#                         design (jscpd ignores `**/*_cli.py` for the same reason)
#   connect/examples/   — adapter scaffold templates, meant to be copied
EXCLUDED_SUFFIXES = ("_cli.py",)
EXCLUDED_PATH_PARTS = ("skills/connect/examples/",)

# Module-level names that are legitimately defined in many modules — script
# entry points, not copy-pasted logic. Never reported regardless of count.
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
    # Flat pytest modules (test_*.py / *_test.py) outside a tests/ dir are
    # fixture helpers too — exclude them for the same reason a tests/ dir is.
    if path.name.startswith("test_") or path.name.endswith("_test.py"):
        return False
    if path.name.endswith(EXCLUDED_SUFFIXES):
        return False
    rel_posix = rel.as_posix()
    return not any(part in rel_posix for part in EXCLUDED_PATH_PARTS)


def _strip_docstring(body: list[ast.stmt]) -> list[ast.stmt]:
    """Drop a leading docstring so copies that differ *only* in their docstring
    (e.g. the five `_subscription_env`) normalize as identical."""
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


def _suppressed(fn: ast.FunctionDef | ast.AsyncFunctionDef, lines: list[str]) -> bool:
    """True if the inline SUPPRESS marker sits anywhere in the def's header — any
    decorator line through the last line of a (possibly multi-line) signature —
    so the marker is honored wherever in the header it is placed, not only on a
    bare single-line `def`."""
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
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(text)
        except (OSError, SyntaxError):
            continue
        lines = text.splitlines()
        rel = path.relative_to(REPO_ROOT).as_posix()
        for node in tree.body:  # module level only — no methods, no nested defs
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if node.name in ALLOWLIST_NAMES:
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
    table = _collect()
    identical, divergent = _dup_groups(table)

    _print_section("identical-duplicate (extract to a shared module)", identical)
    _print_section("divergent-duplicate (unify the contract or rename)", divergent)

    # Fingerprint is the bare helper name; the display carries its kind + sites.
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
