#!/usr/bin/env python3
"""Monkeypatch-setattr smell — flag `monkeypatch.setattr(...)` in defender/ tests.

`monkeypatch.setattr` reaches into a module and swaps a collaborator (a function,
class, or client) at import scope. It is the dependency-injection-avoidance smell
the author-family refactors removed: instead of patching `author._curator` from a
test, the collaborator is now injected via a config/deps seam (AuthorConfig /
CuratorConfig / LeadAuthorDeps / the ticket_writer transport seam), so the test
constructs the object it wants and hands it in. setattr-patching couples tests to
private module layout, survives renames silently, and leaks state across tests
when `undo` is missed.

Scope: this flags `monkeypatch.setattr` only. `monkeypatch.setenv` / `delenv`
(legitimate environment setup) and other fixtures are NOT flagged.

Pre-existing setattr sites are ratcheted via lint_monkeypatch_baseline.json (see
scripts/lint/_baseline.py); the gate fails only on a NEW file+target pair, so new
tests are pushed toward injection while the existing sites are paid down over time.

Suppress an intentional site with `# lint-monkeypatch: ok — <reason>` on the call.

Run from repo root:  python scripts/lint/lint_monkeypatch.py
Regenerate the baseline:  python scripts/lint/lint_monkeypatch.py --update-baseline
Exit 0 = clean (no new sites), 1 = new sites.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

from _baseline import Finding, gate
from _astlib import ScanBlind, read_and_parse

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFENDER = REPO_ROOT / "defender"
BASELINE_PATH = Path(__file__).with_name("lint_monkeypatch_baseline.json")

EXCLUDED_DIRS = (".venv", "__pycache__", "run-visualizations", "run-transcripts")

SUPPRESS = "lint-monkeypatch: ok"


def _in_scope(path: Path) -> bool:
    rel = path.relative_to(DEFENDER)
    return not any(part in EXCLUDED_DIRS for part in rel.parts)


def _is_monkeypatch_setattr(node: ast.Call) -> bool:
    func = node.func
    return (
        isinstance(func, ast.Attribute)
        and func.attr == "setattr"
        and isinstance(func.value, ast.Name)
        and func.value.id == "monkeypatch"
    )


def _target(node: ast.Call) -> str:
    """The attribute being patched, for the fingerprint: a dotted string for the
    `setattr("mod.attr", val)` form, or `obj.attr` for the `setattr(obj, "attr",
    val)` form. Falls back to the unparsed first argument."""
    args = node.args
    if not args:
        return "<unknown>"
    first = args[0]
    if isinstance(first, ast.Constant) and isinstance(first.value, str):
        return first.value
    base = ast.unparse(first)
    if len(args) >= 2:
        second = args[1]
        if isinstance(second, ast.Constant) and isinstance(second.value, str):
            return f"{base}.{second.value}"
        return f"{base}.{ast.unparse(second)}"
    return base


def _suppressed(node: ast.Call, lines: list[str]) -> bool:
    start = node.lineno
    end = getattr(node, "end_lineno", start) or start
    return any(
        SUPPRESS in lines[i - 1] for i in range(start, end + 1) if 0 < i <= len(lines)
    )


def _scan() -> list[Finding]:
    findings: list[Finding] = []
    for path in sorted(DEFENDER.rglob("*.py")):
        if not _in_scope(path):
            continue
        text, tree = read_and_parse(path, path.relative_to(REPO_ROOT).as_posix())
        lines = text.splitlines()
        rel = path.relative_to(REPO_ROOT).as_posix()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not _is_monkeypatch_setattr(node):
                continue
            if _suppressed(node, lines):
                continue
            target = _target(node)
            findings.append(
                Finding(
                    fingerprint=f"{rel}:{target}",
                    display=f"{rel}:{node.lineno}: monkeypatch.setattr({target})",
                )
            )
    return findings


HEADER = (
    "lint_monkeypatch baseline — monkeypatch.setattr sites in defender/ tests "
    "(the DI-avoidance smell; inject a config/deps seam instead). Fingerprint is "
    "file:target (no line number). CI fails on a file:target absent here. "
    "Regenerate: python scripts/lint/lint_monkeypatch.py --update-baseline. "
    'Annotate intentional entries; "" means un-triaged debt to convert to injection.'
)


def main(argv: list[str]) -> int:
    if not DEFENDER.is_dir():
        print(f"defender/ not found at {DEFENDER}", file=sys.stderr)
        return 2
    # A file inside the scan scope that could not be read or parsed never entered the corpus,
    # so a violation could sit in it and this gate would still print 0 findings. Exit 2 — the
    # gate could not run, which is categorically not "clean" (#618/#621/#652).
    try:
        findings = _scan()
    except ScanBlind as exc:
        print(f"lint_monkeypatch: {exc}", file=sys.stderr)
        return 2
    print("Prefer injecting collaborators (config/deps seam) over monkeypatch.setattr.")
    print("Suppress an intentional site with `# lint-monkeypatch: ok — <reason>`.")
    return gate(
        findings, BASELINE_PATH, argv,
        label="lint_monkeypatch", header=HEADER,
    )


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
