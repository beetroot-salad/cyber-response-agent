#!/usr/bin/env python3
"""Every defender program sets up logging — or says why it must not.

Status and diagnostics go through `logging` (`defender/_log.py`). A process that never calls
`configure_from_env()` has no handler, so Python's last-resort handler shows WARNING and up
and silently drops every INFO line; and whatever the process logs is neither JSON nor stamped
with a run. That is how a leaked-worktree line and a whole curator trace went missing (#1115).

So a module with an `if __name__ == "__main__":` block must call `configure_from_env` inside
one. Some programs must NOT: their stderr is read back by the model as a tool result, or they
are a sandbox-side child that imports nothing from `defender`. Mark those on the `if` line with
`# lint-log-setup: ok — <reason>`.

Run from repo root:  python scripts/lint/lint_log_setup.py
Exit 0 = clean, 1 = a program that neither configures nor says why, 2 = could not scan.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

from _baseline import Finding, gate
from _astlib import ScanBlind, read_and_parse

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFENDER = REPO_ROOT / "defender"
BASELINE_PATH = Path(__file__).with_name("lint_log_setup_baseline.json")

EXCLUDED_DIRS = (".venv", "__pycache__", "tests")
SUPPRESS = "lint-log-setup: ok"
SETUP = "configure_from_env"


def _is_main_guard(node: ast.stmt) -> bool:
    """`if __name__ == "__main__"`, alone or as one operand of an `and`."""
    if not isinstance(node, ast.If):
        return False
    tests = node.test.values if isinstance(node.test, ast.BoolOp) else [node.test]
    return any(
        isinstance(t, ast.Compare)
        and isinstance(t.left, ast.Name) and t.left.id == "__name__"
        and any(isinstance(c, ast.Constant) and c.value == "__main__" for c in t.comparators)
        for t in tests
    )


def _calls_setup(block: ast.If) -> bool:
    for node in ast.walk(block):
        if isinstance(node, ast.Call):
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
            if name == SETUP:
                return True
    return False


def _scan() -> list[Finding]:
    findings: list[Finding] = []
    for path in sorted(DEFENDER.rglob("*.py")):
        rel_parts = path.relative_to(DEFENDER).parts
        if any(part in EXCLUDED_DIRS for part in rel_parts):
            continue
        rel = path.relative_to(REPO_ROOT).as_posix()
        text, tree = read_and_parse(path, rel)
        lines = text.splitlines()
        guards = [n for n in tree.body if _is_main_guard(n)]
        if not guards or any(_calls_setup(g) for g in guards):
            continue
        if any(SUPPRESS in lines[g.lineno - 1] for g in guards):
            continue
        findings.append(Finding(
            fingerprint=rel,
            display=f"{rel}:{guards[-1].lineno}: a program that never calls {SETUP}()",
        ))
    return findings


HEADER = (
    "lint_log_setup baseline — defender programs (modules with a __main__ block) that neither "
    "call _log.configure_from_env() nor carry `# lint-log-setup: ok — <reason>`. Ships EMPTY. "
    "Fingerprint is the file. Regenerate: python scripts/lint/lint_log_setup.py "
    "--update-baseline."
)


def main(argv: list[str]) -> int:
    if not DEFENDER.is_dir():
        print(f"defender/ not found at {DEFENDER}", file=sys.stderr)
        return 2
    try:
        findings = _scan()
    except ScanBlind as exc:
        print(f"lint_log_setup: {exc}", file=sys.stderr)
        return 2
    print("Call defender._log.configure_from_env() in the __main__ block, or mark the `if` line")
    print("`# lint-log-setup: ok — <reason>` when the program's stderr is read by the model.")
    return gate(findings, BASELINE_PATH, argv, label="lint_log_setup", header=HEADER,
                require_reasons=True)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
