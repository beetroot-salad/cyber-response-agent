#!/usr/bin/env python3
"""Every defender program sets up logging — or says why it must not.

Status and diagnostics go through `logging` (`defender/_log.py`). A process that never calls
`configure_from_env()` has no handler, so Python's last-resort handler shows WARNING and up
and silently drops every INFO line, and whatever it logs is neither JSON nor stamped with a
run.

So a module with an `if __name__ == "__main__":` block must call `configure_from_env` as a
statement of that block, before anything but imports — resolved to `defender._log`, not matched
by name. Some programs must NOT: their stderr is read back by the model as a tool result, or they
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
from _astlib import ModuleEnv, ScanBlind, callee, module_env, read_and_parse, source_files

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFENDER = REPO_ROOT / "defender"
BASELINE_PATH = Path(__file__).with_name("lint_log_setup_baseline.json")

EXCLUDED_DIRS = (".venv", "__pycache__", "tests")
SUPPRESS = "lint-log-setup: ok"
#: Where the setup call must land, resolved through `_astlib`: an alias counts, an unrelated
#: same-named function does not.
SETUP = "defender._log.configure_from_env"


def _is_name_is_main(test: ast.expr) -> bool:
    """`__name__ == "__main__"`, written either way round."""
    if not (isinstance(test, ast.Compare) and len(test.ops) == 1
            and isinstance(test.ops[0], ast.Eq)):
        return False
    sides = [test.left, *test.comparators]
    return (any(isinstance(s, ast.Name) and s.id == "__name__" for s in sides)
            and any(isinstance(s, ast.Constant) and s.value == "__main__" for s in sides))


def _is_main_guard(node: ast.stmt) -> bool:
    """A top-level `if` that runs only as a program: the test alone, or one operand of an
    `and` (an `or` would run it on import too, so it is not a guard)."""
    if not isinstance(node, ast.If):
        return False
    test = node.test
    if isinstance(test, ast.BoolOp):
        return isinstance(test.op, ast.And) and any(_is_name_is_main(v) for v in test.values)
    return _is_name_is_main(test)


def _calls_setup(block: ast.If, env: ModuleEnv) -> bool:
    """The setup must be a statement of the guard itself (not in a nested function or
    branch), before the guard's first statement that does anything but import."""
    for stmt in block.body:
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
            if callee(stmt.value, env) == SETUP:
                return True
        if not isinstance(stmt, (ast.Import, ast.ImportFrom)):
            return False
    return False


def _scan() -> list[Finding]:
    findings: list[Finding] = []
    for name in source_files(DEFENDER, EXCLUDED_DIRS):
        path = DEFENDER / name
        rel = path.relative_to(REPO_ROOT).as_posix()
        text, tree = read_and_parse(path, rel)
        lines = text.splitlines()
        guards = [n for n in tree.body if _is_main_guard(n)]
        env = module_env(tree)
        if not guards or any(_calls_setup(g, env) for g in guards):
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
