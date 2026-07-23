#!/usr/bin/env python3
"""Reject prompt section assembly that bypasses ``defender._untrusted.wrap``.

The check is delimiter-independent: it does not carry a list of known tags,
headings, or prose labels. Instead it enforces the construction boundary.
Section arguments sent to ``stage_user_message`` must already be ``wrap``
results, and module-level interpolated strings cannot establish an unreviewed
boundary grammar outside that API.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

try:  # package import in tests
    from ._astlib import ScanBlind, read_and_parse
    from ._baseline import Finding, gate
except ImportError:  # direct ``python scripts/lint/...`` execution
    from _astlib import ScanBlind, read_and_parse
    from _baseline import Finding, gate


REPO_ROOT = Path(__file__).resolve().parents[2]
LEARNING = REPO_ROOT / "defender" / "learning"
BASELINE_PATH = Path(__file__).with_name("lint_stage_prompt_frames_baseline.json")
EXCLUDED_DIRS = frozenset({".venv", "__pycache__", "tests"})
SUPPRESS = "lint-stage-frame: ok"


def _call_name(node: ast.Call) -> str | None:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None


def _is_wrap_call(node: ast.AST) -> bool:
    return isinstance(node, ast.Call) and _call_name(node) == "wrap"


def _suppressed(node: ast.AST, lines: list[str]) -> bool:
    start = getattr(node, "lineno", 0)
    end = getattr(node, "end_lineno", start) or start
    return any(
        SUPPRESS in lines[index - 1]
        for index in range(start, end + 1)
        if 0 < index <= len(lines)
    )


def _relative(path: Path, scope: Path) -> str:
    try:
        return path.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return path.relative_to(scope).as_posix()


def _module_interpolations(
    tree: ast.Module, rel: str, lines: list[str]
) -> list[Finding]:
    findings: list[Finding] = []
    for statement in tree.body:
        if not isinstance(statement, (ast.Assign, ast.AnnAssign)):
            continue
        for node in ast.walk(statement):
            if not isinstance(node, ast.JoinedStr) or _suppressed(node, lines):
                continue
            findings.append(
                Finding(
                    fingerprint=(
                        f"{rel}:module-interpolation:"
                        f"{ast.dump(node, include_attributes=False)}"
                    ),
                    display=(
                        f"{rel}:{node.lineno}: module-level interpolated boundary "
                        "bypasses defender._untrusted.wrap"
                    ),
                )
            )
    return findings


def _stage_message_arguments(
    tree: ast.Module, rel: str, lines: list[str]
) -> list[Finding]:
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if (
            not isinstance(node, ast.Call)
            or _call_name(node) != "stage_user_message"
        ):
            continue
        for index, argument in enumerate(node.args[1:], start=1):
            if _is_wrap_call(argument) or isinstance(argument, ast.Starred):
                continue
            if _suppressed(argument, lines):
                continue
            findings.append(
                Finding(
                    fingerprint=(
                        f"{rel}:stage-user-message:{index}:"
                        f"{ast.dump(argument, include_attributes=False)}"
                    ),
                    display=(
                        f"{rel}:{argument.lineno}: stage_user_message section "
                        "argument is not rendered by wrap"
                    ),
                )
            )
    return findings


def _scan(scope: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in sorted(scope.rglob("*.py")):
        try:
            relative_parts = path.relative_to(scope).parts
        except ValueError:
            continue
        if any(part in EXCLUDED_DIRS for part in relative_parts):
            continue
        rel = _relative(path, scope)
        text, tree = read_and_parse(path, rel)
        lines = text.splitlines()
        findings.extend(_module_interpolations(tree, rel, lines))
        findings.extend(_stage_message_arguments(tree, rel, lines))
    return findings


HEADER = (
    "lint_stage_prompt_frames baseline — prompt section boundaries must be "
    "constructed with defender._untrusted.wrap; the detector is independent of "
    "specific delimiter spellings. Regenerate only for a documented exception: "
    "python scripts/lint/lint_stage_prompt_frames.py --update-baseline."
)


def main(
    argv: list[str],
    *,
    scope: Path = LEARNING,
    baseline_path: Path = BASELINE_PATH,
) -> int:
    try:
        findings = _scan(scope)
    except ScanBlind as exc:
        print(f"lint_stage_prompt_frames: {exc}", file=sys.stderr)
        return 2
    return gate(
        findings,
        baseline_path,
        argv,
        label="lint_stage_prompt_frames",
        header=HEADER,
    )


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
