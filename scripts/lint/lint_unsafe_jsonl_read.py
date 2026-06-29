#!/usr/bin/env python3
"""Unsafe JSONL-read smell — flag hand-rolled per-line ``json.loads`` file readers
under ``defender/`` that bypass the shared tolerant reader.

A JSONL queue (``_pending/findings.jsonl``, ``actor_observations.jsonl``,
``executed_queries.jsonl``, ``lessons_loaded.jsonl`` …) is appended to live and
read back by the off-process drains. An append can be interrupted mid-write, so
the last line is sometimes torn. A reader that re-rolls ::

    for line in path.read_text().splitlines():
        rec = json.loads(line)          # raises JSONDecodeError on a torn line

is BOTH a dedup smell (it copies the parse/skip skeleton) AND a safety bug: a
``json.JSONDecodeError`` is neither ``RunUnprocessable``, ``StageAbort`` nor
``AuthorError``, so it escapes every drain guard and crashes the worker every
tick until the queue is hand-fixed (#446). The fix is to route every file-line
JSON read through the single tolerant reader, ``defender._io.read_jsonl_rows``,
which skips torn/blank lines.

What this flags: a ``for`` loop whose iterable is derived from reading a file
(``<p>.read_text().splitlines()`` / ``.split(...)``, ``open(...)``/``<p>.open()``,
or a name bound to one of those in a ``with``/assignment) whose body calls
``json.loads(...)`` on the loop line (directly or via an intermediate like
``s = line.strip()``).

What it does NOT flag: ``json.loads(path.read_text())`` (a single whole-file
document, not line-delimited) and ``for raw in stdout.splitlines(): json.loads``
(parsing an in-memory subprocess stream, not a file) — neither has the torn-file
failure mode, and the latter cannot use the Path-based shared reader.

The one sanctioned file-line reader is ``read_jsonl_rows`` itself (in
``defender/_io.py``); mark it (and any other deliberate exception) with
``# lint-jsonl-read: ok — <reason>`` on the ``for`` line. Pre-existing sites are
ratcheted via
``lint_unsafe_jsonl_read_baseline.json`` (see scripts/lint/_baseline.py); the
gate fails only on a NEW file+function pair.

Run from repo root:  python scripts/lint/lint_unsafe_jsonl_read.py
Regenerate the baseline:  python scripts/lint/lint_unsafe_jsonl_read.py --update-baseline
Exit 0 = clean (no new sites), 1 = new sites.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

from _baseline import Finding, gate

REPO_ROOT = Path(__file__).resolve().parents[2]
SCOPE = REPO_ROOT / "defender"
BASELINE_PATH = Path(__file__).with_name("lint_unsafe_jsonl_read_baseline.json")

EXCLUDED_DIRS = (".venv", "__pycache__", "run-visualizations", "run-transcripts")

SUPPRESS = "lint-jsonl-read: ok"


def _in_scope(path: Path) -> bool:
    return not any(part in EXCLUDED_DIRS for part in path.parts)


def _is_open_call(node: ast.expr) -> bool:
    """``open(...)`` or ``<expr>.open(...)`` (Path.open) — yields a file handle."""
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if isinstance(func, ast.Name) and func.id == "open":
        return True
    return isinstance(func, ast.Attribute) and func.attr == "open"


def _iterates_file_lines(it: ast.expr, fh_names: set[str]) -> bool:
    """True if ``for _ in <it>`` walks the lines of a file on disk.

    Matches the read-text-and-split idiom, direct file-handle iteration, and a
    name bound to ``open(...)``/``.open()`` earlier in the function. Crucially
    NOT matched: ``<str>.splitlines()`` where the base is a plain value (e.g. a
    subprocess ``stdout`` string), which has no torn-file failure mode.
    """
    # `<expr>.read_text(...).splitlines(...)` or `.split(...)`
    if (
        isinstance(it, ast.Call)
        and isinstance(it.func, ast.Attribute)
        and it.func.attr in ("splitlines", "split")
        and isinstance(it.func.value, ast.Call)
        and isinstance(it.func.value.func, ast.Attribute)
        and it.func.value.func.attr == "read_text"
    ):
        return True
    # `for line in open(p):` / `for line in p.open():`
    if _is_open_call(it):
        return True
    # `with p.open() as fh: for line in fh:` / `fh = open(p); for line in fh:`
    return isinstance(it, ast.Name) and it.id in fh_names


def _filehandle_names(func: ast.AST) -> set[str]:
    """Names bound to a file handle (``open``/``.open``) anywhere in ``func``,
    via a ``with`` item or a plain assignment."""
    names: set[str] = set()
    for node in ast.walk(func):
        if isinstance(node, ast.With):
            for item in node.items:
                if (
                    _is_open_call(item.context_expr)
                    and isinstance(item.optional_vars, ast.Name)
                ):
                    names.add(item.optional_vars.id)
        elif isinstance(node, ast.Assign) and _is_open_call(node.value):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name):
                    names.add(tgt.id)
    return names


def _root_name(expr: ast.expr) -> str | None:
    """The root ``Name`` id of an attribute/call/subscript chain, e.g.
    ``line.strip()`` -> ``line``; ``s`` -> ``s``."""
    cur: ast.expr = expr
    while True:
        if isinstance(cur, ast.Name):
            return cur.id
        if isinstance(cur, ast.Attribute):
            cur = cur.value
        elif isinstance(cur, ast.Call):
            cur = cur.func
        elif isinstance(cur, ast.Subscript):
            cur = cur.value
        else:
            return None


def _is_json_loads(call: ast.Call) -> bool:
    func = call.func
    return (
        isinstance(func, ast.Attribute)
        and func.attr == "loads"
        and isinstance(func.value, ast.Name)
        and func.value.id == "json"
    )


def _loop_targets(target: ast.expr) -> set[str]:
    if isinstance(target, ast.Name):
        return {target.id}
    if isinstance(target, (ast.Tuple, ast.List)):
        return {e.id for e in target.elts if isinstance(e, ast.Name)}
    return set()


def _parses_line_as_json(for_node: ast.For) -> bool:
    """True if the loop body calls ``json.loads`` on the loop line — directly or
    through an intermediate (``s = line.strip(); json.loads(s)``)."""
    derived = _loop_targets(for_node.target)
    if not derived:
        return False
    # Propagate line-derived names through simple assignments (two passes so a
    # one-step chain like `s = line.strip()` is captured regardless of walk order).
    for _ in range(2):
        for node in ast.walk(for_node):
            if (
                isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and _root_name(node.value) in derived
            ):
                derived.add(node.targets[0].id)
    for node in ast.walk(for_node):
        if (
            isinstance(node, ast.Call)
            and _is_json_loads(node)
            and node.args
            and _root_name(node.args[0]) in derived
        ):
            return True
    return False


def _suppressed(for_node: ast.For, lines: list[str]) -> bool:
    start = for_node.lineno
    end = getattr(for_node, "end_lineno", start) or start
    return any(
        SUPPRESS in lines[i - 1] for i in range(start, end + 1) if 0 < i <= len(lines)
    )


def _scan_file(rel: str, tree: ast.AST, lines: list[str]) -> list[Finding]:
    findings: list[Finding] = []

    def visit(node: ast.AST, func_name: str, fh_names: set[str]) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            func_name = node.name
            fh_names = _filehandle_names(node)
        if (
            isinstance(node, ast.For)
            and _iterates_file_lines(node.iter, fh_names)
            and _parses_line_as_json(node)
            and not _suppressed(node, lines)
        ):
            findings.append(
                Finding(
                    fingerprint=f"{rel}:{func_name}",
                    display=(
                        f"{rel}:{node.lineno}: hand-rolled json.loads over file "
                        f"lines in {func_name}() — use read_jsonl_rows"
                    ),
                )
            )
        for child in ast.iter_child_nodes(node):
            visit(child, func_name, fh_names)

    visit(tree, "<module>", set())
    return findings


def _scan() -> list[Finding]:
    findings: list[Finding] = []
    for path in sorted(SCOPE.rglob("*.py")):
        if not _in_scope(path):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(text)
        except (OSError, SyntaxError):
            continue
        rel = path.relative_to(REPO_ROOT).as_posix()
        findings.extend(_scan_file(rel, tree, text.splitlines()))
    return findings


HEADER = (
    "lint_unsafe_jsonl_read baseline — hand-rolled per-line json.loads file "
    "readers under defender/ that bypass _io.read_jsonl_rows (a "
    "dedup smell + the #446 torn-line crash class). Fingerprint is file:function "
    "(no line number). CI fails on a file:function absent here. Regenerate: "
    "python scripts/lint/lint_unsafe_jsonl_read.py --update-baseline. Annotate "
    'intentional entries; "" = un-triaged debt to route through read_jsonl_rows.'
)


def main(argv: list[str]) -> int:
    if not SCOPE.is_dir():
        print(f"defender/ not found at {SCOPE}", file=sys.stderr)
        return 2
    findings = _scan()
    print(
        "Route file-line JSON reads through defender._io.read_jsonl_rows "
        "(tolerant of torn/blank lines); a bare json.loads(line) crashes the "
        "drains on a torn append (#446)."
    )
    print("Mark the sanctioned reader with `# lint-jsonl-read: ok — <reason>`.")
    return gate(
        findings, BASELINE_PATH, argv,
        label="lint_unsafe_jsonl_read", header=HEADER,
    )


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
