#!/usr/bin/env python3
"""Unsafe JSONL-I/O smell: flag hand-rolled per-line JSONL reads/appends under ``defender/``
that bypass the shared ``defender._io`` helpers.

JSONL queues (``_pending/findings.jsonl``, ``executed_queries.jsonl`` …) are appended to live
and read back by off-process drains. Two hand-rolled shapes recur:

READ — a torn last line crashes the drain ::

    for line in path.read_text().splitlines():
        rec = json.loads(line)          # raises JSONDecodeError on a torn line

``json.JSONDecodeError`` is not ``RunUnprocessable``, ``StageAbort`` or ``AuthorError``, so it
escapes every drain guard and crashes the worker every tick until the queue is hand-fixed.
Route reads through ``defender._io.read_jsonl_rows``, which skips torn/blank lines.

APPEND — ``append_jsonl``'s body inlined ::

    with path.open("a") as fh:
        fh.write(json.dumps(row) + "\n")

Copies drift from the helper (mkdir-on-demand, empty-rows no-op). Route appends through
``defender._io.append_jsonl``.

The READ check flags a ``for`` loop whose iterable reads a file
(``<p>.read_text().splitlines()`` / ``.split(...)``, ``open(...)``/``<p>.open()``, or a name
bound to one of those) whose body calls ``json.loads(...)`` on the loop line, directly or via
an intermediate like ``s = line.strip()``.

``json`` calls and openers are identified by resolved origin (``_astlib``), so aliases and
from-imports count, and the opener's mode comes from the callee's own positional slot
(``codecs.open(p, "a")`` is path-first).

The APPEND check flags ``<fh>.write(json.dumps(...) + "\n")`` where ``<fh>`` is a local
handle opened in append mode in the same function. This targets the ``append_jsonl`` drift
while skipping long-lived streaming writers held as instance state and atomic whole-file
rewrites (a separate concern, not gated here).

Neither check flags ``json.loads(path.read_text())`` (one whole-file document),
``for raw in stdout.splitlines(): json.loads`` (an in-memory stream), or a single-object
``fh.write(json.dumps(obj, indent=2))`` with no per-line newline.

The sanctioned reader/appender (``read_jsonl_rows``/``append_jsonl`` in ``defender/_io.py``)
and any other deliberate exception are marked with ``# lint-jsonl-io: ok — <reason>`` on the
``for``/``write`` line. Pre-existing sites are ratcheted via
``lint_unsafe_jsonl_io_baseline.json`` (see scripts/lint/_baseline.py); the gate fails only
on a new file+function pair.

Run from repo root:  python scripts/lint/lint_unsafe_jsonl_io.py
Regenerate the baseline:  python scripts/lint/lint_unsafe_jsonl_io.py --update-baseline
Exit 0 = clean (no new sites), 1 = new sites.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

from _astlib import (
    ScanBlind,
    read_and_parse,
    ModuleEnv,
    callee,
    module_env,
    open_mode,
    opener_slot,
    root_name,
    str_value,
)
from _baseline import Finding, gate

REPO_ROOT = Path(__file__).resolve().parents[2]
SCOPE = REPO_ROOT / "defender"
BASELINE_PATH = Path(__file__).with_name("lint_unsafe_jsonl_io_baseline.json")

EXCLUDED_DIRS = (".venv", "__pycache__")

# The legacy read-only marker is still accepted.
SUPPRESS_MARKERS = ("lint-jsonl-io: ok", "lint-jsonl-read: ok")


def _in_scope(path: Path) -> bool:
    return not any(part in EXCLUDED_DIRS for part in path.parts)


def _is_test_module(rel: str) -> bool:
    """A ``tests/`` dir or a flat ``test_*.py`` / ``*_test.py`` / ``conftest.py``. The
    append check skips these: fixtures must sometimes hand-roll deliberately torn/non-JSON
    lines to exercise the reader's tolerance. The read check still covers them — a torn-line
    crash is a real bug anywhere a live file is read."""
    p = Path(rel)
    return (
        "tests" in p.parts
        or p.name == "conftest.py"
        or (p.name.startswith("test_") and p.suffix == ".py")
        or p.name.endswith("_test.py")
    )


def _is_open_call(node: ast.expr, env: ModuleEnv) -> bool:
    """``open(...)`` / ``io.open(...)`` / ``<p>.open(...)`` — anything that yields a file
    handle, identified by resolved origin (``_astlib.opener_slot``) so the mode is read from
    the callee's real slot.
    """
    return isinstance(node, ast.Call) and opener_slot(node, env) is not None


def _iterates_file_lines(it: ast.expr, fh_names: set[str], env: ModuleEnv) -> bool:
    """True if ``for _ in <it>`` walks the lines of a file on disk.

    Matches the read-text-and-split idiom, direct file-handle iteration, and a name bound to
    ``open(...)``/``.open()`` in the function. Not ``<str>.splitlines()`` on a plain value
    (e.g. subprocess ``stdout``), which has no torn-file failure mode.
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
    if _is_open_call(it, env):
        return True
    # `with p.open() as fh: for line in fh:` / `fh = open(p); for line in fh:`
    return isinstance(it, ast.Name) and it.id in fh_names


def _filehandle_names(func: ast.AST, env: ModuleEnv, *, append_only: bool = False) -> set[str]:
    """Names bound to a file handle anywhere in ``func``, via a ``with`` item or a plain
    assignment. With ``append_only``, only handles whose resolved mode contains ``a``."""
    names: set[str] = set()

    def _accept(call: ast.expr) -> bool:
        if not _is_open_call(call, env):
            return False
        if not append_only:
            return True
        mode = open_mode(call, env)  # type: ignore[arg-type]
        return mode is not None and "a" in mode

    for node in ast.walk(func):
        if isinstance(node, ast.With):
            for item in node.items:
                if _accept(item.context_expr) and isinstance(item.optional_vars, ast.Name):
                    names.add(item.optional_vars.id)
        elif isinstance(node, ast.Assign) and _accept(node.value):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name):
                    names.add(tgt.id)
    return names


def _is_json_call(call: ast.AST, attr: str, env: ModuleEnv) -> bool:
    """True if ``call`` lands in ``json.<attr>``, however it was spelled."""
    return isinstance(call, ast.Call) and callee(call, env) == f"json.{attr}"


def _loop_targets(target: ast.expr) -> set[str]:
    if isinstance(target, ast.Name):
        return {target.id}
    if isinstance(target, (ast.Tuple, ast.List)):
        return {e.id for e in target.elts if isinstance(e, ast.Name)}
    return set()


def _parses_line_as_json(for_node: ast.For, env: ModuleEnv) -> bool:
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
                and root_name(node.value) in derived
            ):
                derived.add(node.targets[0].id)
    for node in ast.walk(for_node):
        if (
            _is_json_call(node, "loads", env)
            and node.args
            and root_name(node.args[0]) in derived
        ):
            return True
    return False


def _writes_json_line(call: ast.Call, append_fh_names: set[str], env: ModuleEnv) -> bool:
    """True if ``call`` is ``<fh>.write(<expr containing json.dumps(...) and a
    newline literal>)`` on a local append-mode handle — the ``append_jsonl`` body."""
    func = call.func
    if not (
        isinstance(func, ast.Attribute)
        and func.attr == "write"
        and isinstance(func.value, ast.Name)
        and func.value.id in append_fh_names
        and call.args
    ):
        return False
    has_dumps = has_newline = False
    for node in ast.walk(call.args[0]):
        if _is_json_call(node, "dumps", env):
            has_dumps = True
        elif isinstance(node, (ast.Constant, ast.Name)):
            # Through module consts too, so hoisting `NEWLINE = "\n"` does not evade the check.
            value = str_value(node, env)
            if value is not None and "\n" in value:
                has_newline = True
    return has_dumps and has_newline


def _suppressed(node: ast.AST, lines: list[str]) -> bool:
    start = node.lineno
    end = getattr(node, "end_lineno", start) or start
    return any(
        any(m in lines[i - 1] for m in SUPPRESS_MARKERS)
        for i in range(start, end + 1)
        if 0 < i <= len(lines)
    )


def _scan_file(rel: str, tree: ast.AST, lines: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()  # one finding per (fingerprint) per file
    is_test = _is_test_module(rel)  # append check is skipped for test fixtures
    env = module_env(tree)

    def report(fingerprint: str, finding: Finding) -> None:
        if fingerprint not in seen:
            seen.add(fingerprint)
            findings.append(finding)

    def visit(node: ast.AST, func_name: str, fh_names: set[str], append_fh_names: set[str]) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            func_name = node.name
            fh_names = _filehandle_names(node, env)
            append_fh_names = _filehandle_names(node, env, append_only=True)
        if (
            isinstance(node, ast.For)
            and _iterates_file_lines(node.iter, fh_names, env)
            and _parses_line_as_json(node, env)
            and not _suppressed(node, lines)
        ):
            report(
                f"{rel}:{func_name}",
                Finding(
                    fingerprint=f"{rel}:{func_name}",
                    display=(
                        f"{rel}:{node.lineno}: hand-rolled json.loads over file "
                        f"lines in {func_name}() — use read_jsonl_rows"
                    ),
                ),
            )
        if (
            not is_test
            and isinstance(node, ast.Call)
            and _writes_json_line(node, append_fh_names, env)
            and not _suppressed(node, lines)
        ):
            report(
                f"{rel}:{func_name}:append",
                Finding(
                    fingerprint=f"{rel}:{func_name}:append",
                    display=(
                        f"{rel}:{node.lineno}: hand-rolled json.dumps append to a "
                        f"file in {func_name}() — use append_jsonl"
                    ),
                ),
            )
        for child in ast.iter_child_nodes(node):
            visit(child, func_name, fh_names, append_fh_names)

    visit(tree, "<module>", set(), set())
    return findings


def _scan(root: Path) -> list[Finding]:
    """Findings under ``root``, fingerprints relative to it (drivable on a tmp tree)."""
    findings: list[Finding] = []
    for path in sorted(root.rglob("*.py")):
        if not _in_scope(path):
            continue
        text, tree = read_and_parse(path, path.relative_to(root).as_posix())
        rel = path.relative_to(root).as_posix()
        findings.extend(_scan_file(rel, tree, text.splitlines()))
    return findings


HEADER = (
    "lint_unsafe_jsonl_io baseline — hand-rolled per-line json.loads readers and "
    "json.dumps+newline appends under defender/ that bypass _io.read_jsonl_rows / "
    "_io.append_jsonl (a dedup smell + the #446 torn-line read crash). Fingerprint "
    "is file:function (':append' suffix for the append check; no line number), file "
    "relative to the scan scope. CI fails on a fingerprint absent here. Regenerate: "
    "python scripts/lint/lint_unsafe_jsonl_io.py --update-baseline. Annotate "
    'intentional entries; "" = un-triaged debt to route through the shared _io helpers.'
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
    # An unreadable file never entered the corpus. Exit 2: the gate could not run, which is
    # not "clean".
    try:
        findings = _scan(root)
    except ScanBlind as exc:
        print(f"lint_unsafe_jsonl_io: {exc}", file=sys.stderr)
        return 2
    print(
        "Route file-line JSON reads through defender._io.read_jsonl_rows (tolerant "
        "of torn/blank lines; a bare json.loads(line) crashes the drains on a torn "
        "append, #446) and JSONL appends through defender._io.append_jsonl."
    )
    print("Mark a sanctioned reader/appender with `# lint-jsonl-io: ok — <reason>`.")
    return gate(
        findings, baseline, args,
        label="lint_unsafe_jsonl_io", header=HEADER,
    )


if __name__ == "__main__":
    sys.exit(main())
