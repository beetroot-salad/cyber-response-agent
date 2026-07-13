#!/usr/bin/env python3
"""Unsafe JSONL-I/O smell — flag hand-rolled per-line JSONL reads/appends under
``defender/`` that bypass the shared ``defender._io`` helpers.

A JSONL queue (``_pending/findings.jsonl``, ``actor_observations.jsonl``,
``executed_queries.jsonl``, ``lessons_loaded.jsonl`` …) is appended to live and
read back by the off-process drains. Two hand-rolled shapes recur, each a dedup
smell and (on the read side) a safety bug:

READ — a torn last line crashes the drain ::

    for line in path.read_text().splitlines():
        rec = json.loads(line)          # raises JSONDecodeError on a torn line

A ``json.JSONDecodeError`` is neither ``RunUnprocessable``, ``StageAbort`` nor
``AuthorError``, so it escapes every drain guard and crashes the worker every
tick until the queue is hand-fixed (#446). Route reads through the single
tolerant reader ``defender._io.read_jsonl_rows``, which skips torn/blank lines.

APPEND — the json.dumps+newline write skeleton copied across modules ::

    with path.open("a") as fh:
        fh.write(json.dumps(row) + "\n")

This is ``append_jsonl``'s body inlined; a fourth/fifth copy drifts from the
helper (mkdir-on-demand, empty-rows no-op). Route appends through
``defender._io.append_jsonl``. (#447 hoisted both helpers into ``defender/_io.py``.)

What the READ check flags: a ``for`` loop whose iterable is derived from reading a
file (``<p>.read_text().splitlines()`` / ``.split(...)``, ``open(...)``/``<p>.open()``,
or a name bound to one of those in a ``with``/assignment) whose body calls
``json.loads(...)`` on the loop line (directly or via an intermediate like
``s = line.strip()``).

The ``json`` call is identified by its RESOLVED ORIGIN (``scripts/lint/_astlib.py``), not
by the spelling ``json.``: ``import json as j`` and ``from json import loads`` are the same
case as the dotted form. Before #602 the check required ``call.func.value.id == "json"``,
so either of those made the gate blind to the very idiom it exists to stop.

What the APPEND check flags: ``<fh>.write(json.dumps(...) + "\n")`` where ``<fh>``
is a local handle opened in *append* mode (``open(p, "a")`` / ``p.open("a")``) in
the same function. Restricting to append-mode local handles is deliberate: it
targets exactly the ``append_jsonl`` drift and skips both long-lived streaming
writers that hold an open handle as instance state (``observe.py``'s
``self._fh``, a ``"w"`` log stream) and atomic whole-file rewrites (the
``write_atomic`` / ``tmp.write_text``+``os.replace`` pattern, a separate
non-JSONL concern that is NOT gated here).

What neither check flags: ``json.loads(path.read_text())`` (a single whole-file
document, not line-delimited); ``for raw in stdout.splitlines(): json.loads``
(parsing an in-memory subprocess stream, not a file); and a single-object
``fh.write(json.dumps(obj, indent=2))`` with no per-line newline.

The one sanctioned reader/appender are ``read_jsonl_rows``/``append_jsonl``
themselves (in ``defender/_io.py``); mark them (and any other deliberate
exception) with ``# lint-jsonl-io: ok — <reason>`` on the ``for``/``write`` line.
Pre-existing sites are ratcheted via ``lint_unsafe_jsonl_io_baseline.json`` (see
scripts/lint/_baseline.py); the gate fails only on a NEW file+function pair.

Run from repo root:  python scripts/lint/lint_unsafe_jsonl_io.py
Regenerate the baseline:  python scripts/lint/lint_unsafe_jsonl_io.py --update-baseline
Exit 0 = clean (no new sites), 1 = new sites.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

from _astlib import ModuleEnv, callee, module_env, root_name, str_value
from _baseline import Finding, gate

REPO_ROOT = Path(__file__).resolve().parents[2]
SCOPE = REPO_ROOT / "defender"
BASELINE_PATH = Path(__file__).with_name("lint_unsafe_jsonl_io_baseline.json")

EXCLUDED_DIRS = (".venv", "__pycache__", "run-visualizations", "run-transcripts")

# Accept the legacy read-only marker too, so any pre-#447 suppression keeps working.
SUPPRESS_MARKERS = ("lint-jsonl-io: ok", "lint-jsonl-read: ok")


def _in_scope(path: Path) -> bool:
    return not any(part in EXCLUDED_DIRS for part in path.parts)


def _is_test_module(rel: str) -> bool:
    """A ``tests/`` dir or a flat ``test_*.py`` / ``*_test.py`` / ``conftest.py`` —
    the test-fixture category the duplicate-helper gate also exempts. The APPEND
    check skips these: a fixture re-implementing the json.dumps+newline write is by
    design, and some MUST hand-roll to write deliberately-torn/non-json lines that
    exercise the reader's tolerance (``append_jsonl`` only emits valid JSON). The
    READ check still covers them — a torn-line crash (#446) is a real bug anywhere
    a live file is read, including a replay harness."""
    p = Path(rel)
    return (
        "tests" in p.parts
        or p.name == "conftest.py"
        or (p.name.startswith("test_") and p.suffix == ".py")
        or p.name.endswith("_test.py")
    )


def _is_open_call(node: ast.expr) -> bool:
    """``open(...)`` or ``<expr>.open(...)`` (Path.open) — yields a file handle."""
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if isinstance(func, ast.Name) and func.id == "open":
        return True
    return isinstance(func, ast.Attribute) and func.attr == "open"


def _open_mode(call: ast.Call) -> str | None:
    """The mode string of an ``open(...)``/``.open(...)`` call, or None if not a
    string literal. ``open(p, "a")`` reads the 2nd positional; ``p.open("a")``
    the 1st; both honor a ``mode=`` keyword. A mode-less open defaults to read."""
    func = call.func
    mode_arg: ast.expr | None = None
    if isinstance(func, ast.Name) and func.id == "open":
        mode_arg = call.args[1] if len(call.args) >= 2 else None
    elif isinstance(func, ast.Attribute) and func.attr == "open":
        mode_arg = call.args[0] if call.args else None
    if mode_arg is None:
        for kw in call.keywords:
            if kw.arg == "mode":
                mode_arg = kw.value
                break
    if mode_arg is None:
        return "r"  # open default
    return mode_arg.value if isinstance(mode_arg, ast.Constant) and isinstance(mode_arg.value, str) else None


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


def _filehandle_names(func: ast.AST, *, append_only: bool = False) -> set[str]:
    """Names bound to a file handle (``open``/``.open``) anywhere in ``func``,
    via a ``with`` item or a plain assignment. With ``append_only``, restrict to
    handles opened in append mode (mode string containing ``a``)."""
    names: set[str] = set()

    def _accept(call: ast.expr) -> bool:
        if not _is_open_call(call):
            return False
        if not append_only:
            return True
        mode = _open_mode(call)  # type: ignore[arg-type]
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
    """True if ``call`` lands in ``json.<attr>`` — however it was SPELLED.

    This used to require ``call.func.value.id == "json"``, so ``import json as j`` or
    ``from json import loads`` made the whole gate blind to the very idiom it exists to
    stop (#602). Resolving the callee makes every spelling one case."""
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
            # Through module consts too: hoisting `NEWLINE = "\n"` is good style and
            # must not double as the way to evade the append check.
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
            fh_names = _filehandle_names(node)
            append_fh_names = _filehandle_names(node, append_only=True)
        if (
            isinstance(node, ast.For)
            and _iterates_file_lines(node.iter, fh_names)
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
    """Findings under ``root``, fingerprints relative to it — so the gate is
    drivable on an injected tmp tree, not just the repo checkout."""
    findings: list[Finding] = []
    for path in sorted(root.rglob("*.py")):
        if not _in_scope(path):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(text)
        except (OSError, SyntaxError):
            continue
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
    findings = _scan(root)
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
