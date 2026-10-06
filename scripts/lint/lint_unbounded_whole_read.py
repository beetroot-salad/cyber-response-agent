#!/usr/bin/env python3
"""Unbounded whole-file read: flag a read under ``defender/`` that takes a whole file into
memory by path with no size limit (#1188).

A whole-file read sizes its buffer from the file. A box-planted sparse file (``truncate -s
1T``) once made that a ``MemoryError``, which is not an ``OSError`` and so skipped every
reader's fail-safe path and crashed the host process. The writer side now holds: every box
starts with ``--ulimit fsize=READ_LIMIT`` (#1198), so no file a box process writes exceeds
``defender._io.READ_LIMIT``. That bound covers box writes only. Host processes write files
too (tool writes for the model, logs, queues, alert copies), and a new reader of a new tree
inherits whatever bound that tree's writers have. This gate makes each such read a
deliberate, reasoned choice; it does not force migration to ``_io``.

What it flags, under ``defender/`` production code (tests and the root ``_io.py`` excluded):

- ``read_text`` / ``read_bytes`` — ``<x>.read_text(...)`` / ``<x>.read_bytes(...)``, by
  attribute name (any receiver), and the class-qualified ``Path.read_text(p)`` form,
  resolved through ``_astlib`` so ``pathlib.Path.read_bytes(p)`` and an aliased import count.
- ``uncapped`` — a call to one of ``_io``'s limit-taking readers whose ``limit=`` turns the
  cap off or is something this gate cannot check. The reader set is every top-level def in
  ``<root>/_io.py`` with a ``limit`` parameter, and the cap is that file's ``READ_LIMIT``:
  both are read from the source, so a new reader is covered without editing this gate. A
  call matches by resolved callee (``defender._io.<reader>``, aliases included) or, when the
  callee does not resolve, by attribute name, so an injected ``io: Any = _real_io`` module
  is caught too. Silent: no ``limit=``, an int literal ``<= READ_LIMIT``, or a name whose
  origin is ``defender._io.READ_LIMIT``. Everything else fires (``None``, a bigger literal,
  a variable, a module constant, arithmetic): ``_astlib`` keeps only str constants, and
  failing safe is cheaper than evaluating ints.

And it fails, unbaselinably, on **default drift**: an ``_io`` reader whose ``limit`` default
is anything but the bare name ``READ_LIMIT``. ``_io.py`` is outside the scan, so flipping a
default to ``None`` would otherwise uncap every caller with no finding. A required ``limit``
(no default) is not drift.

What it does not flag: reads through an open handle (``f.read()``, ``json.load(f)``,
``open(p).read()``) and ``sys.stdin`` — ``_astlib`` has no handle tracking, and none reads a
path today; a ``limit`` passed through ``**kwargs``; a second identical read in a function
that already has one (the fingerprint has no line number, so the two share an entry).

Fingerprint: ``defender/<file>:<function>:<kind>:<detail>``. ``<function>`` is the innermost
enclosing def (``<module>`` at top level). ``<detail>`` is ``ast.unparse`` of the receiver for
the attribute form, of the first argument for the class-qualified form (the receiver there is
the class), and the reader's name in ``_io`` for ``uncapped``.

Ratcheted via ``lint_unbounded_whole_read_baseline.json`` with ``require_reasons``: every
entry says who writes the file and what bounds it. "Bounded at the writer by the box fsize
limit" holds only for a file every writer of which is a box process; a run-dir file a host
tool also writes names that writer's bound as well.

Run from repo root:  python scripts/lint/lint_unbounded_whole_read.py
Regenerate the baseline:  python scripts/lint/lint_unbounded_whole_read.py --update-baseline
Exit 0 = clean, 1 = new finding / un-reasoned entry / ``_io`` default drift, 2 = scan blind.
"""
from __future__ import annotations

import ast
import operator
import sys
from collections.abc import Callable
from pathlib import Path

from _astlib import ModuleEnv, ScanBlind, callee, module_env, origin, read_and_parse
from _baseline import Finding, gate
from lint_run_records import module_and_package
from lint_unpinned_text_io import _is_test_module

REPO_ROOT = Path(__file__).resolve().parents[2]
SCOPE = REPO_ROOT / "defender"
BASELINE_PATH = Path(__file__).with_name("lint_unbounded_whole_read_baseline.json")

EXCLUDED_DIRS = (".venv", "__pycache__")
#: The shared bounded read step, relative to the scan root. Excluded from the scan, and the
#: source of the reader set and the cap.
IO_REL = "_io.py"
IO_MODULE = "defender._io"
CAP_NAME = "READ_LIMIT"

_PATH_READS = ("read_text", "read_bytes")
_PATH_CLASS = "pathlib.Path"

_BINOPS: dict[type[ast.operator], Callable[[int, int], int]] = {
    ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
    ast.FloorDiv: operator.floordiv, ast.Pow: operator.pow, ast.LShift: operator.lshift,
}


def _int_expr(node: ast.expr) -> int | None:
    """An int built from literals and ``+ - * // ** <<`` (``64 * 1024 * 1024``), else None."""
    if isinstance(node, ast.Constant):
        value = node.value
        return value if isinstance(value, int) and not isinstance(value, bool) else None
    if isinstance(node, ast.BinOp) and (op := _BINOPS.get(type(node.op))):
        left, right = _int_expr(node.left), _int_expr(node.right)
        return None if left is None or right is None else op(left, right)
    return None


def _limit_params(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[bool, ast.expr | None]:
    """(has a ``limit`` parameter, its default or None) — positional or keyword-only."""
    a = fn.args
    positional = [*a.posonlyargs, *a.args]
    pos_defaults: list[ast.expr | None] = (
        [None] * (len(positional) - len(a.defaults)) + list(a.defaults))
    pairs = [*zip(positional, pos_defaults), *zip(a.kwonlyargs, a.kw_defaults)]
    for arg, default in pairs:
        if arg.arg == "limit":
            return True, default
    return False, None


def _io_defs(io_path: Path) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
    _, tree = read_and_parse(io_path, IO_REL)
    return [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]


def _io_contract(io_path: Path) -> tuple[frozenset[str], int]:
    """The limit-taking reader names and the evaluated ``READ_LIMIT`` of ``io_path``."""
    if not io_path.is_file():
        raise ScanBlind(
            f"{IO_REL}: not found at {io_path} — the gate reads the limit-taking reader set and "
            f"{CAP_NAME} from it, so without it an uncapped read cannot be seen."
        )
    _, tree = read_and_parse(io_path, IO_REL)
    cap: int | None = None
    for node in tree.body:
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name) and node.targets[0].id == CAP_NAME):
            cap = _int_expr(node.value)
    if cap is None:
        raise ScanBlind(f"{IO_REL}: no int-valued top-level `{CAP_NAME} = ...` to compare against")
    readers = frozenset(fn.name for fn in _io_defs(io_path) if _limit_params(fn)[0])
    return readers, cap


def _drifted_defaults(io_path: Path) -> list[str]:
    """``_io`` readers whose ``limit`` default is not the bare name ``READ_LIMIT``."""
    drifted = []
    for fn in _io_defs(io_path):
        has, default = _limit_params(fn)
        if has and default is not None and not (
                isinstance(default, ast.Name) and default.id == CAP_NAME):
            drifted.append(fn.name)
    return drifted


def _in_scope(rel: str) -> bool:
    return not any(part in EXCLUDED_DIRS for part in Path(rel).parts)


def _path_read(call: ast.Call, env: ModuleEnv) -> tuple[str, str] | None:
    """(kind, detail) for a direct ``read_text``/``read_bytes``, else None."""
    func = call.func
    if not isinstance(func, ast.Attribute) or func.attr not in _PATH_READS:
        return None
    if origin(func.value, env) == _PATH_CLASS:
        # `Path.read_text(p)`: the receiver is the class, the file is the first argument.
        return (func.attr, ast.unparse(call.args[0])) if call.args else None
    return func.attr, ast.unparse(func.value)


def _reader_of(call: ast.Call, env: ModuleEnv, readers: frozenset[str]) -> str | None:
    """The ``_io`` reader this call reaches, by resolved callee or, unresolved, attribute name."""
    resolved = callee(call, env)
    if resolved is not None:
        module, _, name = resolved.rpartition(".")
        return name if module == IO_MODULE and name in readers else None
    func = call.func
    if isinstance(func, ast.Attribute) and func.attr in readers:
        return func.attr
    return None


def _cap_checked(value: ast.expr, env: ModuleEnv, cap: int) -> bool:
    """Is this ``limit=`` value one the gate can show is at most the cap?"""
    if isinstance(value, ast.Constant):
        number = _int_expr(value)
        return number is not None and number <= cap
    return origin(value, env) == f"{IO_MODULE}.{CAP_NAME}"


def _uncapped(call: ast.Call, env: ModuleEnv, readers: frozenset[str], cap: int) -> str | None:
    reader = _reader_of(call, env, readers)
    if reader is None:
        return None
    limit = next((kw.value for kw in call.keywords if kw.arg == "limit"), None)
    if limit is None or _cap_checked(limit, env, cap):
        return None
    return reader


_ADVICE = {
    "read_text": "whole-file read_text with no size limit",
    "read_bytes": "whole-file read_bytes with no size limit",
    "uncapped": "an _io reader called with its cap off or unverifiable",
}


def _scan_file(rel: str, tree: ast.Module, readers: frozenset[str], cap: int) -> list[Finding]:
    module, package = module_and_package(rel)
    env = module_env(tree, module=module, package=package)
    findings: list[Finding] = []
    seen: set[str] = set()

    def visit(node: ast.AST, func_name: str) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            func_name = node.name
        if isinstance(node, ast.Call):
            hit = _path_read(node, env)
            if hit is None and (reader := _uncapped(node, env, readers, cap)):
                hit = ("uncapped", reader)
            if hit is not None:
                kind, detail = hit
                fingerprint = f"{rel}:{func_name}:{kind}:{detail}"
                if fingerprint not in seen:
                    seen.add(fingerprint)
                    findings.append(Finding(
                        fingerprint=fingerprint,
                        display=f"{rel}:{node.lineno}: {_ADVICE[kind]} — {detail} "
                                f"(in {func_name}())",
                    ))
        for child in ast.iter_child_nodes(node):
            visit(child, func_name)

    visit(tree, "<module>")
    return findings


def _scan(root: Path) -> list[Finding]:
    """Findings under ``root``, fingerprints relative to it (drivable on a tmp tree)."""
    readers, cap = _io_contract(root / IO_REL)
    findings: list[Finding] = []
    for path in sorted(root.rglob("*.py")):
        rel = path.relative_to(root).as_posix()
        if rel == IO_REL or not _in_scope(rel) or _is_test_module(rel):
            continue
        _, tree = read_and_parse(path, rel)
        findings.extend(_scan_file(rel, tree, readers, cap))
    return findings


HEADER = (
    "lint_unbounded_whole_read baseline — whole-file reads by path with no size limit in "
    "defender/ production code (#1188). Fingerprint is defender/<file>:<function>:<kind>:"
    "<detail> (kind read_text|read_bytes|uncapped; detail = receiver, the class-qualified "
    "form's first argument, or the _io reader's name). Every entry needs a reason saying who "
    "writes the file and what bounds it; 'bounded at the writer by the box fsize limit' only "
    "when every writer is a box process. Regenerate: python "
    "scripts/lint/lint_unbounded_whole_read.py --update-baseline, then annotate."
)


def main(
    argv: list[str] | None = None,
    *,
    scope: Path | None = None,
    baseline_path: Path | None = None,
) -> int:
    # DI/test seams: the tests drive injected tmp trees and baselines.
    args = sys.argv[1:] if argv is None else argv
    baseline = BASELINE_PATH if baseline_path is None else baseline_path
    root = SCOPE if scope is None else scope
    if not root.is_dir():
        print(f"scan scope not found at {root}", file=sys.stderr)
        return 2
    # An injected scope scans unprefixed (the tests' fingerprints); the real run prefixes
    # the repo-relative root.
    prefix = "" if scope is not None else f"{root.relative_to(REPO_ROOT).as_posix()}/"
    try:
        findings = [
            Finding(fingerprint=prefix + f.fingerprint, display=prefix + f.display)
            for f in _scan(root)
        ]
        drifted = _drifted_defaults(root / IO_REL)
    except ScanBlind as exc:
        print(f"lint_unbounded_whole_read: {exc}", file=sys.stderr)
        return 2
    print(
        "Read a whole file through defender._io (read_text_utf8 / read_plain / read_guarded …, "
        "capped at READ_LIMIT), or baseline the site with who writes the file and what bounds it."
    )
    rc = gate(
        findings, baseline, args,
        label="lint_unbounded_whole_read", header=HEADER, require_reasons=True,
    )
    if drifted:
        print(
            f"\n[lint_unbounded_whole_read] _io reader(s) whose `limit` default is not "
            f"{CAP_NAME}: {', '.join(drifted)} — that uncaps every caller at once and cannot "
            "be baselined. Restore the default."
        )
        return 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
