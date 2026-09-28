"""#1133 D6 — the census: every write into an episode tree goes through the `Episode` handle,
and the handle writes only through the rooted core (O1).

An AST scan of the modules D6 names collects every call from D6's pinned vocabulary:

* the path seams `write_guarded`, `read_guarded`, `read_bytes_guarded`, `read_plain`,
  `read_plain_bytes`, `locked_for_rewrite`, `guarded_mkdir`, `open_guarded`, `write_atomic`,
  `append_jsonl`, and `stage_trace_path` — called bare, through an `as` alias, or as an
  attribute of any receiver (`_io.write_guarded`);
* `os.open`, `os.unlink`, `os.remove`, `os.rename`, `os.replace` (through any alias of `os`);
* the attribute calls `.open`, `.mkdir`, `.write_text`, `.write_bytes`, `.unlink`, `.rmdir`,
  `.touch`, on any receiver;
* `shutil.<anything>`.

Each hit is keyed `(module, enclosing function, callee)`, never by line: the module relative to
the `defender` package, dotted; the enclosing `def`s (and classes) joined with `.`, or
`<module>`; the callee as spelled above (`os.unlink`, `.mkdir`, `shutil.copy2`,
`write_guarded`). The collected set must EQUAL D6's residue: the queue writer (N-d), the
archive's copy lane (N-a), the review's scratch ledger and its temp-dir cleanup. A residue
entry the final tree no longer has is removed from `RESIDUE`, never kept.

A second scan holds `defender/_episode_handle.py` to D1: it calls no vocabulary entry, no raw
`os` / `shutil` / builtin `open`, no `Path` I/O method, and no `_io` function but the rooted
ones — and it does call `rooted_read`, `rooted_write`, `rooted_mkdir` and `rooted_unlink`.

A module that is missing or does not parse fails the scan.

Red before #1133: the migrated modules still make the path-seam and raw calls the handle
replaces, and `_episode_handle.py` does not exist.
"""
from __future__ import annotations

import ast
import inspect
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import pytest

from defender import _io

#: The `defender` package's own directory (a namespace package: located through a module in it).
PACKAGE = Path(_io.__file__).resolve().parent

#: D6's module list.
MODULES = (
    "learning/branch/cli.py",
    "learning/branch/staging.py",
    "learning/branch/timing.py",
    "learning/branch/archive.py",
    "learning/branch/capture.py",
    "learning/branch/ledger.py",
    "learning/branch/review.py",
    "learning/judge/__init__.py",
    "learning/judge/enqueue.py",
    "runtime/branch/_family.py",
    "scripts/visualize/visualize_episode.py",
)

#: D6's pinned vocabulary.
PATH_SEAMS = frozenset({
    "write_guarded", "read_guarded", "read_bytes_guarded", "read_plain", "read_plain_bytes",
    "locked_for_rewrite", "guarded_mkdir", "open_guarded", "write_atomic", "append_jsonl",
    "stage_trace_path",
})
RAW_OS = frozenset({"open", "unlink", "remove", "rename", "replace"})
_RAW_OS_ORIGINS = frozenset(f"os.{op}" for op in RAW_OS)
ATTR_CALLS = frozenset({"open", "mkdir", "write_text", "write_bytes", "unlink", "rmdir", "touch"})

#: D6's residue, exactly.
RESIDUE = frozenset({
    # The queue writer (N-d: learning state, #1134/#1135).
    ("learning.judge.enqueue", "_append_validated_rows", "guarded_mkdir"),
    ("learning.judge.enqueue", "_append_validated_rows", ".open"),
    ("learning.judge.enqueue", "_append_validated_rows", "write_guarded"),
    # The archive's copy lane (N-a).
    ("learning.branch.archive", "_screen_destinations", ".unlink"),
    ("learning.branch.archive", "archive_episode", "shutil.copy2"),
    ("learning.branch.archive", "archive_episode", "shutil.copytree"),
    # The review's scratch ledger, a fresh system temp tree, and its cleanup.
    ("learning.branch.review", "scratch_ledger", ".mkdir"),
    ("learning.branch.review", "scratch_ledger", ".write_text"),
    ("learning.branch.review", "review", "shutil.rmtree"),
})

#: `_io` functions that do no I/O; any OTHER public `_io` function called from the handle is a
#: path seam or a raw reader it must not use.
_IO_PURE = frozenset({"json_nesting_depth", "load_json_artifact", "parse_jsonl_row",
                      "json_safe", "staged_leaf", "stage_name", "is_hard_linked",
                      "is_plain_entry"})
#: `pathlib.Path` methods that touch the filesystem, beyond D6's attribute calls.
_PATH_IO = frozenset({"read_text", "read_bytes", "exists", "is_file", "is_dir", "is_symlink",
                      "iterdir", "glob", "rglob", "stat", "lstat", "resolve", "symlink_to",
                      "hardlink_to", "rename", "replace", "chmod", "samefile", "readlink"})
#: `os` functions that touch no file.
_OS_PURE = frozenset({"os.fspath", "os.fsdecode", "os.fsencode"})
#: What the handle must call (through its `io=` seam).
_ROOTED_REQUIRED = frozenset({"rooted_read", "rooted_write", "rooted_mkdir", "rooted_unlink"})


def _astlib() -> Any:
    """The gates' shared name resolver (`scripts/lint/_astlib.py`), imported the way the suites
    reach it: "where does this call come from", resolved through aliases and scopes."""
    from defender.tests._by_path import import_lint_lib

    return import_lint_lib("_astlib")


def _callee(call: ast.Call, env: Any) -> str | None:
    """The vocabulary entry `call` is, or `None`. A call through a module (any alias, any
    from-import) is resolved to its origin by `_astlib`; a call on a value (`p.unlink()`,
    `self._io.write_guarded(...)`) is judged by its attribute name."""
    origin = _astlib().callee(call, env)
    if origin is not None:
        if origin.startswith("shutil.") or origin in _RAW_OS_ORIGINS:
            return origin
        if origin.rsplit(".", 1)[-1] in PATH_SEAMS:
            return origin.rsplit(".", 1)[-1]
    f = call.func
    if not isinstance(f, ast.Attribute):
        return None
    if origin is None and f.attr in PATH_SEAMS:
        return f.attr
    if f.attr in ATTR_CALLS:
        return f".{f.attr}"
    return None


class _Calls(ast.NodeVisitor):
    """Every call in a module, with the qualified name of its enclosing `def`s."""

    def __init__(self) -> None:
        self.stack: list[str] = []
        self.calls: list[tuple[str, ast.Call]] = []

    def _scoped(self, node: ast.AST, name: str) -> None:
        self.stack.append(name)
        self.generic_visit(node)
        self.stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._scoped(node, node.name)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._scoped(node, node.name)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._scoped(node, node.name)

    def visit_Call(self, node: ast.Call) -> None:
        self.calls.append((".".join(self.stack) or "<module>", node))
        self.generic_visit(node)


def _parse(path: Path) -> ast.Module:
    if not path.is_file():
        pytest.fail(f"D6 scans {path}, which does not exist — the census cannot vouch for it")
    try:
        return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except SyntaxError as bad:
        pytest.fail(f"{path} does not parse ({bad}) — an unparseable module passes no census")


def census_of(module: str, tree: ast.Module) -> set[tuple[str, str, str]]:
    env = _astlib().module_env(tree)
    calls = _Calls()
    calls.visit(tree)
    out = set()
    for where, call in calls.calls:
        callee = _callee(call, env)
        if callee is not None:
            out.add((module, where, callee))
    return out


def _module_name(rel: str) -> str:
    dotted = rel.removesuffix(".py").replace("/", ".")
    return dotted.removesuffix(".__init__")


def collect(rels: Iterable[str] = MODULES) -> set[tuple[str, str, str]]:
    found: set[tuple[str, str, str]] = set()
    for rel in rels:
        found |= census_of(_module_name(rel), _parse(PACKAGE / rel))
    return found


def test_d6_the_scanner_sees_every_vocabulary_spelling_including_aliases():
    """The scanner's own positive control: every spelling of every vocabulary entry — bare, as
    an attribute of any receiver, through an `import ... as` or `from ... import ... as` alias —
    is collected with its enclosing function; a non-vocabulary call is not."""
    source = '''
import os as _os
import shutil as sh
from os import replace as swap
from defender._io import write_guarded as wg, guarded_mkdir
from defender import _io
from defender.runtime.observe import stage_trace_path


class Holder:
    def method(self, p):
        wg(p, "x")
        _io.append_jsonl(p, [])
        p.touch()


def outer(p):
    def inner():
        guarded_mkdir(p, base=p)
        _os.unlink(p)
        swap(p, p)
    sh.copy2(p, p)
    p.write_text("x")
    p.read_text()
    stage_trace_path(p, "n")
    _os.path.join("a", "b")


_os.open("x", 0)
'''
    got = census_of("m", ast.parse(source))
    assert got == {
        ("m", "Holder.method", "write_guarded"), ("m", "Holder.method", "append_jsonl"),
        ("m", "Holder.method", ".touch"),
        ("m", "outer.inner", "guarded_mkdir"), ("m", "outer.inner", "os.unlink"),
        ("m", "outer.inner", "os.replace"),
        ("m", "outer", "shutil.copy2"), ("m", "outer", ".write_text"),
        ("m", "outer", "stage_trace_path"),
        ("m", "<module>", "os.open"),
    }, got


def test_d6_the_migrated_modules_make_no_episode_io_but_the_declared_residue():
    """O1 / D6: across D6's modules, the path-seam and raw-I/O calls are exactly the residue.
    Every other episode write or path-seam read now goes through the `Episode` handle (or a
    `Bound`), which this vocabulary does not name."""
    found = collect()
    extra = sorted(found - RESIDUE)
    missing = sorted(RESIDUE - found)
    report = ("D6's census differs from its residue.\n"
              + "".join(f"  still calls (move it onto the Episode handle): {e}\n" for e in extra)
              + "".join(f"  residue entry gone (remove it from RESIDUE): {m}\n" for m in missing))
    assert not extra, report
    assert not missing, report


def _io_functions() -> frozenset[str]:
    return frozenset(
        name for name, obj in vars(_io).items()
        if inspect.isfunction(obj) and obj.__module__ == _io.__name__
        and not name.startswith("_"))


def test_d6_the_episode_handle_does_io_only_through_the_rooted_core():
    """D1 / D6's second assertion: `_episode_handle.py` calls no vocabulary entry, no `os.*` or
    `shutil.*` operation, no builtin `open`, no filesystem method of a `Path`, and no `_io`
    function except the rooted ones; and it does call `rooted_read`, `rooted_write`,
    `rooted_mkdir` and `rooted_unlink`, so the check is not vacuous."""
    path = PACKAGE / "_episode_handle.py"
    tree = _parse(path)
    vocabulary = census_of("_episode_handle", tree)
    assert vocabulary == set(), f"the handle makes path-seam or raw calls: {sorted(vocabulary)}"

    env = _astlib().module_env(tree)
    io_funcs = _io_functions()
    calls = _Calls()
    calls.visit(tree)
    violations, rooted = [], set()
    for where, call in calls.calls:
        f = call.func
        origin = _astlib().callee(call, env)
        name = (origin.rsplit(".", 1)[-1] if origin is not None
                else f.attr if isinstance(f, ast.Attribute) else None)
        if name is None:
            continue
        if name.startswith("rooted_"):
            rooted.add(name)
        elif origin is not None and (origin == "builtins.open" or (
                origin.split(".")[0] in ("os", "shutil")
                and not (origin.startswith("os.path.") or origin in _OS_PURE))):
            violations.append((where, origin))
        elif name in io_funcs and name not in _IO_PURE and (
                origin is None or origin.startswith(_io.__name__ + ".")):
            violations.append((where, name))
        elif origin is None and name in _PATH_IO:
            violations.append((where, f".{name}"))
    assert not violations, f"the handle does I/O outside the rooted core: {violations}"
    assert rooted >= _ROOTED_REQUIRED, (
        f"the handle never calls {sorted(_ROOTED_REQUIRED - rooted)} — its verbs must reach "
        "the rooted core")
