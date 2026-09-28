"""#1133 D6 — the census: every write into an episode tree goes through the `Episode` handle,
and the handle writes only through the rooted core (O1).

An AST scan of the modules D6 names collects every CALL to, and every other REFERENCE to, a
write-capable callee. D6's pinned vocabulary, widened (#1133 §3) to an allowlist over all
write-capable I/O, so a migrated site reverted to a link-following write cannot stay green:

* the path seams `write_guarded`, `read_guarded`, `read_bytes_guarded`, `read_plain`,
  `read_plain_bytes`, `locked_for_rewrite`, `guarded_mkdir`, `open_guarded`, `write_atomic`,
  `append_jsonl`, and `stage_trace_path` — bare, through an `as` alias, or as an attribute of
  any receiver (`_io.write_guarded`, `self.io.write_guarded`);
* every `defender._io` writer the seams are built on: any `rooted_*` (from `_io`, or as an
  attribute of any receiver), `open_nofollow_fd`, `open_unnamed`, `open_unnamed_at`,
  `sweep_staged`, and any private `_io._<name>`;
* builtin `open`, `io.open`, `codecs.open` — any call, whatever its mode;
* `os.open`, `os.makedirs`, `os.mkdir`, `os.write`, `os.fdopen`, `os.link`, `os.symlink`,
  `os.rename`, `os.renames`, `os.replace`, `os.unlink`, `os.remove`, `os.removedirs`,
  `os.rmdir`, `os.truncate`, `os.mkfifo`, `os.mknod` (through any alias of `os`);
* `shutil.<anything>`;
* `getattr(<_io, os or shutil>, ...)` and `vars(<the same>)` — a callee named by string — and
  `importlib.import_module` / `__import__` of one of those modules (or `io`, `codecs`), a module
  bound where no import names it;
* the `Path` attribute calls `.open`, `.mkdir`, `.write_text`, `.write_bytes`, `.unlink`,
  `.rmdir`, `.touch`, `.symlink_to`, `.hardlink_to`, on any receiver, and `.rename` /
  `.replace` called with ONE argument (`Path.rename(target)`; `str.replace(old, new)` takes
  two and is not I/O);
* the link-following reads `.read_text` and `.read_bytes` on any receiver: O1 moves the
  path-seam reads of episode records onto the handle (or a `Bound`), so a record read that
  follows a link is as much a census hit as a write. The few such reads left are of things
  that are not episode records, each named in the residue.

A reference is anything that is not a call's callee: a module-level alias (`_put =
write_guarded`, whose later `_put(...)` calls are then resolved to `write_guarded` in the
function that makes them), a keyword or default value (`write=write_guarded`), a branch of an
expression (`w if w is not None else write_guarded`). A seam held is a seam used, so a
reference is keyed exactly as a call is.

Each hit is keyed `(module, enclosing scope, callee)`, never by line: the module relative to
the `defender` package, dotted; the enclosing `def`s (and classes) joined with `.`, or
`<module>`; the callee as spelled above (`os.unlink`, `.mkdir`, `shutil.copy2`,
`builtins.open`, `write_guarded`, `rooted_write`, `getattr(defender._io)`). The collected set
must EQUAL D6's residue: the queue writer (N-d), the archive's copy lane (N-a), the review's
scratch ledger and its temp-dir cleanup, and D3's one deliberate bypass — a directly
constructed `Ledger` (no episode behind it) appends through the rooted core itself. A residue
entry the final tree no longer has is removed from `RESIDUE`, never kept.

A second scan holds `defender/_episode_handle.py` to D1: it calls or references no
vocabulary entry but the rooted core's own (`rooted_*`, through its `io=` seam), no raw `os` /
`shutil` / builtin `open`, no `Path` I/O method, and no `_io` function but the rooted ones —
and it does call `rooted_read`, `rooted_write`, `rooted_mkdir` and `rooted_unlink`.

A module that is missing or does not parse fails the scan.

Red before #1133: the migrated modules still make the path-seam and raw calls the handle
replaces, and `_episode_handle.py` does not exist. The widened vocabulary is red against an
implementation that reverts a migrated site to builtin `open` / `os.makedirs`, or keeps a path
seam under an alias or as a default value.
"""
from __future__ import annotations

import ast
import builtins
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

#: D6's pinned vocabulary: the path seams, spelled by their own name wherever they come from.
PATH_SEAMS = frozenset({
    "write_guarded", "read_guarded", "read_bytes_guarded", "read_plain", "read_plain_bytes",
    "locked_for_rewrite", "guarded_mkdir", "open_guarded", "write_atomic", "append_jsonl",
    "stage_trace_path",
})
#: The `_io` writers beneath the seams (plus any `rooted_*` and any private `_io._<name>`).
IO_WRITERS = frozenset({"open_nofollow_fd", "open_unnamed", "open_unnamed_at", "sweep_staged"})
_IO = "defender._io"
RAW_OS = frozenset({
    "open", "makedirs", "mkdir", "write", "fdopen", "link", "symlink", "rename", "renames",
    "replace", "unlink", "remove", "removedirs", "rmdir", "truncate", "mkfifo", "mknod",
})
_RAW_OS_ORIGINS = frozenset(f"os.{op}" for op in RAW_OS)
OPENERS = frozenset({"builtins.open", "io.open", "codecs.open"})
#: `Path` I/O methods, judged by attribute name on any receiver.
ATTR_CALLS = frozenset({"open", "mkdir", "write_text", "write_bytes", "unlink", "rmdir", "touch",
                        "symlink_to", "hardlink_to", "rename", "replace",
                        "read_text", "read_bytes"})
#: Of those, the ones a `str` also has: a call counts only with `Path`'s one-argument shape.
_ONE_ARG_ONLY = frozenset({"rename", "replace"})
#: Of those, the ones whose bare REFERENCE (`cb = p.unlink`) is unambiguous enough to count.
_ATTR_REFS = ATTR_CALLS - _ONE_ARG_ONLY - {"open"}
#: The modules a `getattr(<module>, "...")` or `vars(<module>)` may not reach into.
_GETATTR_MODULES = frozenset({_IO, "os", "shutil"})
#: The modules a dynamic import may not bind.
_DYNAMIC_MODULES = frozenset({*_GETATTR_MODULES, "io", "codecs"})
_DYNAMIC_IMPORTS = frozenset({"importlib.import_module", "builtins.__import__"})

#: D6's residue, exactly, re-derived on the final tree.
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
    # D3's one deliberate bypass: a `Ledger` constructed directly (no episode behind it, tests
    # only) appends through the rooted core rather than through the handle.
    ("learning.branch.ledger", "Ledger._append", "rooted_mkdir"),
    ("learning.branch.ledger", "Ledger._append", "rooted_write"),
    # Link-following reads of things that are not episode records: a sibling's scrub verdict,
    # the sidecar beside its run dir (screened by `artifact_file` first); the source run's
    # investigation and alert (run records, #1105); the episode page's own stylesheet asset.
    ("learning.branch.cli", "_scrub_ran", ".read_text"),
    ("learning.branch.cli", "_fence_count", ".read_text"),
    ("learning.branch.cli", "_alert_document", ".read_text"),
    ("scripts.visualize.visualize_episode", "<module>", ".read_text"),
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
_BUILTINS = frozenset(dir(builtins))


def _astlib() -> Any:
    """The gates' shared name resolver (`scripts/lint/_astlib.py`), imported the way the suites
    reach it: "where does this call come from", resolved through aliases and scopes."""
    from defender.tests._by_path import import_lint_lib

    return import_lint_lib("_astlib")


def _key_of_origin(origin: str | None) -> str | None:
    """The vocabulary entry a resolved dotted origin is, or `None`."""
    if origin is None:
        return None
    if origin.startswith("shutil.") or origin in _RAW_OS_ORIGINS or origin in OPENERS:
        return origin
    last = origin.rsplit(".", 1)[-1]
    if last in PATH_SEAMS:
        return last
    if origin.startswith(_IO + "."):
        name = origin[len(_IO) + 1:]
        if name.startswith("rooted_") or name in IO_WRITERS:
            return name
        if name.startswith("_"):
            return f"_io.{name}"
    return None


def _name_origin(node: ast.Name, env: Any) -> str | None:
    """A bare name's origin in its own scope: an import, a builtin, or nothing (a local)."""
    e = env.scope_of.get(node, env)
    if node.id in e.defines:
        return None
    if node.id in e.imports:
        return e.imports[node.id]
    if node.id in _BUILTINS:
        return f"builtins.{node.id}"
    return None


def _value_key(node: ast.expr, env: Any, aliases: dict[str, str]) -> str | None:
    """The vocabulary entry an expression NAMES (a callee, or a referenced value), or `None`.
    A module-level alias resolves to what it was bound to; an attribute on a value (not a
    module) is judged by its attribute name."""
    if isinstance(node, ast.Name):
        if node.id in aliases:
            return aliases[node.id]
        return _key_of_origin(_name_origin(node, env))
    if isinstance(node, ast.Attribute):
        key = _key_of_origin(_astlib().origin(node, env))
        if key is not None:
            return key
        if _astlib().origin(node.value, env) is None and (
                node.attr in PATH_SEAMS or node.attr in IO_WRITERS
                or node.attr.startswith("rooted_")):
            return node.attr
    return None


def _call_key(call: ast.Call, env: Any, aliases: dict[str, str]) -> str | None:
    """The vocabulary entry `call` is, or `None`."""
    f = call.func
    key = _value_key(f, env, aliases)
    if key is not None:
        return key
    origin = _astlib().callee(call, env)
    if origin in ("builtins.getattr", "builtins.vars") and call.args:
        target = _astlib().origin(call.args[0], env)
        if target in _GETATTR_MODULES:
            return f"{origin.removeprefix('builtins.')}({target})"
    if origin in _DYNAMIC_IMPORTS and call.args:
        named = _astlib().str_value(call.args[0], env)
        if named in _DYNAMIC_MODULES:
            return f"import_module({named})"
    if isinstance(f, ast.Attribute) and origin is None and f.attr in ATTR_CALLS:
        if f.attr in _ONE_ARG_ONLY and not (
                (len(call.args) == 1 and not call.keywords)
                or (not call.args and [k.arg for k in call.keywords] == ["target"])):
            return None
        return f".{f.attr}"
    return None


def _ref_key(node: ast.expr, env: Any, aliases: dict[str, str]) -> str | None:
    """The vocabulary entry a non-call reference names, or `None`."""
    key = _value_key(node, env, aliases)
    if key is not None:
        return key
    if (isinstance(node, ast.Attribute) and node.attr in _ATTR_REFS
            and _astlib().origin(node, env) is None):
        return f".{node.attr}"
    return None


def module_aliases(tree: ast.Module, env: Any) -> dict[str, str]:
    """Module-level `NAME = <vocabulary entry>` bindings (chains followed), name -> entry."""
    aliases: dict[str, str] = {}
    changed = True
    while changed:
        changed = False
        for node in tree.body:
            if isinstance(node, ast.Assign) and len(node.targets) == 1:
                target, value = node.targets[0], node.value
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                target, value = node.target, node.value
            else:
                continue
            if not isinstance(target, ast.Name):
                continue
            key = _value_key(value, env, aliases)
            if key is not None and aliases.get(target.id) != key:
                aliases[target.id] = key
                changed = True
    return aliases


class _Scoped(ast.NodeVisitor):
    """Every call, and every name or attribute read that is not a call's callee (nor an inner
    link of a longer attribute chain), with the qualified name of its enclosing `def`s."""

    def __init__(self) -> None:
        self.stack: list[str] = []
        self.calls: list[tuple[str, ast.Call]] = []
        self.refs: list[tuple[str, ast.expr]] = []
        self._not_refs: set[int] = set()

    def _scoped(self, node: ast.AST, name: str) -> None:
        self.stack.append(name)
        self.generic_visit(node)
        self.stack.pop()

    def _where(self) -> str:
        return ".".join(self.stack) or "<module>"

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._scoped(node, node.name)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._scoped(node, node.name)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._scoped(node, node.name)

    def visit_Call(self, node: ast.Call) -> None:
        self.calls.append((self._where(), node))
        self._not_refs.add(id(node.func))
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        self._not_refs.add(id(node.value))
        if isinstance(node.ctx, ast.Load) and id(node) not in self._not_refs:
            self.refs.append((self._where(), node))
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, ast.Load) and id(node) not in self._not_refs:
            self.refs.append((self._where(), node))


def _parse(path: Path) -> ast.Module:
    if not path.is_file():
        pytest.fail(f"D6 scans {path}, which does not exist — the census cannot vouch for it")
    try:
        return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except SyntaxError as bad:
        pytest.fail(f"{path} does not parse ({bad}) — an unparseable module passes no census")


def census_of(module: str, tree: ast.Module) -> set[tuple[str, str, str]]:
    env = _astlib().module_env(tree)
    aliases = module_aliases(tree, env)
    seen = _Scoped()
    seen.visit(tree)
    out = set()
    for where, call in seen.calls:
        callee = _call_key(call, env, aliases)
        if callee is not None:
            out.add((module, where, callee))
    for where, node in seen.refs:
        callee = _ref_key(node, env, aliases)
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
    an attribute of any receiver, through an `import ... as` or `from ... import ... as` alias,
    through a module-level assignment alias, as a non-call reference (a keyword or default
    value, a branch of an expression), as a `getattr` / `vars` on `_io` or `os`, through a
    dynamic import — is collected with its
    enclosing scope; a non-vocabulary call is not, nor `str.replace`'s two-argument shape, nor a
    local value that shadows an imported name."""
    source = '''
import codecs
import importlib
import os as _os
import shutil as sh
from os import replace as swap
from defender._io import write_guarded as wg, guarded_mkdir, rooted_write, read_guarded
from defender import _io
from defender.runtime.observe import stage_trace_path

_put = wg
_again = _put
_raw = _io.append_jsonl
_reader: object = read_guarded


class Holder:
    sink = _io.write_atomic

    def method(self, p):
        wg(p, "x")
        _io.append_jsonl(p, [])
        p.touch()
        self.io.rooted_unlink(p, "n")


def outer(p, write=wg):
    def inner():
        guarded_mkdir(p, base=p)
        _os.unlink(p)
        swap(p, p)
    sh.copy2(p, p)
    p.write_text("x")
    p.read_text()
    stage_trace_path(p, "n")
    _os.path.join("a", "b")


def aliased(p):
    _put(p, "x")
    _again(p, "y")
    _raw(p, [])


def referenced(p, w=None):
    chosen = w if w is not None else _io.locked_for_rewrite
    call_later(hook=_os.makedirs)
    return chosen


def raw(p):
    with open(p, "w") as fh:
        fh.write("x")
    _os.makedirs(p, exist_ok=True)
    _os.mkdir(p)
    fd = _os.open(p, 0)
    _os.write(fd, b"x")
    _os.fdopen(fd, "w")
    _os.link(p, p)
    _os.symlink(p, p)
    _os.rmdir(p)
    codecs.open(p, "w")
    p.symlink_to(p)
    p.hardlink_to(p)
    p.rename(p)
    p.replace(target=p)
    "a-b".replace("-", "_")
    rooted_write(p, "n", "x", mode="append")
    getattr(_io, "write_guarded")(p, "x")
    vars(_os)["unlink"](p)
    _io._replace_at(0, 0, "n", p, "x", None)
    importlib.import_module("shutil").rmtree(p)
    getattr(p, "name")
    importlib.import_module("json")


def shadowed(open, rooted_write):
    open(1)
    rooted_write(2)


_os.open("x", 0)
'''
    got = census_of("m", ast.parse(source))
    assert got == {
        # Module-level aliases and the references that bind them.
        ("m", "<module>", "write_guarded"), ("m", "<module>", "append_jsonl"),
        ("m", "<module>", "read_guarded"), ("m", "<module>", "os.open"),
        ("m", "Holder", "write_atomic"),
        ("m", "Holder.method", "write_guarded"), ("m", "Holder.method", "append_jsonl"),
        ("m", "Holder.method", ".touch"), ("m", "Holder.method", "rooted_unlink"),
        # A default value is a reference in the function it belongs to.
        ("m", "outer", "write_guarded"),
        ("m", "outer.inner", "guarded_mkdir"), ("m", "outer.inner", "os.unlink"),
        ("m", "outer.inner", "os.replace"),
        ("m", "outer", "shutil.copy2"), ("m", "outer", ".write_text"),
        ("m", "outer", ".read_text"), ("m", "outer", "stage_trace_path"),
        # Calls through a module-level alias resolve to what the alias names.
        ("m", "aliased", "write_guarded"), ("m", "aliased", "append_jsonl"),
        ("m", "referenced", "locked_for_rewrite"), ("m", "referenced", "os.makedirs"),
        ("m", "raw", "builtins.open"), ("m", "raw", "os.makedirs"), ("m", "raw", "os.mkdir"),
        ("m", "raw", "os.open"), ("m", "raw", "os.write"), ("m", "raw", "os.fdopen"),
        ("m", "raw", "os.link"), ("m", "raw", "os.symlink"), ("m", "raw", "os.rmdir"),
        ("m", "raw", "codecs.open"), ("m", "raw", ".symlink_to"), ("m", "raw", ".hardlink_to"),
        ("m", "raw", ".rename"), ("m", "raw", ".replace"), ("m", "raw", "rooted_write"),
        ("m", "raw", "getattr(defender._io)"), ("m", "raw", "vars(os)"),
        ("m", "raw", "_io._replace_at"), ("m", "raw", "import_module(shutil)"),
    }, sorted(got)


def test_d6_the_migrated_modules_make_no_episode_io_but_the_declared_residue():
    """O1 / D6: across D6's modules, the calls to and references to write-capable callees are
    exactly the residue. Every other episode write or path-seam read now goes through the
    `Episode` handle (or a `Bound`), which this vocabulary does not name."""
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
    """D1 / D6's second assertion: `_episode_handle.py` calls or references no vocabulary entry
    but the rooted core's own `rooted_*` (reached through its `io=` seam), no `os.*` or
    `shutil.*` operation, no builtin `open`, no filesystem method of a `Path`, and no `_io`
    function except the rooted ones; and it does call `rooted_read`, `rooted_write`,
    `rooted_mkdir` and `rooted_unlink`, so the check is not vacuous."""
    path = PACKAGE / "_episode_handle.py"
    tree = _parse(path)
    vocabulary = {hit for hit in census_of("_episode_handle", tree)
                  if not hit[2].startswith("rooted_")}
    assert vocabulary == set(), f"the handle makes path-seam or raw calls: {sorted(vocabulary)}"

    env = _astlib().module_env(tree)
    io_funcs = _io_functions()
    calls = _Scoped()
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
