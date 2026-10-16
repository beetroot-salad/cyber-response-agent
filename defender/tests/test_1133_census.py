"""#1133 D6' — the census, rev 2 (rev 3's D7'' removes the rows R1 made dead: `episode._answers`'
`path` parameter, and `delta_o` / `_answers` as N-b readers and a tolerated door): every write
into an episode tree goes through the `Episode` handle, the handle reaches the core only by
`hold` / `hold_new` and the `Held` verbs, and (O5) no function takes a path to something below
the episode dir.

**The first scan** (D6, whose allowlist and vocabulary stand) collects, across D6's modules plus
`run.py`, `learning/branch/episode.py` and `learning/judge/{family,render,run}.py` (D6'), every
CALL to and every other REFERENCE to a write-capable callee:

* the path seams `write_guarded`, `read_guarded`, `read_bytes_guarded`, `read_plain`,
  `read_plain_bytes`, `locked_for_rewrite`, `guarded_mkdir`, `open_guarded`, `append_jsonl`,
  and `stage_trace_path` (`write_atomic` left the vocabulary when #1235 deleted it) — bare,
  through an `as` alias, or as an attribute of any receiver (`_io.write_guarded`,
  `self.io.write_guarded`);
* every `defender._io` writer: any `rooted_*`, rev 2's `hold` and `hold_new` (a module that
  holds a root itself is a second handle), `open_nofollow_fd`, `open_unnamed`,
  `open_unnamed_at`, `sweep_staged`, and any private `_io._<name>`;
* builtin `open`, `io.open`, `codecs.open` — any call, whatever its mode;
* `os.open`, `os.makedirs`, `os.mkdir`, `os.write`, `os.fdopen`, `os.link`, `os.symlink`,
  `os.rename`, `os.renames`, `os.replace`, `os.unlink`, `os.remove`, `os.removedirs`,
  `os.rmdir`, `os.truncate`, `os.mkfifo`, `os.mknod` (through any alias of `os`);
* `shutil.<anything>`;
* `getattr(<_io, os or shutil>, ...)`, `vars(<the same>)`, and `importlib.import_module` /
  `__import__` of one of those modules (or `io`, `codecs`);
* the `Path` methods `.open`, `.mkdir`, `.write_text`, `.write_bytes`, `.unlink`, `.rmdir`,
  `.touch`, `.symlink_to`, `.hardlink_to`, `.link_to`, `.rename`, `.replace`, and the
  link-following reads `.read_text` and `.read_bytes`, on any receiver that is not a module
  or a `defender` class whose body defines the method — a value of any kind (a local, a path
  a module holds), a class from outside the checkout, or the `Path` class itself (`Path.unlink(p)`, `map(Path.read_text, ps)`). On a value, the
  names a `str` also has count, when called, only in `Path`'s shape: `.rename` / `.replace`
  called with ONE argument. A bare reference counts in every name.

A reference is anything that is not a call's callee (a module-level alias, a keyword or default
value, a branch of an expression) and is keyed exactly as a call is. Each hit is keyed
`(module, enclosing scope, callee)`, never by line. The collected set must EQUAL the residue:
the queue writer (N-d), the archive's copy lane (N-a), and the link-following reads of things
that are not episode records. `Ledger._append` makes no `rooted_*` write: every `Ledger` is
built by `for_world`, so it appends through its episode's record. (#1224 retired the staging
and review modules, and the review's scratch with them.)

**The handle scan** holds `defender/_episode_handle.py` to D1'/D2': it reaches the core only
through `hold` and `hold_new` (its `io=` seam), and does I/O only through the `Held` it gets
back — `held.mkdir(rel)` / `held.unlink(rel)` (a call carrying the name positionally is a
`Held` verb; `Path.mkdir()` / `Path.unlink()` take no positional name, and their positional
`mode` / `missing_ok` is a non-string constant) and `read` / `write` /
`view` / `close`, none of which is vocabulary. No `rooted_*`, no path seam, no raw `os` /
`shutil` / builtin `open`, no `Path` method that touches the filesystem (the #1134 census's
list, called or referenced, by the same receiver rule), no other I/O-doing `_io` function; and it does
call `hold` and `hold_new`, so the check is not vacuous.

**The O5 scan** (D6') covers every function, public or private, of the same modules:

* *Parameters.* A parameter named `path`, `*_path`, `manifest`, `draw_dir` or `world_dir`, or
  annotated with a path type, and not named `episode_dir` / `episodes_root` / `source*` /
  `run_dir*`, must be on `PARAM_ALLOWLIST` `(module, function, parameter, reason)`. The rule is
  read as O5 is narrowed — "a path to something BELOW the episode dir":
  - a path type is a concrete `Path` / `PosixPath` / `os.PathLike` / `StrPath`, optionally
    unioned with `str` / `bytes` / `None`; a pure path (`PurePath`, `PurePosixPath`) is a
    relative name resolved under a held or bound root, which is the handle's own model, and a
    container or callable of paths is not itself a path;
  - a NAMED parameter whose annotation names neither a path type nor `str` / `bytes`
    (`manifest: dict[str, Any]`, a parsed document) is not a path;
  - a path-typed parameter named for a root outside every episode tree (`OUTSIDE_EPISODE`:
    the sibling runs base, settings, tenants, lessons, the judge queue, the repository) is not
    below an episode dir.
  The allowlist is the O5 carve-outs plus the path-typed functions that do no episode write
  (D3' "stay path-typed"): an HTTP request path, a path inside a git revision, the queue
  writer's files (N-d), the investigation's alert input. Every row must still be flagged on the
  tree (a row the tree no longer has is removed, never kept); `PARAM_TOLERATED` rows may be
  present or not.
* *Calls.* `EpisodePaths(`, `base_file(` and `staged_path(` are called only in `NB_READERS`:
  the root-binding readers and path-typed functions D3' names, and the O5 carve-outs.
* *Doors.* `Episode.open` / `Episode.create` are used — called, or referenced any other way
  (a module-level alias's right-hand side, an argument, a local alias) — only in the doors D3'
  names (`DOORS`, #1224's pre-flight `preflight_replay` among them). The scan resolves import
  aliases, module attributes and module-level assignment aliases of the class or of a door
  (`module_aliases`, keyed by the door scan's own resolver), counts a door verb on a value's
  class (`type(ep).open`), and keys any `getattr` / `vars` reach into the class as a hit of
  its own. Each door in `DOORS_REQUIRED` does call its verb, so the scan is not vacuous; and
  the `Episode`'s public class/static methods are exactly `open` and `create`, with no public
  function in `_episode_handle`, so there is no third door the scan does not look for.

Every scan is self-tested on synthetic source: each violating shape is collected, each compliant
shape is not. A module that is missing or does not parse fails the scan.

Red on the rev-2 tree (rev 3's rows): `episode._answers(path)` is flagged and no longer
allowed, `delta_o` / `_answers` call `EpisodePaths(` / `base_file(` outside `NB_READERS`, and
`delta_o` opens an `Episode` outside the doors.
"""
from __future__ import annotations

import ast
import builtins
import functools
import importlib
import inspect
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import pytest

from defender import _io
from defender.tests import _census1134 as C

#: The `defender` package's own directory (a namespace package: located through a module in it).
PACKAGE = Path(_io.__file__).resolve().parent

#: D6's module list, plus `run.py` and the readers D6' adds to the O5 scan (the census scans
#: them too: none may make an episode write around the handle).
MODULES = (
    "learning/branch/cli.py",
    "learning/branch/timing.py",
    "learning/branch/archive.py",
    "learning/branch/capture.py",
    "learning/branch/ledger.py",
    "learning/branch/outcome.py",
    "learning/judge/__init__.py",
    "learning/judge/enqueue.py",
    "runtime/branch/_family.py",
    "scripts/visualize/visualize_episode.py",
    "run.py",
    "learning/branch/episode.py",
    "learning/judge/family.py",
    "learning/judge/render.py",
    "learning/judge/run.py",
)
#: The O5 scan's modules: the same set (D6').
O5_MODULES = MODULES

#: D6's pinned vocabulary: the path seams, spelled by their own name wherever they come from.
PATH_SEAMS = frozenset({
    "write_guarded", "read_guarded", "read_bytes_guarded", "read_plain", "read_plain_bytes",
    "locked_for_rewrite", "guarded_mkdir", "open_guarded", "append_jsonl",
    "stage_trace_path",
})
#: The `_io` writers beneath the seams (plus any `rooted_*` and any private `_io._<name>`),
#: rev 2's held-root core among them.
CORE = frozenset({"hold", "hold_new"})
IO_WRITERS = frozenset({"move_at", "open_lock_at", "open_nofollow_fd", "open_unnamed",
                        "open_unnamed_at", "sweep_staged",
                        *CORE})
_IO = "defender._io"
RAW_OS = frozenset({
    "open", "makedirs", "mkdir", "write", "fdopen", "link", "symlink", "rename", "renames",
    "replace", "unlink", "remove", "removedirs", "rmdir", "truncate", "mkfifo", "mknod",
})
_RAW_OS_ORIGINS = frozenset(f"os.{op}" for op in RAW_OS)
OPENERS = frozenset({"builtins.open", "io.open", "codecs.open"})
#: D6's `Path` methods: the writes and the link-following reads, judged by attribute name on
#: any receiver but a module or a defining `defender` class (`_path_verb`). A subset of the
#: #1134 census's `Path` verbs.
ATTR_CALLS = frozenset({"open", "mkdir", "write_text", "write_bytes", "unlink", "rmdir", "touch",
                        "symlink_to", "hardlink_to", "link_to", "rename", "replace",
                        "read_text", "read_bytes"})
assert ATTR_CALLS <= C.ATTRS, sorted(ATTR_CALLS - C.ATTRS)
#: The modules a `getattr(<module>, "...")` or `vars(<module>)` may not reach into.
_GETATTR_MODULES = frozenset({_IO, "os", "shutil"})
#: The modules a dynamic import may not bind.
_DYNAMIC_MODULES = frozenset({*_GETATTR_MODULES, "io", "codecs"})
_DYNAMIC_IMPORTS = frozenset({"importlib.import_module", "builtins.__import__"})

#: The residue D6' leaves, exactly, re-derived on the final tree.
RESIDUE = frozenset({
    # (The queue writer's three rows are gone: #1135 moved it onto the learning-state handle, so
    # it makes no guarded write of its own any more.)
    # The archive's copy lane (N-a).
    ("learning.branch.archive", "_screen_destinations", ".unlink"),
    ("learning.branch.archive", "archive_episode", "shutil.copy2"),
    ("learning.branch.archive", "archive_episode", "shutil.copytree"),
    # Link-following reads of things that are not episode records: a sibling's scrub verdict,
    # the sidecar beside its run dir (screened by `artifact_file` first); the source run's
    # investigation and alert (run records, #1105); the episode page's own stylesheet asset.
    # #1105 PR 2 (decision C): the tenant-scoped runs repository's `open(run_id)` — a run
    # opened by id through its owner, not a `Path.open` — which this census's by-name rule
    # cannot tell apart from one. (VERIFY's and the page's per-arm opens left with PR 2's
    # review: both take every arm from one hold, `EpisodeRuns.arms`.)
    ("learning.branch.cli", "_open_launch_source", ".open"),
    ("run", "_open_world_source", ".open"),
})

#: `_io` functions that do no I/O; any OTHER public `_io` function called from the handle is a
#: path seam or a raw reader it must not use.
_IO_PURE = frozenset({"json_nesting_depth", "load_json_artifact", "parse_jsonl_row",
                      "json_safe", "staged_leaf", "stage_name", "is_hard_linked",
                      "is_plain_entry"})
#: Every `pathlib.Path` method that touches the filesystem: the #1134 census's list, one list
#: for both censuses.
_PATH_IO = C.ATTRS
#: `os` functions that touch no file.
_OS_PURE = frozenset({"os.fspath", "os.fsdecode", "os.fsencode"})
#: The `Held` verbs that share a name with a `Path` I/O method: a call carrying the name
#: positionally (`held.mkdir(rel)`, `held.unlink(rel)`) is the verb, since `Path.mkdir()` and
#: `Path.unlink()` take no positional name.
_HELD_NAMED_VERBS = frozenset({"mkdir", "unlink"})
_BUILTINS = frozenset(dir(builtins))


def _astlib() -> Any:
    """The gates' shared name resolver (`scripts/lint/_astlib.py`), imported the way the suites
    reach it: "where does this call come from", resolved through aliases and scopes."""
    from defender.tests._by_path import import_lint_lib

    return import_lint_lib("_astlib")


def _tree() -> Any:
    """The #1134 census's view of this checkout (one per process, shared with that census): which
    dotted origins are modules, which `defender` classes define what, and where a `defender`
    re-export leads."""
    return C.tree_of(PACKAGE.parent)


def _scan(rel: str, tree: ast.Module) -> Any:
    """The #1134 census's resolver for one module (`rel`, a path under `defender/`): its scope
    tree (`.env`, what `_astlib` resolves against), `resolve` (a relative import made absolute,
    a `defender` re-export followed), `origin` (that, and the module's own top-level names),
    and the `Path`-verb rule."""
    return C.ModuleScan(_tree(), rel, tree)


def _path_verb(node: ast.Attribute, scan: Any, verbs: frozenset[str],
               call: ast.Call | None = None) -> str | None:
    """`.<verb>` when `node` is a `Path` method in `verbs` — called (`call`) or only referenced —
    on what may be a path, or `None`: the #1134 census's rule (`ModuleScan.path_verb`), one
    rule for both. Not on a module, nor on a `defender` class whose own body defines the verb
    (``Episode.open``: a `defender` function, which the census judges as any other); on
    anything else — a local, a value a module holds (`_paths.REPO_ROOT`), a value's class
    (`type(p)`), a class from outside the checkout — in the verb's own shape; on `Path` itself
    (`pathlib.PosixPath`, an import alias, a re-export) in any shape. A class bound by
    assignment (`P = Path`) is a value, so its two-argument `rename` / `replace` is not seen."""
    return f".{node.attr}" if scan.path_verb(node, call, verbs) else None


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


def _name_origin(node: ast.Name, scan: Any) -> str | None:
    """A bare name's origin in its own scope: an import (resolved, `ModuleScan.resolve`), a
    builtin, or nothing (a local)."""
    e = scan.env.scope_of.get(node, scan.env)
    if node.id in e.defines:
        return None
    if node.id in e.imports:
        return scan.resolve(e.imports[node.id])
    if node.id in _BUILTINS:
        return f"builtins.{node.id}"
    return None


def _value_key(node: ast.expr, scan: Any, aliases: dict[str, str]) -> str | None:
    """The vocabulary entry an expression NAMES (a callee, or a referenced value), `Path`
    verbs aside, or `None`. A module-level alias resolves to what it was bound to; an attribute
    on anything but a module or a `defender` class that defines it is judged by its name."""
    if isinstance(node, ast.Name):
        if node.id in aliases:
            return aliases[node.id]
        return _key_of_origin(_name_origin(node, scan))
    if isinstance(node, ast.Attribute):
        key = _key_of_origin(scan.origin(node))
        if key is not None:
            return key
        if not scan.owns(scan.origin(node.value), node.attr) and (
                node.attr in PATH_SEAMS or node.attr in IO_WRITERS
                or node.attr.startswith("rooted_")):
            return node.attr
    return None


def _ref_key(node: ast.expr, scan: Any, aliases: dict[str, str],
             verbs: frozenset[str] = ATTR_CALLS) -> str | None:
    """The vocabulary entry a non-call reference names, a `Path` verb in `verbs` among them, or
    `None`."""
    key = _value_key(node, scan, aliases)
    if key is None and isinstance(node, ast.Attribute):
        return _path_verb(node, scan, verbs)
    return key


def _call_key(call: ast.Call, scan: Any, aliases: dict[str, str],
              verbs: frozenset[str] = ATTR_CALLS) -> str | None:
    """The vocabulary entry `call` is, a `Path` verb in `verbs` among them, or `None`."""
    f = call.func
    key = _value_key(f, scan, aliases)
    if key is not None:
        return key
    origin = scan.resolve(_astlib().callee(call, scan.env))
    if origin in ("builtins.getattr", "builtins.vars") and call.args:
        target = scan.origin(call.args[0])
        if target in _GETATTR_MODULES:
            return f"{origin.removeprefix('builtins.')}({target})"
    if origin in _DYNAMIC_IMPORTS and call.args:
        named = _astlib().str_value(call.args[0], scan.env)
        if named in _DYNAMIC_MODULES:
            return f"import_module({named})"
    if isinstance(f, ast.Attribute):
        return _path_verb(f, scan, verbs, call)
    return None


def module_aliases(tree: ast.Module, resolver: Any, key: Any = _ref_key) -> dict[str, str]:
    """Module-level `NAME = <entry>` bindings (chains followed), name -> entry. `key(node,
    resolver, aliases)` says what entry an expression names: the census vocabulary (`_ref_key`,
    against a `_scan`) unless another is given (the door scan's `_door_key`, against an
    `_astlib` env)."""
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
            named = key(value, resolver, aliases)
            if named is not None and aliases.get(target.id) != named:
                aliases[target.id] = named
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


def census_of(rel: str, tree: ast.Module) -> set[tuple[str, str, str]]:
    """The hits of `tree`, scanned as the module at `rel` (a path under `defender/`)."""
    module = _module_name(rel)
    scan = _scan(rel, tree)
    aliases = module_aliases(tree, scan)
    seen = _Scoped()
    seen.visit(tree)
    out = set()
    for where, call in seen.calls:
        callee = _call_key(call, scan, aliases)
        if callee is not None:
            out.add((module, where, callee))
    for where, node in seen.refs:
        callee = _ref_key(node, scan, aliases)
        if callee is not None:
            out.add((module, where, callee))
    return out


def _module_name(rel: str) -> str:
    dotted = rel.removesuffix(".py").replace("/", ".")
    return dotted.removesuffix(".__init__")


def collect(rels: Iterable[str] = MODULES) -> set[tuple[str, str, str]]:
    found: set[tuple[str, str, str]] = set()
    for rel in rels:
        found |= census_of(rel, _parse(PACKAGE / rel))
    return found


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


# ---------------------------------------------------------------------------------------------
# The handle scan (D1' / D2'): the core only by `hold` / `hold_new`, I/O only through `Held`
# ---------------------------------------------------------------------------------------------


def _io_functions() -> frozenset[str]:
    return frozenset(
        name for name, obj in vars(_io).items()
        if inspect.isfunction(obj) and obj.__module__ == _io.__name__
        and not name.startswith("_"))


def _is_held_verb(call: ast.Call, scan: Any) -> bool:
    """`<value>.mkdir(rel)` / `<value>.unlink(rel)`: a `Held` verb, not `Path` I/O. A first
    positional that is a non-string constant is `Path`'s `mode` / `missing_ok`
    (`p.mkdir(0o755)`, `p.unlink(True)`), not a name."""
    f = call.func
    if not (isinstance(f, ast.Attribute) and f.attr in _HELD_NAMED_VERBS and call.args):
        return False
    first = call.args[0]
    if isinstance(first, ast.Constant) and not isinstance(first.value, str):
        return False
    return _astlib().callee(call, scan.env) is None


def _raw_io(call: ast.Call, scan: Any, io_funcs: frozenset[str]) -> str | None:
    """Beyond the vocabulary (and the `Path` methods `_call_key` judges): any `os` / `shutil`
    operation, builtin `open`, or an I/O-doing `_io` function other than the core."""
    f = call.func
    origin = scan.resolve(_astlib().callee(call, scan.env))
    name = (origin.rsplit(".", 1)[-1] if origin is not None
            else f.attr if isinstance(f, ast.Attribute) else None)
    if name is None:
        return None
    if origin is not None and (origin == "builtins.open" or (
            origin.split(".")[0] in ("os", "shutil")
            and not (origin.startswith("os.path.") or origin in _OS_PURE))):
        return origin
    if name in io_funcs and name not in _IO_PURE and name not in CORE and (
            origin is None or origin.startswith(_io.__name__ + ".")):
        return name
    return None


def handle_scan(tree: ast.Module) -> tuple[list[tuple[str, str]], set[str]]:
    """The handle module's I/O outside `Held` and its core, and the core calls it makes.

    Returns `(violations, core)`: `violations` are `(scope, callee)` pairs, `core` the subset of
    `CORE` the module calls."""
    scan = _scan("_episode_handle.py", tree)
    aliases = module_aliases(tree, scan, functools.partial(_ref_key, verbs=_PATH_IO))
    io_funcs = _io_functions()
    seen = _Scoped()
    seen.visit(tree)
    violations: list[tuple[str, str]] = []
    core: set[str] = set()
    for where, call in seen.calls:
        if _is_held_verb(call, scan):
            continue
        key = _call_key(call, scan, aliases, _PATH_IO)
        if key in CORE:
            core.add(key)
            continue
        raw = key if key is not None else _raw_io(call, scan, io_funcs)
        if raw is not None:
            violations.append((where, raw))
    for where, node in seen.refs:
        key = _ref_key(node, scan, aliases, _PATH_IO)
        if key is not None and key not in CORE:
            violations.append((where, key))
    return violations, core


def test_d6_the_episode_handle_does_io_only_through_hold_and_its_held():
    """D1' / D2' / D6': `_episode_handle.py` reaches the core only through `hold` and
    `hold_new` (its `io=` seam) and does I/O only through the `Held` they return: no `rooted_*`,
    no path seam, no `bind`, no `os.*` / `shutil.*` operation, no builtin `open`, no filesystem
    method of a `Path`, no other I/O-doing `_io` function. It does call `hold` and `hold_new`,
    so the check is not vacuous."""
    violations, core = handle_scan(_parse(PACKAGE / "_episode_handle.py"))
    assert not violations, (
        f"the handle does I/O around its held root: {sorted(set(violations))}")
    assert core == set(CORE), (
        f"the handle never calls {sorted(CORE - core)} — `Episode.open` is one `io.hold`, "
        "`Episode.create` one `io.hold_new`")


# ---------------------------------------------------------------------------------------------
# The O5 scan (D6'): no function takes a path below the episode dir
# ---------------------------------------------------------------------------------------------

#: O5's exemptions by name, as D6' words them: the episode dir itself, the episodes root, a
#: source run, a run dir.
_O5_EXEMPT_EXACT = frozenset({"episode_dir", "episodes_root"})
_O5_EXEMPT_PREFIX = ("source", "run_dir")
#: O5's named parameters.
_O5_NAMED = frozenset({"path", "manifest", "draw_dir", "world_dir"})
#: Path-typed parameters named for a root outside every episode tree: the sibling runs base,
#: the tenant's settings, the data root (#1120; the episodes root is refused inside it), the
#: lessons folder, the judge queue, the defender checkout, a git work tree. None is below an
#: episode dir.
OUTSIDE_EPISODE = frozenset({"runs_base", "settings_dir", "data_root", "lessons_dir",
                             "queue_dir", "defender_dir", "cwd"})
#: Concrete, I/O-capable path types (a `PurePath` is a relative name, not a path to open).
_PATH_TYPES = frozenset({"Path", "PosixPath", "PathLike", "StrPath"})
_TEXT_TYPES = frozenset({"str", "bytes"})

#: D6' parameter allowlist `(module, function, parameter, reason)`: the O5 carve-outs, and the
#: path-typed functions D3' keeps that do no episode write. Every row must still be flagged.
_CARVE_READ = "O5 carve-out: a path-taking reader of a run-shaped tree or a base file"
_GIT = "a path inside a git revision (`git show <rev>:<path>`), not a file on disk"
_ALERT = "the investigation's alert input, a run file read before any episode exists"
#: Rev 3 (R1) removes `episode._answers(path)`'s row: `_answers` takes the rows `delta_o` read
#: through its one `bind`, not a path.
PARAM_ALLOWLIST = frozenset({
    ("run", "_run_investigation_lifecycle.scrub_tree", "tree",
     "scrub callback takes the lifecycle tree; verdict reads/writes use its bound Run"),
    ("learning.branch.ledger", "Ledger._absorb", "path", _CARVE_READ),
    ("learning.judge.family", "leads_by_id", "world_dir", _CARVE_READ),
    # (#1234 removed `run._resolves(world_dir, …)` and `run._draw_document(world_dir, …)`: the
    # one pointer resolver is `pointers._resolves` over the episode's bound view, and the draw
    # document is built from the validated reply alone — neither takes a path.)
    ("learning.judge", "_memoized_show.invoke", "path", _GIT),
    ("learning.judge.render", "_git_show_default", "path", _GIT),
    ("run", "_Investigate.__call__", "alert_path", _ALERT),
    ("run", "_drive_investigation", "alert_path", _ALERT),
    ("run", "_materialize_run", "alert", _ALERT),
})
#: Rows that may be present or not: D3' leaves the sibling's `resume_world` shape open (its door
#: `run.main` opens the episode from the manifest's parent; `resume_world` may keep taking the
#: manifest path it refuses by name, or take the `Episode`).
PARAM_TOLERATED = frozenset({
    ("run", "resume_world", "manifest"),
})

#: Where `EpisodePaths(`, `base_file(` and `staged_path(` may be called, `(module, function)`
#: (a nested scope counts as its enclosing function): the readers that bind at the episode root
#: (O3 / N-b), the functions D3' keeps path-typed, and the O5 carve-outs.
NB_READERS = frozenset({
    # D3' "stay path-typed": pre-door, or the episode dir itself.
    ("learning.branch.cli", "preflight_episode"),
    ("learning.branch.cli", "refuse_claimed_episode"),
    # (#1105 PR 2 deleted `episode_dir_for` — the owner's `episode_dir` — and
    # `sibling_runs_base`, F-13.)
    ("learning.branch.cli", "sibling_argv"),
    ("runtime.branch._family", "resume_world_from"),
    ("run", "main"),
    # The root-binding readers (O3, N-b).
    ("learning.judge", "read_grade"),
    ("learning.judge", "_existing_grade"),
    ("learning.judge", "_grade_from_document"),
    ("learning.judge.enqueue", "enqueue"),
    ("learning.judge.enqueue", "enqueue_report"),
    ("learning.judge.family", "raw_manifest"),
    ("learning.judge.family", "grade_family"),
    ("learning.judge.family", "_grade_world"),
    ("learning.judge.family", "_repository_leads"),
    ("learning.judge.render", "render"),
    ("learning.judge.render", "_render_bound_world"),
    ("scripts.visualize.visualize_episode", "load_episode"),
    ("scripts.visualize.visualize_episode", "_read_grade"),
    ("scripts.visualize.visualize_episode", "_Episode"),
    # The O5 carve-outs: the stale-`served/*.jsonl` glob (the launcher's door), the
    # path-taking readers and their one caller each, and the containment arithmetic. Rev 3 (R1) removes
    # `episode._answers` and `episode.delta_o`: `delta_o` reads the base and each world's served
    # file through its one `bind` (`read_jsonl(LAYOUT.served_base)`, `read_jsonl(LAYOUT.
    # served_world(token))`), naming no path.
    ("learning.branch.cli", "prepare_episode"),
    ("learning.branch.ledger", "Ledger._absorb"),
    ("learning.judge.family", "leads_by_id"),
    ("scripts.visualize.visualize_episode", "_load_world_leads"),
})
_O5_CALLS = frozenset({"EpisodePaths", "base_file", "staged_path"})

#: The doors D3' names, and #1224's pre-flight: where `Episode.open` / `Episode.create` may be
#: called. `grade_episode`'s one orchestration body `_grade_episode` (where its `bind` is today)
#: counts as the door.
DOORS = frozenset({
    ("learning.branch.cli", "prepare_episode"),
    ("run", "main"),
    ("learning.judge", "grade_episode"),
    ("learning.judge", "_grade_episode"),
    ("scripts.visualize.visualize_episode", "render_episode"),
    ("learning.branch.cli", "preflight_replay"),
})
#: Callers D3' does not place but whose callees take the `Episode`: the page script's `main`
#: hands one to `_write_page`, and may open its own. Rev 3 (R1) removes `delta_o`: it opens no
#: `Episode`, reading the manifest as `load_family(bound)` through its one `bind`.
DOORS_TOLERATED = frozenset({
    ("scripts.visualize.visualize_episode", "main"),
})
#: What the doors must call, so the scan is not vacuous: `(module, function-or-alternatives,
#: verb)`.
DOORS_REQUIRED = (
    ("learning.branch.cli", ("prepare_episode",), "create"),
    ("run", ("main",), "open"),
    ("learning.branch.cli", ("preflight_replay",), "open"),
    # #1105 PR 2 (decision C, declared changes 3 and 4): the judge's and the page's doors take an
    # episode id and hold their `Episode` through the tenant's runs repository
    # (`runs.episode_files(ep)`, `runs.episode(ep)`), which opens it by id — so neither calls
    # `Episode.open` itself any more.
)


class _Functions(ast.NodeVisitor):
    """Every `def` with its qualified name (enclosing classes and `def`s joined with `.`)."""

    def __init__(self) -> None:
        self.stack: list[str] = []
        self.defs: list[tuple[str, ast.FunctionDef | ast.AsyncFunctionDef]] = []

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()

    def _def(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self.stack.append(node.name)
        self.defs.append((".".join(self.stack), node))
        self.generic_visit(node)
        self.stack.pop()

    visit_FunctionDef = _def
    visit_AsyncFunctionDef = _def


def _annotation(node: ast.expr | None) -> ast.expr | None:
    """A parameter's annotation as an expression (a quoted one parsed)."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        try:
            return ast.parse(node.value, mode="eval").body
        except SyntaxError:
            return None
    return node


def _members(node: ast.expr) -> list[ast.expr]:
    """A union's members, `None` dropped (`X | None`, `Optional[X]`, `Union[X, Y]`)."""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        return _members(node.left) + _members(node.right)
    if isinstance(node, ast.Subscript):
        head = _type_name(node.value)
        if head in ("Optional", "Union"):
            inner = node.slice
            parts = inner.elts if isinstance(inner, ast.Tuple) else [inner]
            return [m for p in parts for m in _members(p)]
    if isinstance(node, ast.Constant) and node.value is None:
        return []
    if isinstance(node, ast.Name) and node.id == "None":
        return []
    return [node]


def _type_name(node: ast.expr) -> str | None:
    """A member's outer type name: `Path`, `os.PathLike[str]` -> `PathLike`, `dict[...]` ->
    `dict`."""
    if isinstance(node, ast.Subscript):
        return _type_name(node.value)
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _path_typed(ann: ast.expr | None) -> bool:
    """A concrete path type, optionally unioned with `str` / `bytes` / `None`."""
    if ann is None:
        return False
    names = [_type_name(m) for m in _members(ann)]
    return (bool(names) and all(n in _PATH_TYPES | _TEXT_TYPES for n in names)
            and any(n in _PATH_TYPES for n in names))


def _names_no_path(ann: ast.expr | None) -> bool:
    """An annotation that names neither a path type nor `str` / `bytes` anywhere at its top
    level (`dict[str, Any]`, `Held`): the named parameter is not a path."""
    if ann is None:
        return False
    names = [_type_name(m) for m in _members(ann)]
    return bool(names) and not any(n in _PATH_TYPES | _TEXT_TYPES for n in names)


def _o5_flagged(name: str, ann: ast.expr | None) -> bool:
    if name in _O5_EXEMPT_EXACT or name.startswith(_O5_EXEMPT_PREFIX):
        return False
    named = name in _O5_NAMED or name.endswith("_path")
    if named and not _names_no_path(ann):
        return True
    return _path_typed(ann) and name not in OUTSIDE_EPISODE


def o5_params(module: str, tree: ast.Module) -> set[tuple[str, str, str]]:
    """Every `(module, function, parameter)` O5's parameter rule flags."""
    found = _Functions()
    found.visit(tree)
    out = set()
    for qual, node in found.defs:
        a = node.args
        params = [*a.posonlyargs, *a.args, *a.kwonlyargs,
                  *([a.vararg] if a.vararg else []), *([a.kwarg] if a.kwarg else [])]
        for arg in params:
            if _o5_flagged(arg.arg, _annotation(arg.annotation)):
                out.add((module, qual, arg.arg))
    return out


def _scoped_calls(tree: ast.Module) -> list[tuple[str, ast.Call]]:
    seen = _Scoped()
    seen.visit(tree)
    return seen.calls


def o5_calls(module: str, tree: ast.Module) -> set[tuple[str, str, str]]:
    """Every `(module, scope, name)` call of `EpisodePaths` / `base_file` / `staged_path`,
    resolved through import aliases, as a module attribute, bare, or on any receiver."""
    env = _astlib().module_env(tree)
    out = set()
    for where, call in _scoped_calls(tree):
        origin = _astlib().callee(call, env)
        f = call.func
        name = (origin.rsplit(".", 1)[-1] if origin is not None
                else f.id if isinstance(f, ast.Name)
                else f.attr if isinstance(f, ast.Attribute) else None)
        if name in _O5_CALLS:
            out.add((module, where, name))
    return out


_EPISODE = "Episode"
_DOOR_VERBS = frozenset({"open", "create"})
#: The builtins that reach into a class by name: a hit on `Episode` whatever attribute they ask.
_CLASS_REACH = frozenset({"builtins.getattr", "builtins.vars"})


def _class_of_value(node: ast.expr, env: Any) -> bool:
    """`type(v)` or `v.__class__`: a value's class, which may be an `Episode`."""
    if isinstance(node, ast.Call):
        return _astlib().callee(node, env) == "builtins.type" and len(node.args) == 1
    return isinstance(node, ast.Attribute) and node.attr == "__class__"


def _door_key(node: ast.expr, env: Any, aliases: dict[str, str]) -> str | None:
    """What an expression names among the handle's doors: `"Episode"` (the class), `"Episode.open"`
    / `"Episode.create"`, or `None`. Resolved through import aliases, module attributes and
    module-level assignment aliases (`_Ep = Episode`, `_reopen = Episode.open`); a door verb on a
    value's class (`type(ep).open`, `ep.__class__.create`) counts as the door."""
    if isinstance(node, ast.Name) and node.id in aliases:
        return aliases[node.id]
    if isinstance(node, ast.Attribute) and node.attr in _DOOR_VERBS and (
            _class_of_value(node.value, env) or _door_key(node.value, env, aliases) == _EPISODE):
        return f"{_EPISODE}.{node.attr}"
    if not isinstance(node, (ast.Name, ast.Attribute)):
        return None
    parts = (_astlib().origin(node, env) or ast.unparse(node)).split(".")
    if parts[-1] == _EPISODE:
        return _EPISODE
    if len(parts) >= 2 and parts[-2] == _EPISODE and parts[-1] in _DOOR_VERBS:
        return f"{_EPISODE}.{parts[-1]}"
    return None


def o5_doors(module: str, tree: ast.Module) -> set[tuple[str, str, str]]:
    """Every `(module, scope, verb)` use of `Episode.open` / `Episode.create` — a call, and any
    other reference (a module-level alias's right-hand side, an argument, a default) — resolved
    through import aliases, module attributes and module-level assignment aliases (the census's
    `module_aliases`), plus a door verb on a value's class; and every `getattr` / `vars` reach
    into the `Episode` class (verb `getattr` / `vars`), whatever it asks for."""
    env = _astlib().module_env(tree)
    aliases = module_aliases(tree, env, _door_key)
    seen = _Scoped()
    seen.visit(tree)
    out = set()
    for where, call in seen.calls:
        named = _door_key(call.func, env, aliases)
        if named is not None and named != _EPISODE:
            out.add((module, where, named.rsplit(".", 1)[1]))
        reach = _astlib().callee(call, env)
        if reach in _CLASS_REACH and call.args and (
                _class_of_value(call.args[0], env)
                or _door_key(call.args[0], env, aliases) == _EPISODE):
            out.add((module, where, reach.removeprefix("builtins.")))
    for where, node in seen.refs:
        named = _door_key(node, env, aliases)
        if named is not None and named != _EPISODE:
            out.add((module, where, named.rsplit(".", 1)[1]))
    return out


def _within(where: str, function: str) -> bool:
    return where == function or where.startswith(function + ".")


def _allowed(hit: tuple[str, str, str], allowed: Iterable[tuple[str, str]]) -> bool:
    return any(hit[0] == module and _within(hit[1], fn) for module, fn in allowed)


def _o5_collect(scan: Any) -> set[tuple[str, str, str]]:
    found: set[tuple[str, str, str]] = set()
    for rel in O5_MODULES:
        found |= scan(_module_name(rel), _parse(PACKAGE / rel))
    return found


def test_o5_no_function_takes_a_path_below_the_episode_dir_but_the_allowlist():
    """O5 / D6' (parameters): across the O5 modules, every flagged parameter is on
    `PARAM_ALLOWLIST` (or tolerated), and every allowlist row is still flagged on the tree. A
    writer takes the `Episode`, a path-seam reader the `Episode` or a view."""
    found = _o5_collect(o5_params)
    allowed = {row[:3] for row in PARAM_ALLOWLIST}
    extra = sorted(found - allowed - PARAM_TOLERATED)
    stale = sorted(allowed - found)
    report = ("O5's parameter scan differs from its allowlist.\n"
              + "".join(f"  takes a path below the episode dir (take the Episode or a view): "
                        f"{e}\n" for e in extra)
              + "".join(f"  allowlist row gone (remove it from PARAM_ALLOWLIST): {m}\n"
                        for m in stale))
    assert not extra, report
    assert not stale, report


def test_o5_episode_paths_base_file_and_staged_path_are_called_only_by_root_readers():
    """O5 / D6' (calls): `EpisodePaths(`, `base_file(` and `staged_path(` are called only in
    `NB_READERS`. A writer reaches a path through the `Episode`'s own records (`.path`), and a
    judge or page reader through the view it was handed."""
    found = _o5_collect(o5_calls)
    extra = sorted(hit for hit in found if not _allowed(hit, NB_READERS))
    assert not extra, (
        "names a path below the episode dir outside a root-binding reader (take the Episode's "
        "record, or a view):\n" + "".join(f"  {e}\n" for e in extra))


def test_o5_only_the_doors_open_or_create_an_episode():
    """O5 / D3' / D6' (doors): `Episode.open` / `Episode.create` are called only in the doors
    (plus the tolerated callers D3' does not place); and `cli.prepare_episode` creates, and
    `run.main`, `grade_episode`, `render_episode` and `cli.preflight_replay` open, so the scan
    is not vacuous."""
    found = _o5_collect(o5_doors)
    extra = sorted(hit for hit in found if not _allowed(hit, DOORS | DOORS_TOLERATED))
    missing = [
        (module, fns, verb) for module, fns, verb in DOORS_REQUIRED
        if not any(hit[0] == module and hit[2] == verb and any(_within(hit[1], fn) for fn in fns)
                   for hit in found)]
    assert not extra, (
        "opens or creates an Episode outside a door (take the door's Episode instead):\n"
        + "".join(f"  {e}\n" for e in extra))
    assert not missing, f"a door that must open or create its Episode does not: {missing}"


def test_o5_the_episodes_only_constructors_are_its_two_doors():
    """The door scan keys on `Episode.open` / `Episode.create`, so those must be the only ways to
    have an `Episode`: its public class- and static methods are exactly `open` and `create`
    (a third, `Episode.at(d)`, would be a door no scan looks for), and `_episode_handle`
    defines no public module-level function (an `open_episode(d)` wrapper would be one too)."""
    handle_mod = importlib.import_module("defender._episode_handle")
    episode = handle_mod.Episode
    constructors = {
        n for n in dir(episode) if not n.startswith("_")
        and isinstance(inspect.getattr_static(episode, n), (classmethod, staticmethod))}
    assert constructors == {"open", "create"}, (
        f"the Episode's public class/static methods are {sorted(constructors)}, not exactly "
        "the doors open and create")
    functions = {n for n, v in vars(handle_mod).items() if not n.startswith("_")
                 and inspect.isfunction(v) and v.__module__ == handle_mod.__name__}
    assert functions == set(), (
        f"_episode_handle defines public functions {sorted(functions)}: a door outside "
        "Episode.open / Episode.create")
