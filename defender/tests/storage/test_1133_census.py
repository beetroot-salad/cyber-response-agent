"""Census: every write into an episode tree goes through the Episode handle, the handle reaches the core only by hold / hold_new and the Held verbs, and no function takes a path to something below the episode dir."""
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
from defender.tests.support.shared.contracts import _census1134 as C

#: The `defender` package's own directory (a namespace package: located through a module in it).
PACKAGE = Path(_io.__file__).resolve().parent

#: D6's module list, plus `run.py` and the readers D6' adds to the O5 scan (the census scans
#: them too: none may make an episode write around the handle).
MODULES = (
    "learning/branch/cli.py",
    "learning/branch/preflight.py",
    "learning/branch/verification.py",
    "learning/branch/questioner_launch.py",
    "learning/branch/timing.py",
    "learning/branch/archive.py",
    "learning/branch/capture.py",
    "learning/branch/ledger.py",
    "learning/branch/outcome.py",
    "learning/judge/__init__.py",
    "learning/judge/_grade_record.py",
    "learning/judge/_records.py",
    "learning/judge/enqueue.py",
    "runtime/branch/_family.py",
    "presentation/visualize_episode.py",
    "presentation/episode_models.py",
    "presentation/episode_transcript.py",
    "presentation/episode_worlds.py",
    "presentation/episode_verdict.py",
    "presentation/episode_findings.py",
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
# The facade re-exports these owners; the resolver follows imports to their definitions.
_IO_MODULES = frozenset({_IO, "defender._filesystem.write", "defender._filesystem.bound",
                         "defender._filesystem.json"})
RAW_OS = frozenset({
    "open", "makedirs", "mkdir", "write", "fdopen", "link", "symlink", "rename", "renames",
    "replace", "unlink", "remove", "removedirs", "rmdir", "truncate", "mkfifo", "mknod",
})
_RAW_OS_ORIGINS = frozenset(f"os.{op}" for op in RAW_OS)
OPENERS = frozenset({"builtins.open", "io.open", "codecs.open"})
ATTR_CALLS = frozenset({"open", "mkdir", "write_text", "write_bytes", "unlink", "rmdir", "touch",
                        "symlink_to", "hardlink_to", "link_to", "rename", "replace",
                        "read_text", "read_bytes"})
assert ATTR_CALLS <= C.ATTRS, sorted(ATTR_CALLS - C.ATTRS)
#: The modules a `getattr(<module>, "...")` or `vars(<module>)` may not reach into.
_GETATTR_MODULES = frozenset({*_IO_MODULES, "os", "shutil"})
#: The modules a dynamic import may not bind.
_DYNAMIC_MODULES = frozenset({*_GETATTR_MODULES, "io", "codecs"})
_DYNAMIC_IMPORTS = frozenset({"importlib.import_module", "builtins.__import__"})

#: The residue D6' leaves, exactly, re-derived on the final tree.
RESIDUE = frozenset({
    ("learning.branch.archive", "_screen_destinations", ".unlink"),
    ("learning.branch.archive", "archive_episode", "shutil.copy2"),
    ("learning.branch.archive", "archive_episode", "shutil.copytree"),
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
_HELD_NAMED_VERBS = frozenset({"mkdir", "unlink"})
_BUILTINS = frozenset(dir(builtins))


def _astlib() -> Any:
    """The gates' shared name resolver (`tooling/lint/_astlib.py`), imported the way the suites
    reach it: "where does this call come from", resolved through aliases and scopes."""
    from defender.tests.support.shared.contracts._by_path import import_lint_lib

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
    if origin.rpartition(".")[0] in _IO_MODULES:
        name = last
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
        if inspect.isfunction(obj) and obj.__module__ in _IO_MODULES
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
            origin is None or origin.rpartition(".")[0] in _IO_MODULES):
        return name
    return None


def handle_scan(tree: ast.Module) -> tuple[list[tuple[str, str]], set[str]]:
    """The handle module's I/O outside `Held` and its core, and the core calls it makes.

    Returns `(violations, core)`: `violations` are `(scope, callee)` pairs, `core` the subset of
    `CORE` the module calls."""
    scan = _scan("episodes/_episode_handle.py", tree)
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
    violations, core = handle_scan(_parse(PACKAGE / "episodes/_episode_handle.py"))
    assert not violations, (
        f"the handle does I/O around its held root: {sorted(set(violations))}")
    assert core == set(CORE), (
        f"the handle never calls {sorted(CORE - core)} — `Episode.open` is one `io.hold`, "
        "`Episode.create` one `io.hold_new`")


#: O5's exemptions by name, as D6' words them: the episode dir itself, the episodes root, a
#: source run, a run dir.
_O5_EXEMPT_EXACT = frozenset({"episode_dir", "episodes_root"})
_O5_EXEMPT_PREFIX = ("source", "run_dir")
#: O5's named parameters.
_O5_NAMED = frozenset({"path", "manifest", "draw_dir", "world_dir"})
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
    ("learning.judge", "_memoized_show.invoke", "path", _GIT),
    ("learning.judge.render", "_git_show_default", "path", _GIT),
    ("run", "_Investigate.__call__", "alert_path", _ALERT),
    ("run", "_drive_investigation", "alert_path", _ALERT),
    ("run", "_materialize_run", "alert", _ALERT),
    ("run", "_materialize_run", "settings",
     "the run copy's settings file: a host path of the tenant's settings dir the builder copies "
     "into the run dir (#1108 P4), not a path below an episode dir"),
})
PARAM_TOLERATED = frozenset({
    ("run", "resume_world", "manifest"),
})

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
    # read_manifest consumes the walked Bound; it needs no path-construction exception.
    ("learning.judge.family", "grade_family"),
    ("learning.judge.family", "_grade_world"),
    ("learning.judge.family", "_repository_leads"),
    ("learning.judge.render", "render"),
    ("learning.judge.render", "_render_bound_world"),
    ("presentation.visualize_episode", "load_episode"),
    ("presentation.visualize_episode", "_read_grade"),
    ("presentation.visualize_episode", "_Episode"),
    ("learning.branch.cli", "prepare_episode"),
    ("learning.branch.ledger", "Ledger._absorb"),
    ("learning.judge.family", "leads_by_id"),
    ("presentation.visualize_episode", "_load_world_leads"),
})
_O5_CALLS = frozenset({"EpisodePaths", "base_file", "staged_path"})

DOORS: frozenset[tuple[str, str]] = frozenset()
DOORS_TOLERATED: frozenset[tuple[str, str]] = frozenset()
WALK_OWNER_DIR = "run_repository"
WALK_DOORS_REQUIRED = ("create", "open")
WALK_CALLS_REQUIRED = (
    ("learning.branch.cli", "create_episode", None),
    ("run", "episode", "require_roster"),
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
    found = _o5_collect(o5_calls)
    extra = sorted(hit for hit in found if not _allowed(hit, NB_READERS))
    assert not extra, (
        "names a path below the episode dir outside a root-binding reader (take the Episode's "
        "record, or a view):\n" + "".join(f"  {e}\n" for e in extra))


def _method_calls(module: str, tree: ast.Module) -> set[tuple[str, str, frozenset[str]]]:
    out = set()
    for _where, call in _scoped_calls(tree):
        if isinstance(call.func, ast.Attribute):
            out.add((module, call.func.attr,
                     frozenset(k.arg for k in call.keywords if k.arg is not None)))
    return out


def _walk_calls_missing(found: set[tuple[str, str, frozenset[str]]]) -> list[tuple[str, str, Any]]:
    return [(module, method, keyword) for module, method, keyword in WALK_CALLS_REQUIRED
            if not any(m == module and name == method and (keyword is None or keyword in kws)
                       for m, name, kws in found)]


def test_o5_only_the_doors_open_or_create_an_episode():
    found = _o5_collect(o5_doors)
    extra = sorted(hit for hit in found if not _allowed(hit, DOORS | DOORS_TOLERATED))
    owner: set[tuple[str, str, str]] = set()
    for path in sorted((PACKAGE / WALK_OWNER_DIR).glob("*.py")):
        owner |= o5_doors(_module_name(f"{WALK_OWNER_DIR}/{path.name}"), _parse(path))
    owner_missing = [verb for verb in WALK_DOORS_REQUIRED if not any(h[2] == verb for h in owner)]
    calls: set[tuple[str, str, frozenset[str]]] = set()
    for rel in O5_MODULES:
        calls |= _method_calls(_module_name(rel), _parse(PACKAGE / rel))
    missing = _walk_calls_missing(calls)
    assert not extra, (
        "opens or creates an Episode outside the runs repository's walk (take the walked "
        "view's episode instead):\n" + "".join(f"  {e}\n" for e in extra))
    assert not owner_missing, (
        f"the walk owner ({WALK_OWNER_DIR}/) does not call Episode.{owner_missing} — the episode "
        f"is opened or created somewhere the door scans do not look: {sorted(owner)}")
    assert not missing, f"a former door does not reach the runs repository's walk: {missing}"


def test_o5_the_walk_call_census_finds_what_it_is_meant_to_find():
    good_cli = ast.parse("def launch(runs):\n    return runs.create_episode()\n")
    good_run = ast.parse("def main(runs, ep, label):\n"
                         "    return runs.episode(ep, require_roster=True)\n")
    assert _walk_calls_missing(_method_calls("learning.branch.cli", good_cli)
                               | _method_calls("run", good_run)) == []
    bare_ref = ast.parse("def launch(runs):\n    door = runs.create_episode\n    return door\n")
    no_kw = ast.parse("def main(runs, ep):\n    return runs.episode(ep)\n")
    assert _walk_calls_missing(_method_calls("learning.branch.cli", bare_ref)
                               | _method_calls("run", no_kw)) == [
        ("learning.branch.cli", "create_episode", None), ("run", "episode", "require_roster")]
    elsewhere = _method_calls("learning.judge", good_cli) | _method_calls("learning.judge", good_run)
    assert len(_walk_calls_missing(elsewhere)) == 2



def test_o5_the_episodes_only_constructors_are_its_two_doors():
    handle_mod = importlib.import_module("defender.episodes._episode_handle")
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
