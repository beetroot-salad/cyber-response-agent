#!/usr/bin/env python3
"""Run-layout fence (#1105 D7): outside the runs repository and its owner modules, production
code may not take a run-folder layout name, an episode-runs name, `Tenant.runs` or a run-handle
constructor, except where a category below exempts it or the allow-list names the use.

It is an INTERIM fence (#1105 rev 4.1 F): it exists because the repository still hands out
paths (`run.run_dir`, a member's `.path`), and it goes when #1082 stops handing them out. PR 1's
allow-list named every unmigrated use; PR 2 migrated each and emptied it (D7″), so a new use
has no hatch but an owner hand-out.

What is gated:

* every layout name the door (`defender.run_repository`) serves, read from the swept tree's
  `run_repository/_layout.py` (its public module-level bindings, of every form), minus the
  eight `HELPERS`. A new export is gated until it is listed. Exempt in the layout-exempt
  categories below;
* the episode-runs names: `EpisodePaths.runs` / `.sibling_run_dir`, `EpisodeLayout.runs` /
  `.run` / `.run_page` / `.sibling_run_dir`, `Episode.runs` and `RUNS_DIRNAME`;
* `Tenant.runs`;
* the handle constructors: a call `Run(...)` / `ArchivedWorld(...)`, and any reference to
  `Run.at`, `Run.for_tenant`, `Run.under` or `ArchivedWorld.at`; and the repository's own
  constructors, a call `RunsRepository(...)` / `EpisodeRuns(...)` (#1105 PR 2: the accepted
  `Tenant` hands the repository out, and the repository the episode view). Importing any of
  them for a type is not gated.

The last three are gated in every category but the owners.

What is flagged: every import of a gated layout name or `RUNS_DIRNAME` wherever it sits
(function bodies, `try`, `if TYPE_CHECKING:`), under any static spelling (aliased, relative at
any depth, from a relay module, read off a module alias of the door or `_layout`); a star import
from the door or an owner; a read, write or delete of a gated member on a receiver typed as its
owner class — through a parameter or local annotation (`Optional`, `X | None`, a string), an
annotated return, a dataclass field, a `with` / `async with` / `for` / comprehension target, the
walrus, `Episode.open(...)` — and a class-level read (`Tenant.runs`). A re-export is flagged at
the relay's own import.

Recorded gaps (not flagged): `getattr` / `importlib` routes, untyped receivers, a plain class
alias or subclass, `type()` / `__class__`, `__new__`, copies, and the binding forms not listed
above (`match`, `except ... as`, tuple targets).

The allow-list is the only hatch — there is no inline suppression. An entry is
`(module, enclosing qualified function or "<module>", gated name, count)`; a use beyond its
count, a use in another function and an unlisted use are findings, and so are a stale entry
(count above the uses) and a duplicate entry. Decorators and defaults key under the scope
that evaluates them; a lambda keys under the def it sits in. An annotation is not a use and is
not scanned for one (it still types a receiver, above).

Sweep: `defender/` minus `evals/` and `tests/`, every `__pycache__`, hidden directory and venv
(`venv`, `.venv`, or a directory holding `pyvenv.cfg`). A module that does not parse or decode
is a finding, never skipped.

Run from anywhere:  python scripts/lint/lint_run_layout_imports.py [--root DIR]
"""
from __future__ import annotations

import argparse
import ast
import collections
import dataclasses
import sys
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path

import _astlib

#: The checkout's own `defender/`, so a run from any directory or worktree sweeps itself.
DEFENDER = Path(__file__).resolve().parents[2] / "defender"

_DOOR = "defender.run_repository"

#: The eight layout names that are not gated: predicates and shape constants (D7).
HELPERS: frozenset[str] = frozenset({
    "artifact_file", "artifact_dir", "plain_file", "contained_payload", "LEAD_ID_RE",
    "gather_summaries_shape", "is_case_answer_key", "GATHER_RAW_SHAPE",
})

_LESSONS = "learning/author/lessons/run.py"
_FORWARD = "learning/author/verify_forward/forward.py"
_CLI = "learning/branch/cli.py"
_VE = "scripts/visualize/visualize_episode.py"

#: D7's table: every production importer of the layout in exactly one row, by its path under
#: `defender/`. `owners` are exempt; the layout-exempt rows below may take layout names; a
#: module in no row gets no exemption.
CATEGORIES: Mapping[str, Sequence[str]] = {
    "owners": (
        "run_repository/__init__.py", "run_repository/_layout.py", "run_repository/_handle.py",
        "run_repository/_lookup.py", "run_repository/_record.py", "run_repository/_held.py",
        "run_repository/_id.py",
        "run_repository/_errors.py", "_episode_paths.py", "_episode_handle.py", "_tenant.py",
    ),
    # N-a: the running investigation does not migrate; its record writes are #1165.
    "running-investigation": (
        "hooks/budget_enforcer.py", "hooks/record_lead.py",
        "runtime/challenge_gate.py", "runtime/circuit_breaker.py", "runtime/close_tool.py",
        "runtime/driver/__init__.py", "runtime/driver/_build.py",
        "runtime/lead_zero/__init__.py", "runtime/lead_zero/_capture.py", "runtime/observe.py",
        "runtime/permission/files.py", "runtime/permission/policies/_common.py",
        "runtime/run_end.py", "runtime/scrub.py", "runtime/session_store.py",
        "runtime/tools/_deps.py", "runtime/tools/_document.py", "runtime/tools/_files.py",
        "runtime/tools_gather.py", "runtime/toon_gate.py", "runtime/box/_lifecycle.py",
        "runtime/branch/__init__.py", "runtime/branch/_frontier.py", "runtime/branch/_seed.py",
        "runtime/branch/_spec.py", "runtime/case_ticket.py",
        "scripts/gather_tools/record_query.py", "skills/invlang/corpus.py",
        # #1105 PR 2 (row 26): `infra_env` takes `DEFENDER_RUNS_BASE` from the run folder's
        # own hand-out (`RunPaths.runs_base_env`).
        "runtime/box/_docker.py",
    ),
    # A `/` join onto a layout value here is `lint_run_records` arm (b)'s finding, not this one.
    "names-only": (
        "_report.py", "_artifact_schema.py", "runtime/compaction.py", "learning/branch/seams.py",
        # F-09 (#1105 PR 2): learning/judge/render.py left this row (J3 took its last name).
        "learning/judge/__init__.py",
        "learning/author/verify_forward/checks.py", "learning/core/config.py",
        "scripts/workspace_map.py", "api/demo.py",
    ),
    "run-lifecycle": ("run.py", "run_common.py", "scripts/case_history/ticket_writer.py"),
    "path-taking-readers": (
        "learning/lead_repository.py", "scripts/visualize/visualize_run.py",
        "scripts/visualize/visualize_runtime.py", "scripts/visualize/visualize_messages.py",
        "scripts/visualize/visualize_data.py", "scripts/visualize/visualize_primitives.py",
        # F-09 (#1105 PR 2): D5's callers, migrated onto ids at their edges, keep reading the
        # run folder they were handed (`run.run_dir`) by its layout names.
        "learning/branch/archive.py", "learning/branch/questioner/__init__.py",
        "learning/leads/lead_author/__init__.py",
    ),
    "not-a-run": (_VE,),
    # N-f: exempt only inside the four readers in `DEFERRED_LEGACY`; #1166 deletes them.
    "deferred_legacy": (_LESSONS, _FORWARD),
    "helpers-only": (
        "learning/branch/ledger.py", "learning/judge/run.py",
        # F-09 (#1105 PR 2): the launcher opens runs by id; it keeps only the predicates.
        _CLI,
    ),
}

#: The rows whose modules may take layout names (never the other gated names).
_LAYOUT_EXEMPT_ROWS = ("running-investigation", "names-only", "run-lifecycle",
                       "path-taking-readers", "not-a-run")

#: The four legacy readers, keyed by (module, function): layout names are exempt inside them
#: only, so a use elsewhere in either module (lessons/run.py holds the live drain) is not.
DEFERRED_LEGACY: frozenset[tuple[str, str]] = frozenset({
    (_LESSONS, "disposition_for"), (_LESSONS, "_has_confident_ground_truth"),
    (_FORWARD, "load_run_context"), (_FORWARD, "expected_disposition"),
})

#: The allow-list: (module, function, name, count). PR 1 listed every unmigrated use; PR 2
#: replaced each site and emptied it (D7″'s end state). An entry is a hatch nobody should need.
ALLOW_LIST: Sequence[tuple[str, str, str, int]] = ()


#: Owner classes and their gated members, by canonical origin.
_EPISODE = "defender._episode_handle.Episode"
_EPISODE_PATHS = "defender._episode_paths.EpisodePaths"
_EPISODE_LAYOUT = "defender._episode_paths.EpisodeLayout"
_TENANT = "defender._tenant.Tenant"
_RUN = f"{_DOOR}.Run"
_ARCHIVED = f"{_DOOR}.ArchivedWorld"
_REPOSITORY = f"{_DOOR}.RunsRepository"
_EPISODE_VIEW = f"{_DOOR}.EpisodeRuns"
_GATED_MEMBERS: dict[str, frozenset[str]] = {
    _EPISODE: frozenset({"runs"}),
    _EPISODE_PATHS: frozenset({"runs", "sibling_run_dir"}),
    _EPISODE_LAYOUT: frozenset({"runs", "run", "run_page", "sibling_run_dir"}),
    _TENANT: frozenset({"runs"}),
    _RUN: frozenset({"at", "for_tenant", "under"}),
    _ARCHIVED: frozenset({"at"}),
    _REPOSITORY: frozenset(),
    _EPISODE_VIEW: frozenset(),
}
_CONSTRUCTORS = frozenset({_RUN, _ARCHIVED, _REPOSITORY, _EPISODE_VIEW})
_RUNS_DIRNAME = "RUNS_DIRNAME"
#: Star imports of these modules bind gated names wholesale.
_STAR_SOURCES = frozenset({_DOOR, "defender._episode_paths", "defender._episode_handle",
                           "defender._tenant"})

_OPTIONAL = frozenset({"Optional"})
_UNION = frozenset({"Union"})
_CONTAINERS = frozenset({
    "list", "List", "Sequence", "MutableSequence", "Iterable", "Iterator", "Collection",
    "tuple", "Tuple", "set", "Set", "frozenset", "FrozenSet", "AbstractSet", "Generator",
    "AsyncIterable", "AsyncIterator",
})
_CONTEXTS = frozenset({"AbstractContextManager", "ContextManager", "AbstractAsyncContextManager",
                       "AsyncContextManager"})


@dataclasses.dataclass(frozen=True)
class Finding:
    """One gated use (`key` set), or a stale / duplicate entry or unreadable module (`key`
    None). `display` names the module, the function and the name."""

    key: tuple[str, str, str] | None
    display: str


def canonical(origin: str) -> str:
    """A run-repository origin in its door spelling (`_astlib.door_spelling`):
    `defender.run_repository._layout.X` and `defender.run_repository.X` are one name."""
    return _astlib.door_spelling(origin)


# ==========================================================================================
# What a module binds, and what an expression's type is: the receiver typing.
# ==========================================================================================

Type = tuple[str, str]  # (kind: "val" | "iter" | "cm", canonical class origin)


@dataclasses.dataclass
class _Module:
    """One module's static facts: its `_astlib` scope tree (what each name is bound to, after
    real scoping), and the shapes of its own top-level classes, functions and values."""

    name: str
    package: str
    env: _astlib.ModuleEnv
    classes: dict[str, ast.ClassDef]
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef]
    values: dict[str, ast.expr]  # module-level `NAME = <expr>` / `NAME: <ann>`

    def imported(self, name: str) -> str | None:
        """What a module-level import binds `name` to, absolute and canonical."""
        dotted = self.env.imports.get(name)
        return canonical(dotted) if dotted else None


def _module_facts(rel: str, tree: ast.Module) -> _Module:
    classes: dict[str, ast.ClassDef] = {}
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    values: dict[str, ast.expr] = {}
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            classes[node.name] = node
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions[node.name] = node
        elif isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(
                node.targets[0], ast.Name):
            values[node.targets[0].id] = node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            values[node.target.id] = node.annotation if node.value is None else node.value
    module, package = _astlib.module_and_package(rel)
    return _Module(module, package, _astlib.module_env(tree, module=module, package=package),
                   classes, functions, values)


class _Program:
    """The swept tree's modules, parsed on demand, so a receiver's type can be read from the
    module that defines it (`Episode.open`'s return, `RunTenant.tenant`, `LAYOUT`'s class)."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self._cache: dict[str, _Module | None] = {}

    def add(self, mod: _Module) -> None:
        self._cache[mod.name] = mod

    def module(self, dotted: str) -> _Module | None:
        if dotted in self._cache:
            return self._cache[dotted]
        found: _Module | None = None
        if dotted.startswith("defender."):
            rel = Path(*dotted.split(".")[1:])
            for cand in (rel.with_suffix(".py"), rel / "__init__.py"):
                path = self.root / cand
                if path.is_file():
                    try:
                        tree = _astlib.parse_source(path.read_text(encoding="utf-8"), cand.as_posix())
                    except (_astlib.ScanBlind, OSError, UnicodeDecodeError):
                        break  # the sweep reports the file itself; here it only types nothing
                    found = _module_facts(cand.as_posix(), tree)
                    break
        self._cache[dotted] = found
        return found

    def split(self, origin: str) -> tuple[_Module, str] | None:
        """The module defining `origin` and the name within it (the longest module prefix)."""
        parts = origin.split(".")
        for cut in range(len(parts) - 1, 0, -1):
            mod = self.module(".".join(parts[:cut]))
            if mod is not None:
                return mod, ".".join(parts[cut:])
        return None

    def resolve(self, origin: str, depth: int = 0) -> str:
        """Follow a re-binding (`from x import Y` in the defining module) to the class's own
        origin; class origins stay as they are."""
        origin = canonical(origin)
        if depth > 5 or origin.startswith(_DOOR + "."):
            return origin
        hit = self.split(origin)
        if hit is None:
            return origin
        mod, name = hit
        target = mod.imported(name) if "." not in name and name not in mod.classes else None
        if target is not None:
            return self.resolve(target, depth + 1)
        return origin

    def class_def(self, origin: str) -> tuple[_Module, ast.ClassDef] | None:
        hit = self.split(origin)
        if hit is None:
            return None
        mod, name = hit
        cls = mod.classes.get(name)
        return (mod, cls) if cls is not None else None

    def function_def(self, origin: str) -> tuple[_Module, ast.FunctionDef | ast.AsyncFunctionDef] | None:
        hit = self.split(origin)
        if hit is None:
            return None
        mod, name = hit
        fn = mod.functions.get(name)
        return (mod, fn) if fn is not None else None


def _annotation_type(node: ast.expr | None, mod: _Module, prog: _Program,
                     local_classes: Mapping[str, str] | None = None) -> Type | None:
    """The owner type an annotation names: `X`, `Optional[X]`, `X | None`, `"X"`, a container
    of X (`("iter", X)`) or a context manager of X (`("cm", X)`)."""
    if node is None:
        return None
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        try:
            node = ast.parse(node.value, mode="eval").body
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            return None
        return _annotation_type(node, mod, prog, local_classes)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        return (_annotation_type(node.left, mod, prog, local_classes)
                or _annotation_type(node.right, mod, prog, local_classes))
    if isinstance(node, ast.Subscript):
        base = _dotted(node.value)
        head = base.rpartition(".")[2] if base else ""
        args = node.slice.elts if isinstance(node.slice, ast.Tuple) else [node.slice]
        if head in _OPTIONAL or head in _UNION:
            for arg in args:
                got = _annotation_type(arg, mod, prog, local_classes)
                if got is not None:
                    return got
            return None
        inner = _annotation_type(args[0], mod, prog, local_classes) if args else None
        if inner is None or inner[0] != "val":
            return None
        if head in _CONTAINERS:
            return ("iter", inner[1])
        if head in _CONTEXTS:
            return ("cm", inner[1])
        return None
    if isinstance(node, (ast.Name, ast.Attribute)):
        origin = _name_origin(node, mod, local_classes)
        if origin is None:
            return None
        return ("val", prog.resolve(origin))
    return None


def _dotted(node: ast.expr) -> str | None:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    return ".".join([node.id, *reversed(parts)])


def _name_origin(node: ast.expr, mod: _Module,
                 local_classes: Mapping[str, str] | None = None) -> str | None:
    """The canonical dotted origin of a `Name.attr...` chain: a top-level definition of `mod`,
    or what `_astlib.origin` resolves it to in the scope it sits in (None for a local)."""
    root = node
    while isinstance(root, ast.Attribute):
        root = root.value
    if not isinstance(root, ast.Name):
        return None
    dotted = _dotted(node) or ""
    head, _, rest = dotted.partition(".")
    if head in mod.classes or head in mod.functions or head in mod.values:
        base = f"{mod.name}.{head}"
        return canonical(f"{base}.{rest}" if rest else base)
    if local_classes and head in local_classes:
        return canonical(f"{local_classes[head]}.{rest}" if rest else local_classes[head])
    origin = _astlib.origin(node, mod.env)
    return canonical(origin) if origin else None


def _dataclass_fields(cls: ast.ClassDef) -> dict[str, ast.expr]:
    return {n.target.id: n.annotation for n in cls.body
            if isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name)}


def _method(cls: ast.ClassDef, name: str) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    for n in cls.body:
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name:
            return n
    return None


# ==========================================================================================
# The scan of one module.
# ==========================================================================================

@dataclasses.dataclass
class _Use:
    function: str
    name: str
    lineno: int


class _Scanner:
    """One module's gated uses, each keyed by its enclosing qualified function."""

    def __init__(self, rel: str, tree: ast.Module, prog: _Program, layout: frozenset[str]):
        self.rel = rel
        self.tree = tree
        self.prog = prog
        self.layout = layout
        self.mod = _module_facts(rel, tree)
        prog.add(self.mod)
        self.package = self.mod.package
        self.uses: list[_Use] = []
        self._import_nodes: set[int] = set()

    # -- typing ---------------------------------------------------------------------------------

    def _ref(self, node: ast.expr, env: Mapping[str, Type]) -> str | None:
        """The canonical origin `node` statically names (a class, function or value), or None
        for a local value."""
        if self._rooted_in_env(node, env):
            return None
        origin = _name_origin(node, self.mod)
        return self.prog.resolve(origin) if origin is not None else None

    def _class_ref(self, node: ast.expr, env: Mapping[str, Type]) -> str | None:
        """The class (canonical origin) `node` names, when it is a static reference to one."""
        origin = self._ref(node, env)
        if origin is None or not (origin in _GATED_MEMBERS
                                  or self.prog.class_def(origin) is not None):
            return None
        return origin

    def _value_type(self, origin: str) -> Type | None:
        """The type of a module-level value (`LAYOUT = EpisodeLayout()`, `X: Tenant`)."""
        hit = self.prog.split(origin)
        if hit is None:
            return None
        mod, name = hit
        expr = mod.values.get(name)
        if expr is None:
            return None
        if isinstance(expr, ast.Call):
            cls = _name_origin(expr.func, mod)
            return ("val", self.prog.resolve(cls)) if cls else None
        return _annotation_type(expr, mod, self.prog)

    def _returns(self, origin: str) -> Type | None:
        fn = self.prog.function_def(origin)
        if fn is not None:
            return _annotation_type(fn[1].returns, fn[0], self.prog)
        return None

    def _member_type(self, cls_origin: str, attr: str, *, call: bool) -> Type | None:
        hit = self.prog.class_def(cls_origin)
        if hit is None:
            return None
        mod, cls = hit
        if call:
            meth = _method(cls, attr)
            return _annotation_type(meth.returns, mod, self.prog) if meth else None
        field = _dataclass_fields(cls).get(attr)
        if field is not None:
            return _annotation_type(field, mod, self.prog)
        meth = _method(cls, attr)  # a property's annotated return
        if meth is not None and any(_dotted(d) in ("property", "functools.cached_property",
                                                   "cached_property") for d in meth.decorator_list):
            return _annotation_type(meth.returns, mod, self.prog)
        return None

    def type_of(self, node: ast.expr, env: Mapping[str, Type]) -> Type | None:
        if isinstance(node, ast.Name):
            if node.id in env:
                return env[node.id]
            origin = _name_origin(node, self.mod)
            return self._value_type(origin) if origin else None
        if isinstance(node, ast.NamedExpr):
            return self.type_of(node.value, env)
        if isinstance(node, ast.Await):
            return self.type_of(node.value, env)
        if isinstance(node, ast.Attribute):
            origin = None if self._rooted_in_env(node, env) else _name_origin(node, self.mod)
            if origin is not None:
                got = self._value_type(origin)
                if got is not None:
                    return got
            recv = self.type_of(node.value, env)
            if recv is not None and recv[0] == "val":
                return self._member_type(recv[1], node.attr, call=False)
            return None
        if isinstance(node, ast.Call):
            func = node.func
            cls = self._class_ref(func, env)
            if cls is not None:
                return ("val", cls)
            ref = self._ref(func, env)
            if ref is not None:
                ret = self._returns(ref)
                if ret is not None:
                    return ret
            if isinstance(func, ast.Attribute):
                owner = self._class_ref(func.value, env)
                if owner is not None and self.prog.class_def(owner) is not None:
                    return self._member_type(owner, func.attr, call=True)
                recv = self.type_of(func.value, env)
                if recv is not None and recv[0] == "val":
                    return self._member_type(recv[1], func.attr, call=True)
        return None

    @staticmethod
    def _rooted_in_env(node: ast.expr, env: Mapping[str, Type]) -> bool:
        while isinstance(node, ast.Attribute):
            node = node.value
        return isinstance(node, ast.Name) and node.id in env

    # -- binding forms --------------------------------------------------------------------------

    def _bind_target(self, target: ast.expr, typ: Type | None, env: dict[str, Type]) -> None:
        if isinstance(target, ast.Name) and typ is not None and typ[0] == "val":
            env[target.id] = typ

    @staticmethod
    def _element(typ: Type | None) -> Type | None:
        return ("val", typ[1]) if typ is not None and typ[0] == "iter" else None

    @staticmethod
    def _entered(typ: Type | None) -> Type | None:
        if typ is None:
            return None
        return ("val", typ[1]) if typ[0] in ("cm", "val") else None

    def _function_env(self, fn: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda,
                      outer: Mapping[str, Type]) -> dict[str, Type]:
        env = dict(outer)
        args = fn.args
        for a in (*args.posonlyargs, *args.args, *args.kwonlyargs,
                  *([args.vararg] if args.vararg else []),
                  *([args.kwarg] if args.kwarg else [])):
            env.pop(a.arg, None)
            typ = _annotation_type(getattr(a, "annotation", None), self.mod, self.prog)
            if typ is not None:
                env[a.arg] = typ
        if isinstance(fn, ast.Lambda):
            return env
        # Locals, flow-insensitively, twice so a chain (`t = f(); x = t.tenant`) settles.
        body = list(_own_nodes(fn.body))
        for _ in range(2):
            for node in body:
                if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                    typ = _annotation_type(node.annotation, self.mod, self.prog)
                    if typ is None and node.value is not None:
                        typ = self.type_of(node.value, env)
                    if typ is not None:
                        env[node.target.id] = typ
                elif isinstance(node, ast.Assign):
                    typ = self.type_of(node.value, env)
                    for t in node.targets:
                        self._bind_target(t, typ, env)
                elif isinstance(node, ast.NamedExpr):
                    self._bind_target(node.target, self.type_of(node.value, env), env)
                elif isinstance(node, (ast.With, ast.AsyncWith)):
                    for item in node.items:
                        if item.optional_vars is not None:
                            self._bind_target(item.optional_vars,
                                              self._entered(self.type_of(item.context_expr, env)),
                                              env)
                elif isinstance(node, (ast.For, ast.AsyncFor)):
                    self._bind_target(node.target, self._element(self.type_of(node.iter, env)),
                                      env)
        return env

    # -- the walk -------------------------------------------------------------------------------

    def scan(self) -> list[_Use]:
        self._walk_body(self.tree.body, "<module>", {})
        return self.uses

    def _walk_body(self, body: list[ast.stmt], scope: str, env: dict[str, Type]) -> None:
        for stmt in body:
            self._walk(stmt, scope, env)

    def _walk(self, node: ast.AST, scope: str, env: dict[str, Type]) -> None:  # noqa: C901 — one branch per scope-introducing node
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for d in node.decorator_list:
                self._walk(d, scope, env)
            for default in (*node.args.defaults, *node.args.kw_defaults):
                if default is not None:
                    self._walk(default, scope, env)
            qual = node.name if scope == "<module>" else f"{scope}.{node.name}"
            inner = self._function_env(node, env)
            self._walk_body(node.body, qual, inner)
            return
        if isinstance(node, ast.ClassDef):
            for d in (*node.decorator_list, *node.bases, *(k.value for k in node.keywords)):
                self._walk(d, scope, env)
            qual = node.name if scope == "<module>" else f"{scope}.{node.name}"
            self._walk_body(node.body, qual, env)
            return
        if isinstance(node, ast.Lambda):
            for default in (*node.args.defaults, *node.args.kw_defaults):
                if default is not None:
                    self._walk(default, scope, env)
            self._walk(node.body, scope, self._function_env(node, env))
            return
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            inner = dict(env)
            for gen in node.generators:
                self._walk(gen.iter, scope, inner)
                self._bind_target(gen.target, self._element(self.type_of(gen.iter, inner)), inner)
                for cond in gen.ifs:
                    self._walk(cond, scope, inner)
            elts = [node.key, node.value] if isinstance(node, ast.DictComp) else [node.elt]
            for e in elts:
                self._walk(e, scope, inner)
            return
        if isinstance(node, (ast.arg, ast.arguments)):
            return  # annotations name types; a type is not a use
        if isinstance(node, ast.AnnAssign):
            if node.value is not None:
                self._walk(node.value, scope, env)
            self._walk(node.target, scope, env)
            return
        if isinstance(node, ast.ImportFrom):
            self._import(node, scope)
            return
        if isinstance(node, ast.Attribute):
            if self._attribute(node, scope, env):
                return
        elif isinstance(node, ast.Call):
            cls = self._class_ref(node.func, env)
            if cls in _CONSTRUCTORS:
                self._use(scope, cls.rpartition(".")[2], node)
        for child in ast.iter_child_nodes(node):
            self._walk(child, scope, env)

    def _use(self, scope: str, name: str, node: ast.AST) -> None:
        self.uses.append(_Use(scope, name, getattr(node, "lineno", 0)))

    def _import(self, node: ast.ImportFrom, scope: str) -> None:
        source = canonical(_astlib.import_source(node, self.package))
        if not source.startswith("defender"):
            return
        for a in node.names:
            if a.name == "*":
                if source in _STAR_SOURCES:
                    self._use(scope, "*", node)
            elif self._is_layout(f"{source}.{a.name}"):
                self._use(scope, a.name, node)
            elif a.name == _RUNS_DIRNAME:
                self._use(scope, _RUNS_DIRNAME, node)

    def _is_layout(self, origin: str) -> bool:
        """Whether `origin` is a layout name, judged by where it is DEFINED: followed through
        every relay module that re-binds it (`_episode_paths.ALERT` is the door's `ALERT`), so a
        name merely spelled like a layout name elsewhere (invlang's `PROVENANCE`) is not one."""
        head, _, last = self.prog.resolve(origin).rpartition(".")
        return head == _DOOR and last in self.layout

    def _attribute(self, node: ast.Attribute, scope: str, env: Mapping[str, Type]) -> bool:
        """Flag `node` if it is a gated read; True when its value need not be walked."""
        if not self._rooted_in_env(node, env):
            origin = _name_origin(node, self.mod)
            if origin is not None:
                head, _, last = origin.rpartition(".")
                if self._is_layout(origin):
                    self._use(scope, last, node)
                    return True
                if head.startswith("defender") and last == _RUNS_DIRNAME:
                    self._use(scope, _RUNS_DIRNAME, node)
                    return True
        owner = self._class_ref(node.value, env)
        if owner is None:
            recv = self.type_of(node.value, env)
            owner = recv[1] if recv is not None and recv[0] == "val" else None
        if owner is not None and node.attr in _GATED_MEMBERS.get(owner, ()):
            self._use(scope, f"{owner.rpartition('.')[2]}.{node.attr}", node)
        return False


def _own_nodes(body: list[ast.stmt]) -> Iterator[ast.AST]:
    """Every node of a function body that is not inside a nested def, class or lambda."""
    stack: collections.deque[ast.AST] = collections.deque(body)
    while stack:
        node = stack.popleft()
        yield node
        for child in ast.iter_child_nodes(node):
            if not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef,
                                      ast.Lambda)):
                stack.append(child)


# ==========================================================================================
# The sweep.
# ==========================================================================================

def layout_names(root: Path) -> frozenset[str]:
    """The swept tree's layout universe: every public name `run_repository/_layout.py` binds at
    module level, in any form (assignment, tuple unpack, annotated, a `for` target, inside an
    `if`, a def or a class). ScanBlind when there is none to read — the file is missing,
    unreadable or binds nothing: an empty universe gates no name, so a lint that ran on it
    would pass everything (fail closed, as #1134's census does)."""
    rel = "run_repository/_layout.py"
    path = root / rel
    try:
        tree = _astlib.parse_source(path.read_text(encoding="utf-8"), rel)
    except (OSError, UnicodeDecodeError) as exc:
        raise _astlib.ScanBlind(f"{rel}: the layout universe cannot be read under {root} "
                                f"({exc.__class__.__name__}) — nothing would be gated") from None
    names: set[str] = set()
    stack: list[ast.AST] = list(tree.body)
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
            continue
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            continue
        targets: list[ast.expr] = []
        if isinstance(node, ast.Assign):
            targets = list(node.targets)
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
            targets = [node.target]
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            targets = [node.target]
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            targets = [i.optional_vars for i in node.items if i.optional_vars is not None]
        for t in targets:
            names |= {n.id for n in ast.walk(t) if isinstance(n, ast.Name)}
        for field in ("body", "orelse", "finalbody", "handlers"):
            stack.extend(getattr(node, field, []) or [])
    universe = frozenset(n for n in names if not n.startswith("_")) - HELPERS
    if not universe:
        raise _astlib.ScanBlind(f"{rel}: binds no public layout name under {root} — nothing "
                                "would be gated")
    return universe


def sweep_files(root: Path) -> list[Path]:
    """Every `.py` in the sweep, through the shared listing (`_astlib.source_files`): `root`
    minus `evals/` and `tests/`, caches, hidden directories and venvs (pruned before descent),
    and minus what git ignores."""

    def pruned(d: Path) -> bool:
        if d.name.startswith(".") or (d.parent == root and d.name == "evals"):
            return True
        try:
            return (d / "pyvenv.cfg").is_file()
        except OSError:
            return False  # unreadable: kept, so the listing reports it blind

    return [root / rel
            for rel in _astlib.source_files(root, ("__pycache__", "venv", "tests"), prune=pruned)]


def _row_of(rel: str) -> str | None:
    if rel.startswith("run_repository/"):
        return "owners"
    for row, mods in CATEGORIES.items():
        if rel in mods:
            return row
    return None


def _exempt(rel: str, row: str | None, use: _Use, layout: frozenset[str]) -> bool:
    if row == "owners":
        return True
    is_layout = use.name in layout
    if row in _LAYOUT_EXEMPT_ROWS:
        return is_layout
    if row == "deferred_legacy":
        return is_layout and (rel, use.function) in DEFERRED_LEGACY
    return False


def scan(root: Path = DEFENDER, *,
         allow_list: Sequence[tuple[str, str, str, int]] | None = None) -> list[Finding]:
    """The whole sweep of `root`, judged against `allow_list` (`None` means `ALLOW_LIST`)."""
    root = Path(root)
    entries = list(ALLOW_LIST if allow_list is None else allow_list)
    try:
        layout = layout_names(root)
    except _astlib.ScanBlind as exc:
        return [Finding(None, str(exc))]
    prog = _Program(root)
    findings: list[Finding] = []
    uses: dict[tuple[str, str, str], list[_Use]] = collections.defaultdict(list)
    for path in sweep_files(root):
        rel = path.relative_to(root).as_posix()
        row = _row_of(rel)
        if row == "owners":
            continue
        try:
            tree = _astlib.parse_source(path.read_text(encoding="utf-8"), rel)
            with _astlib.scan_guard(rel):
                found = _Scanner(rel, tree, prog, layout).scan()
        except _astlib.ScanBlind as exc:
            findings.append(Finding(None, str(exc)))
            continue
        except (OSError, UnicodeDecodeError) as exc:
            findings.append(Finding(None, f"{rel}: cannot be read ({exc.__class__.__name__}) "
                                          "— an unread module is not certified clean"))
            continue
        for use in found:
            if not _exempt(rel, row, use, layout):
                uses[(rel, use.function, use.name)].append(use)
    seen: collections.Counter[tuple[str, str, str]] = collections.Counter()
    allowed: dict[tuple[str, str, str], int] = {}
    for entry in entries:
        module, function, name, count = entry
        key = (module, function, name)
        seen[key] += 1
        if seen[key] > 1:
            findings.append(Finding(None, f"{module} {function}(): duplicate allow-list entry "
                                          f"for {name} — each use is listed once, with a count"))
            continue
        allowed[key] = count
        have = len(uses.get(key, ()))
        if have < count:
            findings.append(Finding(None, f"{module} {function}(): stale allow-list entry for "
                                          f"{name} (count {count}, {have} use(s)) — remove or "
                                          "lower it"))
    for key, found in sorted(uses.items()):
        if len(found) <= allowed.get(key, 0):
            continue
        module, function, name = key
        for use in found:
            findings.append(Finding(key, f"{module}:{use.lineno} {function}(): {name} — outside "
                                         "the runs repository, name a run by (tenant, run id) "
                                         "and take paths from the Run its repository opens"))
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=DEFENDER,
                        help="a defender/-shaped tree to sweep (default: this checkout's)")
    args = parser.parse_args(argv)
    try:
        found = scan(args.root)
    except _astlib.ScanBlind as exc:  # the listing itself is blind: no scan happened
        print(f"[lint_run_layout_imports] {exc}", file=sys.stderr)
        return 2
    for f in found:
        print(f.display)
    print(f"[lint_run_layout_imports] {len(found)} finding(s).")
    if found:
        print("\nOutside defender/run_repository/ and its owner modules, take no run-layout "
              "name, episode-runs name, Tenant.runs or handle constructor (#1105 D7). The "
              "allow-list in this file is the only hatch; there is no inline suppression.")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
