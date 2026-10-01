"""Shared AST resolution for the lint gates: answer "where does this call come from", not "how
was it spelled".

This module is the declared owner of that question, for gates and suites alike, and
`lint_hand_rolled_name_resolution.py` enforces it: a module that parses shipped source and
decides what a name refers to by matching its spelling fails unless it goes through here.
Reach it from a gate by bare name (`from _astlib import callee`) and from a test through
`tests/_by_path.import_lint_lib`. If you are about to write `node.func.id == "..."`,
`alias.asname`, or a walk over `ast.ImportFrom` to decide a binding, use `callee()` or
`origin()` instead. (Not an `@owns` tag: that names a field with a sole producer; this is a
sole implementation of a derivation.)

Spelling-based identification ("is this written as ``re.something(...)``?") is blind to an
alias (``import re as regex``) or a from-import (``from re import search``). It also cannot
know the callee's arity: ``Path.open(mode)`` takes the mode first, but every module opener
(``codecs.open(file, mode)``, ``gzip.open(file, mode)``) takes the path first. Resolving the
callee supplies the mode's slot and default.

``callee()`` returning None is a signal, not a failure: the receiver is a value rather than a
module (``p.open("r")``, ``zf.open(n)``). A gate that wants the duck-typed case must key on
the attribute name and skip only via a positive table of origins; "skip whatever resolves"
turns every resolvable receiver into a false negative. ``zf.open(n)`` and ``p.open("r")`` are
indistinguishable here; telling them apart needs local-binding tracking, which this module
does not do.

Names resolve against the scope they are used in, not a flat module map: function-local
imports must be collected (a local ``import re as regex`` is a plausible evasion), but binding
them module-wide makes any same-named local elsewhere resolve to a module.

``from re import *`` would be unsound, but ruff F403 (``--select E,F`` repo-wide) makes a
star-import unmergeable, so the resolver can be sound without dataflow.
"""
from __future__ import annotations

import ast
import builtins
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

_BUILTIN_NAMES = frozenset(dir(builtins))


class ScanBlind(RuntimeError):
    """A file inside a gate's own scan scope could not be read or parsed. The gate cannot
    report on what it did not read, and must not report clean."""


def read_and_parse(path: Path, rel: str) -> tuple[str, ast.Module]:
    """Read and parse one file of a gate's scan scope, or raise ScanBlind.

    Swallowing the error would drop the file from the corpus and let the gate report clean
    with a violation sitting in the skipped file. Raising (rather than warn-and-continue) is
    right because the scope is first-party source: an unparseable file there is already
    failing ruff, mypy and pytest.

    ``errors="replace"`` means decoding cannot raise, so ``UnicodeDecodeError`` (a
    ``ValueError``, not an ``OSError``) is not caught.
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise ScanBlind(
            f"{rel}: could not be read ({exc.__class__.__name__}: {exc}) — it is inside this "
            f"gate's scan scope, so skipping it would shrink the scanned corpus silently."
        ) from exc
    try:
        tree = ast.parse(text)
    except SyntaxError as exc:
        raise ScanBlind(
            f"{rel}: could not be parsed ({exc.__class__.__name__}: {exc}) — it is inside this "
            f"gate's scan scope, so it was never examined. Fix the syntax and re-run; a file "
            f"this gate cannot parse is a file it cannot clear."
        ) from exc
    return text, tree


def read_source(path: Path, rel: str) -> str:
    """The text-only twin of `read_and_parse`, for a gate that scans lines rather than an AST."""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise ScanBlind(
            f"{rel}: could not be read ({exc.__class__.__name__}: {exc}) — it is inside this "
            f"gate's scan scope, so skipping it would shrink the scanned corpus silently."
        ) from exc


_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)


@dataclass(frozen=True)
class ModuleEnv:
    """What one scope binds — the module's, or a function's.

    ``imports`` — bound name -> dotted origin::

        import re                   -> {"re": "re"}
        import re as regex          -> {"regex": "re"}
        import os.path              -> {"os": "os"}        # `import a.b` binds `a`
        import os.path as osp       -> {"osp": "os.path"}
        from re import search       -> {"search": "re.search"}
        from re import search as s  -> {"s": "re.search"}
        from .mod import y          -> {"y": ".mod.y"}     # leading dot: never collides
                                                           # with a stdlib origin
    ``consts``  — module-level ``NAME = "<str literal>"`` bindings, minus any the scope
    rebinds.
    ``defines`` — names bound to something other than an import (def/class, assignments,
    parameters, loop and ``with`` targets); these shadow a builtin or import of that name.

    ``scope_of`` maps every node to the env of its scope, keyed by the node object (AST
    nodes hash by identity) so the nodes stay alive; an ``id()`` key could alias a recycled
    address onto the wrong scope.
    """

    imports: dict[str, str]
    consts: dict[str, str]
    defines: frozenset[str]
    scope_of: dict[ast.AST, ModuleEnv] = field(
        default_factory=dict, compare=False, repr=False
    )
    #: Names directly bound, in this scope's own statements, to a name-owner instance — an
    #: `Owner(...)` construction, a chained alias of one, or a parameter annotated with an
    #: owner class. See `owner_derived`.
    owner_locals: frozenset[str] = field(default_factory=frozenset, compare=False, repr=False)
    #: Names directly bound to a PARTIAL owner instance (an accepted `Tenant`), keyed to its
    #: class's origin; and names bound to a CARRIER of one (a `RunTenant`). See
    #: `PARTIAL_OWNER_ATTRS`.
    partial_owner_locals: Mapping[str, str] = field(
        default_factory=dict, compare=False, repr=False)
    carrier_locals: Mapping[str, str] = field(default_factory=dict, compare=False, repr=False)


def _scope_bindings(scope: ast.AST) -> tuple[dict[str, str], set[str]]:
    """``(imports, other bindings)`` made directly in one scope.

    Stops at every nested function/lambda/class, whose bindings belong to that scope; the
    nested def's name is bound here.
    """
    imports: dict[str, str] = {}
    bound: set[str] = set()

    def walk(node: ast.AST) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                bound.add(child.name)  # the def binds its name here; its body is elsewhere
                continue
            if isinstance(child, ast.Lambda):
                continue  # params + body are a scope of their own
            if isinstance(child, ast.Import):
                for alias in child.names:
                    if alias.asname:
                        imports[alias.asname] = alias.name
                    else:
                        # `import a.b.c` binds only `a`, and `a` refers to package `a`.
                        root = alias.name.split(".")[0]
                        imports[root] = root
                continue
            if isinstance(child, ast.ImportFrom):
                # `level` > 0 is a relative import; keep the leading dots so a relative
                # `.re` can never be mistaken for the stdlib `re`.
                prefix = "." * child.level + (child.module or "")
                for alias in child.names:
                    if alias.name == "*":
                        continue  # unresolvable — but ruff F403 makes it unmergeable
                    imports[alias.asname or alias.name] = f"{prefix}.{alias.name}"
                continue
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store):
                bound.add(child.id)          # assign, augassign, for/with target, walrus
            elif isinstance(child, ast.arg):
                bound.add(child.arg)         # a parameter
            elif isinstance(child, ast.ExceptHandler) and child.name:
                bound.add(child.name)        # `except E as name`
            walk(child)

    walk(scope)
    return imports, bound


def _module_consts(tree: ast.AST) -> dict[str, str]:
    """Top-level ``NAME = "<str literal>"`` bindings.

    Module-level only, unlike ``imports``: a function-local string assignment does not
    unambiguously bind a name, and widening it would add false positives on live code.
    """
    consts: dict[str, str] = {}
    for node in getattr(tree, "body", []):
        target: ast.expr | None = None
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
        elif isinstance(node, ast.AnnAssign):
            target = node.target
        if (
            isinstance(target, ast.Name)
            and isinstance(getattr(node, "value", None), ast.Constant)
            and isinstance(node.value.value, str)  # type: ignore[attr-defined]
        ):
            consts[target.id] = node.value.value  # type: ignore[attr-defined]
    return consts


#: The name-owner classes `owner_derived` tags — construction of one, and reads on the instance
#: it builds, resolved by dotted origin so an alias or a from-import still counts.
_OWNER_CLASS_ORIGINS = frozenset({
    "defender._run_paths.RunPaths",
    "defender._episode_paths.EpisodePaths",
    # The file-backed handle: a value reached through `run.facts.<record>` /
    # `run.tables.<table>` is owner-derived like `RunPaths(x).<record>`.
    "defender._run_handle.Run",
    # The episode handle (#1133): `episode.served_base` / `episode.world(label).draw(n)` are
    # owner-derived like `EpisodePaths(ep).<record>`.
    "defender._episode_handle.Episode",
    "defender._episode_paths.WorldPaths",
    # The session store's owner, built from the runs base since one store spans a run and
    # its resumes and forks.
    "defender._run_paths.SessionPaths",
})

#: Owners whose members are owner-derived only for a NAMED set (#1120 M5), keyed by class
#: origin. An accepted `Tenant` owns the data-root record locations — a join onto
#: `tenant.runs` is owner-derived exactly as one onto `EpisodePaths(ep).runs` is — while its
#: knowledge halves (`settings`, `knowledge`, `agent`) are not run records: the settings
#: loaders join onto them by design, and must stay clean.
_TENANT = "defender._tenant.Tenant"
PARTIAL_OWNER_ATTRS: dict[str, frozenset[str]] = {
    _TENANT: frozenset({
        "dir", "row_path", "runs", "sessions", "episodes", "learning", "worktrees"}),
}

#: Calls that RETURN a partial owner instance: `accept_tenant(...)` is the only constructor of
#: a `Tenant`, so an unannotated local bound to its result is one.
_PARTIAL_OWNER_FACTORIES: dict[str, str] = {"defender._tenant.accept_tenant": _TENANT}

#: Classes one of whose members IS a partial owner instance: `RunTenant.tenant` is the run's
#: accepted `Tenant`, so `run_tenant.tenant.learning` is reached through the owner.
_PARTIAL_OWNER_CARRIERS: dict[str, dict[str, str]] = {
    "defender.runtime.run_tenant.RunTenant": {"tenant": _TENANT},
}

#: The owner modules' module-level singletons — stateless layout values a caller imports rather
#: than constructs. `RunPaths(d).alert` is a path; `RUN_LAYOUT.alert` is the same record's name
#: relative to the run dir (the form `_io.Bound`'s readers take). Both are owner-derived.
_OWNER_VALUE_ORIGINS = frozenset({
    "defender._run_paths.RUN_LAYOUT",
    "defender._run_paths.WIRE_LOG_NAMES",
    "defender._episode_paths.LAYOUT",
    "defender._episode_paths.WORLD_LEAVES",
})

#: The handle sub-collections an owner-rooted attribute chain may pass through (for
#: `run.facts.<record>`). Named rather than recursing through any attribute: otherwise
#: `paths.<anything>.<record>` would be accepted once `paths` is tagged, silencing the gate's
#: "unresolvable accessor use" arm for that name.
_OWNER_SUBCOLLECTIONS = frozenset({
    "tables", "facts", "documents", "observability", "session",
    # `WorldPaths.rel`: the same world's records in relative form.
    "rel",
})

#: Owner methods that return another owner handle rather than a path:
#: `EpisodePaths(d).world(label)` is a `WorldPaths`, `LAYOUT.world(label)` a `WorldLayout`.
#: Named, not inferred: tagging the result of every owner call would make `paths.alert` an
#: owner instance and silence the join arm on the values it exists to judge.
_OWNER_SUBHANDLE_METHODS = frozenset({"world"})


def _is_subhandle_call(node: ast.expr, owners: set[str], env: ModuleEnv) -> bool:
    """`<owner>.world(label)` — a call naming a declared sub-handle method on an owner."""
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in _OWNER_SUBHANDLE_METHODS
        and _owner_instance_in(node.func.value, owners, env)
    )


def _partial_owner_of(
    node: ast.expr, partials: Mapping[str, str], carriers: Mapping[str, str], env: ModuleEnv,
) -> str | None:
    """The class origin of the partial owner instance `node` evaluates to, or None: a
    construction or a factory call, a local tagged as one, or a carrier's member
    (`run_tenant.tenant`)."""
    if isinstance(node, ast.Call):
        called = callee(node, env)
        if called in PARTIAL_OWNER_ATTRS:
            return called
        return _PARTIAL_OWNER_FACTORIES.get(called or "")
    if isinstance(node, ast.Name):
        return partials.get(node.id)
    if isinstance(node, ast.Attribute):
        carrier = None
        if isinstance(node.value, ast.Name):
            carrier = carriers.get(node.value.id)
        elif isinstance(node.value, ast.Call):
            carrier = callee(node.value, env)
        return _PARTIAL_OWNER_CARRIERS.get(carrier or "", {}).get(node.attr)
    return None


def _partial_owner_member(
    node: ast.expr, partials: Mapping[str, str], carriers: Mapping[str, str], env: ModuleEnv,
) -> bool:
    """`node` is `<partial owner>.<one of its owned members>` — `tenant.runs`, never
    `tenant.settings`."""
    if not isinstance(node, ast.Attribute):
        return False
    owner = _partial_owner_of(node.value, partials, carriers, env)
    return owner is not None and node.attr in PARTIAL_OWNER_ATTRS[owner]


def _partial_locals(
    scope: ast.AST, imports: dict[str, str], consts: dict[str, str], defines: frozenset[str],
    inherited: tuple[Mapping[str, str], Mapping[str, str]],
) -> tuple[dict[str, str], dict[str, str]]:
    """`(partial owner locals, carrier locals)` bound in `scope`'s own statements: a parameter
    annotated with a partial owner or a carrier class, or a local assigned a partial owner
    instance (`t = accept_tenant(...)`, `t = run_tenant.tenant`) or a carrier construction."""
    probe_env = ModuleEnv(imports=imports, consts=consts, defines=defines, scope_of={})
    partials = dict(inherited[0])
    carriers = dict(inherited[1])
    if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
        for arg in (*scope.args.posonlyargs, *scope.args.args, *scope.args.kwonlyargs):
            ann = arg.annotation
            if not isinstance(ann, (ast.Name, ast.Attribute)):
                continue
            annotated = _origin(ann, probe_env)
            if annotated in PARTIAL_OWNER_ATTRS:
                partials[arg.arg] = annotated
            elif annotated in _PARTIAL_OWNER_CARRIERS:
                carriers[arg.arg] = annotated

    def walk(node: ast.AST) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                continue
            if (
                isinstance(child, ast.Assign) and len(child.targets) == 1
                and isinstance(child.targets[0], ast.Name)
            ):
                target = child.targets[0].id
                partials.pop(target, None)
                carriers.pop(target, None)
                owner = _partial_owner_of(child.value, partials, carriers, probe_env)
                if owner is not None:
                    partials[target] = owner
                elif (isinstance(child.value, ast.Call)
                      and callee(child.value, probe_env) in _PARTIAL_OWNER_CARRIERS):
                    carriers[target] = callee(child.value, probe_env) or ""
            walk(child)

    walk(scope)
    return partials, carriers


def _owner_locals(
    scope: ast.AST, imports: dict[str, str], consts: dict[str, str],
    defines: frozenset[str], inherited: frozenset[str],
    partials: Mapping[str, str] | None = None, carriers: Mapping[str, str] | None = None,
) -> frozenset[str]:
    """Names bound, in `scope`'s own statements (never a nested def), to a name-owner
    instance: an `Owner(...)` construction, a chained alias of one (`x = y` with `y` tagged,
    or `x = owner.attr`, so a join onto it is still caught), or — in a function scope — a
    parameter annotated with an owner class. `inherited` is the enclosing scope's tagged
    names this scope has not shadowed."""
    probe_env = ModuleEnv(imports=imports, consts=consts, defines=defines, scope_of={})
    owners: set[str] = set(inherited)
    partials = partials or {}
    carriers = carriers or {}

    def is_owner_expr(node: ast.expr) -> bool:
        if isinstance(node, ast.Call):
            return (callee(node, probe_env) in _OWNER_CLASS_ORIGINS
                    or _is_subhandle_call(node, owners, probe_env))
        if isinstance(node, ast.Name):
            return node.id in owners or _origin(node, probe_env) in _OWNER_VALUE_ORIGINS
        if isinstance(node, ast.Attribute):
            return (_owner_instance_in(node.value, owners, probe_env)
                    or _partial_owner_member(node, partials, carriers, probe_env))
        return False

    if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
        for arg in (*scope.args.posonlyargs, *scope.args.args, *scope.args.kwonlyargs):
            ann = arg.annotation
            if isinstance(ann, (ast.Name, ast.Attribute)) and (
                _origin(ann, probe_env) in _OWNER_CLASS_ORIGINS
            ):
                owners.add(arg.arg)

    def walk(node: ast.AST) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                continue
            if (
                isinstance(child, ast.Assign) and len(child.targets) == 1
                and isinstance(child.targets[0], ast.Name)
            ):
                target = child.targets[0].id
                if is_owner_expr(child.value):
                    owners.add(target)
                else:
                    owners.discard(target)  # rebound to something that is not owner-derived
            walk(child)

    walk(scope)
    return frozenset(owners)


def _owner_instance_in(node: ast.expr, owners: set[str], env: ModuleEnv) -> bool:
    if isinstance(node, ast.Call):
        return (callee(node, env) in _OWNER_CLASS_ORIGINS
                or _is_subhandle_call(node, owners, env))
    if isinstance(node, ast.Name):
        return node.id in owners or _origin(node, env) in _OWNER_VALUE_ORIGINS
    if isinstance(node, ast.Attribute):
        # An attribute chain rooted at an owner stays owner-derived only through a declared
        # sub-collection; any other member is a container this pass cannot see into, which
        # the "unresolvable accessor use" arm handles.
        if node.attr not in _OWNER_SUBCOLLECTIONS:
            return False
        return _owner_instance_in(node.value, owners, env)
    return False


def _child_env(func: ast.AST, parent: ModuleEnv) -> ModuleEnv:
    """The env inside one function: the enclosing env with this scope's own bindings
    applied. A local non-import binding shadows an inherited import, and a local import
    rebinds on top of it."""
    local_imports, bound = _scope_bindings(func)
    imports = {n: o for n, o in parent.imports.items() if n not in bound}
    imports.update(local_imports)
    defines = frozenset((set(parent.defines) | bound) - set(local_imports))
    consts = {n: v for n, v in parent.consts.items() if n not in bound}
    inherited = frozenset(n for n in parent.owner_locals if n not in bound)
    partials, carriers = _partial_locals(
        func, imports, consts, defines,
        ({n: o for n, o in parent.partial_owner_locals.items() if n not in bound},
         {n: o for n, o in parent.carrier_locals.items() if n not in bound}))
    return ModuleEnv(
        imports=imports,
        consts=consts,
        defines=defines,
        scope_of=parent.scope_of,
        owner_locals=_owner_locals(func, imports, consts, defines, inherited, partials, carriers),
        partial_owner_locals=partials,
        carrier_locals=carriers,
    )


def _tag(node: ast.AST, env: ModuleEnv, scope_of: dict[ast.AST, ModuleEnv]) -> None:
    """Record, for every node, the env of the scope it sits in."""
    for child in ast.iter_child_nodes(node):
        scope_of[child] = env
        # A ClassDef is not a scope in the chain: Python does not close methods over the
        # class body, so a method's enclosing scope is the module (or enclosing function).
        # Class-body bindings are therefore invisible — accepted, and rare in this tree.
        _tag(child, _child_env(child, env) if isinstance(child, _SCOPES) else env, scope_of)


def module_env(tree: ast.AST) -> ModuleEnv:
    """Build the scope tree for one module and return its root (module-level) env.

    Every node is tagged with its scope's env, so ``callee``/``origin``/``str_value`` resolve
    a name against the innermost scope that binds it while callers pass the one env returned.

    Scoping is what makes collecting function-local imports safe: a function that binds
    ``p`` to a module must not make ``p.write_text(...)`` in another function (where ``p`` is
    a ``Path``) resolve to that module.

    A bail-out on ambiguity is not an option: for ``lint_unpinned_text_io`` a None callee
    means flag (the duck-typed ``p.open()``), while for the jsonl and frontmatter gates it
    means skip. Only real scoping is safe for all of them.
    """
    scope_of: dict[ast.AST, ModuleEnv] = {}
    imports, bound = _scope_bindings(tree)
    defines = frozenset(bound)
    consts = _module_consts(tree)
    partials, carriers = _partial_locals(tree, imports, consts, defines, ({}, {}))
    root = ModuleEnv(
        imports=imports,
        consts=consts,
        defines=defines,
        scope_of=scope_of,
        owner_locals=_owner_locals(
            tree, imports, consts, defines, frozenset(), partials, carriers),
        partial_owner_locals=partials,
        carrier_locals=carriers,
    )
    _tag(tree, root, scope_of)
    return root


def owner_derived(node: ast.expr, env: ModuleEnv) -> bool:
    """Is `node`'s value derived from a name owner (`RunPaths`/`EpisodePaths`) — an
    `Owner(x).attr` chain, a local bound to an owner construction (or owner-derived value)
    in the same function, or a parameter annotated with an owner type?

    Resolved against `node`'s scope. A `Name` qualifies when `_owner_locals` tagged it; an
    `Attribute` when its receiver resolves as an owner instance (`RunPaths(x).gather_raw`,
    `paths.gather_raw`). A join `.../ lead_id` onto either is what `lint_run_records` flags."""
    e = _env_at(node, env)
    if isinstance(node, ast.Name):
        return node.id in e.owner_locals
    if isinstance(node, ast.Attribute):
        return (_owner_instance_in(node.value, set(e.owner_locals), e)
                or _partial_owner_member(node, e.partial_owner_locals, e.carrier_locals, e))
    if isinstance(node, ast.Call):
        return callee(node, e) in _OWNER_CLASS_ORIGINS
    return False


def _env_at(node: ast.AST, env: ModuleEnv) -> ModuleEnv:
    """The env of the scope ``node`` sits in. Falls back to ``env`` for a node that was
    not tagged — a synthetic node, or one from a different tree."""
    return env.scope_of.get(node, env)


def origin(node: ast.expr, env: ModuleEnv) -> str | None:
    """The dotted origin of a pure ``Name.attr.attr`` chain rooted at an imported name,
    resolved against the scope ``node`` sits in.

    ``os`` -> ``"os"``; ``regex`` -> ``"re"``; ``re.error`` -> ``"re.error"``.
    ``p`` -> None (a local value, even one sharing a name with an import in another
    function). ``zipfile.ZipFile(p)`` -> None: a Call makes it a value, and walking through
    it would confuse the value's origin with its constructor's.
    """
    return _origin(node, _env_at(node, env))


def _origin(node: ast.expr, env: ModuleEnv) -> str | None:
    """``origin`` against an already-resolved scope env."""
    parts: list[str] = []
    cur: ast.expr = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if not isinstance(cur, ast.Name):
        return None
    if cur.id in env.defines:
        return None  # a local/param of that name shadows the import
    base = env.imports.get(cur.id)
    if base is None:
        return None
    return ".".join([base, *reversed(parts)])


def callee(call: ast.Call, env: ModuleEnv) -> str | None:
    """The dotted origin of the called function, or None when the receiver is a value
    rather than a module.

        re.search(...) / regex.search(...) / search(...)   -> "re.search"
        subprocess.run(...) / run(...)                     -> "subprocess.run"
        open(...)      [not imported, not shadowed]        -> "builtins.open"
        p.open("r") / p.read_text() / zf.open(n)           -> None   <- duck-typed

    Resolves against the call's scope. ``env.defines`` is consulted before ``env.imports``
    so a shadowing local wins. The ``builtins.<id>`` fallback fires only for a Name in
    neither map, so a parameter named ``input`` or a ``def open(...)`` cannot fabricate an
    origin.
    """
    env = _env_at(call, env)
    func = call.func
    if isinstance(func, ast.Name):
        if func.id in env.defines:
            return None
        if func.id in env.imports:
            return env.imports[func.id]
        if func.id in _BUILTIN_NAMES:
            return f"builtins.{func.id}"
        return None
    if isinstance(func, ast.Attribute):
        return origin(func, env)  # re-resolves func's scope — the same one, by construction
    return None


def root_name(node: ast.expr) -> str | None:
    """The loose root Name of an attribute/call/subscript chain, walking through calls:
    ``line.strip()`` -> ``"line"``; ``zipfile.ZipFile(p).open`` -> ``"zipfile"``.

    For value-derivation tracking (which local a value came from); it is not module
    resolution and must not be used as one — use ``origin``.
    """
    cur: ast.expr = node
    while True:
        if isinstance(cur, ast.Attribute):
            cur = cur.value
        elif isinstance(cur, ast.Subscript):
            cur = cur.value
        elif isinstance(cur, ast.Call):
            cur = cur.func
        else:
            break
    return cur.id if isinstance(cur, ast.Name) else None


def str_args(call: ast.Call, env: ModuleEnv) -> list[str]:
    """The string args of a call — positional and keyword (so ``re.compile(pattern=…)``
    is seen), tuple elements flattened (so ``startswith(("a", "b"))`` is), and Names
    resolved through ``env.consts``.

    Const resolution matters: hoisting a literal to a module constant is good style, and a
    detector reading inline Constants only would make that the one way to evade the gate.
    """
    out: list[str] = []
    for arg in [*call.args, *(kw.value for kw in call.keywords)]:
        if isinstance(arg, ast.Tuple):
            out.extend(v for el in arg.elts if (v := str_value(el, env)) is not None)
        elif (v := str_value(arg, env)) is not None:
            out.append(v)
    return out


def arg_at(call: ast.Call, index: int, keyword: str) -> ast.expr | None:
    """The argument in positional slot ``index`` or passed as ``keyword=``. The slot is a
    property of the callee (``builtins.open(file, mode)`` puts mode at 1, ``Path.open(mode)``
    at 0), so the caller passes the index it resolved."""
    if index >= 0 and len(call.args) > index:
        return call.args[index]
    for kw in call.keywords:
        if kw.arg == keyword:
            return kw.value
    return None


def str_value(node: ast.expr | None, env: ModuleEnv) -> str | None:
    """A single expression's string value — an inline literal, or a module constant that
    the node's own scope has not rebound to something else."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return _env_at(node, env).consts.get(node.id)
    return None


# Openers that take `encoding=`, keyed by resolved origin -> (mode's positional slot, mode's
# default). Both are properties of the callee: module-level openers are path-first, unlike
# `Path.open(mode)`. Verified against inspect.signature.
OPENERS = {
    "builtins.open": (1, "r"),
    "io.open": (1, "r"),                          # io.open IS builtins.open
    "codecs.open": (1, "r"),
    "os.fdopen": (1, "r"),                        # wraps an fd — still decodes under the locale
    "gzip.open": (1, "rb"),                       # binary by default, but takes encoding= in text mode
    "bz2.open": (1, "rb"),
    "lzma.open": (1, "rb"),
    "tempfile.NamedTemporaryFile": (0, "w+b"),
    "tempfile.TemporaryFile": (0, "w+b"),
    "tempfile.SpooledTemporaryFile": (1, "w+b"),  # max_size comes FIRST — mode is slot 1
}
# `Path.open(mode)` and friends: the receiver is a value, so the callee never resolves.
# Duck-typed on purpose — the case the gates most exist to catch.
DUCK_OPENER = (0, "r")
# Genuinely encoding-less: `os.open` returns an fd (its third arg is the permission bits,
# not a text mode); `tarfile.open` has no `encoding` parameter.
NO_ENCODING_OPENERS = ("os.open", "tarfile.open")


def opener_slot(call: ast.Call, env: ModuleEnv) -> tuple[int, str] | None:
    """``(mode's positional slot, mode's default)`` for an opener call, or None if this
    call is not an opener.

    An origin is skipped only via the positive ``NO_ENCODING_OPENERS`` table, never because
    it merely resolved: the receiver may be an imported object (``PATHS.lessons_dir.open()``
    resolves to ``defender._paths.PATHS.lessons_dir.open``), and treating it as "not an
    opener" would drop exactly the Path-like text open these gates exist to catch.

    A tabled origin gets the callee's real slot/default; any other ``.open`` falls back to
    the duck opener. The cost is a possible false alarm on an untabled module opener, which
    the suppression marker answers.
    """
    o = callee(call, env)
    if o in NO_ENCODING_OPENERS:
        return None
    if o in OPENERS:
        return OPENERS[o]
    func = call.func
    if isinstance(func, ast.Attribute) and func.attr == "open":
        return DUCK_OPENER
    return None


def open_mode(call: ast.Call, env: ModuleEnv) -> str | None:
    """The mode an opener call opens in — the callee's own default when no mode is passed.

    None means there is no readable mode: the call is not an opener, or the mode is an
    expression rather than a literal/module-const.
    """
    slot = opener_slot(call, env)
    if slot is None:
        return None
    index, default = slot
    arg = arg_at(call, index, "mode")
    return default if arg is None else str_value(arg, env)


def has_kw(call: ast.Call, name: str) -> bool:
    return any(kw.arg == name for kw in call.keywords)


def kw_is_true(call: ast.Call, name: str) -> bool:
    """True only for a literal ``name=True``, or a module const bound to it."""
    for kw in call.keywords:
        if kw.arg == name and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False
