"""#1120 piece 1 — O3's one acceptance frame, as censuses over the production tree, and D1's
`Tenant` layout members against CI's dead-code gate.

O3: a tenant is accepted by ONE function returning a `Tenant`, so no entry point accepts a
tenant another refuses. Two censuses observe it (doc O3, "Observed by"): `Tenant(` is
constructed only inside `accept_tenant`, and `resolve_data_root` is called only from the entry
points (once per entry module), never from `runs_base_for`, `tenant_of_run_dir` or
`materialize_run`, which take a `Tenant` or the data root instead (C8). N10 (auto) sets their
strength: the construction census also reports `dataclasses.replace(t, …)` and `type(t)(…)`,
and `Tenant` itself refuses a construction outside `accept_tenant` at run time (a
module-private sentinel checked in `__post_init__`) while a copy or pickle of an accepted one
is allowed; the call census uses RESOLVED references — a from-import alias and a
module-attribute call both count — and `getattr`/`importlib` by string is its stated floor.

Each census is a same-file AST walk over `defender/` (tests excluded) and the repo's
`scripts/`, and each is driven over a planted tmp copy too, so a census that finds nothing
cannot pass for one that looked. See `_spec1120.py` for the coined names.
"""
from __future__ import annotations

import ast
import copy
import dataclasses
import functools
import json
import os
import pickle
import re
import subprocess
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import pytest

from defender import _tenant
from defender import run as run_py
from defender.scripts import tenant as tenant_py
from defender.tests._by_path import import_lint_lib
from defender.tests.tenant_1120_piece1 import _spec1120 as H

#: The repo's scope-aware name resolver (`scripts/lint/_astlib.py`): both censuses ask it
#: what a call resolves to, never the call's spelling (N10's resolved references).
_AST = import_lint_lib("_astlib")
#: The owner module, where `Tenant` and `resolve_data_root` are module-level defs.
_OWNER_FILE = "defender/_tenant.py"

#: The production tree the censuses walk: `defender/` minus its tests, plus the repo's lints.
_SCANNED_ROOTS = (H.DEFENDER, H.REPO_ROOT / "scripts")
_SKIPPED_PARTS = {"tests", ".venv", "__pycache__", "runs"}


def _production_files(roots: Iterable[Path] = _SCANNED_ROOTS) -> list[Path]:
    files = []
    for root in roots:
        for py in sorted(root.rglob("*.py")):
            if not _SKIPPED_PARTS & set(py.relative_to(root).parts):
                files.append(py)
    return files


def _rel(path: Path) -> str:
    try:
        return path.relative_to(H.REPO_ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def _functions_by_node(tree: ast.Module) -> dict[int, str]:
    """`id(node) -> the qualified name of the innermost def enclosing it` for every node."""
    owner: dict[int, str] = {}

    def walk(node: ast.AST, scope: str) -> None:
        for child in ast.iter_child_nodes(node):
            inner = scope
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                inner = f"{scope}.{child.name}" if scope else child.name
            owner[id(child)] = inner
            walk(child, inner)

    walk(tree, "")
    return owner


@functools.cache
def _loaded_at(path: Path, stamp: tuple[int, int]) -> tuple[ast.Module, Any, dict[int, str]]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return tree, _AST.module_env(tree), _functions_by_node(tree)


def _loaded(path: Path) -> tuple[ast.Module, Any, dict[int, str]]:
    """`(tree, resolver env, def-scope map)` of `path`, built once per process and file state:
    every census here walks the same production files, and the env/scope builds are whole-tree
    walks. The trees are only read."""
    st = path.stat()
    return _loaded_at(path, (st.st_mtime_ns, st.st_size))


# ======================================================================================
# Census 1: who constructs a `Tenant`.
# ======================================================================================

def _mentions_tenant(node: ast.AST) -> bool:
    """The operand is a tenant by name — `tenant`, `x.tenant` (a `RunTenant`'s member) or
    `t` — never a `run_tenant`, whose own `replace` is not a `Tenant` construction."""
    return re.search(r"(^|\.)(tenant|t)$", ast.unparse(node)) is not None


def _owner_def_call(node: ast.Call, env, name: str, *, is_owner: bool) -> bool:
    """Inside the owner module a bare call to its own module-level def: `_astlib.callee`
    returns None for a def-bound name by design, so the owner's own binding is the fact."""
    func = node.func
    return (is_owner and isinstance(func, ast.Name)
            and func.id == name  # lint-ast-resolve: ok — the owner's own module-level def binds this name; callee() declines def-bound names
            and name in env.defines)


def _tenant_constructions(files: Iterable[Path]) -> list[tuple[str, str, str]]:
    """Every call that RESOLVES to `defender._tenant.Tenant` (a from-import, an alias or a
    module attribute, and the owner's own bare `Tenant(`), and every `dataclasses.replace` /
    `copy.replace` or `type(<tenant>)(…)` call whose operand names a tenant (N10), as
    `(file, enclosing function, shape)`."""
    found = []
    for path in files:
        tree, env, scope = _loaded(path)
        rel = _rel(path)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            resolved = _AST.callee(node, env)
            shape = None
            if (resolved == "defender._tenant.Tenant"
                    or _owner_def_call(node, env, "Tenant", is_owner=rel == _OWNER_FILE)):
                shape = "Tenant("
            elif (resolved in {"dataclasses.replace", "copy.replace"}
                  and node.args and _mentions_tenant(node.args[0])):
                shape = "replace("
            elif (isinstance(func, ast.Call) and _AST.callee(func, env) == "builtins.type"
                  and func.args and _mentions_tenant(func.args[0])):
                shape = "type(t)("
            if shape:
                found.append((rel, scope.get(id(node), ""), shape))
    return found


_PLANTED_CONSTRUCTIONS = '''

import dataclasses

from defender._tenant import Tenant


def _planted_direct(data_root, row):
    return Tenant(id="acme", data_root=data_root, row=row)


def _planted_replace(tenant):
    return dataclasses.replace(tenant, data_root="/elsewhere")


def _planted_type_call(tenant):
    return type(tenant)(tenant.id, tenant.data_root, tenant.row)
'''


@pytest.mark.gate
def test_1120_tenant_is_constructed_only_inside_accept_tenant(
        data_root: Path, tmp_path: Path) -> None:
    """An AST census of defender/ (excluding tests/) and scripts/ finds exactly one
    construction of Tenant: the call inside defender/_tenant.py's accept_tenant, which is the
    census's positive control. It also reports a dataclasses.replace of a tenant and a
    type(tenant)(…) call (N10), and a Tenant construction planted in a tmp copy of a scanned
    module is reported, each by its enclosing function. At run time the same frame holds:
    constructing Tenant directly outside accept_tenant, through dataclasses.replace on an
    accepted tenant, or through type(tenant)(…) raises (a module-private sentinel checked in
    __post_init__, N10), while a copy.copy or a pickle round-trip of an accepted Tenant is
    allowed and equals it."""
    found = _tenant_constructions(_production_files())
    assert found == [("defender/_tenant.py", "accept_tenant", "Tenant(")], (
        "Tenant must be constructed exactly once, inside accept_tenant, and nowhere else "
        f"(O3): the census found {found}")

    planted = tmp_path / "defender" / "run_common.py"
    planted.parent.mkdir(parents=True)
    planted.write_text((H.DEFENDER / "run_common.py").read_text(encoding="utf-8")
                       + _PLANTED_CONSTRUCTIONS, encoding="utf-8")
    shapes = {(fn, shape) for _file, fn, shape in _tenant_constructions([planted])}
    assert {("_planted_direct", "Tenant("), ("_planted_replace", "replace("),
            ("_planted_type_call", "type(t)(")} <= shapes, (
        f"the census missed a planted construction: {sorted(shapes)}")

    # The run-time leg: the class itself refuses a construction outside accept_tenant.
    tenant_cls = _tenant.Tenant
    H.adopted(data_root)
    accepted = H.accept(_tenant, data_root)
    assert type(accepted) is tenant_cls
    # A sentinel refusal: TenantRefused from __post_init__, or the TypeError/ValueError a
    # missing init-only sentinel raises — never an AttributeError (the class is there).
    refusals = (_tenant.TenantRefused, TypeError, ValueError)
    with pytest.raises(refusals):
        tenant_cls(id=accepted.id, data_root=accepted.data_root, row=accepted.row)
    with pytest.raises(refusals):
        dataclasses.replace(accepted, data_root=accepted.data_root)
    with pytest.raises(refusals):
        type(accepted)(accepted.id, accepted.data_root, accepted.row)
    assert copy.copy(accepted) == accepted
    assert pickle.loads(pickle.dumps(accepted)) == accepted  # noqa: S301 — our own object


# ======================================================================================
# Census 2: who calls `resolve_data_root`.
# ======================================================================================

#: The O3 entry modules that take a tenant in piece 1 (correction 3 / F8), each allowed ONE
#: call site; `tenant.py` one per subcommand that resolves the root (`setup`, `check <id>`).
#: Not held_out: an evaluation tool outside the application takes no tenant (human, PR #1157),
#: so a call there is one outside the entry points. Not ticket_adapter: #1107 removed its command
#: line (fork TICKET-ADAPTER-CLI-REMOVED-BY-1107), so it is no entry point.
_ENTRY_MODULES = {
    "defender/run.py": 1,
    "defender/learning/branch/cli.py": 1,
    "defender/scripts/tenant.py": 2,
    "defender/scripts/policy_cli.py": 1,
    "defender/skills/connect/validate_scaffold.py": 1,
}

#: Functions that take a Tenant or the data root after piece 1 and must resolve nothing (C8).
_NEVER_RESOLVE = ("runs_base_for", "tenant_of_run_dir", "materialize_run")

_RESOLVER = "defender._tenant.resolve_data_root"


def _resolve_calls(files: Iterable[Path]) -> list[tuple[str, str]]:
    """Every call that RESOLVES to `resolve_data_root` (`_astlib.callee`: a from-import, an
    aliased one, a module attribute through any import form; the owner's own bare call), as
    `(file, enclosing function)`. Floor: a call through `getattr`/`importlib` by string is
    not seen."""
    calls = []
    for path in files:
        tree, env, scope = _loaded(path)
        rel = _rel(path)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and (
                    _AST.callee(node, env) == _RESOLVER
                    or _owner_def_call(node, env, "resolve_data_root",
                                       is_owner=rel == _OWNER_FILE)):
                calls.append((rel, scope.get(id(node), "")))
    return calls


_PLANTED_ALIAS = '''

from defender._tenant import resolve_data_root as _rdr
from defender import _tenant as _owner


def _planted_alias():
    return _rdr()


def _planted_module_attribute():
    return _owner.resolve_data_root()
'''


def test_1120_resolve_data_root_is_called_once_and_only_from_entry_points(
        tmp_path: Path) -> None:
    """A resolved-reference census of defender/ (excluding tests/) and scripts/ finds calls to
    resolve_data_root in the entry points that take a tenant (O3's list as correction 3 scopes
    it: run.py, the branch launcher, tenant.py's setup and check, policy_cli, validate_scaffold —
    not held_out, which takes no tenant, nor generate_case, removed: human on PR #1157, nor
    ticket_adapter, whose command line #1107 removed) and nowhere else: not in defender/_tenant.py beyond the definition itself, and not inside runs_base_for, tenant_of_run_dir or
    materialize_run, which take a Tenant or the data root instead (C8). Each calling entry
    module holds exactly one call site (tenant.py at most one per subcommand that resolves the
    root). The census finding run.py's call is its positive control, and a call planted in a
    tmp copy of a scanned module through a from-import alias, and one through a module
    attribute, are both reported (N10); a call by string through getattr or importlib is the
    census's stated floor."""
    assert "resolve_data_root" in dir(_tenant), "the owner lost resolve_data_root itself"
    calls = _resolve_calls(_production_files())
    by_module: dict[str, list[str]] = {}
    for rel, fn in calls:
        by_module.setdefault(rel, []).append(fn)

    assert "defender/run.py" in by_module, (
        f"the census does not find run.py's call — run.py must resolve the data root itself, "
        f"once (the census's positive control): {by_module}")
    outside = {m: fns for m, fns in by_module.items() if m not in _ENTRY_MODULES}
    assert outside == {}, (
        f"resolve_data_root is called outside the entry points (O3: nothing below an entry "
        f"point resolves the root again): {outside}")
    over = {m: fns for m, fns in by_module.items() if len(fns) > _ENTRY_MODULES.get(m, 0)}
    assert over == {}, f"an entry module resolves the data root more than once: {over}"
    inside = [(m, fn) for m, fn in calls
              if any(part in _NEVER_RESOLVE for part in fn.split("."))]
    assert inside == [], f"a function that takes a Tenant or the root resolves it: {inside}"

    planted = tmp_path / "defender" / "run_common.py"
    planted.parent.mkdir(parents=True)
    planted.write_text((H.DEFENDER / "run_common.py").read_text(encoding="utf-8")
                       + _PLANTED_ALIAS, encoding="utf-8")
    planted_fns = {fn for _rel_path, fn in _resolve_calls([planted])}
    assert {"_planted_alias", "_planted_module_attribute"} <= planted_fns, (
        f"the census missed a planted aliased or module-attribute call: {sorted(planted_fns)}")


# ======================================================================================
# Census 3 (V14, human): setup REACHES run start's own readiness function.
# ======================================================================================

def _module_of(path: Path, root: Path) -> str:
    parts = path.relative_to(root).with_suffix("").parts
    return ".".join(parts[:-1] if parts[-1] == "__init__" else parts)


def _own_def_callee(node: ast.Call, env, top_defs: set[str], module: str) -> str | None:
    """A bare call to a module-level def of the SAME module: `_astlib.callee` declines a
    def-bound name by design, so the module's own binding is the fact."""
    func = node.func
    if (isinstance(func, ast.Name) and _AST.callee(node, env) is None
            and func.id in top_defs):  # lint-ast-resolve: ok — the module's own top-level def binds this name; callee() declines def-bound names
        return f"{module}.{func.id}"
    return None


def _call_graph(files: Iterable[Path], root: Path = H.REPO_ROOT) -> dict[str, set[str]]:
    """`module.top_level_def -> every dotted callee its body RESOLVES to` (`_astlib.callee`: a
    from-import, an alias, a module attribute through any import form, a function-local import;
    plus a bare call to the module's own def). A nested def, a lambda or a method folds into its
    top-level def. Floor: a call through a value (a passed-in function, `getattr` by string)
    and a re-export under another module's name are not followed."""
    graph: dict[str, set[str]] = {}
    for path in files:
        tree, env, scope = _loaded(path)
        module = _module_of(path, root)
        top_defs = {n.name for n in tree.body
                    if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))}
        for name in top_defs:
            graph.setdefault(f"{module}.{name}", set())
        for node in ast.walk(tree):
            owner = scope.get(id(node), "") if isinstance(node, ast.Call) else ""
            if not owner:
                continue
            resolved = _AST.callee(node, env) or _own_def_callee(node, env, top_defs, module)
            if resolved:
                graph.setdefault(f"{module}.{owner.split('.')[0]}", set()).add(resolved)
    return graph


def _reach(graph: dict[str, set[str]], start: str, target: str) -> list[str]:
    """The call path from `start` to `target` through `graph`, or [] when none exists."""
    parent: dict[str, str] = {start: ""}
    frontier = [start]
    while frontier:
        node = frontier.pop(0)
        if node == target:
            path = [node]
            while parent[path[-1]]:
                path.append(parent[path[-1]])
            return path[::-1]
        for nxt in sorted(graph.get(node, ())):
            if nxt not in parent:
                parent[nxt] = node
                frontier.append(nxt)
    return []


#: What a hand-copied rule list calls instead of the function (92r2 #1's "V10 is narrower than
#: its own reason"): the readiness function's own parts.
_READINESS_PARTS = ("defender.runtime.verb_dispositions.run_grants",
                    "defender.runtime.verb_dispositions.require_gather_query",
                    "defender.runtime.run_tenant.correlation_dispatch")

_PLANTED_SETUPS = '''

from defender.runtime import run_tenant as _rt_owner
from defender.runtime import verb_dispositions as _vd
from defender.runtime.run_tenant import resolve_run_tenant as _ready


def _planted_setup_direct(folder):
    return _ready(folder, defender_dir=None, dispatches_lead_zero=True)


def _planted_setup_via_helper(folder):
    return _planted_adopt(folder)


def _planted_adopt(folder):
    return _rt_owner.resolve_run_tenant(folder, defender_dir=None, dispatches_lead_zero=True)


def _planted_setup_hand_copied(folder):
    grants = _vd.run_grants(folder)
    _vd.require_gather_query(grants)
    return _rt_owner.correlation_dispatch(folder, _rt_owner.catalog_templates(None),
                                          grants.correlation)
'''


def test_1120_setup_reaches_run_starts_own_readiness_function(tmp_path: Path) -> None:
    """V14 (human): setup calls the SAME function run start uses to decide a tenant can run —
    never a hand-copied rule list (its folder rules — the settings files' parse, mapping.yaml
    included — stay its own, V18). A resolved-reference call graph of defender/ (excluding
    tests/) and scripts/ finds a path from tenant.py's setup function to run start's readiness
    function (`_spec1120.RUN_READINESS`, today runtime/run_tenant.resolve_run_tenant: the grants
    load, require_gather_query, the lead-zero agreement), directly or through any helper. The
    positive control: the same graph finds run.main's path to it (the function the census names
    IS the one run start reaches). The planted controls, in a tmp copy of tenant.py: a setup
    calling it through a from-import alias, and one calling it through a helper and a module
    attribute, are both found; a setup calling run_grants, require_gather_query and
    correlation_dispatch itself — the same rules, copied — is NOT."""
    scanned = _production_files()
    assert H.script_of(tenant_py) in scanned, "the census does not scan the tenant.py setup runs"
    graph = _call_graph(scanned)
    run_path = _reach(graph, f"{run_py.__name__}.main", H.RUN_READINESS)
    assert run_path, (
        f"run.main does not reach {H.RUN_READINESS} — the census's positive control; if the "
        f"readiness function moved, rename RUN_READINESS in _spec1120.py")
    assert H.SETUP_FUNCTION in graph, (
        f"tenant.py defines no {H.SETUP_FUNCTION} — rename SETUP_FUNCTION in _spec1120.py")
    setup_path = _reach(graph, H.SETUP_FUNCTION, H.RUN_READINESS)
    copied = [part for part in _READINESS_PARTS if _reach(graph, H.SETUP_FUNCTION, part)]
    assert setup_path, (
        f"setup does not reach run start's readiness function {H.RUN_READINESS} (V14); it "
        f"reaches these of its parts on its own: {copied} (run.main's path: {run_path})")

    planted = tmp_path / "defender" / "scripts" / "tenant.py"
    planted.parent.mkdir(parents=True)
    planted.write_text(H.script_of(tenant_py).read_text(encoding="utf-8")
                       + _PLANTED_SETUPS, encoding="utf-8")
    merged = {**graph, **_call_graph([planted], root=tmp_path)}
    found = {fn: bool(_reach(merged, f"defender.scripts.tenant.{fn}", H.RUN_READINESS))
             for fn in ("_planted_setup_direct", "_planted_setup_via_helper",
                        "_planted_setup_hand_copied")}
    assert found == {"_planted_setup_direct": True, "_planted_setup_via_helper": True,
                     "_planted_setup_hand_copied": False}, (
        f"the census misjudged a planted setup: {found}")


# ======================================================================================
# s083: the layout members no production code reads yet, against CI's dead-code gate.
# ======================================================================================

_VULTURE_BASELINE = H.REPO_ROOT / "scripts" / "lint" / "lint_vulture_baseline.json"
_NEW_TENANT_FINDING = re.compile(r"defender/_tenant\.py:\d+: unused property '(\w+)'")


@pytest.mark.gate
def test_1120_s8_tenant_layout_members_with_no_production_reader(data_root: Path) -> None:
    """Tenant carries all nine D1 path properties (dir, runs, sessions, episodes, learning,
    worktrees, knowledge, settings, agent) and the row file's path property, each a Path on an
    accepted tenant — some with no production reader until D11 or D12. CI's dead-code gate
    (scripts/lint/lint_vulture.py, run as CI runs it) reports no NEW finding for any of them:
    each is read, or baselined with a reason naming the later design step (a D-number) that
    reads it. The stale TenantPaths baseline row is gone: no baseline reason for
    defender/_tenant.py still names TenantPaths (PO-x)."""
    H.adopted(data_root)
    accepted = H.accept(_tenant, data_root)
    members = (*H.TENANT_PATH_PROPERTIES, H.ROW_PATH_PROPERTY)
    not_paths = {m: type(getattr(accepted, m, None)).__name__ for m in members
                 if not isinstance(getattr(accepted, m, None), Path)}
    assert not_paths == {}, f"Tenant lacks a D1 path property, or it is not a Path: {not_paths}"

    vulture_bin = Path(sys.executable).parent
    proc = subprocess.run(  # noqa: S603 — fixed argv, the repo's own lint
        [sys.executable, str(H.REPO_ROOT / "scripts" / "lint" / "lint_vulture.py")],
        cwd=str(H.REPO_ROOT), capture_output=True, text=True, timeout=300, check=False,
        env={**os.environ, "PATH": f"{vulture_bin}{os.pathsep}{os.environ.get('PATH', '')}"})
    text = proc.stdout + proc.stderr
    assert proc.returncode in (0, 1), f"the dead-code gate could not run:\n{text}"
    new = sorted({m for m in _NEW_TENANT_FINDING.findall(text) if m in members})
    assert new == [], (
        f"the dead-code gate reports NEW findings for Tenant's layout members {new} — read "
        f"each, or baseline it with a reason naming the step that reads it:\n{text}")

    entries = json.loads(_VULTURE_BASELINE.read_text(encoding="utf-8"))
    rows = entries.get("entries", entries)
    tenant_rows = {k: v for k, v in rows.items() if k.startswith("defender/_tenant.py:")}
    stale = {k: v for k, v in tenant_rows.items() if "TenantPaths" in str(v)}
    assert stale == {}, f"the stale TenantPaths baseline rows are still there: {stale}"
    unexplained = {k: v for k, v in tenant_rows.items()
                   if any(f"'{m}'" in k for m in members) and not re.search(r"\bD\d+\b", str(v))}
    assert unexplained == {}, (
        f"a Tenant layout member is baselined without naming the step that reads it: "
        f"{unexplained}")
