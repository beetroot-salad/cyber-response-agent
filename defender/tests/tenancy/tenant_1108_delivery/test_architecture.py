"""Explicit host identities, package ownership and where tenant delivery is wired (#1108 P4)."""
from __future__ import annotations

import ast
import importlib

from ._support import DEFENDER, target

_OWNER = "learning/author/version_control/"


def production_trees():
    for path in sorted(DEFENDER.rglob("*.py")):
        relative = path.relative_to(DEFENDER)
        if any(part in {"tests", ".venv", "__pycache__"} for part in relative.parts):
            continue
        yield relative.as_posix(), ast.parse(path.read_text(encoding="utf-8"))


def non_docstring_nodes(tree):
    docstrings = set()
    for node in ast.walk(tree):
        if (isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
                and node.body and isinstance(node.body[0], ast.Expr)):
            value = node.body[0].value
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                docstrings.add(id(value))
    return [node for node in ast.walk(tree) if id(node) not in docstrings]


def test_delivery_has_no_disk_credential_location():
    target()
    assert list(_spellings("git-credentials")) == []


#: P3's delivery package. P4 wires it into host-side delivery processes (drains, `tenant.py`,
#: the launch-time publish child); the run process never imports it (P-3).
_DELIVERY = "defender.learning.author.version_control"
_TENANT_DELIVERY = f"{_DELIVERY}.delivery.TenantDelivery"


def _p4_census():
    # The #1108 P4 census engine (symbol resolution and the static import closure); lazy, so
    # this module collects whatever state that contract is in.
    return importlib.import_module("defender.tests.tenancy.tenant_1108_p4.test_census")


def _delivery_modules(closure):
    return sorted(m for m in closure if m == _DELIVERY or m.startswith(_DELIVERY + "."))


def test_the_run_process_never_imports_tenant_delivery():
    """P-3 (#1108 P4, replacing P3's dormancy ban): the run process — `run.py` and
    `run_common.py` and everything they import, at module level, inside a function, or by
    an `import_module` string — never reaches the delivery package. The launch-time publish
    is a separate child process; the run only receives its outcome."""
    target()
    census = _p4_census()
    closure = census.static_import_closure(census.RUN_ENTRIES)
    assert len(closure) > 50, "the closure walk found almost nothing: it is blind, not clean"
    reached = _delivery_modules(closure)
    chains = []
    for module in reached:
        chain, at = [], module
        while at is not None:
            chain.append(at)
            at = closure[at]
        chains.append(" <- ".join(chain))
    assert reached == [], "the run process imports tenant delivery:\n  " + "\n  ".join(chains)


def test_the_run_closure_walk_sees_lazy_aliased_and_string_imports(tmp_path):
    """P-3 positive control: on a planted tree, the same walk reaches the delivery package
    through a function-local aliased from-import two modules away and through an
    `import_module` string — the evasions a module-level-only walk would miss — while a
    module only NAMED to spawn a child (`-m`, the separate publish process P-3 wants) is not
    an import."""
    census = _p4_census()
    root = tmp_path / "defender"
    for rel, text in {
        "run.py": "def main():\n    from .helper import go\n    return go()\n",
        "helper.py": ("import importlib\n"
                      "def go():\n"
                      "    from defender.learning.author import version_control as vc\n"
                      "    return vc, importlib.import_module('defender.learning.author.version_control.delivery')\n"),
        "quiet.py": ("import subprocess, sys\n"
                     "def main():\n"
                     "    return subprocess.run([sys.executable, '-m', "
                     "'defender.learning.author.version_control.delivery'])\n"),
        "learning/__init__.py": "", "learning/author/__init__.py": "",
        "learning/author/version_control/__init__.py": "",
        "learning/author/version_control/delivery.py": "class TenantDelivery: ...\n",
    }.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text, encoding="utf-8")
    reached = _delivery_modules(census.static_import_closure(("defender.run",), root=root))
    assert reached == [_DELIVERY, f"{_DELIVERY}.delivery"], reached
    assert _delivery_modules(census.static_import_closure(("defender.quiet",), root=root)) == []


def _references_tenant_delivery(path, tree, census) -> bool:
    """Does the module at `path` (under `defender/`) reference `TenantDelivery`, resolved by
    symbol — an import of it under any alias, through the package door, or an attribute
    chain reaching it?"""
    astlib = census._astlib
    resolver = census.Census()
    module, package = astlib.module_and_package(path)
    env = astlib.module_env(tree, module=module, package=package)
    for node in ast.walk(tree):
        origins = []
        if isinstance(node, ast.ImportFrom):
            source = astlib.import_source(node, package)
            origins = [f"{source}.{alias.name}" for alias in node.names]
        elif isinstance(node, (ast.Name, ast.Attribute)):
            origins = [astlib.origin(node, env) or ""]
        for found in origins:
            canonical = resolver.canonical(found) if found else ""
            if canonical == _TENANT_DELIVERY or canonical.startswith(_TENANT_DELIVERY + "."):
                return True
    return False


def test_the_caller_census_resolves_aliases_and_the_door():
    """Positive/negative control for the caller census: an aliased import through the
    package door and a module-alias attribute chain are references; a same-named local
    class is not."""
    census = _p4_census()
    door = ast.parse("from defender.learning.author.version_control import TenantDelivery as TD\n"
                     "def f(t):\n    return TD.open(t)\n")
    chain = ast.parse("import defender.learning.author.version_control as vc\n"
                      "def f(t):\n    return vc.TenantDelivery.open(t)\n")
    local = ast.parse("class TenantDelivery: ...\ndef f(t):\n    return TenantDelivery()\n")
    assert _references_tenant_delivery("learning/core/planted.py", door, census)
    assert _references_tenant_delivery("learning/core/planted.py", chain, census)
    assert not _references_tenant_delivery("learning/core/planted.py", local, census)


def test_tenant_delivery_has_production_callers_outside_the_run_process():
    """#1108 P4 wires P3's delivery (replacing the dormancy ban): `TenantDelivery` is
    referenced by at least one production module outside its package — a host-side delivery
    process (drains, revert, `tenant.py`, the publish child) — and none of them is in the run
    process's import closure."""
    target()
    census = _p4_census()
    module_of = census._astlib.module_and_package
    callers = {module_of(path)[0] for path, tree in production_trees()
               if not path.startswith(_OWNER) and _references_tenant_delivery(path, tree, census)}
    assert callers, "TenantDelivery has no production caller: P4 wires none"
    in_run = sorted(callers & set(census.static_import_closure(census.RUN_ENTRIES)))
    assert in_run == [], f"TenantDelivery callers inside the run process: {in_run}"


#: Prose a model may be handed: every text file of these kinds under `defender/` except the
#: operator docs and the tests, plus the two shipped tenant knowledge trees' agent halves.
_PROSE_SUFFIXES = frozenset({".md", ".txt", ".yaml", ".yml", ".j2", ".jinja", ".tmpl"})
_OPERATOR_DOCS = frozenset({"README.md", "CLAUDE.md", "AGENTS.md"})


def _agent_facing_text():
    for path in sorted(DEFENDER.rglob("*")):
        relative = path.relative_to(DEFENDER)
        if (relative.parts[0] in {"docs", "tests", ".venv"} or "__pycache__" in relative.parts
                or path.name in _OPERATOR_DOCS or path.suffix not in _PROSE_SUFFIXES
                or not path.is_file()):
            continue
        yield path
    for tree in ("tenant-template", "tenant-fixture"):
        yield from (p for p in sorted((DEFENDER.parent / "knowledge" / tree / "agent").rglob("*"))
                    if p.is_file())


def _folded(node):
    """The string a constant expression spells, else None: a literal, `+` of spelled parts, an
    f-string whose parts all spell, a literal separator's join over literal elements. Computed
    spellings beyond these (slicing, `chr`, a value read at run time) are out of a census's reach."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _folded(node.left), _folded(node.right)
        return None if left is None or right is None else left + right
    if isinstance(node, ast.JoinedStr):
        parts = [_folded(value) for value in node.values]
        return None if None in parts else "".join(parts)
    if isinstance(node, ast.FormattedValue) and node.format_spec is None and node.conversion in (-1, ord("s")):
        return _folded(node.value)
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "join"  # lint-ast-resolve: ok — str.join on a literal receiver; no binding to resolve
            and len(node.args) == 1 and isinstance(node.args[0], (ast.List, ast.Tuple))):
        separator, parts = _folded(node.func.value), [_folded(e) for e in node.args[0].elts]
        return None if separator is None or None in parts else separator.join(parts)
    return None


def _spellings(name):
    """Every outermost constant expression in production source that spells `name`."""
    for path, tree in production_trees():
        hits = [node for node in non_docstring_nodes(tree)
                if not isinstance(node, ast.expr_context) and name in (_folded(node) or "")]
        inner = {id(child) for node in hits for child in ast.walk(node) if child is not node}
        yield from ((path, node.lineno, _folded(node)) for node in hits if id(node) not in inner)


def test_code_check_file_name_is_owned_by_the_box_package_and_absent_from_agent_text():
    from defender import box
    from defender.box import _oracle
    name = box.CODE_CHECK_FILE  # a zero-implementation tree is not a successful census
    spelled = sorted(_spellings(name))
    assert len(spelled) == 1, f"the check file's name must be spelled exactly once: {spelled}"
    path, _line, value = spelled[0]
    assert path.startswith("box/"), spelled
    assert value == name, spelled
    assert [f for f in _oracle.RUNNER_FILES if name in f] == [f"defender/{name}"]
    named = [str(p.relative_to(DEFENDER.parent)) for p in _agent_facing_text()
             if name.encode() in p.read_bytes()]
    assert named == [], f"agent-facing text names the box's check file: {named}"
