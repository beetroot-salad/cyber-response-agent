"""#1080 group `integrations`: the generic HTTP check and the fault types, the Elastic grammar,
and the adapter-private endpoint table the adapters hand to the moved check.

SCOPE CUT (2026-10-04, human): `scripts/adapters/` — the fault types, the generic HTTP check,
the Elastic grammar and the endpoint table — stays where it is; its move is owned by #1172 (with
#1121 for the Elastic grammar), and this group's tests are parked with it
(`spec-flow/specs/parked/1080/parked_integrations.py`, with the coined `TABLE_KW` and the
`goldens/integrations.json` capture). Kept here: s025's `ParamsTooDeep` cell, which rides with
`record_query`'s query-rule slice into the flat tier.
"""
from __future__ import annotations

import ast
import importlib
import importlib.util
from collections.abc import Callable
from types import ModuleType
from typing import Any

from defender.tests.scripts_1080_split import _spec1080 as S


# ======================================================================================
# The one normaliser and row comparison (shared with the golden capture)
# ======================================================================================


def _run(fn: Callable[..., Any], /, *args: Any, **kwargs: Any) -> tuple[Any, Exception | None]:
    try:
        return fn(*args, **kwargs), None
    except Exception as e:  # noqa: BLE001 — the exception IS the observed outcome
        return None, e


# ======================================================================================
# Locating the moved code (at call time, never at import)
# ======================================================================================


def _import(relpath: str, line: int, dotted: str) -> ModuleType:
    try:
        return importlib.import_module(dotted)
    except ModuleNotFoundError as e:
        raise AssertionError(
            f"{relpath}:{line} imports {dotted}, which no longer exists — a site left on the old "
            f"path ({e})") from e


def _holder(relpath: str, line: int, base: str, attr: str) -> Any:
    """What `from <base> import <attr>` binds: a submodule, or an attribute of `base`."""
    if importlib.util.find_spec(base) is not None:
        mod = _import(relpath, line, base)
        if hasattr(mod, attr):
            return getattr(mod, attr)
    return _import(relpath, line, f"{base}.{attr}")


def _from_import(relpath: str, node: ast.ImportFrom, pkg: list[str], name: str,
                 read_as_attr: set[str]) -> list[tuple[str, Any]]:
    base = node.module or ""
    if node.level:
        parent = pkg[: len(pkg) - (node.level - 1)] if node.level > 1 else pkg
        base = ".".join([*parent, node.module] if node.module else parent)
    out: list[tuple[str, Any]] = []
    for a in node.names:
        if a.name == name:
            mod = _import(relpath, node.lineno, base)
            assert hasattr(mod, name), (
                f"{relpath}:{node.lineno} imports {name} from {base}, which has no such name")
            out.append((base, getattr(mod, name)))
        elif (a.asname or a.name) in read_as_attr:
            held = _holder(relpath, node.lineno, base, a.name)
            if isinstance(held, ModuleType) and hasattr(held, name):
                out.append((held.__name__, getattr(held, name)))
    return out


def _bindings(relpath: str, name: str) -> list[tuple[str, Any]]:
    """Every object `relpath` binds to `name` through an import — at module level or inside a
    function body — as (the module it is taken from, the object), each import resolved by
    really importing the module it names. Covers `from M import name`, and a module imported
    (under any alias) whose attribute `name` the file reads (`case_ticket.CaseTicketError`)."""
    src = (S.REPO_ROOT / relpath).read_text(encoding="utf-8")
    tree = ast.parse(src, filename=relpath)
    pkg = S.dotted(relpath).split(".")
    if not relpath.endswith("__init__.py"):
        pkg = pkg[:-1]
    read_as_attr = {n.value.id for n in ast.walk(tree) if isinstance(n, ast.Attribute)
                    and n.attr == name and isinstance(n.value, ast.Name)}
    out: list[tuple[str, Any]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            out += _from_import(relpath, node, pkg, name, read_as_attr)
        elif isinstance(node, ast.Import):
            for a in node.names:
                if a.asname and a.asname in read_as_attr:
                    held = _import(relpath, node.lineno, a.name)
                    if hasattr(held, name):
                        out.append((a.name, getattr(held, name)))
    return out


def _assert_bound_to(relpath: str, name: str, obj: Any) -> None:
    """Every binding `relpath` holds for `name` IS `obj`, taken from a module outside
    `defender/scripts/` (a binding left on the old path, or a copy, fails)."""
    found = _bindings(relpath, name)
    assert found, f"{relpath} binds no `{name}` through any import"
    for source, got in found:
        assert got is obj, (
            f"{relpath} binds `{name}` from {source} to a different object than its one "
            f"definition ({S.home_of(name)}) — two class objects, so a raise on one side is "
            "missed by the catch on the other")
        if not S.AT_BASE:
            assert not source.startswith("defender.scripts."), (
                f"{relpath} still takes `{name}` from {source}, the old path")


# ======================================================================================
# The tests
# ======================================================================================


def test_moved_exception_type_raised_on_one_side_and_caught_on_the_other():
    """Each moved exception type has one definition. Under the 2026-10-04 scope cut that is
    `ParamsTooDeep`, which rides with the query-rule slice into the flat tier; the code that
    raises it and the code that catches it bind the same class object, with every catch site
    repointed (capture, estate registry, _family, query_tool). A second definition or a catch
    site left on the old path is a failure. (The VisualizeFailed, CaseTicketError, ViewNameError
    and fault-type cells read modules the cut leaves in place; they are parked with #1105, the
    case_ticket follow-up #1190 and #1172.)

    Observed: the type has exactly one definition in the tree; every listed site's import of it
    (module-level or inside a function) resolves to that object; and a raise from the moved
    params normaliser is caught by each site's binding."""
    assert len(S.definitions("ParamsTooDeep")) == 1, (
        f"`ParamsTooDeep` has {len(S.definitions('ParamsTooDeep'))} definitions: "
        f"{list(S.definitions('ParamsTooDeep'))}")

    too_deep = S.moved("ParamsTooDeep")
    for relpath in ("defender/learning/branch/capture.py",
                    "defender/learning/branch/estate/registry.py",
                    "defender/runtime/branch/_family.py", "defender/runtime/query_tool.py"):
        _assert_bound_to(relpath, "ParamsTooDeep", too_deep)
    deep: Any = []
    for _ in range(40):
        deep = [deep]
    exc = _run(S.query_rule("_json_safe_params"), {"q": deep})[1]
    assert type(exc) is too_deep, f"the nesting refusal is {exc!r}"
