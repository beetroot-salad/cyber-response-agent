"""#1160 — the run-records owner lint tags an owner through every binding shape.

`lint_run_records`' join arm reports a literal-free `/` join onto a value that holds an owner
instance. The tagging behind it (`scripts/lint/_astlib.py`: `_partial_locals`, `_owner_locals`,
`_partial_owner_of`) used to see only a plain single-target `name = <owner>` and dropped the tag
on any later rebinding, so these escaped in silence:

* O1 — the join is reported whatever binding shape put the owner in the name: an annotated
  local, a literal tuple/list unpack, a multi-target assign, a carrier alias (`rt2 = rt`), a
  cross-module carrier factory (`resolve_tenant`, `run_tenant_for`), and a same-module factory
  (a top-level def annotated `-> Tenant` / `-> RunTenant`, in either the Name or the
  `_tenant.Tenant` attribute form). Full owners too: `p: RunPaths = RunPaths(d)`.
* O2 — tags are sticky: a join made while a name held an owner stays reported after the name
  is rebound (`= None`, an annotated rebind, a tuple rebind).
* O3 — the census: every public top-level function in the sweep annotated `-> Tenant` /
  `-> RunTenant` sits in `_astlib._PARTIAL_OWNER_FACTORIES` or in the carrier-factory table.
  The design doc leaves that table's name open; these tests fix it as
  `_astlib._CARRIER_FACTORIES`, a dict of factory origin -> carrier class origin
  (`"defender.runtime.run_tenant.resolve_tenant": "defender.runtime.run_tenant.RunTenant"`),
  beside `_PARTIAL_OWNER_FACTORIES`.
* O4 — the knowledge halves stay clean through every new shape: joins onto
  `tenant.settings` / `.knowledge` / `.agent` and `run_tenant.settings`. A call-result unpack
  (`a, b = f()`) is not traced, and a parameter, local or nested def that shadows a
  module-level factory is not the factory.
* O5 — the live sweep stays at 0 findings with an empty allow-list. Pinned already by
  `test_1077_gate.py::test_gate_passes_with_an_empty_allow_list` (gate-marked, run by CI's
  `lint` job); not repeated here.

Every cell is a function of its own in ONE planted module, scanned once through the 1120 suite's
`_scan_planted` (`lint_run_records.scan` over a tmp tree, the way CI drives the gate), so a
finding is attributed to its cell with `_in(displays, fn)`. A reported cell asserts the JOIN
finding specifically: `p: RunPaths = RunPaths(d); p.gather_raw / x` was reported today as
"unresolvable accessor use", an outcome that disappears by design and is NOT pinned here. Every
clean cell runs beside the `control` join (`EpisodePaths(ep).runs / x`, reported) and beside a
reported twin of the same binding shape onto an owned member (named in `CLEAN`), so its
emptiness cannot pass because the arm or the tagging is dead.
"""
from __future__ import annotations

import ast
import textwrap
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import pytest

from defender.tests import _spec1077 as S
from defender.tests._by_path import cached_parse, import_lint_lib
from defender.tests.tenant_1120_piece1.test_1120_lints_and_fixture import (
    JOIN_FINDING,
    _in,
    _lint_run_records,
    _scan_planted,
)

#: The class origins the factory tables map to.
TENANT = "defender._tenant.Tenant"
RUN_TENANT = "defender.runtime.run_tenant.RunTenant"

_ACCEPT = "accept_tenant(root, tid, defender_dir=root)"
_RESOLVE = "resolve_tenant(root, tid, defender_dir=root, dispatches_lead_zero=False)"

#: One module, one function per cell. `_f` / `_g` / `_h` are the same-module factories (M3):
#: literal-free, `...` bodies, annotated in each form the live tree uses.
PLANTED = textwrap.dedent(f"""\
    from pathlib import Path

    from defender import _tenant
    from defender._episode_paths import EpisodePaths
    from defender._run_paths import RunPaths
    from defender._tenant import Tenant, accept_tenant
    from defender.runtime import run_tenant as run_tenant_mod
    from defender.runtime.run_tenant import RunTenant, resolve_tenant, run_tenant_for


    def _f(root: Path) -> RunTenant:
        ...


    def _g(root: Path) -> Tenant:
        ...


    def _h(root: Path) -> _tenant.Tenant:
        ...


    def control(ep: Path, x: str) -> Path:
        return EpisodePaths(ep).runs / x


    # ---- O1: reported, whatever shape bound the owner ------------------------------------

    def ann_assign_tenant(root: Path, tid: str, x: str) -> Path:
        t: Tenant = {_ACCEPT}
        return t.runs / x


    def carrier_factory_via_module(root: Path, tid: str, x: str) -> Path:
        rt = run_tenant_mod.{_RESOLVE}
        return rt.tenant.learning / x


    def carrier_factory(root: Path, tid: str, x: str) -> Path:
        rt = {_RESOLVE}
        return rt.tenant.runs / x


    def carrier_factory_chain(t: Tenant, root: Path, x: str) -> Path:
        return run_tenant_for(t, defender_dir=root, dispatches_lead_zero=False).tenant.runs / x


    def local_carrier_factory(root: Path, x: str) -> Path:
        rt = _f(root)
        return rt.tenant.episodes / x


    def local_tenant_factory_chain(root: Path, x: str) -> Path:
        return _g(root).runs / x


    def local_tenant_factory_attribute_annotation(root: Path, x: str) -> Path:
        t = _h(root)
        return t.sessions / x


    def tuple_unpack(root: Path, tid: str, x: str) -> Path:
        t, n = {_ACCEPT}, 1
        return t.runs / x


    def list_unpack(root: Path, tid: str, x: str) -> Path:
        [t, n] = [{_ACCEPT}, 1]
        return t.worktrees / x


    def multi_target_first(root: Path, tid: str, x: str) -> Path:
        a = b = {_ACCEPT}
        return a.runs / x


    def multi_target_last(root: Path, tid: str, x: str) -> Path:
        a = b = {_ACCEPT}
        return b.runs / x


    def carrier_alias(rt: RunTenant, x: str) -> Path:
        rt2 = rt
        return rt2.tenant.runs / x


    def ann_assign_run_paths(d: Path, x: str) -> Path:
        p: RunPaths = RunPaths(d)
        return p.gather_raw / x


    def owner_tuple_unpack(d: Path, x: str) -> Path:
        p, n = RunPaths(d), 1
        return p.gather_raw / x


    def owner_multi_target(d: Path, x: str) -> Path:
        p = q = RunPaths(d)
        return p.gather_raw / x


    # ---- O2: a join made before a rebinding stays reported --------------------------------

    def sticky_tenant(root: Path, tid: str, x: str) -> Path:
        t = {_ACCEPT}
        out = t.runs / x
        t = None
        return out


    def sticky_run_paths(d: Path, x: str) -> Path:
        p = RunPaths(d)
        out = p.gather_raw / x
        p = None
        return out


    def sticky_carrier_parameter(rt: RunTenant, x: str) -> Path:
        out = rt.tenant.runs / x
        rt = None
        return out


    def sticky_tenant_annotated_rebind(root: Path, tid: str, x: str) -> Path:
        t = {_ACCEPT}
        out = t.runs / x
        t: object = None
        return out


    def sticky_run_paths_unpack_rebind(d: Path, x: str) -> Path:
        p = RunPaths(d)
        out = p.gather_raw / x
        p, n = None, 0
        return out


    # ---- O4: clean, through every new shape ------------------------------------------------

    def carrier_factory_tenant_settings(root: Path, tid: str, x: str) -> Path:
        rt = {_RESOLVE}
        return rt.tenant.settings / x


    def carrier_factory_own_settings(root: Path, tid: str, x: str) -> Path:
        rt = {_RESOLVE}
        return rt.settings / x


    def carrier_factory_chain_agent(t: Tenant, root: Path, x: str) -> Path:
        return run_tenant_for(t, defender_dir=root, dispatches_lead_zero=False).tenant.agent / x


    def ann_assign_tenant_knowledge(root: Path, tid: str, x: str) -> Path:
        t: Tenant = {_ACCEPT}
        return t.knowledge / x


    def local_carrier_factory_settings(root: Path, x: str) -> Path:
        rt = _f(root)
        return rt.tenant.settings / x


    def local_carrier_factory_own_settings(root: Path, x: str) -> Path:
        rt = _f(root)
        return rt.settings / x


    def local_tenant_factory_chain_knowledge(root: Path, x: str) -> Path:
        return _g(root).knowledge / x


    def tuple_unpack_settings(root: Path, tid: str, x: str) -> Path:
        t, n = {_ACCEPT}, 1
        return t.settings / x


    def multi_target_agent(root: Path, tid: str, x: str) -> Path:
        a = b = {_ACCEPT}
        return b.agent / x


    def carrier_alias_knowledge(rt: RunTenant, x: str) -> Path:
        rt2 = rt
        return rt2.tenant.knowledge / x


    def carrier_alias_own_settings(rt: RunTenant, x: str) -> Path:
        rt2 = rt
        return rt2.settings / x


    def unpack_call_result(root: Path, pair, x: str) -> Path:
        a, b = pair(root)
        return a.runs / x


    def shadowed_by_parameter(_g, x: str, y: str) -> Path:
        return _g(x).runs / y


    def shadowed_by_local(root: Path, other, x: str) -> Path:
        _g = other
        return _g(root).runs / x


    def shadowed_by_nested_def(root: Path, x: str) -> Path:
        def _g(r: Path) -> Path:
            ...
        return _g(root).runs / x
    """)

#: O1 — each must carry the JOIN finding.
REPORTED = (
    "ann_assign_tenant", "carrier_factory_via_module", "carrier_factory", "carrier_factory_chain",
    "local_carrier_factory", "local_tenant_factory_chain",
    "local_tenant_factory_attribute_annotation", "tuple_unpack", "list_unpack",
    "multi_target_first", "multi_target_last", "carrier_alias", "ann_assign_run_paths",
    "owner_tuple_unpack", "owner_multi_target",
)

#: O2 — the join precedes a rebinding of the owner's name in the same scope.
STICKY = (
    "sticky_tenant", "sticky_run_paths", "sticky_carrier_parameter",
    "sticky_tenant_annotated_rebind", "sticky_run_paths_unpack_rebind",
)

#: O4 — clean cell -> its reported twin: the same binding shape joined onto an owned member,
#: pinned by `test_a_join_through_each_binding_shape_is_reported` against the same scan.
CLEAN = {
    "carrier_factory_tenant_settings": "carrier_factory",
    "carrier_factory_own_settings": "carrier_factory",
    "carrier_factory_chain_agent": "carrier_factory_chain",
    "ann_assign_tenant_knowledge": "ann_assign_tenant",
    "local_carrier_factory_settings": "local_carrier_factory",
    "local_carrier_factory_own_settings": "local_carrier_factory",
    "local_tenant_factory_chain_knowledge": "local_tenant_factory_chain",
    "tuple_unpack_settings": "tuple_unpack",
    "multi_target_agent": "multi_target_last",
    "carrier_alias_knowledge": "carrier_alias",
    "carrier_alias_own_settings": "carrier_alias",
    # Untraced: a call result's elements are unknown, and `runs` is a bare word, so not even
    # the "unresolvable accessor use" arm fires.
    "unpack_call_result": "tuple_unpack",
    # The module-level `_g` is a factory; a scope that rebinds `_g` calls something else.
    "shadowed_by_parameter": "local_tenant_factory_chain",
    "shadowed_by_local": "local_tenant_factory_chain",
    "shadowed_by_nested_def": "local_tenant_factory_chain",
}


@pytest.fixture(scope="module")
def displays(tmp_path_factory: pytest.TempPathFactory) -> list[str]:
    """`lint_run_records.scan` over a tmp tree holding only `PLANTED`, once for the module."""
    return _scan_planted(tmp_path_factory.mktemp("owner_tagging_1160"),
                         "runtime/owner_tagging_1160.py", PLANTED)


def _joins(displays: list[str], fn: str) -> list[str]:
    return [d for d in _in(displays, fn) if JOIN_FINDING in d]


def _assert_control_live(displays: list[str]) -> None:
    assert _joins(displays, "control"), "the join arm is not live:\n" + "\n".join(displays)


def _assert_planted(fn: str) -> None:
    # A misspelt cell name would make `_in` empty: a reported cell would fail for no reason,
    # and a clean cell would pass vacuously.
    assert f"\ndef {fn}(" in PLANTED, f"{fn} is not a function of the planted module"


@pytest.mark.parametrize("cell", REPORTED)
def test_a_join_through_each_binding_shape_is_reported(displays: list[str], cell: str) -> None:
    """O1: a literal-free join onto a name (or call) holding an owner instance is reported as a
    join, whichever binding shape put the owner there."""
    _assert_planted(cell)
    _assert_control_live(displays)
    assert _joins(displays, cell), (
        f"the join in {cell}() is not reported as {JOIN_FINDING!r}; its findings: "
        f"{_in(displays, cell)}")


@pytest.mark.parametrize("cell", STICKY)
def test_a_join_made_before_the_name_is_rebound_stays_reported(
        displays: list[str], cell: str) -> None:
    """O2: rebinding the owner's name later in the scope does not hide a join made while it held
    the owner — the scope's forward pass never untags a name."""
    _assert_planted(cell)
    _assert_control_live(displays)
    assert _joins(displays, cell), (
        f"the join in {cell}() is hidden by the later rebinding; its findings: "
        f"{_in(displays, cell)}")


@pytest.mark.parametrize("cell", sorted(CLEAN))
def test_knowledge_halves_and_untraced_shapes_stay_clean(displays: list[str], cell: str) -> None:
    """O4: joins onto the knowledge halves, onto an untraced call-result unpack, and onto a call
    to a name that shadows a module-level factory report nothing — beside the live control and
    a reported twin of the same shape."""
    _assert_planted(cell)
    _assert_control_live(displays)
    twin = CLEAN[cell]
    assert twin in REPORTED, f"{cell}'s twin {twin} is not a reported cell"
    assert _in(displays, cell) == [], (
        f"{cell}() is reported, while it must stay clean (its twin {twin}() is the reported "
        f"form): {_in(displays, cell)}")


# ======================================================================================
# O3 / M4 — the census of public Tenant / RunTenant factories.
# ======================================================================================

#: The class a factory returns -> the `_astlib` table it must be listed in.
_TABLE_FOR = {TENANT: "_PARTIAL_OWNER_FACTORIES", RUN_TENANT: "_CARRIER_FACTORIES"}

#: The public factories the live tree holds today (#1160's census, c6).
_TODAY = {
    "defender._tenant.accept_tenant": TENANT,
    "defender.runtime.run_tenant.resolve_tenant": RUN_TENANT,
    "defender.runtime.run_tenant.run_tenant_for": RUN_TENANT,
}


def _module_parts(path: Path, repo: Path) -> list[str]:
    parts = list(path.relative_to(repo).with_suffix("").parts)
    return parts[:-1] if parts[-1] == "__init__" else parts


def _absolute(found: str, package: list[str]) -> list[str]:
    """`_astlib`'s relative origin (`._tenant.Tenant`) as the absolute origins it may name.
    `from . import m` and `from .m import x` both spell one extra leading dot per level, so a
    relative origin is read at both levels; the census keeps whichever names a factory class."""
    if not found.startswith("."):
        return [found]
    rest = found.lstrip(".")
    dots = len(found) - len(rest)
    out = []
    for level in (dots, dots - 1):
        if 1 <= level <= len(package):
            out.append(".".join([*package[:len(package) - level + 1], *rest.split(".")]))
    return out


def _returned_class(ann: ast.expr, env: Any, module: str, package: list[str],
                    classes: set[str]) -> str | None:
    """The factory class (`TENANT` / `RUN_TENANT`) a return annotation names, or None.

    Resolved through `_astlib` against the module scope, where a return annotation evaluates:
    an import (`Tenant`, `_tenant.Tenant`, a relative import) resolves to its origin. A class
    the module defines itself (`Tenant` inside `_tenant.py`) has no import to resolve, so it is
    named from the module's own path. A string annotation is parsed first."""
    astlib = import_lint_lib("_astlib")
    if isinstance(ann, ast.Constant) and isinstance(ann.value, str):
        try:
            ann = ast.parse(ann.value, mode="eval").body
        except SyntaxError:
            return None
    if not isinstance(ann, (ast.Name, ast.Attribute)):
        return None
    found = astlib._origin(ann, env)  # the module-scope resolver M3 itself names
    if found is None and isinstance(ann, ast.Name) and ann.id in classes:
        found = f"{module}.{ann.id}"
    if found is None:
        return None
    return next((c for c in _absolute(found, package) if c in _TABLE_FOR), None)


def _factory_census(files: Iterable[Path], repo: Path) -> dict[str, str]:
    """{public top-level function's origin: the factory class its return annotation names}
    over `files`. Private names, methods and nested defs are not factories (M4)."""
    astlib = import_lint_lib("_astlib")
    out: dict[str, str] = {}
    for path in files:
        rel = path.relative_to(repo).as_posix()
        text, tree = cached_parse(path, rel)
        if "Tenant" not in text:
            continue  # every spelling that resolves to either class carries the word
        env = astlib.module_env(tree)
        parts = _module_parts(path, repo)
        module = ".".join(parts)
        package = parts if path.name == "__init__.py" else parts[:-1]
        classes = {n.name for n in tree.body if isinstance(n, ast.ClassDef)}
        for node in tree.body:
            if (not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                    or node.name.startswith("_") or node.returns is None):
                continue
            cls = _returned_class(node.returns, env, module, package, classes)
            if cls is not None:
                out[f"{module}.{node.name}"] = cls
    return out


def _unlisted(census: dict[str, str]) -> list[str]:
    """Census entries missing from the table their class belongs in (or listed against the
    wrong class)."""
    astlib = import_lint_lib("_astlib")
    tables = {cls: getattr(astlib, name, {}) for cls, name in _TABLE_FOR.items()}
    return sorted(f"{fn} -> {cls} (belongs in _astlib.{_TABLE_FOR[cls]})"
                  for fn, cls in census.items() if tables[cls].get(fn) != cls)


def test_every_public_tenant_or_run_tenant_factory_in_the_sweep_is_tabled() -> None:
    """O3 / M4: every public top-level function in the swept tree (plus `_tenant.py` and
    `runtime/run_tenant.py`) annotated `-> Tenant` / `-> RunTenant` is listed —
    `_PARTIAL_OWNER_FACTORIES` for a Tenant, `_CARRIER_FACTORIES` for a RunTenant — so a new
    public factory cannot leave its callers' joins untagged in silence. The census must find
    today's three, so a resolver that finds nothing cannot pass it."""
    gate = _lint_run_records()
    defender = gate.DEFENDER
    files = sorted({*gate.sweep_files(), defender / "_tenant.py",
                    defender / "runtime" / "run_tenant.py"})
    census = _factory_census(files, defender.parent)
    missing = {fn: cls for fn, cls in _TODAY.items() if census.get(fn) != cls}
    assert missing == {}, f"the census does not see today's public factories: {missing}"
    assert _unlisted(census) == [], (
        "public factories missing from _astlib's factory tables:\n  "
        + "\n  ".join(_unlisted(census)))


_FRESH_FACTORIES = """\
from pathlib import Path

from defender import _tenant
from defender._tenant import Tenant
from defender.runtime.run_tenant import RunTenant


def open_tenant(root: Path) -> Tenant:
    ...


def open_tenant_by_module(root: Path) -> _tenant.Tenant:
    ...


async def open_run_tenant(root: Path) -> RunTenant:
    ...


def open_quoted(root: Path) -> "Tenant":
    ...


def _private(root: Path) -> Tenant:
    ...


def unrelated(root: Path) -> Path:
    ...


class Holder:
    def method(self) -> Tenant:
        ...


def outer() -> None:
    def inner() -> Tenant:
        ...
"""

_FRESH_OWNER = """\
class Tenant:
    ...


def accept_tenant(root) -> Tenant:
    ...


def another_acceptance(root) -> Tenant:
    ...
"""


def test_the_census_reports_a_public_factory_missing_from_the_tables(tmp_path: Path) -> None:
    """The census detects what it exists to catch: new public factories in a swept module (each
    annotation form, an async def among them) and one beside `Tenant` in its own module are
    reported unlisted; private, method, nested and non-factory defs are not factories; a
    factory listed against the wrong class is reported."""
    fresh = S.plant(tmp_path, "defender/runtime/fresh_factories.py", _FRESH_FACTORIES)
    owner = S.plant(tmp_path, "defender/_tenant.py", _FRESH_OWNER)
    census = _factory_census([fresh, owner], tmp_path)
    assert census == {
        "defender.runtime.fresh_factories.open_tenant": TENANT,
        "defender.runtime.fresh_factories.open_tenant_by_module": TENANT,
        "defender.runtime.fresh_factories.open_run_tenant": RUN_TENANT,
        "defender.runtime.fresh_factories.open_quoted": TENANT,
        "defender._tenant.accept_tenant": TENANT,
        "defender._tenant.another_acceptance": TENANT,
    }, census
    unlisted = _unlisted(census)
    assert [u.split(" ")[0] for u in unlisted] == sorted(
        fn for fn in census if fn != "defender._tenant.accept_tenant"), unlisted
    assert _unlisted({"defender._tenant.accept_tenant": RUN_TENANT}), (
        "a Tenant factory listed nowhere as a RunTenant factory must be reported")
