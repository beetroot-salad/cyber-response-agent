"""#1160 — the run-records owner lint tags an owner through every binding shape (amended design).

`lint_run_records`' join arm reports a literal-free `/` join onto a value that holds an owner
instance. The tagging behind it lives in `scripts/lint/_astlib.py`. The design amendment
(issue #1160, "Design amendment", D1–D6) replaces the first cut's bare-name factory matching
with name RESOLUTION and one table. These tests pin the amended design:

* O1 — the join is reported whatever binding shape put the owner in the name: a plain assign,
  an annotated assign (tagged from its value, whatever the annotation says), every target of a
  multi-target assign (`a = b = v`), a carrier alias (`rt2 = rt`), an `await` (D5), and a call
  to any `_TENANT_FACTORIES` entry — imported or same-module, bound to a local or chained off
  the call. Full owners too: `p: RunPaths = RunPaths(d)`, `p = q = RunPaths(d)`.
* D1 / D2 — a same-module factory tags its callers ONLY because its dotted origin
  (`defender.<the module's path, dotted>.<name>`) is an entry of the one table: the same planted
  module with no entry tags nothing, and the same source planted under another path (another
  module) tags nothing. Inside a planted `runtime/run_tenant.py` that defines its own
  `RunTenant` and `resolve_tenant`, both resolve as they do everywhere else.
* D3 — a parameter annotation resolves by origin: a string (`"RunTenant"`), an aliased import
  (`RunTenant as RT`), an attribute (`_tenant.Tenant`), the module's own `class RunTenant`;
  while a module's own UNRELATED `class Tenant` is not the accepted `Tenant`.
* D6 — literal unpacking is not traced: an unpacked name is never tagged, on either the tenant
  or the full-owner side (the first cut traced it; `a, b = b, a` then leaked a tag, review
  finding #7). Pinned as a non-obligation beside a plain-assign twin that is reported. Starred,
  nested and length-mismatched unpacks, and unparseable string annotations, scan without
  raising.
* O2 — tags are sticky: a join made while a name held an owner stays reported after the name
  is rebound — to a constant, an annotated or unpacked constant, a call, a name, an attribute.
* O3 / D4 — the census: every top-level `def` / `async def` in the sweep, public AND private,
  whose return annotation resolves to `Tenant` / `RunTenant` is in `_TENANT_FACTORIES` with that
  class, and every entry names such a function (no stale entries).
* O4 — the knowledge halves stay clean through every shape (`tenant.settings` / `.knowledge` /
  `.agent`, `run_tenant.settings`). A same-module factory name shadowed by a parameter, a local,
  a nested def, a closure parameter, a function-local import, or a module-level rebinding is
  not the factory — for the `Tenant` factory `_g` and the carrier factory `_f`.
* O5 — the live sweep stays at 0 findings with an empty allow-list. Pinned already by
  `test_1077_gate.py::test_gate_passes_with_an_empty_allow_list` (gate-marked, run by CI's
  `lint` job); not repeated here.

**What these tests require of `_astlib`** (names the design leaves open are fixed here):

* `_TENANT_FACTORIES: dict[str, str]` — factory origin -> the class origin it returns
  (`"defender.runtime.run_tenant.resolve_tenant": "defender.runtime.run_tenant.RunTenant"`).
  The ONE table (D2). The first cut's `_PARTIAL_OWNER_FACTORIES`, `_CARRIER_FACTORIES` and
  `ModuleEnv.factory_defs` are gone; nothing here reads them.
* `module_env(tree, module=None)` — `module` is the dotted module name its own top-level
  def / async def / class names resolve under (D1). `lint_run_records` passes
  `defender.` + the file's path relative to the defender dir, dotted, without `.py`; that
  plumbing is pinned through `scan()` behaviour, never through its structure.
* `annotated_class(ann, env) -> str | None` — the dotted origin of the class an annotation
  expression names, resolved against `env` (D3): a `Name` or an `Attribute` through the scope's
  imports (a relative import may keep its leading dots, as `ModuleEnv.imports` records them);
  a `str` constant, parsed first — None, never an exception, when it does not parse; and the
  module's own top-level class as `<module>.<name>` (D1). None for anything else. The census
  passes the module's ROOT env, since a return annotation evaluates at module scope.

The planted modules are scanned through the 1120 suite's `_scan_planted`
(`lint_run_records.scan` over a tmp tree, the way CI drives the gate), each cell a function of
its own, so a finding is attributed to its cell by the function name in its display. A reported
cell asserts the JOIN finding specifically. Every clean cell runs beside its module's live
control (`EpisodePaths(ep).runs / x`) and beside a reported twin of the same binding shape onto
an owned member, so its emptiness cannot pass because the arm or the tagging is dead. Table
entries for planted modules go into a FRESH copy of `_astlib` (`_gate_with_table`); the shared
module that every other gate and suite imports is never written.
"""
from __future__ import annotations

import ast
import re
import sys
import textwrap
import uuid
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import pytest

from defender.tests import _spec1077 as S
from defender.tests._by_path import (
    LINT_DIR,
    cached_parse,
    import_lint_lib,
    load_lint_gate,
    load_module,
)
from defender.tests.tenant_1120_piece1.test_1120_lints_and_fixture import (
    JOIN_FINDING,
    _in,
    _lint_run_records,
    _scan_planted,
)

#: The class origins `_TENANT_FACTORIES` maps to.
TENANT = "defender._tenant.Tenant"
RUN_TENANT = "defender.runtime.run_tenant.RunTenant"

_ACCEPT = "accept_tenant(root, tid, defender_dir=root)"
_RESOLVE = "resolve_tenant(root, tid, defender_dir=root, dispatches_lead_zero=False)"


def _joins(displays: list[str], fn: str) -> list[str]:
    return [d for d in _in(displays, fn) if JOIN_FINDING in d]


def _at(displays: list[str], rel: str, fn: str) -> list[str]:
    """`fn`'s findings in the planted module at `rel` — for a tree holding several modules,
    one source among them planted twice."""
    return [d for d in _in(displays, fn) if d.startswith(f"{rel}:")]


def _joins_at(displays: list[str], rel: str, fn: str) -> list[str]:
    return [d for d in _at(displays, rel, fn) if JOIN_FINDING in d]


def _assert_control_live(displays: list[str], control: str = "control") -> None:
    assert _joins(displays, control), "the join arm is not live:\n" + "\n".join(displays)


def _assert_planted(fn: str, source: str) -> None:
    # A misspelt cell name would make `_in` empty: a reported cell would fail for no reason,
    # and a clean cell would pass vacuously. Nested defs and methods count, async ones too.
    assert re.search(rf"^\s*(?:async\s+)?def {re.escape(fn)}\(", source, re.MULTILINE), (
        f"{fn} is not a function of the planted module")


# ======================================================================================
# O1 / O2 / O4 / D3 / D6 — one module, scanned under the stock table.
# ======================================================================================

#: Every cell here reaches a factory through an import the stock table already holds
#: (`accept_tenant`, `resolve_tenant`, `run_tenant_for`), so no table entry is needed.
PLANTED = textwrap.dedent(f"""\
    from pathlib import Path

    from defender import _tenant
    from defender._episode_paths import EpisodePaths
    from defender._run_paths import RunPaths
    from defender._tenant import Tenant, accept_tenant
    from defender._tenant import Tenant as T
    from defender.runtime import run_tenant as run_tenant_mod
    from defender.runtime.run_tenant import RunTenant, resolve_tenant, run_tenant_for
    from defender.runtime.run_tenant import RunTenant as RT


    def control(ep: Path, x: str) -> Path:
        return EpisodePaths(ep).runs / x


    # ---- O1: reported, whatever shape bound the owner ------------------------------------

    def plain_assign_tenant(root: Path, tid: str, x: str) -> Path:
        t = {_ACCEPT}
        return t.runs / x


    def plain_assign_run_paths(d: Path, x: str) -> Path:
        p = RunPaths(d)
        return p.alert / x


    def ann_assign_tenant(root: Path, tid: str, x: str) -> Path:
        t: Tenant = {_ACCEPT}
        return t.runs / x


    def ann_assign_tenant_loose_annotation(root: Path, tid: str, x: str) -> Path:
        t: object = {_ACCEPT}
        return t.runs / x


    def carrier_factory_via_module(root: Path, tid: str, x: str) -> Path:
        rt = run_tenant_mod.{_RESOLVE}
        return rt.tenant.learning / x


    def carrier_factory(root: Path, tid: str, x: str) -> Path:
        rt = {_RESOLVE}
        return rt.tenant.runs / x


    def carrier_factory_resolve_chain(root: Path, tid: str, x: str) -> Path:
        return {_RESOLVE}.tenant.runs / x


    def carrier_factory_chain(t: Tenant, root: Path, x: str) -> Path:
        return run_tenant_for(t, defender_dir=root, dispatches_lead_zero=False).tenant.runs / x


    def carrier_factory_for_local(t: Tenant, root: Path, x: str) -> Path:
        rt = run_tenant_for(t, defender_dir=root, dispatches_lead_zero=False)
        return rt.tenant.runs / x


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


    def ann_assign_run_paths_loose_annotation(d: Path, x: str) -> Path:
        p: object = RunPaths(d)
        return p.gather_raw / x


    def owner_multi_target(d: Path, x: str) -> Path:
        p = q = RunPaths(d)
        return p.gather_raw / x


    def owner_multi_target_last(d: Path, x: str) -> Path:
        p = q = RunPaths(d)
        return q.gather_raw / x


    # ---- D3: a parameter annotation resolves by origin, in each form -----------------------

    def string_annotated_carrier(rt: "RunTenant", x: str) -> Path:
        return rt.tenant.runs / x


    def string_annotated_tenant(t: "Tenant", x: str) -> Path:
        return t.runs / x


    def string_annotated_tenant_attribute(t: "_tenant.Tenant", x: str) -> Path:
        return t.learning / x


    def string_annotated_run_paths(p: "RunPaths", x: str) -> Path:
        return p.gather_raw / x


    def aliased_annotation_carrier(rt: RT, x: str) -> Path:
        return rt.tenant.runs / x


    def aliased_annotation_tenant(t: T, x: str) -> Path:
        return t.sessions / x


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


    def sticky_tenant_rebound_to_call(root: Path, tid: str, other, x: str) -> Path:
        t = {_ACCEPT}
        out = t.runs / x
        t = other(root)
        return out


    def sticky_tenant_rebound_to_name(root: Path, tid: str, q, x: str) -> Path:
        t = {_ACCEPT}
        out = t.runs / x
        t = q
        return out


    def sticky_tenant_rebound_to_attribute(root: Path, tid: str, obj, x: str) -> Path:
        t = {_ACCEPT}
        out = t.runs / x
        t = obj.attr
        return out


    def sticky_run_paths_rebound_to_call(d: Path, other, x: str) -> Path:
        p = RunPaths(d)
        out = p.gather_raw / x
        p = other(d)
        return out


    def sticky_run_paths_rebound_to_name(d: Path, q, x: str) -> Path:
        p = RunPaths(d)
        out = p.gather_raw / x
        p = q
        return out


    def sticky_run_paths_rebound_to_attribute(d: Path, obj, x: str) -> Path:
        p = RunPaths(d)
        out = p.gather_raw / x
        p = obj.attr
        return out


    # ---- O4: clean, through every shape ---------------------------------------------------

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


    def multi_target_agent(root: Path, tid: str, x: str) -> Path:
        a = b = {_ACCEPT}
        return b.agent / x


    def carrier_alias_knowledge(rt: RunTenant, x: str) -> Path:
        rt2 = rt
        return rt2.tenant.knowledge / x


    def carrier_alias_own_settings(rt: RunTenant, x: str) -> Path:
        rt2 = rt
        return rt2.settings / x


    def string_annotated_carrier_settings(rt: "RunTenant", x: str) -> Path:
        return rt.tenant.settings / x


    def unpack_call_result(root: Path, pair, x: str) -> Path:
        a, b = pair(root)
        return a.runs / x


    # ---- D6: an unpacked name is never tagged ----------------------------------------------

    def tuple_unpack(root: Path, tid: str, x: str) -> Path:
        t, n = {_ACCEPT}, 1
        return t.runs / x


    def tuple_unpack_second(root: Path, tid: str, x: str) -> Path:
        n, t = 1, {_ACCEPT}
        return t.runs / x


    def list_unpack(root: Path, tid: str, x: str) -> Path:
        [t, n] = [{_ACCEPT}, 1]
        return t.worktrees / x


    def swap_unpack(root: Path, tid: str, n, x: str) -> Path:
        t = {_ACCEPT}
        out = n.runs / x
        t, n = n, t
        return out


    def owner_tuple_unpack(d: Path, x: str) -> Path:
        p, n = RunPaths(d), 1
        return p.alert / x


    def owner_swap_unpack(d: Path, q, x: str) -> Path:
        p = RunPaths(d)
        out = q.alert / x
        p, q = q, p
        return out
    """)

#: O1 / D3 — each must carry the JOIN finding.
REPORTED = (
    "plain_assign_tenant", "plain_assign_run_paths", "ann_assign_tenant",
    # The tag comes from the VALUE: an annotation that names no owner still tags.
    "ann_assign_tenant_loose_annotation",
    "carrier_factory_via_module", "carrier_factory", "carrier_factory_resolve_chain",
    "carrier_factory_chain", "carrier_factory_for_local",
    # Every target of `a = b = v`, on the tenant and the full-owner side.
    "multi_target_first", "multi_target_last", "owner_multi_target", "owner_multi_target_last",
    "carrier_alias", "ann_assign_run_paths", "ann_assign_run_paths_loose_annotation",
    # D3: a string, an attribute in a string, an aliased import — in both walkers.
    "string_annotated_carrier", "string_annotated_tenant", "string_annotated_tenant_attribute",
    "string_annotated_run_paths", "aliased_annotation_carrier", "aliased_annotation_tenant",
)

#: O2 — the join precedes a rebinding of the owner's name in the same scope: to a constant, an
#: annotated or unpacked constant, a call, another name, an attribute.
STICKY = (
    "sticky_tenant", "sticky_run_paths", "sticky_carrier_parameter",
    "sticky_tenant_annotated_rebind", "sticky_run_paths_unpack_rebind",
    "sticky_tenant_rebound_to_call", "sticky_tenant_rebound_to_name",
    "sticky_tenant_rebound_to_attribute", "sticky_run_paths_rebound_to_call",
    "sticky_run_paths_rebound_to_name", "sticky_run_paths_rebound_to_attribute",
)

#: O4 — clean cell -> its reported twin: the same binding shape joined onto an owned member.
CLEAN = {
    "carrier_factory_tenant_settings": "carrier_factory",
    "carrier_factory_own_settings": "carrier_factory",
    "carrier_factory_chain_agent": "carrier_factory_chain",
    "ann_assign_tenant_knowledge": "ann_assign_tenant",
    "multi_target_agent": "multi_target_last",
    "carrier_alias_knowledge": "carrier_alias",
    "carrier_alias_own_settings": "carrier_alias",
    "string_annotated_carrier_settings": "string_annotated_carrier",
    # Untraced: a call result's elements are unknown, and `runs` is a bare word, so not even
    # the "unresolvable accessor use" arm fires.
    "unpack_call_result": "plain_assign_tenant",
}

#: D6 — unpacked cell -> its plain-assign twin. Each joins onto a bare-word member (`runs`,
#: `worktrees`, `alert`), so an untagged name raises no "unresolvable accessor use" either and
#: the cell is wholly clean. `swap_unpack` / `owner_swap_unpack` are review finding #7: the
#: swapped-in name held no owner when it was joined.
UNPACKED = {
    "tuple_unpack": "plain_assign_tenant",
    "tuple_unpack_second": "plain_assign_tenant",
    "list_unpack": "plain_assign_tenant",
    "swap_unpack": "plain_assign_tenant",
    "owner_tuple_unpack": "plain_assign_run_paths",
    "owner_swap_unpack": "plain_assign_run_paths",
}


@pytest.fixture(scope="module")
def displays(tmp_path_factory: pytest.TempPathFactory) -> list[str]:
    """`lint_run_records.scan` over a tmp tree holding only `PLANTED`, once for the module."""
    return _scan_planted(tmp_path_factory.mktemp("owner_tagging_1160"),
                         "runtime/owner_tagging_1160.py", PLANTED)


@pytest.mark.parametrize("cell", REPORTED)
def test_a_join_through_each_binding_shape_is_reported(displays: list[str], cell: str) -> None:
    """O1 / D3: a literal-free join onto a name (or call) holding an owner instance is reported
    as a join, whichever binding shape — or parameter annotation form — put the owner there."""
    _assert_planted(cell, PLANTED)
    _assert_control_live(displays)
    assert _joins(displays, cell), (
        f"the join in {cell}() is not reported as {JOIN_FINDING!r}; its findings: "
        f"{_in(displays, cell)}")


@pytest.mark.parametrize("cell", STICKY)
def test_a_join_made_before_the_name_is_rebound_stays_reported(
        displays: list[str], cell: str) -> None:
    """O2: rebinding the owner's name later in the scope does not hide a join made while it held
    the owner — the scope's forward pass never untags a name."""
    _assert_planted(cell, PLANTED)
    _assert_control_live(displays)
    assert _joins(displays, cell), (
        f"the join in {cell}() is hidden by the later rebinding; its findings: "
        f"{_in(displays, cell)}")


@pytest.mark.parametrize("cell", sorted(CLEAN))
def test_knowledge_halves_and_untraced_shapes_stay_clean(displays: list[str], cell: str) -> None:
    """O4: joins onto the knowledge halves, and onto an untraced call-result unpack, report
    nothing — beside the live control and a reported twin of the same shape."""
    _assert_planted(cell, PLANTED)
    _assert_control_live(displays)
    twin = CLEAN[cell]
    assert _joins(displays, twin), f"{cell}'s twin {twin}() is not reported: {displays}"
    assert _in(displays, cell) == [], (
        f"{cell}() is reported, while it must stay clean (its twin {twin}() is the reported "
        f"form): {_in(displays, cell)}")


@pytest.mark.parametrize("cell", sorted(UNPACKED))
def test_an_unpacked_name_is_never_tagged(displays: list[str], cell: str) -> None:
    """D6 (a non-obligation, pinned): literal unpacking is not traced, on the tenant side or
    the full-owner side, so `t, n = accept_tenant(...), 1; t.runs / x` reports nothing — beside
    the live control and the plain assign of the same value, which is reported. Tracing it
    leaked a tag through `a, b = b, a` onto a name that held no owner at its join."""
    _assert_planted(cell, PLANTED)
    _assert_control_live(displays)
    twin = UNPACKED[cell]
    assert _joins(displays, twin), f"the plain-assign twin {twin}() is not reported: {displays}"
    assert _in(displays, cell) == [], (
        f"{cell}() tags an unpacked name, which D6 leaves untraced: {_in(displays, cell)}")


# ======================================================================================
# D1 / D3 — inside `runtime/run_tenant.py`, its own `RunTenant` and `resolve_tenant` resolve
# as they do everywhere else.
# ======================================================================================

#: Planted AT `runtime/run_tenant.py`, so the module is `defender.runtime.run_tenant`:
#: `resolve_tenant` here IS the stock table's `defender.runtime.run_tenant.resolve_tenant`, and
#: `RunTenant` here IS the carrier class. Scanned under the stock table: no fresh entry.
RUN_TENANT_OWN = textwrap.dedent("""\
    from pathlib import Path

    from defender import _tenant
    from defender._episode_paths import EpisodePaths


    class RunTenant:
        tenant: _tenant.Tenant


    def resolve_tenant(data_root: Path, tenant_id: str) -> RunTenant:
        ...


    def run_tenant_module_control(ep: Path, x: str) -> Path:
        return EpisodePaths(ep).runs / x


    def own_factory_local(root: Path, tid: str, x: str) -> Path:
        rt = resolve_tenant(root, tid)
        return rt.tenant.runs / x


    def own_factory_chain(root: Path, tid: str, x: str) -> Path:
        return resolve_tenant(root, tid).tenant.learning / x


    def own_class_parameter(rt: RunTenant, x: str) -> Path:
        return rt.tenant.runs / x


    def own_class_string_parameter(rt: "RunTenant", x: str) -> Path:
        return rt.tenant.episodes / x


    def own_class_construction(t: _tenant.Tenant, x: str) -> Path:
        rt = RunTenant(tenant=t)
        return rt.tenant.sessions / x


    def own_factory_tenant_settings(root: Path, tid: str, x: str) -> Path:
        rt = resolve_tenant(root, tid)
        return rt.tenant.settings / x


    def own_class_parameter_own_settings(rt: RunTenant, x: str) -> Path:
        return rt.settings / x
    """)

RUN_TENANT_OWN_REPORTED = (
    "own_factory_local", "own_factory_chain", "own_class_parameter",
    "own_class_string_parameter", "own_class_construction",
)
RUN_TENANT_OWN_CLEAN = {
    "own_factory_tenant_settings": "own_factory_local",
    "own_class_parameter_own_settings": "own_class_parameter",
}


@pytest.fixture(scope="module")
def run_tenant_displays(tmp_path_factory: pytest.TempPathFactory) -> list[str]:
    return _scan_planted(tmp_path_factory.mktemp("own_run_tenant_1160"),
                         "runtime/run_tenant.py", RUN_TENANT_OWN)


@pytest.mark.parametrize("cell", RUN_TENANT_OWN_REPORTED)
def test_the_run_tenant_modules_own_names_resolve_as_everywhere_else(
        run_tenant_displays: list[str], cell: str) -> None:
    """D1 / D3 (review finding #4): in `runtime/run_tenant.py`, `resolve_tenant(...)` is the
    tabled factory and `RunTenant` the carrier class, by origin — so a join through a local
    bound to the factory, through its chain, through a parameter annotated `RunTenant` (or
    `"RunTenant"`), or through a construction is reported, as it is in any other module."""
    _assert_planted(cell, RUN_TENANT_OWN)
    _assert_control_live(run_tenant_displays, "run_tenant_module_control")
    assert _joins(run_tenant_displays, cell), (
        f"the join in run_tenant.py's {cell}() is not reported; its findings: "
        f"{_in(run_tenant_displays, cell)}")


@pytest.mark.parametrize("cell", sorted(RUN_TENANT_OWN_CLEAN))
def test_the_run_tenant_modules_knowledge_halves_stay_clean(
        run_tenant_displays: list[str], cell: str) -> None:
    """O4 inside `runtime/run_tenant.py`: `rt.tenant.settings` and `rt.settings` stay clean
    beside a reported twin of the same binding."""
    _assert_planted(cell, RUN_TENANT_OWN)
    _assert_control_live(run_tenant_displays, "run_tenant_module_control")
    twin = RUN_TENANT_OWN_CLEAN[cell]
    assert _joins(run_tenant_displays, twin), (
        f"{cell}'s twin {twin}() is not reported: {run_tenant_displays}")
    assert _in(run_tenant_displays, cell) == [], _in(run_tenant_displays, cell)


# ======================================================================================
# D3 — a class merely NAMED `Tenant` is not the owner: annotations resolve by origin.
# ======================================================================================

OWN_CLASS = textwrap.dedent(f"""\
    from pathlib import Path

    from defender import _tenant
    from defender._episode_paths import EpisodePaths
    from defender._tenant import accept_tenant


    class Tenant:
        ...


    def own_class_control(ep: Path, x: str) -> Path:
        return EpisodePaths(ep).runs / x


    def real_class_parameter(t: _tenant.Tenant, x: str) -> Path:
        return t.runs / x


    def imported_factory_twin(root: Path, tid: str, x: str) -> Path:
        t = {_ACCEPT}
        return t.runs / x


    def own_class_parameter(t: Tenant, x: str) -> Path:
        return t.runs / x


    def own_class_string_parameter(t: "Tenant", x: str) -> Path:
        return t.runs / x


    def own_class_construction(x: str) -> Path:
        t = Tenant()
        return t.runs / x


    def own_class_construction_chain(x: str) -> Path:
        return Tenant().runs / x
    """)

#: Clean cell -> its reported twin in the same module.
OWN_CLASS_CLEAN = {
    "own_class_parameter": "real_class_parameter",
    "own_class_string_parameter": "real_class_parameter",
    "own_class_construction": "imported_factory_twin",
    "own_class_construction_chain": "imported_factory_twin",
}


@pytest.fixture(scope="module")
def own_class_displays(tmp_path_factory: pytest.TempPathFactory) -> list[str]:
    return _scan_planted(tmp_path_factory.mktemp("own_tenant_class_1160"),
                         "runtime/own_tenant_class_1160.py", OWN_CLASS)


@pytest.mark.parametrize("cell", sorted(OWN_CLASS_CLEAN))
def test_a_modules_own_class_named_tenant_is_not_the_accepted_tenant(
        own_class_displays: list[str], cell: str) -> None:
    """D3: in a module that defines its own `class Tenant`, a parameter annotated with it (as a
    Name or a string) and a construction of it hold no accepted `Tenant` — their joins stay
    clean, beside the live control and a reported twin (the real `_tenant.Tenant` parameter, or
    `accept_tenant(...)`) in the same module."""
    _assert_planted(cell, OWN_CLASS)
    _assert_control_live(own_class_displays, "own_class_control")
    twin = OWN_CLASS_CLEAN[cell]
    assert _joins(own_class_displays, twin), (
        f"{cell}'s twin {twin}() is not reported: {own_class_displays}")
    assert _in(own_class_displays, cell) == [], (
        f"a module's own class merely named `Tenant` is taken for the accepted one in {cell}(): "
        f"{_in(own_class_displays, cell)}")


# ======================================================================================
# D6 / D3 — shapes nothing traces: the scan completes and tags nothing.
# ======================================================================================

UNTRACED = textwrap.dedent(f"""\
    from pathlib import Path

    from defender._episode_paths import EpisodePaths
    from defender._tenant import Tenant, accept_tenant


    def untraced_control(ep: Path, x: str) -> Path:
        return EpisodePaths(ep).runs / x


    def plain_assign_twin(root: Path, tid: str, x: str) -> Path:
        a = {_ACCEPT}
        return a.runs / x


    def starred_unpack(root: Path, tid: str, x: str) -> Path:
        a, *rest = {_ACCEPT}, 1, 2
        return a.runs / x


    def starred_value_unpack(root: Path, tid: str, more, x: str) -> Path:
        a, b = {_ACCEPT}, *more
        return a.runs / x


    def nested_unpack(root: Path, tid: str, x: str) -> Path:
        (a, (b, c)) = ({_ACCEPT}, (1, 2))
        return a.runs / x


    def length_mismatch_unpack(root: Path, tid: str, x: str) -> Path:
        a, b = {_ACCEPT}, 1, 2
        return a.runs / x


    def unparseable_string_annotation(t: "Tenant[", x: str) -> Path:
        return t.runs / x


    def empty_string_annotation(t: "", x: str) -> Path:
        return t.runs / x
    """)

#: Starred, nested and length-mismatched unpacks (the last parses; it raises only at run time),
#: and string annotations that do not parse.
UNTRACED_CELLS = ("starred_unpack", "starred_value_unpack", "nested_unpack",
                  "length_mismatch_unpack", "unparseable_string_annotation",
                  "empty_string_annotation")


@pytest.fixture(scope="module")
def untraced_displays(tmp_path_factory: pytest.TempPathFactory) -> list[str]:
    """The scan over the untraceable shapes — it must complete, not raise."""
    return _scan_planted(tmp_path_factory.mktemp("untraced_unpacks_1160"),
                         "runtime/untraced_unpacks_1160.py", UNTRACED)


@pytest.mark.parametrize("cell", UNTRACED_CELLS)
def test_an_untraceable_shape_scans_cleanly_and_tags_nothing(
        untraced_displays: list[str], cell: str) -> None:
    """A starred, nested or length-mismatched unpack, and a string annotation that does not
    parse, neither crash the scan nor tag a name — beside the live control and the plain
    assign of the same value, which is reported."""
    _assert_planted(cell, UNTRACED)
    _assert_control_live(untraced_displays, "untraced_control")
    assert _joins(untraced_displays, "plain_assign_twin"), (
        f"the plain assign is not tagged in this module: {untraced_displays}")
    assert _in(untraced_displays, cell) == [], (
        f"{cell}() tags a name nothing traces: {_in(untraced_displays, cell)}")


# ======================================================================================
# D1 / D2 / D5 / O4 — the table is the only route: same-module factories, shadowing,
# module-level rebinding, imported entries, `await`, and the module's dotted name.
# ======================================================================================

#: Same-module factories `_f` / `_g` / `_h` / `_k` / `_af`, literal-free `...` bodies,
#: annotated in each form the live tree uses. The annotations do not make them factories: the
#: table entries do (`_TABLE_ENTRIES`).
SAME_MODULE = textwrap.dedent("""\
    from pathlib import Path

    from defender import _tenant
    from defender._episode_paths import EpisodePaths
    from defender._tenant import Tenant
    from defender._tenant import Tenant as T
    from defender.runtime.run_tenant import RunTenant


    def _f(root: Path) -> RunTenant:
        ...


    def _g(root: Path) -> Tenant:
        ...


    def _h(root: Path) -> _tenant.Tenant:
        ...


    def _k(root: Path) -> T:
        ...


    async def _af(root: Path) -> RunTenant:
        ...


    def same_module_control(ep: Path, x: str) -> Path:
        return EpisodePaths(ep).runs / x


    # ---- reported once the factory's origin is tabled -------------------------------------

    def local_carrier_factory(root: Path, x: str) -> Path:
        rt = _f(root)
        return rt.tenant.episodes / x


    def local_carrier_factory_chain(root: Path, x: str) -> Path:
        return _f(root).tenant.runs / x


    def local_carrier_factory_alias(root: Path, x: str) -> Path:
        rt = _f(root)
        rt2 = rt
        return rt2.tenant.runs / x


    def local_tenant_factory_chain(root: Path, x: str) -> Path:
        return _g(root).runs / x


    def local_tenant_factory_local(root: Path, x: str) -> Path:
        t = _g(root)
        return t.runs / x


    def local_tenant_factory_annotated_local(root: Path, x: str) -> Path:
        t: Tenant = _g(root)
        return t.dir / x


    def local_tenant_factory_attribute_annotation(root: Path, x: str) -> Path:
        t = _h(root)
        return t.sessions / x


    def aliased_annotation_factory(root: Path, x: str) -> Path:
        return _k(root).runs / x


    async def await_local_carrier(root: Path, x: str) -> Path:
        rt = await _af(root)
        return rt.tenant.runs / x


    async def await_chain_carrier(root: Path, x: str) -> Path:
        return (await _af(root)).tenant.runs / x


    class Holder:
        def via_method(self, root: Path, x: str) -> Path:
            return _g(root).runs / x


    def via_closure_outer(root: Path):
        def via_closure(x: str) -> Path:
            return _f(root).tenant.runs / x
        return via_closure


    # ---- clean: the knowledge halves ------------------------------------------------------

    def local_carrier_factory_settings(root: Path, x: str) -> Path:
        rt = _f(root)
        return rt.tenant.settings / x


    def local_carrier_factory_own_settings(root: Path, x: str) -> Path:
        rt = _f(root)
        return rt.settings / x


    def local_tenant_factory_chain_knowledge(root: Path, x: str) -> Path:
        return _g(root).knowledge / x


    async def await_chain_settings(root: Path, x: str) -> Path:
        return (await _af(root)).tenant.settings / x


    # ---- clean: a scope that rebinds the factory's name calls something else --------------

    def shadowed_by_parameter(_g, x: str, y: str) -> Path:
        return _g(x).runs / y


    def shadowed_by_local(root: Path, other, x: str) -> Path:
        _g = other
        return _g(root).runs / x


    def shadowed_by_nested_def(root: Path, x: str) -> Path:
        def _g(r: Path) -> Path:
            ...
        return _g(root).runs / x


    def shadowed_in_closure(_g, y: str):
        def shadowed_in_closure_inner(x: str) -> Path:
            return _g(x).runs / y
        return shadowed_in_closure_inner


    def shadowed_by_local_import(root: Path, x: str) -> Path:
        from other import _g
        return _g(root).runs / x


    def shadowed_carrier_by_parameter(_f, x: str, y: str) -> Path:
        return _f(x).tenant.runs / y


    def shadowed_carrier_by_local(root: Path, other, x: str) -> Path:
        _f = other
        return _f(root).tenant.runs / x


    def shadowed_carrier_by_nested_def(root: Path, x: str) -> Path:
        def _f(r: Path) -> Path:
            ...
        return _f(root).tenant.runs / x


    def shadowed_carrier_in_closure(_f, y: str):
        def shadowed_carrier_in_closure_inner(x: str) -> Path:
            return _f(x).tenant.runs / y
        return shadowed_carrier_in_closure_inner


    def shadowed_carrier_by_local_import(root: Path, x: str) -> Path:
        from other import _f
        return _f(root).tenant.runs / x
    """)

#: `_g` and `_f` are tabled for this module too, then rebound at module level: a module-level
#: name bound by anything other than exactly one def/class does not resolve (D1). `_k`, tabled
#: and never rebound, is the twin proving this module's entries are live.
REBOUND = textwrap.dedent("""\
    from pathlib import Path

    from defender._episode_paths import EpisodePaths
    from defender._tenant import Tenant
    from defender.runtime.run_tenant import RunTenant


    def _f(root: Path) -> RunTenant:
        ...


    def _g(root: Path) -> Tenant:
        ...


    def _k(root: Path) -> Tenant:
        ...


    def _other(root: Path) -> Path:
        ...


    _f = _other
    _g = _other


    def rebound_control(ep: Path, x: str) -> Path:
        return EpisodePaths(ep).runs / x


    def unrebound_factory_chain(root: Path, x: str) -> Path:
        return _k(root).runs / x


    def rebound_tenant_factory_chain(root: Path, x: str) -> Path:
        return _g(root).runs / x


    def rebound_carrier_factory_chain(root: Path, x: str) -> Path:
        return _f(root).tenant.runs / x
    """)

#: Imported factories at origins no real module has, tabled in the fresh copy only — sync and
#: awaited (D5), bound to a local and chained.
TABLE_ROUTE = textwrap.dedent("""\
    from pathlib import Path

    from defender._episode_paths import EpisodePaths
    from defender.fake_factories_1160 import make_run_tenant, make_tenant


    def table_route_control(ep: Path, x: str) -> Path:
        return EpisodePaths(ep).runs / x


    def via_tenant_entry(root: Path, x: str) -> Path:
        t = make_tenant(root)
        return t.runs / x


    def via_tenant_entry_chain(root: Path, x: str) -> Path:
        return make_tenant(root).runs / x


    def via_carrier_entry(root: Path, x: str) -> Path:
        rt = make_run_tenant(root)
        return rt.tenant.runs / x


    def via_carrier_entry_chain(root: Path, x: str) -> Path:
        return make_run_tenant(root).tenant.runs / x


    async def via_tenant_entry_awaited(root: Path, x: str) -> Path:
        t = await make_tenant(root)
        return t.runs / x


    async def via_tenant_entry_awaited_chain(root: Path, x: str) -> Path:
        return (await make_tenant(root)).learning / x


    async def via_carrier_entry_awaited_chain(root: Path, x: str) -> Path:
        return (await make_run_tenant(root)).tenant.runs / x
    """)

#: Where each module is planted. `SAME_MODULE` is planted twice: once at the path its entries
#: are keyed to, once in another package under the same file name — another module, with no
#: entries.
_SAME = "runtime/same_module_1160.py"
_SAME_ELSEWHERE = "learning/branch/same_module_1160.py"
_REBOUND = "runtime/rebound_1160.py"
_ROUTE = "runtime/table_route_1160.py"

TABLE_TREE = {_SAME: SAME_MODULE, _SAME_ELSEWHERE: SAME_MODULE, _REBOUND: REBOUND,
              _ROUTE: TABLE_ROUTE}

_CONTROL = {_SAME: "same_module_control", _SAME_ELSEWHERE: "same_module_control",
            _REBOUND: "rebound_control", _ROUTE: "table_route_control"}

#: The entries the fresh `_astlib` copy adds to `_TENANT_FACTORIES`. The planted modules' dotted
#: names are spelled out — `defender.` + the planted path, dotted, without `.py` — rather than
#: computed, since computing them is the plumbing under test.
_TABLE_ENTRIES = {
    "defender.runtime.same_module_1160._f": RUN_TENANT,
    "defender.runtime.same_module_1160._g": TENANT,
    "defender.runtime.same_module_1160._h": TENANT,
    "defender.runtime.same_module_1160._k": TENANT,
    "defender.runtime.same_module_1160._af": RUN_TENANT,
    "defender.runtime.rebound_1160._f": RUN_TENANT,
    "defender.runtime.rebound_1160._g": TENANT,
    "defender.runtime.rebound_1160._k": TENANT,
    "defender.fake_factories_1160.make_tenant": TENANT,
    "defender.fake_factories_1160.make_run_tenant": RUN_TENANT,
}

SAME_MODULE_REPORTED = (
    "local_carrier_factory", "local_carrier_factory_chain", "local_carrier_factory_alias",
    "local_tenant_factory_chain", "local_tenant_factory_local",
    "local_tenant_factory_annotated_local", "local_tenant_factory_attribute_annotation",
    "aliased_annotation_factory",
    # D5: `await X` evaluates as `X`, bound to a local and inside a chain.
    "await_local_carrier", "await_chain_carrier",
    # A method's and a closure's enclosing scope is the module: the name resolves there.
    "via_method", "via_closure",
)

ROUTE_REPORTED = (
    "via_tenant_entry", "via_tenant_entry_chain", "via_carrier_entry", "via_carrier_entry_chain",
    "via_tenant_entry_awaited", "via_tenant_entry_awaited_chain",
    "via_carrier_entry_awaited_chain",
)

#: (rel, cell) reported once the entries are tabled.
TABLED_REPORTED = (
    *((_SAME, c) for c in SAME_MODULE_REPORTED),
    (_REBOUND, "unrebound_factory_chain"),
    *((_ROUTE, c) for c in ROUTE_REPORTED),
)

#: (rel, clean cell) -> its reported twin in the same module, under the tabled scan.
TABLED_CLEAN = {
    (_SAME, "local_carrier_factory_settings"): "local_carrier_factory",
    (_SAME, "local_carrier_factory_own_settings"): "local_carrier_factory",
    (_SAME, "local_tenant_factory_chain_knowledge"): "local_tenant_factory_chain",
    (_SAME, "await_chain_settings"): "await_chain_carrier",
    # O4: the module-level `_g` is a factory; a scope that rebinds `_g` calls something else.
    (_SAME, "shadowed_by_parameter"): "local_tenant_factory_chain",
    (_SAME, "shadowed_by_local"): "local_tenant_factory_chain",
    (_SAME, "shadowed_by_nested_def"): "local_tenant_factory_chain",
    (_SAME, "shadowed_in_closure_inner"): "local_tenant_factory_chain",
    (_SAME, "shadowed_by_local_import"): "local_tenant_factory_chain",
    # The same five shadows of the carrier factory `_f`.
    (_SAME, "shadowed_carrier_by_parameter"): "local_carrier_factory_chain",
    (_SAME, "shadowed_carrier_by_local"): "local_carrier_factory_chain",
    (_SAME, "shadowed_carrier_by_nested_def"): "local_carrier_factory_chain",
    (_SAME, "shadowed_carrier_in_closure_inner"): "local_carrier_factory_chain",
    (_SAME, "shadowed_carrier_by_local_import"): "local_carrier_factory_chain",
    # A module-level rebinding after the def: the name is not the factory anywhere.
    (_REBOUND, "rebound_tenant_factory_chain"): "unrebound_factory_chain",
    (_REBOUND, "rebound_carrier_factory_chain"): "unrebound_factory_chain",
}

#: Every cell of the tree, at every path it is planted at: nothing in it tags under the stock
#: table, which holds none of `_TABLE_ENTRIES`.
STOCK_CELLS = (
    *TABLED_REPORTED,
    *TABLED_CLEAN,
    *((_SAME_ELSEWHERE, c) for c in SAME_MODULE_REPORTED),
)


def _gate_with_table(entries: dict[str, str]) -> Any:
    """A fresh `lint_run_records` bound to a fresh `_astlib` whose `_TENANT_FACTORIES` also
    holds `entries`.

    The copy is loaded under its own name and stands in for `_astlib` only while the gate copy
    runs its `from _astlib import ...`; then the shared module (the one `import_lint_lib`
    hands every other gate and suite) is put back, untouched — its table is never written."""
    tag = uuid.uuid4().hex
    lib = load_module(LINT_DIR / "_astlib.py", name=f"_astlib_1160_{tag}")
    table = getattr(lib, "_TENANT_FACTORIES", None)
    assert isinstance(table, dict), (
        "_astlib has no `_TENANT_FACTORIES` dict — D2's one table of factory origin -> the "
        "class origin it returns")
    table.update(entries)
    shared = sys.modules.get("_astlib")
    sys.modules["_astlib"] = lib
    try:
        gate = load_lint_gate("lint_run_records", name=f"lint_run_records_1160_{tag}")
    finally:
        if shared is None:
            del sys.modules["_astlib"]
        else:
            sys.modules["_astlib"] = shared
    assert gate.module_env is lib.module_env, "the gate copy is not bound to the table copy"
    leaked = {*entries} & {*getattr(import_lint_lib("_astlib"), "_TENANT_FACTORIES", {})}
    assert not leaked, f"the planted entries leaked into the shared _astlib: {leaked}"
    return gate


@pytest.fixture(scope="module")
def table_tree(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("table_route_1160")
    for rel, source in TABLE_TREE.items():
        S.plant(root, rel, source)
    return root


@pytest.fixture(scope="module")
def stock(table_tree: Path) -> list[str]:
    """The tree scanned by the gate as shipped: the stock table, none of `_TABLE_ENTRIES`."""
    return [f.display for f in _lint_run_records().scan(table_tree)]


@pytest.fixture(scope="module")
def tabled(table_tree: Path) -> list[str]:
    """The same tree scanned by a gate whose table copy also holds `_TABLE_ENTRIES`."""
    return [f.display for f in _gate_with_table(_TABLE_ENTRIES).scan(table_tree)]


def _assert_cell(rel: str, cell: str) -> None:
    _assert_planted(cell, TABLE_TREE[rel])


@pytest.mark.parametrize(("rel", "cell"), STOCK_CELLS)
def test_without_a_table_entry_a_factory_tags_nothing(
        stock: list[str], rel: str, cell: str) -> None:
    """D2: being in `_TENANT_FACTORIES` is the only route by which a call tags its result. With
    no entry, a same-module def annotated `-> Tenant` / `-> RunTenant` (sync or async) and an
    imported function are not factories: every join in the tree is clean, beside each module's
    live control."""
    _assert_cell(rel, cell)
    _assert_control_live(_at(stock, rel, _CONTROL[rel]), _CONTROL[rel])
    assert _at(stock, rel, cell) == [], (
        f"{rel}'s {cell}() is reported with no table entry for its factory — something other "
        f"than the table tags it: {_at(stock, rel, cell)}")


@pytest.mark.parametrize(("rel", "cell"), TABLED_REPORTED)
def test_a_table_entry_tags_its_factorys_callers(
        tabled: list[str], rel: str, cell: str) -> None:
    """D1 / D2 / D5: a call to a tabled origin tags its result — a same-module def through its
    resolved `<module>.<name>` origin, an imported function through its import — bound to a
    local or chained off the call, awaited or not, from a function, a method or a closure."""
    _assert_cell(rel, cell)
    _assert_control_live(_at(tabled, rel, _CONTROL[rel]), _CONTROL[rel])
    assert _joins_at(tabled, rel, cell), (
        f"{rel}'s {cell}() is not reported once its factory is tabled; its findings: "
        f"{_at(tabled, rel, cell)}")


@pytest.mark.parametrize(("rel", "cell"), sorted(TABLED_CLEAN))
def test_a_shadowed_factory_name_and_the_knowledge_halves_stay_clean(
        tabled: list[str], rel: str, cell: str) -> None:
    """O4 / D1: with the factory tabled, a scope that rebinds its name (a parameter, a local, a
    nested def, a closure's enclosing parameter, a function-local import) or a module-level
    rebinding of it calls something else, and a join onto a knowledge half stays clean —
    beside the live control and a reported twin in the same module."""
    _assert_cell(rel, cell)
    _assert_control_live(_at(tabled, rel, _CONTROL[rel]), _CONTROL[rel])
    twin = TABLED_CLEAN[(rel, cell)]
    assert _joins_at(tabled, rel, twin), (
        f"{cell}'s twin {twin}() is not reported in {rel}: {tabled}")
    assert _at(tabled, rel, cell) == [], (
        f"{rel}'s {cell}() is reported, while it must stay clean (its twin {twin}() is the "
        f"reported form): {_at(tabled, rel, cell)}")


@pytest.mark.parametrize("cell", SAME_MODULE_REPORTED)
def test_a_factorys_origin_is_its_modules_path(tabled: list[str], cell: str) -> None:
    """D1's module name: the gate names each scanned module `defender.` + its path, so the
    same source planted in another package, under the same file name, is another module —
    its same-named defs are no table entries, and its joins stay clean while the tabled
    module's are reported."""
    _assert_cell(_SAME_ELSEWHERE, cell)
    _assert_control_live(_at(tabled, _SAME_ELSEWHERE, _CONTROL[_SAME_ELSEWHERE]),
                         _CONTROL[_SAME_ELSEWHERE])
    assert _joins_at(tabled, _SAME, cell), (
        f"{_SAME}'s {cell}() is not reported: {_at(tabled, _SAME, cell)}")
    assert _at(tabled, _SAME_ELSEWHERE, cell) == [], (
        f"{_SAME_ELSEWHERE}'s {cell}() is tagged through entries keyed to {_SAME}'s module: "
        f"{_at(tabled, _SAME_ELSEWHERE, cell)}")


# ======================================================================================
# O3 / D4 — the census: the table holds every Tenant / RunTenant factory, and nothing else.
# ======================================================================================

_FACTORY_CLASSES = (TENANT, RUN_TENANT)

#: The factories the live tree holds today (D2's list): a census that finds none of them —
#: a dead resolver — cannot pass.
_TODAY = {
    "defender._tenant.accept_tenant": TENANT,
    "defender.runtime.run_tenant.resolve_tenant": RUN_TENANT,
    "defender.runtime.run_tenant.run_tenant_for": RUN_TENANT,
    "defender.run._resolve_run_tenant": RUN_TENANT,
    "defender.run._accept_request_tenant": TENANT,
    "defender.learning.branch.cli._episode_tenant": RUN_TENANT,
}


def _module_of(path: Path, repo: Path) -> tuple[str, list[str]]:
    """`(the module's dotted name, its package's parts)` — `pkg/__init__.py` is `pkg`."""
    parts = list(path.relative_to(repo).with_suffix("").parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
        return ".".join(parts), parts
    return ".".join(parts), parts[:-1]


def _absolute(found: str, package: list[str]) -> list[str]:
    """A relative origin as the absolute origins it may name.

    The one fallback this census keeps, and why: D3's resolver covers a Name, an Attribute, a
    string and the module's own class — not a relative import, which `ModuleEnv.imports`
    records with its leading dots (`from ..run_tenant import RunTenant` -> `..run_tenant.
    RunTenant`). The sweep holds one such import of `RunTenant` (`runtime/driver/__init__.py`),
    so without this a factory annotated through it would escape the census. This is path
    arithmetic on an origin `_astlib` already resolved, not name resolution: it decides no
    binding, and it runs only on an origin that starts with a dot. `from . import m` and
    `from .m import x` both spell one extra leading dot per level, so both levels are read; the
    census keeps whichever names a factory class."""
    rest = found.lstrip(".")
    dots = len(found) - len(rest)
    out = []
    for level in (dots, dots - 1):
        if 1 <= level <= len(package):
            out.append(".".join([*package[:len(package) - level + 1], *rest.split(".")]))
    return out


def _factory_class(found: str | None, package: list[str]) -> str | None:
    if found is None:
        return None
    candidates = _absolute(found, package) if found.startswith(".") else [found]
    return next((c for c in candidates if c in _FACTORY_CLASSES), None)


def _factory_census(files: Iterable[Path], repo: Path) -> dict[str, str]:
    """{top-level def / async def's origin: the factory class its return annotation names},
    public and private, over `files` — each annotation resolved by `_astlib.annotated_class`
    against the module's root env built with its dotted name. Methods and nested defs are not
    factories."""
    astlib = import_lint_lib("_astlib")
    out: dict[str, str] = {}
    for path in files:
        text, tree = cached_parse(path, path.relative_to(repo).as_posix())
        if "Tenant" not in text:
            continue  # every spelling that resolves to either class carries the word
        module, package = _module_of(path, repo)
        env = astlib.module_env(tree, module=module)
        for node in tree.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or (
                    node.returns is None):
                continue
            cls = _factory_class(astlib.annotated_class(node.returns, env), package)
            if cls is not None:
                out[f"{module}.{node.name}"] = cls
    return out


def _drift(census: dict[str, str], table: dict[str, str]
           ) -> tuple[dict[str, str], dict[str, str]]:
    """`(unlisted, stale)`: factories the table lacks (or lists against another class), and
    entries naming no function so annotated (missing, unannotated, or another class)."""
    unlisted = {fn: cls for fn, cls in census.items() if table.get(fn) != cls}
    stale = {fn: cls for fn, cls in table.items() if census.get(fn) != cls}
    return unlisted, stale


def test_the_factory_table_is_exactly_the_sweeps_tenant_and_run_tenant_factories() -> None:
    """O3 / D4: every top-level `def` / `async def` in the swept tree (public and private)
    whose return annotation resolves to `Tenant` / `RunTenant` is in `_TENANT_FACTORIES` with
    that class, and every entry names such a function — so a new factory cannot leave its
    callers' joins untagged in silence, and a removed or retyped one cannot leave a stale
    entry. The census must find today's six, so a resolver that finds nothing cannot pass."""
    gate = _lint_run_records()
    defender = gate.DEFENDER
    files = sorted({*gate.sweep_files(), defender / "_tenant.py",
                    defender / "runtime" / "run_tenant.py"})
    census = _factory_census(files, defender.parent)
    missing = {fn: cls for fn, cls in _TODAY.items() if census.get(fn) != cls}
    assert missing == {}, f"the census does not see today's factories: {missing}"
    table = import_lint_lib("_astlib")._TENANT_FACTORIES
    unlisted, stale = _drift(census, dict(table))
    assert unlisted == {}, (
        "factories missing from _astlib._TENANT_FACTORIES (or listed against another class):\n  "
        + "\n  ".join(f"{fn} -> {cls}" for fn, cls in sorted(unlisted.items())))
    assert stale == {}, (
        "_astlib._TENANT_FACTORIES entries naming no function so annotated:\n  "
        + "\n  ".join(f"{fn} -> {cls}" for fn, cls in sorted(stale.items())))


_FRESH_FACTORIES = """\
from pathlib import Path

from defender import _tenant
from defender._tenant import Tenant
from defender.runtime.run_tenant import RunTenant
from defender.runtime.run_tenant import RunTenant as RT


def open_tenant(root: Path) -> Tenant:
    ...


def open_tenant_by_module(root: Path) -> _tenant.Tenant:
    ...


async def open_run_tenant(root: Path) -> RunTenant:
    ...


def open_quoted(root: Path) -> "Tenant":
    ...


def open_quoted_carrier(root: Path) -> "RunTenant":
    ...


def open_aliased(root: Path) -> RT:
    ...


def _private(root: Path) -> Tenant:
    ...


async def _private_async(root: Path) -> RunTenant:
    ...


def unrelated(root: Path) -> Path:
    ...


def unannotated(root: Path):
    ...


def unparseable_quote(root: Path) -> "Tenant[":
    ...


class Holder:
    def method(self) -> Tenant:
        ...


def outer() -> None:
    def inner() -> Tenant:
        ...
"""

#: The owner module's own `Tenant`, resolved through D1 (`module_env(tree, module=...)`).
_FRESH_OWNER = """\
class Tenant:
    ...


def accept_tenant(root) -> Tenant:
    ...


def another_acceptance(root) -> "Tenant":
    ...
"""

#: An unrelated module's own class merely named `Tenant`: not the accepted one.
_FRESH_OWN_CLASS = """\
class Tenant:
    ...


def not_a_factory(root) -> Tenant:
    ...
"""

#: A relative import, the shape `runtime/driver/__init__.py` uses for `RunTenant`.
_FRESH_RELATIVE = """\
from ..run_tenant import RunTenant


def make_run_tenant(root) -> RunTenant:
    ...
"""

_F = "defender.runtime.fresh_factories"

#: What the census must find over the four planted modules.
_FRESH_CENSUS = {
    f"{_F}.open_tenant": TENANT,
    f"{_F}.open_tenant_by_module": TENANT,
    f"{_F}.open_run_tenant": RUN_TENANT,
    f"{_F}.open_quoted": TENANT,
    f"{_F}.open_quoted_carrier": RUN_TENANT,
    f"{_F}.open_aliased": RUN_TENANT,
    f"{_F}._private": TENANT,
    f"{_F}._private_async": RUN_TENANT,
    "defender._tenant.accept_tenant": TENANT,
    "defender._tenant.another_acceptance": TENANT,
    "defender.runtime.driver.make_run_tenant": RUN_TENANT,
}


@pytest.fixture
def fresh_census(tmp_path: Path) -> dict[str, str]:
    files = [
        S.plant(tmp_path, "defender/runtime/fresh_factories.py", _FRESH_FACTORIES),
        S.plant(tmp_path, "defender/_tenant.py", _FRESH_OWNER),
        S.plant(tmp_path, "defender/runtime/own_class.py", _FRESH_OWN_CLASS),
        S.plant(tmp_path, "defender/runtime/driver/__init__.py", _FRESH_RELATIVE),
    ]
    return _factory_census(files, tmp_path)


def test_the_census_resolves_each_annotation_form_by_origin(fresh_census: dict[str, str]) -> None:
    """D3 / D4: the census finds a factory annotated in each form — a Name, an attribute, a
    string (of either class), an aliased import, an async def, a private def, the owner
    module's own class, a relative import — and nothing else: not a def returning something
    else, an unannotated or unparseably annotated def, a method, a nested def, nor a def
    returning an unrelated module's own class merely named `Tenant`."""
    assert fresh_census == _FRESH_CENSUS, fresh_census


def test_the_census_reports_an_unlisted_factory_and_a_stale_entry(
        fresh_census: dict[str, str]) -> None:
    """D4 detects what it exists to catch, against a table given to it (the shared one is
    never written): a private factory left out is unlisted; an entry for a function that does
    not exist, or exists without the annotation, is stale; an entry against the wrong class is
    both. A table equal to the census reports neither."""
    table = {fn: cls for fn, cls in fresh_census.items()
             if fn not in {f"{_F}._private", f"{_F}._private_async"}}
    table.update({
        f"{_F}.gone": TENANT,
        f"{_F}.unrelated": TENANT,
        f"{_F}.open_aliased": TENANT,
    })
    unlisted, stale = _drift(fresh_census, table)
    assert unlisted == {f"{_F}._private": TENANT, f"{_F}._private_async": RUN_TENANT,
                        f"{_F}.open_aliased": RUN_TENANT}, unlisted
    assert stale == {f"{_F}.gone": TENANT, f"{_F}.unrelated": TENANT,
                     f"{_F}.open_aliased": TENANT}, stale
    assert _drift(fresh_census, dict(fresh_census)) == ({}, {})
