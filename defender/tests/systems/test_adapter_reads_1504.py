"""#1504: a catalog adapter declares the non-GET reads it sends and the catalog reads them cold (O1); connect's
validator prints them given only the system (O4). The record judgement's cases are folded into their neighbours."""
from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Any

import pytest


from defender.tests.systems import _reads1504 as X
from defender.tests.systems._rules1470 import rules

ELASTIC_SETTINGS = {"ELASTIC_EVENTS_INDEX": "logs-*", "ELASTIC_ALERTS_INDEX": "alerts-*"}
REPO = Path(__file__).resolve().parents[3]
THREAT_INTEL_SETTINGS = {"THREAT_INTEL_TIMEOUT_SEC": "10"}


def test_1504_o1_each_adapter_declares_exactly_the_non_get_reads_it_sends():
    """Elastic declares its two searches, threat-intel its lookup, a GET-only adapter none (C3's census). (O1)"""
    catalog = rules("Catalog").of_checkout()
    got = {a: tuple(getattr(catalog.entry(a), X.ENTRY_FIELD)) for a in ("elastic", "threat-intel", "cmdb")}
    assert got == {"elastic": X.ELASTIC_READS, "threat-intel": X.THREAT_INTEL_READS, "cmdb": ()}


def test_1504_o1_the_catalog_reads_the_declared_reads_without_running_the_module(tmp_path):
    """An adapter whose import fails still has its declared reads in its catalog entry: they are read cold, like the
    other declarations, so the API can show them without loading the module. (O1)"""
    folder = tmp_path / "checkout" / "integrations"
    folder.mkdir(parents=True)
    (folder / "widget_adapter.py").write_text(textwrap.dedent(f'''\
        PREFIX = "WIDGET"
        REQUIRED_CONFIG_KEYS = ("TIMEOUT_SEC",)
        DISPLAY_NAME = "Widget"
        EXAMPLE = False
        {X.READS_CONSTANT} = (("POST", "/widgets/_find"),)
        raise RuntimeError("never run 1504")
        '''))
    catalog = rules("Catalog").of_checkout(tmp_path / "checkout")
    assert tuple(getattr(catalog.entry("widget"), X.ENTRY_FIELD)) == (("POST", "/widgets/_find"),)


# --- O4: connect's validator prints the reads given only the system --------------------------------------------------

def _validate(*args: str) -> str:
    done = subprocess.run([sys.executable, "-m", "defender.skills.connect.validate_scaffold", *args], cwd=REPO,
                          env={**os.environ, "PYTHONPATH": str(REPO)}, capture_output=True, text=True, timeout=120,
                          check=False)
    out = done.stdout + done.stderr
    assert "Traceback" not in out, out
    return out


def test_1504_o4_the_validator_prints_an_adapters_reads_given_only_the_system():
    """Before `access.yaml` exists: `validate_scaffold <system>` with no folder prints every read that adapter declares, so
    the agent can write them: both of Elastic's, and threat-intel's lookup. (O4)"""
    out = _validate("elastic")
    for route in X.ELASTIC_READS:
        assert X.shown(route) in out, (route, out)
    assert X.shown(X.THREAT_INTEL_READS[0]) in _validate("threat-intel")


# --- #1504 O4 (contract repair r3): exactly each adapter's own reads, in the validator and in the API listing ----------

PLANTED_READS = (("POST", "/widgets/_find"), ("PUT", "/widgets/*/mark"))


def _routes_named(text: str, pool: set[tuple[str, str]]) -> set[tuple[str, str]]:
    """The routes of `pool` that `text` names whole (`METHOD path`, not a prefix of a longer path)."""
    import re

    return {r for r in pool if re.search(rf"(?<![A-Za-z]){re.escape(X.shown(r))}(?=$|[\s,;)`'\"])", text, re.M)}


def _validate_over(checkout: Path | None, system: str) -> str:
    env = {**os.environ, "PYTHONPATH": str(REPO)}
    if checkout is not None:
        env["DEFENDER_DIR"] = str(checkout)
    done = subprocess.run([sys.executable, "-m", "defender.skills.connect.validate_scaffold", system], cwd=REPO,
                          env=env, capture_output=True, text=True, timeout=120, check=False)
    out = done.stdout + done.stderr
    assert "Traceback" not in out, out
    return out


def _planted(tmp_path: Path) -> tuple[Path, Any]:
    checkout = X.plant_adapter(tmp_path / "planted", "widget", reads=repr(PLANTED_READS))
    (checkout / "integrations" / "widget_adapter.md").write_text(
        "## Credential\n\nNone known.\n\n## Pitfalls\n\nNone known.\n", encoding="utf-8")  # O5: only the reads vary
    return checkout, rules("Catalog").of_checkout(checkout)


def test_1504_o4_the_validator_prints_exactly_each_adapters_reads(tmp_path):
    """Given only the system, for every catalog adapter and one planted adapter: the routes the output names are exactly
    that adapter's own entry's reads (none of another adapter's), and an adapter declaring `()` passes a reads row saying
    none. (O4)"""
    checkout, planted = _planted(tmp_path)
    catalog = rules("Catalog").of_checkout()
    cases: list[tuple[Path | None, str, tuple[Any, ...]]] = [
        (None, a, tuple(getattr(catalog.entry(a), X.ENTRY_FIELD))) for a in catalog.adapter_ids]
    cases.append((checkout, "widget", tuple(getattr(planted.entry("widget"), X.ENTRY_FIELD))))
    assert cases[-1][2] == PLANTED_READS, "premise: the planted list is read"
    pool = {r for _, _, reads in cases for r in reads}
    assert {*X.ELASTIC_READS, *X.THREAT_INTEL_READS, *PLANTED_READS} <= pool, pool
    assert any(reads == () for _, _, reads in cases), "premise: some adapter declares none"
    for where, system, reads in cases:
        out = _validate_over(where, system)
        assert _routes_named(out, pool) == set(reads), (system, out)
        rows = [line for line in out.splitlines() if "[✓]" in line and X.READS_ROW_WORD in line]
        assert rows, (system, out)
        if reads == ():
            assert [line for line in rows if X.NO_READS_WORD in line], (system, out)


def test_1504_o4_the_adapters_listing_serves_exactly_each_entrys_reads_from_the_catalog_it_was_built_with(tmp_path):
    """`GET /adapters`' item list (`ConfigRecords.list_adapters`, no database: it reads only the catalog it was built with)
    carries each entry's own reads as `{method, path}`: the checkout's adapters and a planted catalog's adapter. (O4)"""
    import asyncio

    from defender.api.config_records import ConfigRecords

    _checkout, planted = _planted(tmp_path)
    for catalog in (rules("Catalog").of_checkout(), planted):
        items = asyncio.run(ConfigRecords(None, None, catalog, None).list_adapters())  # type: ignore[arg-type]
        shown = {i.adapter_id: [(r["method"], r["path"]) for r in i.model_dump(mode="json")[X.API_FIELD]] for i in items}
        assert shown == {a: list(getattr(catalog.entry(a), X.ENTRY_FIELD)) for a in catalog.adapter_ids}, shown
    assert shown == {"widget": list(PLANTED_READS)}, shown


# --- #1504 A6: one route rule, shown honestly ---------------------------------------------------------------------------

def _usable_catalog_and_tree(tmp_path: Path, source: str | None) -> tuple[Path, Any]:
    """A repo-shaped tree (`defender/integrations/widget_adapter.py` with its reference) whose adapter declares `source`
    as its list, and the catalog read over its `defender/` folder."""
    root = tmp_path / "tree"
    checkout = X.plant_adapter(root / "defender", "widget", reads=source)
    (checkout / "integrations" / "widget_adapter.md").write_text(
        "## Credential\n\nNone known.\n\n## Pitfalls\n\nNone known.\n", encoding="utf-8")
    return root, rules("Catalog").of_checkout(checkout)


def _lint_names_reads(root: Path) -> bool:
    """Whether the catalog declarations lint, run over `root`, reports a finding naming the list constant."""
    done = subprocess.run([sys.executable, str(REPO / "tooling/lint/lint_catalog_declarations.py"), "--root", str(root)],
                          cwd=REPO, env={**os.environ, "PYTHONPATH": str(REPO)}, capture_output=True, text=True,
                          timeout=120, check=False)
    out = done.stdout + done.stderr
    assert "Traceback" not in out, out
    return any(X.READS_CONSTANT in line and "widget_adapter.py" in line for line in out.splitlines())


def _parser_takes(route: tuple[str, str], where: str) -> bool:
    """Whether the tenant access parser takes `route` in an access record's `reads` or `writes`."""
    from defender.kit.faults import ConfigFault
    from defender.tenancy import parse_access
    from defender.tests.support.tenancy import _systems1366 as R

    try:
        parse_access(R.declaration("https://widget.example", **{where: (route,)}), system="widget")
    except ConfigFault:
        return False
    return True


@pytest.mark.parametrize("route", [pytest.param(r, id=name) for name, r in X.SHAPE_BAD])
def test_1504_a61_a_route_of_the_wrong_shape_is_refused_alike_by_the_lint_the_catalog_and_the_access_parser(
        tmp_path, route):
    """One shape rule: a route the access parser refuses (in reads and in writes) is a lint finding naming `READ_ROUTES`
    and makes the catalog entry unusable, naming the route. (A6.1)"""
    root, catalog = _usable_catalog_and_tree(tmp_path, repr((route,)))
    entry = catalog.entry("widget")
    assert (_parser_takes(route, "reads"), _parser_takes(route, "writes")) == (False, False)
    assert _lint_names_reads(root)
    assert getattr(entry, X.ENTRY_FIELD) is None
    assert isinstance(getattr(entry, X.UNUSABLE_FIELD), str)
    assert route[1] in getattr(entry, X.UNUSABLE_FIELD) or route[0] in getattr(entry, X.UNUSABLE_FIELD)


@pytest.mark.parametrize("route", [pytest.param(r, id=name) for name, r in X.SHAPE_GOOD])
def test_1504_a61_a_route_of_the_right_shape_is_taken_alike_by_the_lint_the_catalog_and_the_access_parser(
        tmp_path, route):
    """Control: a well-shaped non-read route is no lint finding, reads as the entry's list with no reason, and the
    access parser takes it in reads and in writes. (A6.1)"""
    root, catalog = _usable_catalog_and_tree(tmp_path, repr((route,)))
    entry = catalog.entry("widget")
    assert _parser_takes(route, "reads")
    assert _parser_takes(route, "writes")
    assert not _lint_names_reads(root)
    assert tuple(getattr(entry, X.ENTRY_FIELD)) == (route,)
    assert getattr(entry, X.UNUSABLE_FIELD) is None


@pytest.mark.parametrize("method", ["GET", "HEAD"])
def test_1504_a61_a_read_method_route_is_taken_by_the_access_parser_but_not_in_a_declared_list(tmp_path, method):
    """Only `READ_ROUTES` excludes the methods that need no declaration: the parser takes `GET /x` in a record's reads, the
    lint and the catalog refuse it in the list. (A6.1)"""
    route = (method, "/x/_a")
    root, catalog = _usable_catalog_and_tree(tmp_path, repr((route,)))
    assert _parser_takes(route, "reads")
    assert _lint_names_reads(root)
    assert getattr(catalog.entry("widget"), X.ENTRY_FIELD) is None


@pytest.mark.parametrize(("source", "usable"), [
    pytest.param("(('POST', '/x/_a'), ('POST', '/x/_a'))", False, id="repeated-route"),
    pytest.param("(('POST', '/x/_a'), ('PUT', '/x/_a'))", True, id="same-path-two-methods"),
    pytest.param("(('POST', '/x/_a'), ('POST', '/x/_b'))", True, id="same-method-two-paths"),
    pytest.param("()", True, id="empty"),
])
def test_1504_a61_the_lint_and_the_catalog_judge_a_whole_list_usable_alike(tmp_path, source, usable):
    """The lint finds the list unusable exactly when the catalog reads no list from it (a repeat); a distinct-route list
    and `()` are usable in both. (A6.1)"""
    root, catalog = _usable_catalog_and_tree(tmp_path, source)
    entry = catalog.entry("widget")
    assert _lint_names_reads(root) is not usable
    assert (getattr(entry, X.ENTRY_FIELD) is not None) is usable
    assert (getattr(entry, X.UNUSABLE_FIELD) is None) is usable


def test_1504_a61_one_list_of_the_methods_that_need_no_declaration_is_judged_alike_by_every_reader(tmp_path):
    """`defender.kit.access.READ_METHODS` is GET and HEAD, and each reader judges exactly them: the proxy's route check
    admits a method with no declared route, Elastic's in-process confinement judges (refuses an undeclared path) and passes
    any other to the proxy, and the lint and the catalog refuse them in `READ_ROUTES`. (A6.1)"""
    from defender.credential_proxy import _scope
    from defender.credential_proxy._refusal import Refused
    from defender.credential_proxy._scope import check_route
    from defender.credential_proxy._tokens import READ
    from defender.integrations.confinement import confine_read_endpoint
    from defender.kit.access import READ_METHODS
    from defender.kit.faults import ConfinementFault
    from defender.tenancy import parse_access
    from defender.tests.support.tenancy import _systems1366 as R

    assert set(READ_METHODS) == {"GET", "HEAD"}
    assert _scope.READ_METHODS is READ_METHODS  # the proxy keeps no copy
    declaration = parse_access(R.declaration("https://widget.example"), system="widget")
    for method in X.METHOD_POOL:
        reads = method in READ_METHODS
        try:
            check_route(declaration, "widget", method, "/undeclared", READ)
            admitted = True
        except Refused:
            admitted = False
        assert admitted is reads, ("proxy", method)
        try:
            confine_read_endpoint("elastic", "http://es:9200/_cat/indices", method=method)
            judged = False
        except ConfinementFault:
            judged = True
        assert judged is reads, ("elastic confinement", method)
        root, catalog = _usable_catalog_and_tree(tmp_path / method, repr(((method, "/x/_a"),)))
        assert _lint_names_reads(root) is reads, ("lint", method)
        assert (getattr(catalog.entry("widget"), X.ENTRY_FIELD) is None) is reads, ("catalog", method)


# --- A6.3: GET /adapters and the validator say honestly when there is no usable list -------------------------------------

def _catalogs_by_kind(tmp_path: Path) -> dict[str, tuple[Path, Any]]:
    """One planted checkout per kind of list: usable, unusable (a good route beside a GET), computed and absent."""
    usable = "(('POST', '/widgets/_good'), ('PUT', '/widgets/*/mark'))"
    unusable = "(('POST', '/widgets/_good'), ('GET', '/widgets/_gone'))"
    sources = {"usable": usable, "unusable": unusable, "unreadable": "tuple([('POST', '/widgets/_good')])",
               "absent": None}
    out = {}
    for kind, source in sources.items():
        checkout = X.plant_adapter(tmp_path / kind, "widget", reads=source)
        (checkout / "integrations" / "widget_adapter.md").write_text(
            "## Credential\n\nNone known.\n\n## Pitfalls\n\nNone known.\n", encoding="utf-8")
        out[kind] = (checkout, rules("Catalog").of_checkout(checkout))
    return out


def _served(catalog: Any) -> dict[str, dict[str, Any]]:
    import asyncio

    from defender.api.config_records import ConfigRecords

    items = asyncio.run(ConfigRecords(None, None, catalog, None).list_adapters())  # type: ignore[arg-type]
    return {i.adapter_id: i.model_dump(mode="json") for i in items}


def test_1504_a63_the_adapters_listing_serves_null_reads_and_a_reason_when_the_list_is_not_usable(tmp_path):
    """`GET /adapters`' item: `reads: null` and the entry's non-empty `reads_unusable` for an unusable, a computed and an
    absent list; the routes and `reads_unusable: null` for a usable one, and for each of the checkout's own adapters. (A6.3)"""
    kinds = _catalogs_by_kind(tmp_path)
    for kind, (_checkout, catalog) in kinds.items():
        item = _served(catalog)["widget"]
        if kind == "usable":
            assert item[X.API_FIELD] == [{"method": "POST", "path": "/widgets/_good"},
                                         {"method": "PUT", "path": "/widgets/*/mark"}], item
            assert item[X.UNUSABLE_FIELD] is None, item
            continue
        assert item[X.API_FIELD] is None, (kind, item)
        reason = item[X.UNUSABLE_FIELD]
        assert isinstance(reason, str), (kind, item)
        assert reason.strip(), (kind, item)
        assert reason == getattr(catalog.entry("widget"), X.UNUSABLE_FIELD), (kind, item)
    assert "/widgets/_gone" in _served(kinds["unusable"][1])["widget"][X.UNUSABLE_FIELD]
    own = _served(rules("Catalog").of_checkout())
    assert {a: i[X.UNUSABLE_FIELD] for a, i in own.items()} == dict.fromkeys(own)
    assert all(isinstance(i[X.API_FIELD], list) for i in own.values()), own


def test_1504_a63_the_openapi_document_declares_reads_nullable_and_reads_unusable_text_or_null_on_the_adapter_item():
    """`openapi.json`'s adapter item: `reads` is an array or null and `reads_unusable` is a string or null. (A6.3)"""
    import json

    schema = json.loads((REPO / "defender/api/openapi.json").read_text(encoding="utf-8"))["components"]["schemas"]
    props = schema["CatalogAdapter"]["properties"]
    reads = props[X.API_FIELD]["anyOf"]
    assert {"type": "null"} in reads
    assert any(branch.get("type") == "array" for branch in reads), reads
    reason = props[X.UNUSABLE_FIELD]["anyOf"]
    assert sorted(branch.get("type") for branch in reason) == ["null", "string"], reason


def test_1504_a63_the_validator_given_only_the_system_prints_the_reason_and_no_routes_for_a_list_that_is_not_usable(
        tmp_path):
    """For an unusable, a computed and an absent list the validator prints the entry's reason, no reads row and none of
    the list's routes to copy; a usable list still prints its routes. (A6.3, O4)"""
    kinds = _catalogs_by_kind(tmp_path)
    out = _validate_over(kinds["usable"][0], "widget")
    assert {r for r in (("POST", "/widgets/_good"), ("PUT", "/widgets/*/mark")) if X.shown(r) in out} == {
        ("POST", "/widgets/_good"), ("PUT", "/widgets/*/mark")}, out
    for kind in ("unusable", "unreadable", "absent"):
        checkout, catalog = kinds[kind]
        reason = getattr(catalog.entry("widget"), X.UNUSABLE_FIELD)
        out = _validate_over(checkout, "widget")
        assert reason in out, (kind, reason, out)
        assert "/widgets/_good" not in out.replace(reason, ""), (kind, out)
        assert not [line for line in out.splitlines() if "[✓]" in line and X.READS_ROW_WORD in line], (kind, out)
