"""#1504: a catalog adapter declares the non-GET reads it sends and the catalog reads them cold (O1); connect's
validator prints them given only the system (O4). The record judgement's cases are folded into their neighbours."""
from __future__ import annotations

import ast
import itertools
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


def _lint_lines(root: Path) -> list[str]:
    """The catalog declarations lint's output lines over `root`."""
    done = subprocess.run([sys.executable, str(REPO / "tooling/lint/lint_catalog_declarations.py"), "--root", str(root)],
                          cwd=REPO, env={**os.environ, "PYTHONPATH": str(REPO)}, capture_output=True, text=True,
                          timeout=300, check=False)
    out = done.stdout + done.stderr
    assert "Traceback" not in out, out
    return out.splitlines()


def _lint_names_reads(root: Path, adapter: str = "widget") -> bool:
    """Whether the lint, run over `root`, reports a finding naming the list constant in `adapter`'s module."""
    return any(X.READS_CONSTANT in line and f"{adapter}_adapter.py" in line for line in _lint_lines(root))


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


def _oracle(method: str, path: str) -> bool:
    """A6.1's route shape, written from the design: the method is upper-case letters, 3 to 10; the path starts with `/` and
    holds no `?` or `#`."""
    import re

    return bool(re.fullmatch(r"[A-Z]{3,10}", method)) and path.startswith("/") and "?" not in path and "#" not in path


def test_1504_a61_the_access_parser_the_lint_and_the_catalog_judge_every_generated_route_alike(tmp_path):
    """Over method x path pools (empty, case, digits, lengths 2/3/10/11, whitespace, control characters, `?`, `#`), one
    adapter per pair: the parser's verdict (in reads and in writes), the lint's and the catalog's each equal the rule as
    A6.1 states it (written here, `oracle`), and a refused route's reason names each non-empty part. (A6.1)"""
    pairs = list(itertools.product(X.SHAPE_METHODS, X.SHAPE_PATHS))
    checkout = tmp_path / "tree" / "defender"
    for i, pair in enumerate(pairs):
        X.plant_adapter(checkout, f"w{i}", reads=repr((pair,)))
        (checkout / "integrations" / f"w{i}_adapter.md").write_text(
            "## Credential\n\nNone known.\n\n## Pitfalls\n\nNone known.\n", encoding="utf-8")
    catalog = rules("Catalog").of_checkout(checkout)
    lines = _lint_lines(tmp_path / "tree")  # the one lint run
    taken_count = 0
    disagree: list[str] = []
    for i, pair in enumerate(pairs):
        taken = {_parser_takes(pair, "reads"), _parser_takes(pair, "writes")}
        entry = catalog.entry(f"w{i}")
        flagged = any(X.READS_CONSTANT in line and f"w{i}_adapter.py" in line for line in lines)
        reason = getattr(entry, X.UNUSABLE_FIELD)
        accepted = _oracle(*pair)
        taken_count += accepted
        if taken != {accepted}:
            disagree.append(f"{pair!r}: the parser takes it = {taken}, the rule says {accepted}")
        if flagged is accepted or (getattr(entry, X.ENTRY_FIELD) is None) is accepted:
            disagree.append(f"{pair!r}: rule accepts={accepted}, lint flags={flagged}, "
                            f"catalog reads={getattr(entry, X.ENTRY_FIELD)!r}")
        elif accepted:
            if tuple(getattr(entry, X.ENTRY_FIELD)) != (pair,) or reason is not None:
                disagree.append(f"{pair!r}: an accepted route is not the entry's list ({reason!r})")
        else:
            parts = [part for part in pair if part]
            if not isinstance(reason, str) or not all(part in reason or repr(part)[1:-1] in reason for part in parts):
                disagree.append(f"{pair!r}: the reason does not name each part: {reason!r}")
    assert 0 < taken_count < len(pairs), "premise: the pools hold routes the parser takes and routes it refuses"
    assert not disagree, "\n".join(disagree)


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


def test_1504_a61_each_reader_of_the_methods_that_need_no_declaration_judges_exactly_them(tmp_path):
    """`defender.kit.access.READ_METHODS` is GET and HEAD, and each reader judges exactly them: the proxy's route check
    admits a method with no declared route, Elastic's in-process confinement judges (refuses an undeclared path) and passes
    any other to the proxy, and the lint and the catalog refuse them in `READ_ROUTES`. (A6.1)"""
    from defender.credential_proxy._refusal import Refused
    from defender.credential_proxy._scope import check_route
    from defender.credential_proxy._tokens import READ
    from defender.integrations.confinement import confine_read_endpoint
    from defender.kit.access import READ_METHODS
    from defender.kit.faults import ConfinementFault
    from defender.tenancy import parse_access
    from defender.tests.support.tenancy import _systems1366 as R

    assert set(READ_METHODS) == {"GET", "HEAD"}
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


# --- A6.1 one owner: no second copy of the method list or the route shape, and each reader takes them from the kit --------

#: Python source the scan below reads: the product tree and the lint scripts, not the tests that exercise them.
SCANNED = ("defender", "tooling/lint")
KIT_ACCESS = "defender/kit/access.py"
#: Where each reader of the rule lives. The kit's names are FORCED in `_reads1504.py`; each reader takes them from the kit.
PROXY, CONFINEMENT = "defender/credential_proxy/_scope.py", "defender/integrations/confinement.py"
LINT, CATALOG, PARSER = ("tooling/lint/lint_catalog_declarations.py", "defender/system_rules/catalog.py",
                         "defender/tenancy/_access.py")
#: The route method's shape as the access parser spells it (A6.1). The proxy's own incoming-request pattern `[A-Z]{1,16}`
#: is another rule (a request line, not a declared route) and is not this.
ROUTE_METHOD_SHAPE = "[A-Z]{3,10}"
#: Fewer files than this read means the scan lost the tree (a path filter that drops it, e.g. a checkout under a folder named
#: like a skipped one), not that the tree is small.
SCANNED_FLOOR = 100


def _source_trees() -> dict[str, ast.Module]:
    skipped = {"tests", ".venv", "__pycache__", "node_modules"}
    trees = {path.relative_to(REPO).as_posix(): ast.parse(path.read_text(encoding="utf-8"))
             for top in SCANNED for path in sorted((REPO / top).rglob("*.py"))
             if not skipped & set(path.relative_to(REPO).parts)}
    assert KIT_ACCESS in trees, "premise: the scan reads the kit's access module"
    assert len(trees) > SCANNED_FLOOR, f"premise: the scan reads the product tree ({len(trees)} files)"
    return trees


def _is_read_method_literal(node: ast.AST) -> bool:
    """Whether `node` is a tuple, list or set literal of exactly the strings GET and HEAD (any case, any order)."""
    if not isinstance(node, (ast.Tuple, ast.List, ast.Set)) or not node.elts:
        return False
    texts = {e.value.upper() for e in node.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)}
    return len(texts) == len(node.elts) == 2 and texts == {"GET", "HEAD"}


def test_1504_a61_no_module_but_the_kit_binds_its_own_read_method_list_or_route_method_shape():
    """Repo-wide AST scan: outside `defender/kit/access.py` no collection literal equals {GET, HEAD} and no string holds
    the route method shape, so the list and the shape each have the one owner. (A6.1)"""
    methods, shape = [], []
    for rel, tree in _source_trees().items():
        if rel == KIT_ACCESS:
            continue
        for node in ast.walk(tree):
            if _is_read_method_literal(node):
                methods.append(f"{rel}:{node.lineno}")
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and ROUTE_METHOD_SHAPE in node.value:
                shape.append(f"{rel}:{node.lineno}")
    assert not methods, f"a second list of the methods that need no declaration: {methods}"
    assert not shape, f"a second copy of the route method shape: {shape}"


def _kit_access_use(tree: ast.Module) -> tuple[bool, bool]:
    """(whether `tree` imports from `defender.kit.access` (a name, or the module), whether it takes `READ_METHODS` from it)."""
    imported = takes_methods = False
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module == "defender.kit.access":
            imported = True
            takes_methods |= any(alias.name == "READ_METHODS" for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module == "defender.kit":
            modules |= {alias.asname or alias.name for alias in node.names if alias.name == "access"}
        elif isinstance(node, ast.Import):
            modules |= {alias.asname or alias.name for alias in node.names if alias.name == "defender.kit.access"}
    imported |= bool(modules)
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr == "READ_METHODS":
            takes_methods |= _dotted(node.value) in {*modules, "defender.kit.access"}
    return imported, takes_methods


def _dotted(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    return f"{_dotted(node.value)}.{node.attr}" if isinstance(node, ast.Attribute) else ""


def test_1504_a61_each_reader_of_the_rule_imports_it_from_the_kit_and_binds_no_literal_of_its_own():
    """The proxy's route check, Elastic's confinement and the lint take `READ_METHODS` from `defender.kit.access`; those and
    the access parser and the catalog reader import the route rule from it, and none binds a {GET, HEAD} literal. (A6.1)"""
    trees = _source_trees()
    for rel in (PROXY, CONFINEMENT, LINT, CATALOG, PARSER):
        assert rel in trees, f"premise: {rel} is scanned"
        imported, takes_methods = _kit_access_use(trees[rel])
        assert imported, f"{rel} does not import from defender.kit.access"
        if rel in (PROXY, CONFINEMENT, LINT):
            assert takes_methods, f"{rel} does not take READ_METHODS from defender.kit.access"
        own = [n.lineno for n in ast.walk(trees[rel]) if _is_read_method_literal(n)]
        assert not own, f"{rel} binds a {{GET, HEAD}} literal of its own at {own}"


def _kit_names(tree: ast.Module) -> tuple[dict[str, str], set[str]]:
    """(local name -> kit name for each name imported from `defender.kit.access`, local names of the module itself)."""
    names: dict[str, str] = {}
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module == X.KIT_ACCESS_MODULE:
            names |= {alias.asname or alias.name: alias.name for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module == "defender.kit":
            modules |= {alias.asname or alias.name for alias in node.names if alias.name == "access"}
        elif isinstance(node, ast.Import):
            modules |= {alias.asname or alias.name for alias in node.names if alias.name == X.KIT_ACCESS_MODULE}
    return names, modules


def _calls_kit_function(tree: ast.Module, function: str) -> bool:
    """Whether `tree` CALLS `defender.kit.access.<function>`: an `ast.Call` whose callee is the imported name or an
    attribute of the imported module (a bare import, or a mention that is not a call, does not count)."""
    names, modules = _kit_names(tree)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        callee = node.func
        if isinstance(callee, ast.Name) and names.get(callee.id) == function:
            return True
        if isinstance(callee, ast.Attribute) and callee.attr == function and _dotted(callee.value) in {*modules, X.KIT_ACCESS_MODULE}:
            return True
    return False


def test_1504_a61_the_route_shape_is_decided_by_calling_the_kits_functions_and_the_list_rule_builds_on_them():
    """The access parser CALLS `route_shape_fault`; the lint and the catalog reader CALL `read_routes_fault` (each from
    `defender.kit.access`, not a bare import); and `read_routes_fault`'s body uses `route_shape_fault` and `READ_METHODS`,
    so the list rule is not a third copy of the shape or the methods. (A6.1)"""
    trees = _source_trees()
    assert _calls_kit_function(trees[PARSER], X.ROUTE_SHAPE_FAULT), f"{PARSER} does not call {X.ROUTE_SHAPE_FAULT}"
    for rel in (LINT, CATALOG):
        assert _calls_kit_function(trees[rel], X.READ_ROUTES_FAULT), f"{rel} does not call {X.READ_ROUTES_FAULT}"
    functions = [n for n in ast.walk(trees[KIT_ACCESS]) if isinstance(n, ast.FunctionDef) and n.name == X.READ_ROUTES_FAULT]
    assert len(functions) == 1, f"{KIT_ACCESS} does not define exactly one {X.READ_ROUTES_FAULT}"
    used = {n.id for f in functions for n in ast.walk(f) if isinstance(n, ast.Name)}
    assert {X.ROUTE_SHAPE_FAULT, X.READ_METHODS_NAME} <= used, f"{X.READ_ROUTES_FAULT} does not use both: {used}"


# --- A6.2 / A6.3: a list that is not usable is "no usable list", with its reason, in every reader ------------------------

#: Every source of "no usable list": readable-but-unusable (tagged with the text the reason names) and unreadable or absent.
NO_USABLE_LIST = [pytest.param(source, needles, id=f"unusable-{name}") for name, source, needles in X.UNUSABLE_LISTS] + [
    pytest.param(source, (), id=f"unreadable-{name}") for name, source in X.UNREADABLE_LISTS]
COMPUTED = "tuple([('POST', '/widgets/_find')])"


def _record(reads: tuple[tuple[str, str], ...]) -> Any:
    from defender.tenancy.models import SystemRecord, TenantRecords
    from defender.tests.support.tenancy import _systems1366 as R

    record = SystemRecord(system_id="widget", version=1, adapter_id="widget", settings={"WIDGET_TIMEOUT_SEC": "10"},
                          access=R.declaration("https://widget.example", reads=reads))
    return TenantRecords(systems={"widget": record})


def _served(catalog: Any) -> dict[str, dict[str, Any]]:
    import asyncio

    from defender.api.config_records import ConfigRecords

    items = asyncio.run(ConfigRecords(None, None, catalog, None).list_adapters())  # type: ignore[arg-type]
    return {i.adapter_id: i.model_dump(mode="json") for i in items}


@pytest.mark.parametrize(("source", "needles"), NO_USABLE_LIST)
def test_1504_a62_a_list_that_is_not_usable_has_no_reads_and_one_reason_in_the_catalog_lint_judgement_api_and_validator(
        tmp_path, source, needles):
    """Whatever makes `READ_ROUTES` no usable list: the entry has `reads None` and a reason naming each offending entry;
    the lint names the list; a record is refused at its access part and held as a fault carrying that reason (not another
    adapter's); the API serves it; the validator fails a row with it and prints no route to copy. (A6.2, A6.3, O3, O4)"""
    from defender.kit.faults import ConfigFault
    from defender.kit.settings import RECORDS
    from defender.systems.run_tenant import record_settings

    root, catalog = _usable_catalog_and_tree(tmp_path / "list", source)
    entry = catalog.entry("widget")
    reason = getattr(entry, X.UNUSABLE_FIELD)
    assert getattr(entry, X.ENTRY_FIELD) is None
    assert isinstance(reason, str), reason
    assert reason.strip()
    for needle in needles:
        assert needle in reason, (needle, reason)
    assert _lint_names_reads(root)
    # a computed list is another cause of no usable list: its reason is not this one's, nor is this one's "unreadable"
    computed = getattr(_usable_catalog_and_tree(tmp_path / "computed", COMPUTED)[1].entry("widget"), X.UNUSABLE_FIELD)
    unusable = bool(needles)
    if unusable:
        assert reason != computed, reason
    for reads in ((), (("POST", "/widgets/_fine_one"),)):
        records = _record(reads)
        faults = list(rules("judge_records")(records, None, catalog=catalog))
        assert [f for f in faults if reason in f and RECORDS.part("widget", "access") in f], (reads, reason, faults)
        named = [f for f in faults if any(needle in f for needle in needles)]
        assert named or not needles, (needles, faults)
        assert all(RECORDS.part("widget", "access") in f for f in named), (reads, named)
        held = record_settings(records, catalog=catalog)["access"]["widget"]
        assert isinstance(held, ConfigFault), held
        assert reason in str(held), (reason, str(held))
        if unusable:
            assert not [f for f in faults if computed in f], (computed, faults)
            assert computed not in str(held), str(held)
    item = _served(catalog)["widget"]
    assert item[X.API_FIELD] is None, item
    assert item[X.UNUSABLE_FIELD] == reason, item
    out = _validate_over(root / "defender", "widget")
    lines = sorted({line.strip() for line in reason.splitlines() if line.strip()}, key=len, reverse=True)
    first = reason.splitlines()[0].strip()
    assert [line for line in out.splitlines() if "[✗]" in line and X.READS_CONSTANT in line and first in line], out
    for line in lines:
        assert line in out, (line, out)  # the whole reason is printed, every non-blank line of it
    rest = out
    for line in lines:
        rest = rest.replace(line, "", 1)
    written = [node.value for node in ast.walk(ast.parse(source or "()", mode="eval"))
               if isinstance(node, ast.Constant) and isinstance(node.value, str) and "/" in node.value]
    for text in (*needles, *written, "/widgets/_find"):
        assert text not in rest, (text, rest)  # nothing to copy is left once the reason is taken out
    assert not [line for line in out.splitlines() if "[✓]" in line and X.READS_ROW_WORD in line], out


def test_1504_a63_the_adapters_listing_serves_a_usable_list_with_no_reason_for_each_planted_and_checkout_adapter(tmp_path):
    """`GET /adapters`' item for a usable list: the routes as `{method, path}` and `reads_unusable: null`, for a planted
    adapter and for each of the checkout's own. (A6.3)"""
    _root, catalog = _usable_catalog_and_tree(tmp_path, "(('POST', '/widgets/_good'), ('PUT', '/widgets/*/mark'))")
    item = _served(catalog)["widget"]
    assert item[X.API_FIELD] == [{"method": "POST", "path": "/widgets/_good"},
                                 {"method": "PUT", "path": "/widgets/*/mark"}], item
    assert item[X.UNUSABLE_FIELD] is None, item
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
