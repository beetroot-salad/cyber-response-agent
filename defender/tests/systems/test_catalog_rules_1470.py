"""#1470 D-E, D8, D11: the record rules sit below `systems`; the catalog keeps an adapter that failed to load as data; each
catalog adapter declares sample settings its own check accepts."""
from __future__ import annotations

import ast
from typing import Any
from pathlib import Path

import pytest

from defender.kit.settings import RECORDS
from defender.tests.support.tenancy import _systems1366 as R
from defender.tests.systems import _reads1504 as X
from defender.tests.systems._rules1470 import rules, write_broken_adapter

#: The catalog's adapters today (design C14: nine); the premise that the sweeps below read them all.
ADAPTERS = 9


def _catalog() -> Any:
    return rules("Catalog").of_checkout()


def _adapter_ids() -> list[str]:
    ids = list(_catalog().adapter_ids)
    assert len(ids) >= ADAPTERS, f"premise: the sweep reads every catalog adapter, got {ids}"
    return ids


def test_1470_d_e_the_registry_names_the_rules_own_are_the_ones_systems_re_exports():
    """`systems.verbs` and `systems.catalog` re-export the registry and catalog names the rules package owns: the same
    objects, not copies, so the one-roster-read contract stands. (D-E, #1035)"""
    import defender.systems.catalog as old_catalog
    import defender.systems.verbs as old_verbs

    for name in ("RosterRead", "read_roster", "RegistryError"):
        assert getattr(old_verbs, name) is rules(name), name
    for name in ("Catalog", "CatalogEntry"):
        assert getattr(old_catalog, name) is rules(name), name


def test_1470_d_e_the_platform_served_names_have_one_owner_the_rules_package_and_systems_serves_exactly_them():
    """`system_rules.PLATFORM_SERVED_NAMES` is the one constant; the systems side's platform-served table is keyed by exactly
    those names (built from it, no second copy). (D-E)"""
    import defender.systems.tacit_registry as tacit
    import defender.systems.verbs as old_verbs

    names = rules("PLATFORM_SERVED_NAMES")
    assert set(names), names
    assert tacit.SYSTEM in names, names
    assert set(old_verbs.PLATFORM_SERVED) == set(names)


def test_1470_d11_each_adapter_declares_sample_settings_cold_with_one_value_per_stored_key():
    """Every catalog adapter has a module-level `SAMPLE_SETTINGS` literal (key -> text) holding exactly the keys a record of
    it stores, read from the source without running the module. (O2, D11)"""
    catalog = _catalog()
    for adapter in _adapter_ids():
        entry = catalog.entry(adapter)
        tree = ast.parse(Path(entry.path).read_text("utf-8"))
        declared = [n.value for n in tree.body if isinstance(n, ast.Assign)
                    and any(isinstance(t, ast.Name) and t.id == "SAMPLE_SETTINGS" for t in n.targets)]
        assert len(declared) == 1, f"{adapter}: SAMPLE_SETTINGS declared {len(declared)} times"
        sample = ast.literal_eval(declared[0])
        assert isinstance(sample, dict), adapter
        assert all(isinstance(k, str) and isinstance(v, str) for k, v in sample.items()), adapter
        assert sorted(sample) == sorted(entry.stored_keys), (adapter, sorted(sample), sorted(entry.stored_keys))


def test_1470_d11_each_adapters_own_settings_check_accepts_its_sample_settings():
    """A record of each catalog adapter holding its sample settings (and an access declaration that fits) is judged with no
    fault: the sample is a value the adapter's check accepts. (O2, D11)"""
    from defender.tenancy.models import SystemRecord, TenantRecords

    catalog = _catalog()
    judge = rules("judge_records")
    for adapter in _adapter_ids():
        sample = dict(catalog.module(adapter).SAMPLE_SETTINGS)
        reads = {"elastic": X.ELASTIC_READS, "threat-intel": X.THREAT_INTEL_READS}.get(adapter, ())  # #1504 O3: exact reads
        record = SystemRecord(system_id=adapter, version=1, adapter_id=adapter, settings=sample,
                              access=R.declaration(f"https://{adapter}.example.test", reads=reads))
        assert list(judge(TenantRecords(systems={adapter: record}), None, catalog=catalog)) == [], adapter


def _broken_checkout(root: Path, counter: Path) -> Path:
    """A checkout whose `integrations/` holds one adapter that fails when imported, and notes each import in `counter`."""
    write_broken_adapter(root / "integrations", counter)
    return root


def test_1470_d8_a_catalog_keeps_the_failed_load_and_raises_it_again_on_each_ask_without_retrying(tmp_path):
    """An adapter that fails to import: every ask for its module raises the first failure itself, and the module is
    imported once, not on each ask. (D8)"""
    counter = tmp_path / "imports"
    catalog = rules("Catalog").of_checkout(_broken_checkout(tmp_path / "checkout", counter))
    assert "broken" in catalog.adapter_ids, "premise: the catalog carries it"
    failures = []
    for _ in range(3):
        with pytest.raises(RuntimeError, match="failed on import 1470") as asked:
            catalog.module("broken")
        failures.append(asked.value)
    assert failures[0] is failures[1] is failures[2]
    assert counter.read_text() == "x", "the broken module was imported once"


def test_1470_d8_a_record_naming_an_adapter_that_failed_to_load_is_a_judgement_fault_not_a_crash(tmp_path):
    """The judgement answers a record of a failed adapter with a fault naming the system, on every ask, never raising.
    (D8; the API's 422)"""
    from defender.tenancy.models import SystemRecord, TenantRecords

    catalog = rules("Catalog").of_checkout(_broken_checkout(tmp_path / "checkout", tmp_path / "imports"))
    record = SystemRecord(system_id="broken", version=1, adapter_id="broken", settings={"BROKEN_TIMEOUT_SEC": "10"},
                          access=R.declaration("https://broken.example.test"))
    for _ in range(2):
        found = list(rules("judge_records")(TenantRecords(systems={"broken": record}), None, catalog=catalog))
        assert len(found) == 1, found
        assert "broken" in found[0], found


# --- #1504 O3: a record's non-GET reads are exactly its adapter's list ---------------------------------------------------

def _sample(adapter: str) -> dict[str, str]:
    return dict(_catalog().entry(adapter).sample_settings or {})


def _judge(adapter: str, reads: tuple[tuple[str, str], ...], *, catalog: Any = None) -> list[str]:
    """connect's judgement of one candidate system of `adapter` holding `reads`, at the store's locator."""
    return rules("judge_system")(adapter, settings=_sample(adapter), access=R.declaration(
        "https://elasticsearch.example:9200", reads=reads), locator=RECORDS, catalog=catalog)


def _named(faults: list[str], route: tuple[str, str], word: str) -> list[str]:
    return [f for f in faults if X.shown(route) in f and word in f]


ELASTIC_PAIR = X.ELASTIC_READS
MISSING_ONE = (ELASTIC_PAIR[0],)
EXTRA_DELETE = ("DELETE", "/*")
NARROWED = ("POST", "/logs-*/_search")


@pytest.mark.parametrize(("reads", "missing", "extra"), [
    pytest.param(MISSING_ONE, [ELASTIC_PAIR[1]], [], id="one-declared-read-missing"),
    pytest.param((), list(ELASTIC_PAIR), [], id="none-listed"),
    pytest.param((*ELASTIC_PAIR, EXTRA_DELETE), [], [EXTRA_DELETE], id="a-read-added"),
    pytest.param((NARROWED, ELASTIC_PAIR[1]), [ELASTIC_PAIR[0]], [NARROWED], id="narrowed-search-is-missing-and-extra"),
    pytest.param((*MISSING_ONE, EXTRA_DELETE), [ELASTIC_PAIR[1]], [EXTRA_DELETE], id="one-missing-one-extra"),
])
def test_1504_o3_a_record_whose_non_get_reads_differ_from_its_adapters_is_refused_naming_each_route_at_its_access_part(
        reads, missing, extra):
    """Elastic's record judged: each missing and each extra route is named as such, at the record's access part. (O3)"""
    faults = _judge("elastic", reads)
    assert faults, "premise: the mismatch is refused"
    assert all(RECORDS.part("elastic", "access") in f for f in faults), faults
    for route in missing:
        assert _named(faults, route, X.MISSING_WORD), (route, faults)
    for route in extra:
        assert _named(faults, route, X.EXTRA_WORD), (route, faults)


@pytest.mark.parametrize("reads", [
    pytest.param(ELASTIC_PAIR, id="exact"),
    pytest.param(tuple(reversed(ELASTIC_PAIR)), id="any-order"),
    pytest.param((*ELASTIC_PAIR, ELASTIC_PAIR[0]), id="a-declared-route-twice"),
    pytest.param((*ELASTIC_PAIR, ("GET", "/_cluster/health"), ("HEAD", "/logs-*")), id="get-and-head-are-not-judged"),
])
def test_1504_o3_a_record_listing_exactly_its_adapters_non_get_reads_is_accepted(reads):
    """Control: the declared reads in any order, repeated, or with a GET or HEAD beside them, are accepted. (O3)"""
    assert _judge("elastic", reads) == []


def test_1504_o3_threat_intel_lists_its_lookup_and_nothing_else():
    """A second adapter's list: its lookup alone is accepted; the lookup plus `DELETE /*` is refused naming the extra
    route; none listed is refused naming the lookup as missing. (O3, C2)"""
    assert _judge("threat-intel", X.THREAT_INTEL_READS) == []
    [extra] = _named(_judge("threat-intel", (*X.THREAT_INTEL_READS, EXTRA_DELETE)), EXTRA_DELETE, X.EXTRA_WORD)
    assert _named(_judge("threat-intel", ()), X.THREAT_INTEL_READS[0], X.MISSING_WORD)


def test_1504_o3_a_get_only_adapter_refuses_any_non_get_read():
    """cmdb declares none: no non-GET read listed is accepted, a `POST` listed is an extra route. (O3)"""
    assert _judge("cmdb", (("GET", "/hosts/*"),)) == []
    assert _named(_judge("cmdb", (("POST", "/hosts/_find"),)), ("POST", "/hosts/_find"), X.EXTRA_WORD)


def test_1504_o3_the_stores_judgement_of_a_tenants_records_refuses_the_mismatch_and_accepts_the_exact_one():
    """`judge_records` over a tenant's records (the save and `tenant check` entry): threat-intel with `DELETE /*`
    listed is refused naming it; with only its lookup the same records are accepted. (O3, C2)"""
    from defender.tenancy.models import SystemRecord, TenantRecords

    def records(reads: tuple[tuple[str, str], ...]) -> Any:
        record = SystemRecord(system_id="threat-intel", version=1, adapter_id="threat-intel",
                              settings=_sample("threat-intel"), access=R.declaration("https://ti.example", reads=reads))
        return TenantRecords(systems={"threat-intel": record})

    judge = rules("judge_records")
    assert list(judge(records(X.THREAT_INTEL_READS), None)) == []
    faults = list(judge(records((*X.THREAT_INTEL_READS, EXTRA_DELETE)), None))
    assert _named(faults, EXTRA_DELETE, X.EXTRA_WORD), faults
    assert len([f for f in faults if X.shown(EXTRA_DELETE) in f]) == 1, "one fault names the route, not one per check"


# The adapters below are planted in a catalog the caller holds, to reach conditions the checkout's own adapters cannot.

def _planted_record(name: str, reads: tuple[tuple[str, str], ...]) -> Any:
    from defender.tenancy.models import SystemRecord, TenantRecords

    record = SystemRecord(system_id=name, version=1, adapter_id=name, settings={f"{name.upper()}_TIMEOUT_SEC": "10"},
                          access=R.declaration(f"https://{name}.example", reads=reads))
    return TenantRecords(systems={name: record})


WIDGET_ROUTE = ("POST", "/widgets/_find")


@pytest.mark.parametrize(("reads_source", "why"), [
    pytest.param(None, "no list declared", id="no-list-declared"),
    pytest.param("tuple([('POST', '/widgets/_find')])", "list not a literal", id="list-not-readable-cold"),
])
def test_1504_o3_a_record_of_an_adapter_without_a_readable_list_is_refused_and_one_with_it_is_not(
        tmp_path, reads_source, why):
    """An adapter whose module declares no list, or one not readable without running it, has its records refused (they
    cannot be judged); the same adapter declaring the list as a literal accepts the matching record. (O3)"""
    catalog = rules("Catalog").of_checkout(X.plant_adapter(tmp_path / "bad", "widget", reads=reads_source))
    faults = list(rules("judge_records")(_planted_record("widget", (WIDGET_ROUTE,)), None, catalog=catalog))
    assert faults, why
    assert all(RECORDS.system("widget") in f for f in faults), faults

    good = rules("Catalog").of_checkout(X.plant_adapter(tmp_path / "good", "widget", reads=repr((WIDGET_ROUTE,))))
    assert list(rules("judge_records")(_planted_record("widget", (WIDGET_ROUTE,)), None, catalog=good)) == []


def test_1504_o3_the_list_judged_is_the_one_of_the_catalog_the_caller_holds(tmp_path):
    """A catalog whose `elastic` declares one other route: the real pair is refused against it (missing the one, extra
    both), the one route is accepted against it; the checkout's own catalog judges the reverse. (O3, R14: one owner)"""
    only = ("POST", "/only/_find")
    held = rules("Catalog").of_checkout(X.plant_adapter(tmp_path / "held", "elastic", reads=repr((only,))))
    judge = rules("judge_records")
    assert list(judge(_planted_record("elastic", (only,)), None, catalog=held)) == []
    faults = list(judge(_planted_record("elastic", ELASTIC_PAIR), None, catalog=held))
    assert _named(faults, only, X.MISSING_WORD), faults
    assert all(_named(faults, r, X.EXTRA_WORD) for r in ELASTIC_PAIR), faults
    assert _judge("elastic", (only,))  # the checkout's own list is another one
    assert _judge("elastic", ELASTIC_PAIR) == []


def test_1504_o3_a_held_access_fault_is_reported_by_the_judgement_though_the_adapters_check_never_reads_the_access(
        tmp_path):
    """An adapter whose `check_settings` never reaches `record_access` still has a mismatched record refused, naming the
    route; its matching record is accepted. (O3, design: the save-time refusal does not depend on adapter code)"""
    catalog = rules("Catalog").of_checkout(X.plant_adapter(tmp_path, "widget", reads=repr((WIDGET_ROUTE,))))
    judge = rules("judge_records")
    assert list(judge(_planted_record("widget", (WIDGET_ROUTE,)), None, catalog=catalog)) == []
    faults = list(judge(_planted_record("widget", ()), None, catalog=catalog))
    assert _named(faults, WIDGET_ROUTE, X.MISSING_WORD), faults
    assert all(RECORDS.part("widget", "access") in f for f in faults), faults


def test_1504_o3_a_changed_case_system_record_shows_the_read_check_not_the_cover_sentence():
    """`cover_fault` is unchanged: a ticket record changed to list a non-GET read is refused with the read check's sentence
    (the route as extra); a change to a second write route keeps the cover sentence. (O3, design: cover_fault unchanged)"""
    from defender.tenancy.models import CaseRecord, SystemRecord, TenantRecords

    comment = ("POST", "/tickets/*/comments")
    settings = dict(R.FIXTURE_FOLDERS["ticket"][0])

    def tenant(*, reads: tuple = (), writes: tuple = (comment,)) -> Any:
        record = SystemRecord(system_id="ticket", version=1, adapter_id="ticket", settings=settings,
                              access=R.declaration("http://soc-playground:8004", reads=reads, writes=writes))
        return TenantRecords(systems={"ticket": record}, case=CaseRecord(version=1, system_id="ticket"))

    judge = rules("judge_records")
    before = tenant()
    assert list(judge(before, None)) == [], "premise: the unchanged record covers the comment route"
    bad_read = ("POST", "/search")
    faults = list(judge(tenant(reads=(bad_read,)), before))
    assert _named(faults, bad_read, X.EXTRA_WORD), faults
    assert not [f for f in faults if "unable to take the comment" in f or "is not a GET" in f], faults
    second_write = ("POST", "/tickets/*/transitions")
    cover = list(judge(tenant(writes=(comment, second_write)), before))
    assert [f for f in cover if "unable to take the comment" in f and X.shown(second_write) in f], cover


# --- #1504 O3 (contract repair r3): the exact-set rule over generated records, and an unreadable list -------------------

#: Planted adapters' lists for the generated sweep: one route, a `*` route beside a PUT, none, and the unusual verbs.
SWEEP_LISTS: dict[str, tuple[tuple[str, str], ...]] = {
    "widgeta": (("POST", "/lookup"),),
    "widgetb": (("POST", "/*/_search"), ("PUT", "/items/*")),
    "widgetc": (),
    "widgetd": (("OPTIONS", "/a/b"), ("TRACE", "/t"), ("CONNECT", "/c"), ("DELETE", "/*"), ("PATCH", "/p/*")),
}
UNUSUAL_VERBS = ("POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT")


def _respelled(route: tuple[str, str]) -> list[tuple[tuple[str, str], str]]:
    """`route` spelled otherwise, each with its kind: path case, a trailing `/`, a doubled `/`, another segment, another
    verb, and the method in lower case (which the route parser refuses)."""
    method, path = route
    *head, last = path.split("/")
    other = "x" if last == "*" else "*" if last else "seg"
    found = [((method, path.upper()), "case"), ((method, path.swapcase()), "case"), ((method, path + "/"), "trailing"),
             ((method, "/" + path), "doubled"), ((method, path.replace("/", "//")), "doubled"),
             ((method, "/".join([*head, other])), "segment"), ((method.lower(), path), "lower-method")]
    found += [((verb, path), "verb") for verb in UNUSUAL_VERBS if verb != method]
    return [(r, kind) for r, kind in found if r != route]


def _sweep_cases(listed: tuple[tuple[str, str], ...], rng: Any) -> list[tuple[tuple[tuple[str, str], ...], str]]:
    """Generated record reads for an adapter declaring `listed`, each with what it varies: the list exactly (shuffled,
    repeated, with GET and HEAD routes beside it, the read methods in lower case too), the list with one respelled route
    added or substituted, and seeded random draws over the whole pool."""
    reads_beside = [("GET", "/_cluster/health"), ("HEAD", "/lookup"), ("GET", "/*/_search"), *(
        (m, p) for _, p in listed for m in ("GET", "HEAD"))]
    pool = [*listed, *reads_beside, ("get", "/lookup"), ("head", "/lookup"), ("PUT", "/items/*"), ("POST", "/lookup"),
            *(r for route in listed for r, _ in _respelled(route)),
            *(r for r, _ in _respelled(("POST", "/lookup")))]
    cases = []
    for n in range(4):
        exact = [*listed, *rng.sample(reads_beside, k=rng.randint(0, len(reads_beside))), *listed[: n % 2]]
        rng.shuffle(exact)
        cases.append((tuple(exact), "exact"))
    for route in listed:
        for spelled, kind in _respelled(route):
            cases.append(((*listed, spelled), f"added-{kind}"))
            cases.append((tuple(spelled if r == route else r for r in listed), f"substituted-{kind}"))
    for spelled, kind in _respelled(("POST", "/lookup")):
        cases.append(((*listed, spelled), f"added-{kind}"))
    for _ in range(40):
        cases.append((tuple(rng.sample(pool, k=rng.randint(0, min(6, len(pool))))), "random"))
    return cases


def _names_route(fault: str, route: tuple[str, str]) -> bool:
    """`fault` names `route` as a whole (`METHOD path`, not a prefix of a longer path or a part of a longer method)."""
    import re

    shown = re.escape(X.shown(route))
    return re.search(rf"(?<![A-Za-z]){shown}(?=$|[\s,;)`'\"])", fault) is not None


def test_1504_o3_a_record_is_accepted_exactly_when_its_non_get_reads_are_its_adapters_list(tmp_path):
    """Over generated records (respelled routes, unusual verbs, read methods beside the list): a record is accepted iff the
    set of its routes whose method is not a read method is its adapter's list; a refusal names each missing route as
    missing and each extra one as extra. A record the route parser refuses (a lower-case method) is refused. (O3)"""
    import importlib
    import random

    from defender.kit.faults import ConfigFault
    from defender.tenancy import parse_access
    from defender.tenancy.models import SystemRecord, TenantRecords

    door = importlib.import_module("defender.credential_proxy")
    is_read = getattr(door, "is_read_method", None) or (lambda method: method in ("GET", "HEAD"))
    rng = random.Random(1504)
    judge = rules("judge_records")
    adapters: list[tuple[str, tuple[tuple[str, str], ...], Any, dict[str, str]]] = [
        ("elastic", X.ELASTIC_READS, _catalog(), _sample("elastic"))]
    for name, listed in SWEEP_LISTS.items():
        catalog = rules("Catalog").of_checkout(X.plant_adapter(tmp_path / name, name, reads=repr(listed)))
        adapters.append((name, listed, catalog, {f"{name.upper()}_TIMEOUT_SEC": "10"}))
    seen: dict[str, set[bool]] = {}
    for name, listed, catalog, settings in adapters:
        for reads, kind in _sweep_cases(listed, rng):
            access = R.declaration(f"https://{name}.example", reads=reads)
            record = SystemRecord(system_id=name, version=1, adapter_id=name, settings=settings, access=access)
            faults = list(judge(TenantRecords(systems={name: record}), None, catalog=catalog))
            case = (name, kind, reads, faults)
            try:
                parse_access(access, system=name)
            except ConfigFault:  # the route parser's refusal: the record is refused, not judged for reads
                assert faults, case
                seen.setdefault("parse-refused", set()).add(True)
                continue
            held = {(m, p) for m, p in reads if not is_read(m)}
            accepted = held == set(listed)
            seen.setdefault(kind, set()).add(accepted)
            if accepted:
                assert faults == [], case
                continue
            assert faults, case
            assert all(RECORDS.part(name, "access") in f for f in faults), case
            for route in set(listed) - held:
                assert [f for f in faults if _names_route(f, route) and X.MISSING_WORD in f], (route, case)
            for route in held - set(listed):
                assert [f for f in faults if _names_route(f, route) and X.EXTRA_WORD in f], (route, case)
    assert seen.get("exact") == {True}, seen
    assert seen.get("parse-refused") == {True}, seen
    for kind in ("case", "trailing", "doubled", "segment", "verb"):
        assert False in seen.get(f"added-{kind}", set()) | seen.get(f"substituted-{kind}", set()), (kind, seen)
    assert seen.get("random") == {True, False}, seen


def _validate_in(checkout: Path, system: str) -> tuple[list[str], str]:
    """Connect's validator given only `system`, over the checkout `checkout` (`DEFENDER_DIR`): its failure rows and output."""
    import os
    import subprocess
    import sys

    repo = Path(__file__).resolve().parents[3]
    done = subprocess.run([sys.executable, "-m", "defender.skills.connect.validate_scaffold", system], cwd=repo,
                          env={**os.environ, "PYTHONPATH": str(repo), "DEFENDER_DIR": str(checkout)},
                          capture_output=True, text=True, timeout=120, check=False)
    out = done.stdout + done.stderr
    assert "Traceback" not in out, out
    return [line for line in out.splitlines() if "[✗]" in line], out


@pytest.mark.parametrize(("reads_source", "readable"), [
    pytest.param(None, False, id="no-list-declared"),
    pytest.param("tuple([('POST', '/widgets/_find')])", False, id="not-a-literal"),
    pytest.param("(('POST', '/widgets/_find', 'more'),)", False, id="a-route-of-three-parts"),
    pytest.param("('POST', '/widgets/_find')", False, id="a-bare-route-not-a-tuple-of-routes"),
    pytest.param("(('POST', 7),)", False, id="a-path-not-text"),
    pytest.param("'POST /widgets/_find'", False, id="a-string"),
    pytest.param("()", True, id="control-an-empty-literal"),
])
def test_1504_o3_an_adapter_without_a_readable_list_refuses_even_a_record_with_no_non_get_reads(
        tmp_path, reads_source, readable):
    """An adapter whose list is missing, not a literal, or a literal not of `(method, path)` text pairs: a record of it
    listing no non-GET read is refused at its system by the judgement, held as a ConfigFault by the run's record builder,
    and connect's validator fails a row naming the list; an empty literal list accepts the same record. (O3, O4)"""
    from defender.kit.faults import ConfigFault
    from defender.systems.run_tenant import record_settings

    checkout = X.plant_adapter(tmp_path / "checkout", "widget", reads=reads_source)
    catalog = rules("Catalog").of_checkout(checkout)
    for reads in ((), (("GET", "/widgets/*"), ("HEAD", "/widgets"))):
        records = _planted_record("widget", reads)
        faults = list(rules("judge_records")(records, None, catalog=catalog))
        access = record_settings(records, catalog=catalog)["access"]["widget"]
        if readable:
            assert faults == [], (reads, faults)
            assert not isinstance(access, ConfigFault), access
            continue
        assert faults, (reads_source, reads)
        assert all(RECORDS.system("widget") in f for f in faults), faults
        assert isinstance(access, ConfigFault), access
        assert RECORDS.system("widget") in str(access), str(access)
    failed, out = _validate_in(checkout, "widget")
    naming = [line for line in failed if X.READS_CONSTANT in line]
    assert bool(naming) is not readable, out


# --- #1504 A6.2: a list that is not usable is "no usable list", with its reason -------------------------------------------

def _unusable_params() -> list[Any]:
    return [pytest.param(source, needles, id=name) for name, source, needles in X.UNUSABLE_LISTS]


def _widget_catalog(tmp_path: Path, source: str | None) -> Any:
    return rules("Catalog").of_checkout(X.plant_adapter(tmp_path / "checkout", "widget", reads=source))


@pytest.mark.parametrize(("source", "needles"), _unusable_params())
def test_1504_a62_a_list_that_is_not_usable_reads_as_no_list_and_its_reason_names_each_offending_entry(
        tmp_path, source, needles):
    """A readable `READ_ROUTES` that is not usable (GET/HEAD, bad shape, repeat, non-pair): the entry has `reads is None`
    and a `reads_unusable` naming each offending entry. (A6.2)"""
    entry = _widget_catalog(tmp_path, source).entry("widget")
    assert getattr(entry, X.ENTRY_FIELD) is None
    reason = getattr(entry, X.UNUSABLE_FIELD)
    assert isinstance(reason, str), reason
    for needle in needles:
        assert needle in reason, (needle, reason)


@pytest.mark.parametrize(("source", "needles"), _unusable_params())
def test_1504_a62_a_record_of_an_adapter_with_an_unusable_list_is_refused_at_access_naming_the_route_not_unreadability(
        tmp_path, source, needles):
    """A record (listing no non-GET read, or one other route) of an adapter with an unusable list is refused at its access
    part with a fault naming the offending route and not saying the list is unreadable; the run's record builder holds
    the same fault. (A6.2, O3)"""
    from defender.kit.faults import ConfigFault
    from defender.systems.run_tenant import record_settings

    catalog = _widget_catalog(tmp_path, source)
    for reads in ((), (("POST", "/widgets/_fine_one"),)):
        records = _planted_record("widget", reads)
        faults = list(rules("judge_records")(records, None, catalog=catalog))
        assert faults, reads
        for needle in needles:
            naming = [f for f in faults if needle in f]
            assert naming, (needle, faults)
            assert all(RECORDS.part("widget", "access") in f for f in naming), naming
        assert not [f for f in faults if "without running" in f], faults
        held = record_settings(records, catalog=catalog)["access"]["widget"]
        assert isinstance(held, ConfigFault), held
        assert all(needle in str(held) for needle in needles), str(held)
        assert "without running" not in str(held), str(held)


@pytest.mark.parametrize("source", [pytest.param(s, id=name) for name, s in X.UNREADABLE_LISTS])
def test_1504_a62_an_absent_or_unreadable_list_has_no_reads_a_reason_and_a_refused_record(tmp_path, source):
    """An absent or computed list: `reads is None`, a `reads_unusable` reason present, and a record of it (even one
    listing no non-GET read) is refused at its access part with a fault naming that reason. (A6.2, O3 unchanged)"""
    catalog = _widget_catalog(tmp_path, source)
    entry = catalog.entry("widget")
    assert getattr(entry, X.ENTRY_FIELD) is None
    reason = getattr(entry, X.UNUSABLE_FIELD)
    assert isinstance(reason, str)
    assert reason.strip()
    faults = list(rules("judge_records")(_planted_record("widget", ()), None, catalog=catalog))
    assert [f for f in faults if reason in f and RECORDS.part("widget", "access") in f], (reason, faults)


def test_1504_a62_a_usable_list_reads_as_itself_with_no_reason_and_its_record_is_accepted(tmp_path):
    """Positive control: a usable literal (and `()`) reads as itself with `reads_unusable is None`, as do the checkout's
    own adapters; the matching record is accepted. (A6.2)"""
    for listed in ((WIDGET_ROUTE, ("PUT", "/widgets/*/mark")), ()):
        catalog = rules("Catalog").of_checkout(X.plant_adapter(tmp_path / f"w{len(listed)}", "widget", reads=repr(listed)))
        entry = catalog.entry("widget")
        assert tuple(getattr(entry, X.ENTRY_FIELD)) == listed
        assert getattr(entry, X.UNUSABLE_FIELD) is None
        assert list(rules("judge_records")(_planted_record("widget", listed), None, catalog=catalog)) == []
    own = _catalog()
    assert {a: getattr(own.entry(a), X.UNUSABLE_FIELD) for a in own.adapter_ids} == dict.fromkeys(own.adapter_ids)
