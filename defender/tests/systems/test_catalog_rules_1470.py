"""#1470 D-E, D8, D11: the record rules sit below `systems`; the catalog keeps an adapter that failed to load as data; each
catalog adapter declares sample settings its own check accepts."""
from __future__ import annotations

import ast
from typing import Any
import textwrap
from pathlib import Path

import pytest

from defender.tests.support.tenancy import _systems1366 as R
from defender.tests.systems._rules1470 import rules

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
        record = SystemRecord(system_id=adapter, version=1, adapter_id=adapter, settings=sample,
                              access=R.declaration(f"https://{adapter}.example.test"))
        assert list(judge(TenantRecords(systems={adapter: record}), None, catalog=catalog)) == [], adapter


def _broken_checkout(root: Path, counter: Path) -> Path:
    """A checkout whose `integrations/` holds one adapter that fails when imported, and notes each import in `counter`."""
    folder = root / "integrations"
    folder.mkdir(parents=True)
    (folder / "broken_adapter.py").write_text(textwrap.dedent(f'''\
        """An adapter whose import fails."""
        PREFIX = "BROKEN"
        REQUIRED_CONFIG_KEYS = ("TIMEOUT_SEC",)
        DISPLAY_NAME = "Broken"
        EXAMPLE = False
        with open({str(counter)!r}, "a") as noted:
            noted.write("x")
        raise RuntimeError("the adapter failed on import 1470")
        '''))
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
