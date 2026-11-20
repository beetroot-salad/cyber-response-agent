"""#1504: a catalog adapter declares the non-GET reads it sends and the catalog reads them cold (O1); connect's
validator prints them given only the system (O4). The record judgement's cases are folded into their neighbours."""
from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Any


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
