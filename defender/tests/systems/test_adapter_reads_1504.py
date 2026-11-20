"""#1504: a catalog adapter declares the non-GET reads it sends and the catalog reads them cold (O1); connect's
validator prints them given only the system (O4). The record judgement's cases are folded into their neighbours."""
from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path


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


# --- O2: a record's reads must be exactly its adapter's ---------------------------------------------------------------

# --- O3: connect's validator prints the reads given only the system --------------------------------------------------

def _validate(*args: str) -> str:
    done = subprocess.run([sys.executable, "-m", "defender.skills.connect.validate_scaffold", *args], cwd=REPO,
                          env={**os.environ, "PYTHONPATH": str(REPO)}, capture_output=True, text=True, timeout=120,
                          check=False)
    out = done.stdout + done.stderr
    assert "Traceback" not in out, out
    return out


def test_1504_o3_the_validator_prints_an_adapters_reads_given_only_the_system():
    """Before `access.yaml` exists: `validate_scaffold elastic` with no folder prints each declared read (relative to
    the base), so the agent can write them. (O3; the run's other rows, e.g. the unstaged tenant half, are not judged)"""
    out = _validate("elastic")
    rows = [line for line in out.splitlines() if all(X.shown(r) in line for r in X.ELASTIC_READS)]
    assert rows, out
