"""Connect's validator over its handoff (#1366 O11): the folder connect hands the operator (`config.env` +
`access.yaml`, the folder `set-system` takes) is judged by the same settings and access judgement the store applies,
with no tenant and no database. Replaces the retired `check_config` over a tenant's `settings/systems/<s>/config.env`
(connect writes no such folder now; its secret-name rule is `lint_catalog_declarations`, K8)."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from defender.tests.support.jobs._jobs1342 import register_tenant
from defender.tests.support.shared._postgres1339 import migrated_database  # noqa: F401 — the fixture
from defender.tests.support.tenancy import _handoff1366 as H
from defender.tests.support.tenancy import _systems1366 as R
from defender.tests.tenancy.tenant_1108_p4._support import published_tenant

REPO = Path(__file__).resolve().parents[4]
CMDB_CONFIG, CMDB_ACCESS = R.FIXTURE_FOLDERS["cmdb"]
#: Keys cmdb's adapter does not read: an access method, a docker context, an unknown one, a secret-named one.
UNDECLARED = ["CMDB_TRANSPORT", "CMDB_DOCKER_CONTEXT", "CMDB_COLOUR", "CMDB_API_TOKEN"]
#: An access declaration `parse_access` refuses (an unknown top-level key).
BAD_ACCESS = R.declaration("http://soc-playground:8001").replace('"reads"', '"colour": "red",\n  "reads"')


def _validated(folder: Path, system: str = "cmdb") -> str:
    """The real validator over a handoff folder, as a process, with no tenant and no database in its environment."""
    env = {k: v for k, v in os.environ.items() if k not in ("DEFENDER_DATA_ROOT", "DEFENDER_DATABASE_DSN")}
    env["PYTHONPATH"] = str(REPO)
    done = subprocess.run([sys.executable, "-m", "defender.skills.connect.validate_scaffold", system,
                           "--handoff", str(folder)], cwd=REPO, env=env, capture_output=True, text=True,
                          timeout=120, check=False)
    return done.stdout + done.stderr


def _folder(where: Path, *, config: dict[str, str] | None = None, access: str | None = None) -> Path:
    return R.system_folder(where, "cmdb", config=CMDB_CONFIG if config is None else config,
                           access=CMDB_ACCESS if access is None else access)


def test_o11_the_handoff_is_judged_by_the_stores_settings_rules_without_a_tenant(tmp_path):
    """Every undeclared key (an access method, a docker context, a secret-named key) is named; the clean folder names
    none of them. (#1366 O11, K1)"""
    clean = _validated(_folder(tmp_path / "clean"))
    assert "validate_scaffold: cmdb" in clean, clean  # printed only once the arguments were accepted
    for key in UNDECLARED:
        assert key not in clean, (key, clean)
        said = _validated(_folder(tmp_path / key, config={**CMDB_CONFIG, key: "x"}))
        assert key in said, (key, said)


@pytest.mark.parametrize("access", [BAD_ACCESS, "access: [unclosed\n"], ids=["unknown-key", "unparsable"])
def test_o11_the_handoffs_access_is_judged_too(tmp_path, access):
    """An access declaration `parse_access` refuses changes the validator's report and fails a row about the access;
    the clean declaration fails none. (#1366 O11)"""
    def failed_access_rows(text: str) -> list[str]:
        return [ln for ln in text.splitlines() if "access" in ln.lower() and "✗" in ln]

    clean = _validated(_folder(tmp_path / "clean"))
    said = _validated(_folder(tmp_path / "bad", access=access))
    assert failed_access_rows(clean) == [], clean
    assert failed_access_rows(said), said


@pytest.mark.postgres
def test_o11_the_handoffs_access_fault_is_the_stores_sentence_located_by_the_file(
        migrated_database, tmp_path, data_root, capsys, monkeypatch):  # noqa: F811
    """The store's access fault sentence appears in the validator's report, located by the file. (#1366 O11, DC6)"""
    monkeypatch.setenv("DEFENDER_DATABASE_DSN", migrated_database)
    with published_tenant(tmp_path / "forge", root=data_root, files=R.import_files()) as t:
        register_tenant(migrated_database, t.tenant_id, data_root=t.data_root, records=None)
        op = R.Operator(t.tenant_id, migrated_database, tmp_path / "op", capsys)
        rc, said = op.import_()
        assert rc == 0, said
        rc, said = op.set_system("cmdb", replaces=1, config=CMDB_CONFIG, access=BAD_ACCESS)
    assert rc != 0, said
    (fault,) = [line.removeprefix("[tenant.py] ").strip() for line in R.lines_naming(said, "colour")]
    sentence = H.store_sentence(fault, "cmdb", "access")
    report = _validated(_folder(tmp_path / "handoff", access=BAD_ACCESS))
    assert any(sentence in line for line in H.handoff_lines(report, "colour", "cmdb", "access")), (sentence, report)
