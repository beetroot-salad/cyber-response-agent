"""Startup checks follow gather permissions and refuse missing adapter references."""
from pathlib import Path

import pytest

from defender.systems import system_status
from defender.systems.verb_grant import GrantError
from defender.systems.verbs import read_roster
from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S

_TABLE = """\
dispositions:
  cmdb:
    get-host: {roles: [gather]}
    health-check: {roles: [gather]}
"""


def _roster(tmp_path: Path):
    adapters = tmp_path / "adapters"
    adapters.mkdir()
    probe = tmp_path / "checks"
    for system in ("cmdb", "identity"):
        (adapters / f"{system}_adapter.py").write_text(
            f"def check_settings(tenant):\n"
            f"    with open({str(probe)!r}, 'a') as out:\n"
            f"        out.write({system!r} + '\\n')\n"
            "def get_host(ctx, *, host: str):\n    return {}\n"
            "VERBS = {'get-host': get_host}\n", encoding="utf-8")
    return read_roster(adapters), probe


def test_a_missing_granted_system_refuses_before_checks_or_run_creation(tmp_path, data_root):
    table = _TABLE + "  absent-system:\n    lookup: {roles: [gather]}\n    health-check: {roles: [gather]}\n"
    S.plant(data_root, table=table)
    tenant = S.resolve(data_root)
    roster, probe = _roster(tmp_path)
    with pytest.raises(GrantError) as invalid:
        system_status.judge_run(roster, tenant, defender_dir=S.DEFENDER)
    assert "absent-system" in str(invalid.value)
    assert tenant.table_pointer in str(invalid.value)
    assert not probe.exists(), "an adapter check ran before the invalid grant was refused"

    rec = S.RunRecorder(tmp_path / "run")
    alert = S.plant_alert(tmp_path / "alert.json")
    rc, refused = S.drive_run(S.run_argv(alert, data_root), rec, roster=roster)
    assert rc is None
    assert isinstance(refused, SystemExit)
    assert refused.code != 0
    assert "absent-system" in str(refused)
    assert tenant.table_pointer in str(refused)
    assert rec.order == [], "startup reached preflight, run creation or lifecycle"
    assert not rec.run_dir_at.exists()
    assert not probe.exists()


def test_an_ungranted_adapter_is_not_checked(tmp_path, data_root):
    S.plant(data_root, table=_TABLE)
    roster, probe = _roster(tmp_path)
    systems = system_status.judge_run(roster, S.resolve(data_root), defender_dir=S.DEFENDER)
    assert probe.read_text(encoding="utf-8").splitlines() == ["cmdb"]
    assert not systems.down
