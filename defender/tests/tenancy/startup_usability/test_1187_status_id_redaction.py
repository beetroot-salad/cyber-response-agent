"""Startup and escaped-fault status reasons hide only identities the host knows."""
from pathlib import Path

import pytest

from defender.runtime import system_status as status
from defender.runtime.run_state import RunState
from defender.runtime.verbs import read_roster
from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S

KNOWN = "0b5c7e2a-4d1f-4a8e-9c3b-2f6d8e1a7c40"
UNKNOWN = "7e3a9c1f-5b2d-4e8a-a6c4-3d1f9b7e5a20"
FAULT = f"unavailable branch {KNOWN}; external request {UNKNOWN}"
SAFE = f"unavailable branch [a run id]; external request {UNKNOWN}"
_TABLE = """\
dispositions:
  cmdb:
    get-host: {roles: [gather]}
    health-check: {roles: [gather]}
"""


@pytest.mark.parametrize(("known", "expected"), [(frozenset({KNOWN}), SAFE), (frozenset(), FAULT)])
def test_reason_scope_keeps_unknown_uuids(known, expected):
    assert status.ReasonScope(known_ids=known).reason(FAULT) == expected


@pytest.mark.parametrize("held_start", [False, True])
def test_escaped_status_views_keep_the_runs_known_id_scope(tmp_path: Path, held_start: bool):
    """Both a normal startup verdict and the standalone fallback reach live status views."""
    state = RunState(tmp_path, UNKNOWN)
    if held_start:
        status.hold_at_start(state, status.RunSystems(
            roster=read_roster(tmp_path), down={},
            scope=status.ReasonScope(known_ids=frozenset({KNOWN}))))
        # The held scope remains authoritative even when the later caller knows none.
        status.mark_escaped(state, "cmdb", FAULT)
    else:
        status.mark_escaped(state, "cmdb", FAULT, known_ids={KNOWN})

    cause = status.down_cause(state, "cmdb")
    assert isinstance(cause, status.NotConfigured)
    assert status.cause_text(cause) == f"not configured: {SAFE}"
    assert status.down_notes(state, ["cmdb"]) == {"cmdb": f"not configured: {SAFE}"}


def test_natural_run_escaped_reason_keeps_ordinary_uuids(tmp_path: Path):
    state = RunState(tmp_path, UNKNOWN)
    status.mark_escaped(state, "cmdb", FAULT)
    assert status.down_notes(state, ["cmdb"]) == {"cmdb": f"not configured: {FAULT}"}


def test_startup_adapter_failure_hides_known_ids_in_status_views(tmp_path: Path, data_root):
    """Drive a real adapter settings failure through startup judgement and its live views."""
    S.plant(data_root, table=_TABLE)
    adapters = tmp_path / "adapters"
    adapters.mkdir()
    (adapters / "cmdb_adapter.py").write_text(
        "from defender.integrations.faults import ConfigFault\n"
        f"def check_settings(tenant):\n    raise ConfigFault({FAULT!r})\n"
        "def get_host(ctx, *, host):\n    return {}\n"
        "VERBS = {'get-host': get_host}\n", encoding="utf-8")
    systems = status.judge_run(read_roster(adapters), S.resolve(data_root),
                               defender_dir=S.DEFENDER, known_ids={KNOWN})
    state = RunState(tmp_path / "run", UNKNOWN)
    status.hold_at_start(state, systems)
    assert status.down_notes(state, ["cmdb"]) == {"cmdb": f"not configured: {SAFE}"}
