from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

import pytest

from defender import run_common
from defender.records._run_id import is_valid_run_id
from defender.run_repository import RunId, RunPaths
from defender.box import container_name
from defender.tests.support.shared.contracts._data_root_1078 import set_up_tenant
from defender.tests.storage.ids_1187 import _spec1187 as S
from defender.tests.support.shared._fixture_uuid import fixture_uuid

TENANT_ID = fixture_uuid("tenant:t658")


def _set_up_tenant(tmp_path, monkeypatch):
    """A fresh, accepted tenant under its own data root — every run names its tenant, and there"""
    data_root = tmp_path / "data"
    monkeypatch.setenv("DEFENDER_DATA_ROOT", str(data_root))
    return set_up_tenant(data_root, TENANT_ID)


VALID_RUN_IDS = (
    "a",
    "9",
    "run-123",
    "a_1",
    "a.b",
    "a..b",
)

INVALID_RUN_IDS = (
    "",
    ".",
    "..",
    "_leading",
    "-leading",
    "run/id",
    r"run\id",
    "../escape",
    "run:id",
    "run id",
    "run\nid",
    "rún",
    "bad\x00id",
)


@pytest.mark.parametrize("run_id", VALID_RUN_IDS)
def test_run_id_slug_accepts_the_container_name_grammar(run_id):
    assert is_valid_run_id(run_id)
    assert container_name(run_id) == f"defender-run-{run_id}"


@pytest.mark.parametrize("run_id", INVALID_RUN_IDS)
def test_run_id_slug_rejects_values_outside_the_container_name_grammar(run_id):
    assert not is_valid_run_id(run_id)
    with pytest.raises(ValueError, match="cannot name a container"):
        container_name(run_id)


@pytest.mark.parametrize("extra", ["positional", "run_id", "pinned"])
def test_materialize_takes_no_run_id_and_writes_nothing_for_one(tmp_path, monkeypatch, extra):
    """#1279 A3 (conflict updated): run setup is handed no id, so the old "refuse an invalid
    explicit id before writing" cases (invalid slug, mixed case, absolute path, `../escape`) are
    unrepresentable. What is left of their point: an id offered in any form is refused before
    anything is written."""
    alert = tmp_path / "fixture.json"
    alert.write_text("{}\n", encoding="utf-8")
    tenant = _set_up_tenant(tmp_path, monkeypatch)
    runs_base = location_path(tenant.runs)

    args, kwargs = {"positional": ((S.SAMPLE_UUID,), {}),
                    "run_id": ((), {"run_id": S.SAMPLE_UUID}),
                    "pinned": ((), {"pinned": True})}[extra]
    with pytest.raises(TypeError):
        run_common.materialize_run(alert, *args, tenant=tenant, **kwargs)

    assert not runs_base.exists()


def test_materialize_mints_a_canonical_run_id_inside_the_runs_base(tmp_path, monkeypatch):
    """#1279 A3 (conflict updated from `test_materialize_accepts_a_valid_run_id` and the
    mixed-case test's tail): the id is the system's own mint — canonical lowercase UUID text,
    different per call, the run dir directly under the runs base with only setup's entries."""
    alert = tmp_path / "fixture.json"
    alert.write_text("{}\n", encoding="utf-8")
    tenant = _set_up_tenant(tmp_path, monkeypatch)
    runs_base = location_path(tenant.runs)

    first = run_common.materialize_run(alert, tenant=tenant).run_dir
    second = run_common.materialize_run(alert, tenant=tenant).run_dir

    assert first != second
    for run_dir in (first, second):
        assert run_dir.parent == runs_base
        assert is_valid_run_id(run_dir.name)
        assert run_dir.name == run_dir.name.casefold()
        assert str(RunId.parse(run_dir.name)) == run_dir.name
        rp = RunPaths(run_dir)
        assert sorted(path.name for path in run_dir.iterdir()) == sorted(
            p.name for p in (rp.alert_input_dir, rp.gather_raw, rp.provenance)
        )
