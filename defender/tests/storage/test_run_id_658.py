from __future__ import annotations

import pytest

from defender import run_common
from defender._run_id import is_valid_run_id
from defender.run_repository import RunPaths
from defender.box import container_name
from defender.tests.support.shared.contracts._data_root_1078 import set_up_tenant

TENANT_ID = "t658"


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

MIXED_CASE_RUN_IDS = ("A_1", "Run-123", "20260101T000000Z-solo")

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


@pytest.mark.parametrize("run_id", INVALID_RUN_IDS)
def test_materialize_rejects_an_invalid_explicit_run_id_before_writing(
    tmp_path, monkeypatch, run_id
):
    alert = tmp_path / "fixture.json"
    alert.write_text("{}\n", encoding="utf-8")
    tenant = _set_up_tenant(tmp_path, monkeypatch)
    runs_base = tenant.runs

    with pytest.raises(SystemExit, match="invalid run id"):
        run_common.materialize_run(alert, run_id, tenant=tenant)

    assert not runs_base.exists()


@pytest.mark.parametrize("run_id", MIXED_CASE_RUN_IDS)
def test_run_id_slug_accepts_mixed_case_and_materialize_refuses_it(tmp_path, monkeypatch, run_id):
    """The slug grammar is case-blind (a container name may carry either case); the run"""
    assert is_valid_run_id(run_id)
    alert = tmp_path / "fixture.json"
    alert.write_text("{}\n", encoding="utf-8")
    tenant = _set_up_tenant(tmp_path, monkeypatch)
    runs_base = tenant.runs

    with pytest.raises(SystemExit, match="invalid run id.*case-stable"):
        run_common.materialize_run(alert, run_id, tenant=tenant)
    assert not runs_base.exists()
    # The host's own mint never produces what its admission refuses.
    from defender._run_id import mint_run_id
    minted = mint_run_id("Fixture-Alert")
    assert minted == minted.casefold()
    assert run_common.materialize_run(
        alert, minted, tenant=tenant).run_dir == runs_base / minted


@pytest.mark.parametrize("run_id", VALID_RUN_IDS)
def test_materialize_accepts_a_valid_run_id(tmp_path, monkeypatch, run_id):
    alert = tmp_path / "fixture.json"
    alert.write_text("{}\n", encoding="utf-8")
    tenant = _set_up_tenant(tmp_path, monkeypatch)
    runs_base = tenant.runs

    run_dir = run_common.materialize_run(alert, run_id, tenant=tenant).run_dir

    assert run_dir == runs_base / run_id
    rp = RunPaths(run_dir)
    assert sorted(path.name for path in run_dir.iterdir()) == sorted(
        p.name for p in (rp.alert_input_dir, rp.gather_raw, rp.provenance)
    )


@pytest.mark.parametrize("kind", [("absolute",), ("traversal",)])
def test_materialize_cannot_create_a_run_outside_the_runs_base(tmp_path, monkeypatch, kind):
    alert = tmp_path / "fixture.json"
    alert.write_text("{}\n", encoding="utf-8")
    outside = tmp_path / "escape"
    run_id = str(outside) if kind == "absolute" else "../escape"
    tenant = _set_up_tenant(tmp_path, monkeypatch)
    runs_base = tenant.runs

    with pytest.raises(SystemExit, match="invalid run id"):
        run_common.materialize_run(alert, run_id, tenant=tenant)

    assert not runs_base.exists()
    assert not outside.exists()
