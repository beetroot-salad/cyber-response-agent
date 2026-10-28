"""#1214 Flow 4: host entry points proceed only for an `active` tenant read through `TenantDirectory` (P3, O4)."""
from __future__ import annotations

import contextlib
import io
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from defender.tests.tenancy.lifecycle_1214._support import LifecycleWorld  # noqa: E402


@pytest.fixture
def world(tmp_path, data_root):
    w = LifecycleWorld(tmp_path, data_root)
    yield w
    w.close()


def _run_start(tenant: str, directory, tmp_path: Path) -> str:
    """`run.main` up to its first refusal or fault; its text ("" if the run finished)."""
    from defender import run as run_py

    alert = tmp_path / "alert.json"
    alert.write_text('{"rule": {"id": "r-1214"}, "alert_timestamp": "2026-10-28T00:00:00Z"}', encoding="utf-8")
    err = io.StringIO()
    try:
        with contextlib.redirect_stderr(err):
            run_py.main([str(alert), "--tenant", tenant, "--no-learn"], directory=directory,
                        preflight=lambda *a, **k: 0, visualize=lambda *a, **k: None,
                        enqueue=lambda *a, **k: False, publish=lambda *a, **k: "",
                        lifecycle=lambda **k: {"output": "", "requests": 0, "truncated_by": None})
    except SystemExit as refused:
        return f"{refused.code}\n{err.getvalue()}"
    except Exception as failed:  # noqa: BLE001 — past acceptance, the next real refusal
        return f"{type(failed).__name__}: {failed}\n{err.getvalue()}"
    return ""


def _drain_start(tenant: str, directory) -> str:
    from defender.learning.core import cli

    err = io.StringIO()
    try:
        with contextlib.redirect_stderr(err):
            cli.main(["loop.py", "--author-drain", "--tenant", tenant], directory=directory)
    except SystemExit as refused:
        return f"{refused.code}\n{err.getvalue()}"
    except Exception as failed:  # noqa: BLE001 — past acceptance, the next real refusal
        return f"{type(failed).__name__}: {failed}\n{err.getvalue()}"
    return ""


def test_run_start_refuses_a_tenant_being_offboarded_and_names_its_state(world, tmp_path):
    """Run start reads the state from PostgreSQL: `offboarding` is refused, naming it (Flow 4, P3)."""
    tenant = world.active_tenant()
    control = _run_start(tenant, world.directory(), tmp_path)
    assert "offboarding" not in control and "not active" not in control, control
    assert world.ops.post(f"/admin/tenants/{tenant}/offboard").status_code == 202
    refused = _run_start(tenant, world.directory(), tmp_path)
    assert "[run.py]" in refused and tenant in refused and "offboarding" in refused, refused


def test_drain_start_refuses_a_tenant_that_is_still_being_created(world):
    """Drain start refuses a `creating` tenant, naming its state; an active one passes that check (Flow 4, P3)."""
    creating = world.create()
    refused = _drain_start(creating, world.directory())
    assert "creating" in refused and creating in refused, refused
    active = world.active_tenant()
    control = _drain_start(active, world.directory())
    assert "creating" not in control and "not active" not in control, control


def test_the_directory_answers_the_state_and_nothing_for_an_unknown_tenant(world):
    """`TenantDirectory.state` is the row's state, `None` for no row; it refuses inside a running loop (Flow 4)."""
    tenant = world.create()
    directory = world.directory()
    assert directory.state(tenant) == "creating"
    assert directory.state("00000000-0000-4000-8000-000000000000") is None

    async def inside_a_loop() -> None:
        directory.state(tenant)
    with pytest.raises(RuntimeError):
        world.call(inside_a_loop)
