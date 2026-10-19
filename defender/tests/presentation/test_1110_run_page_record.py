"""DEFENDER_DEPLOYMENT setting and the run.py render-step hand-off (tenant-bound handle; a failed render leaves exit 0)."""
from __future__ import annotations

import logging
from typing import Any

import pytest

from defender.configuration import _env
from defender import run as run_py
from defender.tests.support.sandbox._spec791 import (
    SpecTail,
    drive_tail,
    loop_paths,
    plant_alert,
    satisfy_entrypoint_keys,
)


def _deployment() -> str:
    from defender.configuration import _env

    return _env.deployment()


def _deployment_logs(caplog, level: int) -> list[str]:
    """Every record at exactly `level` that names the setting — filtered by content rather
    than by logger name, which the design does not fix."""
    return [r.getMessage() for r in caplog.records
            if r.levelno == level and _env.DEPLOYMENT_ENV in r.getMessage()]


def test_1110_o6_unset_is_production_and_logs_nothing(caplog):
    """O6/M4: unset → `production`, silently. Unset is the documented default (a worker that
    missed the variable must not write copies into itself), not a typo."""
    caplog.set_level(logging.DEBUG)
    assert _deployment() == "production"
    assert [r for r in caplog.records if r.levelno >= logging.WARNING] == []


@pytest.mark.parametrize(("raw", "expected"), [
    ("", "production"),
    ("dev", "dev"),
    (" DEV ", "dev"),
    ("Dev", "dev"),
    ("production", "production"),
    (" Production\n", "production"),
])
def test_1110_o6_a_recognised_value_is_read_stripped_and_lowercased_and_logs_nothing(
        monkeypatch, caplog, raw, expected):
    """O6/M4: the two values, stripped and lowercased; empty is unset. None of them is an
    error — the positive control for the typo case below, on the same logger capture."""
    monkeypatch.setenv(_env.DEPLOYMENT_ENV, raw)
    caplog.set_level(logging.DEBUG)
    assert _deployment() == expected
    assert _deployment_logs(caplog, logging.ERROR) == [], (
        f"a recognised value {raw!r} was logged as an error")


@pytest.mark.parametrize("typo", [
    "staging", "prdo", "QA-Box", "true",
    "development", "dev2", "devbox", "prod", "prodution",
])
def test_1110_o6_an_unrecognised_value_is_production_with_one_error_naming_it(
        monkeypatch, caplog, typo):
    monkeypatch.setenv(_env.DEPLOYMENT_ENV, typo)
    caplog.set_level(logging.DEBUG)

    assert _deployment() == "production"

    errors = _deployment_logs(caplog, logging.ERROR)
    assert len(errors) == 1, f"expected one error naming {_env.DEPLOYMENT_ENV}; got {errors!r}"
    (message,) = errors
    assert typo.lower() in message.lower(), f"the error does not name the value {typo!r}: {message!r}"
    assert "dev" in message, f"the error does not name the choice 'dev': {message!r}"
    assert "production" in message, f"the error does not name the choice 'production': {message!r}"


@pytest.fixture
def state(tmp_path, monkeypatch):
    """A learning state root and a runs base under tmp, and a key per provider, so the
    entrypoint's startup preflight cannot fail ahead of the tail these demands are about."""
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(tmp_path / "state"))
    satisfy_entrypoint_keys(monkeypatch, tmp_path)
    return loop_paths(tmp_path)


class _FailingRender(SpecTail):
    """The tail, with a render step that records what it was handed and then fails the way
    the real step reports a failed render."""

    def visualize(self, run: Any, *, update_ticket: bool = False) -> None:
        from defender import run_common

        super().visualize(run, update_ticket=update_ticket)
        raise run_common.VisualizeFailed(f"page for {run.run_dir} not rendered (#1110 O7)")


def test_1110_o1_main_hands_the_render_step_the_tenant_bound_handle_it_materialized(
        tmp_path, state):
    from defender.tenancy import _tenant
    from defender.tests.support.shared.contracts._data_root_1078 import current_data_root
    from defender.tests.support.tenancy._tenants1106 import accept

    tail = SpecTail(state)
    assert drive_tail(run_py.main, plant_alert(tmp_path / "o1"), tail, "--no-learn") == 0

    assert len(tail.visualized) == 1, f"the render step ran {len(tail.visualized)} times"
    (run,) = tail.visualized
    runs_base = _tenant.runs_base_for(accept(current_data_root(), run.tenant_id))
    assert tail.run_dirs == [run.run_dir], (
        "the render step was handed a handle over a different run dir than the lifecycle's")
    assert run.runs_base == runs_base, "the handle is not bound to the configured runs base"
    assert run.tenant_id == _tenant.read_tenant(runs_base).tenant_id, (
        "the handle does not carry the tenant the runs base's tenant record names")
    assert run.observability.runtime_html.path == run.run_dir / "runtime.html"


def test_1110_o7_a_failed_render_step_leaves_the_exit_code_at_0(tmp_path, state, capfd):
    tail = _FailingRender(state)
    rc = drive_tail(run_py.main, plant_alert(tmp_path / "o7"), tail, "--no-learn")

    assert rc == 0
    assert len(tail.visualized) == 1, (
        f"the render step was never reached (ran {tail.names}) — the 0 proves nothing")
    err = capfd.readouterr().err
    assert "not rendered (#1110 O7)" in err, "the failed render was not reported on stderr"
