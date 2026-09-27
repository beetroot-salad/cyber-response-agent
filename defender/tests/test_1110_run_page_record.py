"""#1110 — the run page is a run record; the local copy is a dev-only extra. Unit half.

Two things live here, both cheap (no driven run):

- O6, the deployment setting itself: `_env.deployment()` reads `DEFENDER_DEPLOYMENT` at call
  time, answers `dev` or `production`, treats unset/empty as `production`, and treats anything
  else as `production` WITH one logged ERROR per read naming the variable, the value and the
  choices — never raising (the `DEFENDER_LOG_FORMAT` never-fatal precedent).
- The hand-off in `run.py main` (O1, O7): the post-run render step is handed the run's
  TENANT-BOUND handle — the one the real builder materialized — and a `VisualizeFailed` out of
  it leaves the run's exit code at 0. Driven through `_spec791`'s tail seam over the real
  entrypoint, with the real builder.

The end-to-end half (a real rendered run, the handle's `io` seam, the copy, the snapshot) is
`tests/e2e/test_1110_run_page_record_e2e.py`.

The names under test are imported inside each test, so this file collects against a tree that
does not have them yet.
"""
from __future__ import annotations

import logging
from typing import Any

import pytest

from defender import run as run_py
from defender.tests._spec791 import (
    SpecTail,
    drive_tail,
    loop_paths,
    plant_alert,
    satisfy_entrypoint_keys,
)

DEPLOYMENT_ENV = "DEFENDER_DEPLOYMENT"


def _deployment() -> str:
    from defender import _env

    return _env.deployment()


def _deployment_logs(caplog, level: int) -> list[str]:
    """Every record at exactly `level` that names the setting — filtered by content rather
    than by logger name, which the design does not fix."""
    return [r.getMessage() for r in caplog.records
            if r.levelno == level and DEPLOYMENT_ENV in r.getMessage()]


# ---------------------------------------------------------------------------------------
# O6 — the setting: two values, production by default, a typo is loud and never fatal
# ---------------------------------------------------------------------------------------


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
    monkeypatch.setenv(DEPLOYMENT_ENV, raw)
    caplog.set_level(logging.DEBUG)
    assert _deployment() == expected
    assert _deployment_logs(caplog, logging.ERROR) == [], (
        f"a recognised value {raw!r} was logged as an error")


@pytest.mark.parametrize("typo", [
    "staging", "prdo", "QA-Box", "true",
    # Near-misses of the two values: EXACT values only. A prefix alias (`startswith("dev")`)
    # would turn the copy on for `development`/`dev2`/`devbox`; a `startswith("prod")` one
    # would answer `prod`/`prodution` correctly but SILENTLY — and the typo must be loud.
    "development", "dev2", "devbox", "prod", "prodution",
])
def test_1110_o6_an_unrecognised_value_is_production_with_one_error_naming_it(
        monkeypatch, caplog, typo):
    """O6: anything else is treated as `production` — never `dev` (a typo must not turn the
    copy on), never a raise (a typo must not abort the run) — and is logged as exactly ONE
    error per read, naming the variable, the value it saw, and the choices it accepts. The two
    recognised values are exact: a value that merely starts like one is still a typo."""
    monkeypatch.setenv(DEPLOYMENT_ENV, typo)
    caplog.set_level(logging.DEBUG)

    assert _deployment() == "production"

    errors = _deployment_logs(caplog, logging.ERROR)
    assert len(errors) == 1, f"expected one error naming {DEPLOYMENT_ENV}; got {errors!r}"
    (message,) = errors
    assert typo.lower() in message.lower(), f"the error does not name the value {typo!r}: {message!r}"
    assert "dev" in message, f"the error does not name the choice 'dev': {message!r}"
    assert "production" in message, f"the error does not name the choice 'production': {message!r}"


def test_1110_o6_the_error_is_logged_on_every_read_not_once(monkeypatch, caplog):
    """O6: 'logged as an error on each read' — two reads, two errors. A once-per-process
    latch would hide the typo from every run after the first in a long-lived worker."""
    monkeypatch.setenv(DEPLOYMENT_ENV, "staging")
    caplog.set_level(logging.DEBUG)

    assert [_deployment(), _deployment()] == ["production", "production"]
    assert len(_deployment_logs(caplog, logging.ERROR)) == 2


def test_1110_o6_the_setting_is_read_at_call_time(monkeypatch):
    """M4: read when asked, not frozen at import — the same process answers `dev`, then
    `production`, as the environment changes under it (which is also what lets a test's
    `setenv` reach a module it already imported)."""
    monkeypatch.setenv(DEPLOYMENT_ENV, "dev")
    assert _deployment() == "dev"
    monkeypatch.setenv(DEPLOYMENT_ENV, "production")
    assert _deployment() == "production"
    monkeypatch.delenv(DEPLOYMENT_ENV)
    assert _deployment() == "production"


# ---------------------------------------------------------------------------------------
# O1 / O7 — `run.py main` hands the render step the tenant-bound handle; its failure is not
# the run's
# ---------------------------------------------------------------------------------------


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

    def visualize(self, run: Any) -> None:
        from defender import run_common

        super().visualize(run)
        raise run_common.VisualizeFailed(f"page for {run.run_dir} not rendered (#1110 O7)")


def test_1110_o1_main_hands_the_render_step_the_tenant_bound_handle_it_materialized(
        tmp_path, state):
    """O1 (the hand-off half): the real entrypoint, with the real builder, hands its render
    step the run's TENANT-BOUND handle — the run dir the lifecycle ran in, under the configured
    runs base, carrying the tenant the runs base's tenant record names. Not a bare path, and
    not a `Run.at` over the directory (which has no tenant and no runs base): the page is a
    record of THIS tenant's run, saved through the handle the platform's store backend sits
    behind."""
    from defender import _tenant, run_common

    tail = SpecTail(state)
    assert drive_tail(run_py.main, plant_alert(tmp_path / "o1"), tail, "--no-learn") == 0

    assert len(tail.visualized) == 1, f"the render step ran {len(tail.visualized)} times"
    (run,) = tail.visualized
    runs_base = run_common.resolve_runs_base()
    assert tail.run_dirs == [run.run_dir], (
        "the render step was handed a handle over a different run dir than the lifecycle's")
    assert run.runs_base == runs_base, "the handle is not bound to the configured runs base"
    assert run.tenant_id == _tenant.read_tenant(runs_base).tenant_id, (
        "the handle does not carry the tenant the runs base's tenant record names")
    assert run.observability.runtime_html.path == run.run_dir / "runtime.html"


def test_1110_o7_a_failed_render_step_leaves_the_exit_code_at_0(tmp_path, state, capfd):
    """O7 (the seam half): a render step that raises `VisualizeFailed` does not change the
    run's exit code — the investigation succeeded; its page did not. The failure is reported
    on stderr rather than swallowed.

    Positive control: the render step was reached and handed the run (the raise happened), so
    the 0 is not a run that never got that far. The genuine-crash half — a real renderer
    exception surfacing as `VisualizeFailed` through the real step — is in the e2e module."""
    tail = _FailingRender(state)
    rc = drive_tail(run_py.main, plant_alert(tmp_path / "o7"), tail, "--no-learn")

    assert rc == 0
    assert len(tail.visualized) == 1, (
        f"the render step was never reached (ran {tail.names}) — the 0 proves nothing")
    err = capfd.readouterr().err
    assert "not rendered (#1110 O7)" in err, "the failed render was not reported on stderr"
