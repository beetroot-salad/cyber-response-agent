"""DEFENDER_DEPLOYMENT setting and the run.py render-step hand-off (tenant-bound handle; a failed render leaves exit 0)."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

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
    """Unset → `production`, silently. Unset is the documented default (a worker that
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
    """The two values, stripped and lowercased; empty is unset. None of them is an
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
    satisfy_entrypoint_keys(monkeypatch, tmp_path)
    return loop_paths(tmp_path)


class _FailingRender(SpecTail):
    """The tail, with a render step that records what it was handed and then fails the way
    the real step reports a failed render."""

    def visualize(self, run: Any, *, tenant: Any, update_ticket: bool = False) -> None:
        from defender import run_common

        super().visualize(run, update_ticket=update_ticket)
        raise run_common.VisualizeFailed(f"page for {run.run_dir} not rendered (#1110 O7)")


def test_1110_o1_main_hands_the_render_step_the_tenant_bound_handle_it_materialized(
        tmp_path, state):
    from defender.tests.support.shared.contracts._data_root_1078 import current_data_root
    from defender.tests.support.tenancy._tenants1106 import accept

    tail = SpecTail(state)
    assert drive_tail(run_py.main, plant_alert(tmp_path / "o1"), tail, "--no-learn") == 0

    assert len(tail.visualized) == 1, f"the render step ran {len(tail.visualized)} times"
    (run,) = tail.visualized
    runs_base = location_path(accept(current_data_root(), run.tenant_id).runs)
    assert tail.run_dirs == [run.run_dir], (
        "the render step was handed a handle over a different run dir than the lifecycle's")
    assert location_path(run.runs_base) == runs_base, "the handle is not bound to the configured runs base"
    assert run.tenant_id == runs_base.parent.name, (
        "the handle does not carry the tenant whose runs folder holds the run")
    assert run.observability.runtime_html.path == run.run_dir / "runtime.html"


class _TenantRecording(SpecTail):
    """The tail, noting the tenant the render step is handed beside the run."""

    def __init__(self, *a: Any, **kw: Any) -> None:
        super().__init__(*a, **kw)
        self.visualize_tenants: list[Any] = []

    def visualize(self, run: Any, *, tenant: Any, update_ticket: bool = False) -> None:
        self.visualize_tenants.append(tenant)
        super().visualize(run, update_ticket=update_ticket)


def test_1279_a4_main_hands_the_render_step_the_tenant_it_accepted(tmp_path, state):
    """run.py's accepted `Tenant` rides the visualize seam; nothing downstream accepts it again."""
    from defender.tests.support.shared.contracts._data_root_1078 import current_data_root
    from defender.tests.support.tenancy._tenants1106 import accept

    tail = _TenantRecording(state)
    assert drive_tail(run_py.main, plant_alert(tmp_path / "a4"), tail, "--no-learn") == 0

    (run,) = tail.visualized
    (tenant,) = tail.visualize_tenants
    assert tenant == accept(current_data_root(), run.tenant_id), (
        "the render step was not handed the tenant run.py accepted for this run")


def test_1110_o7_a_failed_render_step_leaves_the_exit_code_at_0(tmp_path, state, capfd):
    tail = _FailingRender(state)
    rc = drive_tail(run_py.main, plant_alert(tmp_path / "o7"), tail, "--no-learn")

    assert rc == 0
    assert len(tail.visualized) == 1, (
        f"the render step was never reached (ran {tail.names}) — the 0 proves nothing")
    err = capfd.readouterr().err
    assert "not rendered (#1110 O7)" in err, "the failed render was not reported on stderr"


# --- #1471 r8 W7: the page has no ticket switch; it shows the receipt whenever one exists -----------------------------

def _page_run(tmp_path, label: str):
    """A run dir the renderer accepts (alert plus a real session store) and its handle."""
    from defender.tests.support.shared._fixture_uuid import fixture_uuid
    from defender.tests.support.shared.contracts._spec1077 import fixture_run
    from defender.tests.support.storage._alert_plant import plant_alert as plant_with_record
    from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S1107

    run_dir = tmp_path / "runs" / fixture_uuid(label)
    run_dir.mkdir(parents=True)
    plant_with_record(run_dir, {"alert_id": "a-1471", "rule": {"id": "r-1471", "description": "spec 1471"},
                                "timestamp": "2026-09-28T00:00:00Z"})
    S1107.seed_session_store(run_dir)
    return run_dir, fixture_run(run_dir), S1107


def _accepted():
    from defender.tests.support.shared.contracts._data_root_1078 import current_data_root, set_up_tenant

    return set_up_tenant(current_data_root())


@pytest.mark.parametrize("receipt", [
    {"key": "SOC-1471-A", "status": "commented", "url": "http://ticket-1471/tickets/SOC-1471-A", "ok": True,
     "reason": None},
    {"key": "SOC-1471-B", "status": "error", "url": None, "ok": False, "reason": "REASON-1471-B the store said no"},
], ids=["commented", "error"])
def test_1471_w7_the_run_page_shows_the_receipt_line_whenever_a_receipt_exists(tmp_path, receipt):
    """Rendered with no flag of any kind, the page carries the receipt's key and status (and reason); with no receipt
    it carries none of them. (W7)"""
    import json

    from defender.presentation import visualize_run

    run_dir, run, S1107 = _page_run(tmp_path, "page-with")
    S1107.receipt_path(run_dir).write_text(json.dumps(receipt), encoding="utf-8")
    visualize_run.publish_page(run, tenant=_accepted())
    page = S1107.page_html(run_dir)
    assert receipt["key"] in page, "the receipt's line is not on the page"
    assert receipt["status"] in page, "the receipt's line is not on the page"
    if receipt["reason"]:
        assert receipt["reason"] in page

    bare_dir, bare, _ = _page_run(tmp_path, "page-without")
    visualize_run.publish_page(bare, tenant=_accepted())
    bare_page = S1107.page_html(bare_dir)
    assert "spec 1471" in bare_page, "control: the receipt-less page rendered"
    assert 'class="ticket-line' not in bare_page
    assert receipt["key"] not in bare_page


def test_1471_w7_no_page_step_takes_an_update_ticket_switch(tmp_path):
    """Each step from the run's render to the page's writer refuses `update_ticket=` as an unexpected keyword. (W7)"""
    from defender import run_common
    from defender.presentation import visualize_run

    _dir, run, _ = _page_run(tmp_path, "page-switch")
    tenant = _accepted()
    for call in (lambda: visualize_run.render_page(run, update_ticket=True),
                 lambda: visualize_run.save_page(run, update_ticket=True),
                 lambda: visualize_run.publish_page(run, tenant=tenant, update_ticket=True),
                 lambda: run_common.visualize(run, tenant=tenant, update_ticket=True)):
        with pytest.raises(TypeError, match="update_ticket"):
            call()
    visualize_run.render_page(run)  # control: the same step without it renders


def test_1471_w7_the_page_command_refuses_update_ticket_like_any_unknown_switch(capsys):
    """`visualize_run.py --update-ticket` is a usage refusal (64) saying so, as a made-up switch is, and its usage line
    no longer offers it. (W7)"""
    from defender.presentation import visualize_run

    rc = visualize_run.main(["visualize_run.py", "--tenant", "t", "--update-ticket", "rid"])
    refused = capsys.readouterr().err
    assert rc == 64, (rc, refused)  # noqa: PLR2004
    assert "unrecognized arguments: --update-ticket" in refused, refused
    assert "[--update-ticket]" not in refused, refused
    assert visualize_run.main(["visualize_run.py", "--tenant", "t", "--made-up", "rid"]) == 64  # noqa: PLR2004
    assert "unrecognized arguments: --made-up" in capsys.readouterr().err


# --- #1546: the page names no folder of the host -----------------------------------------------------------------------------

def test_1546_the_run_page_is_the_same_bytes_under_any_root_and_names_neither_its_run_folder_nor_its_root(tmp_path):
    """One run, its whole root copied under another root of another name: the real renderer gives the same bytes over both,
    and neither page holds the run folder's path, the root's path or the root's name. The page is rendered in the job's
    root (`.job-roots/<claim>/...`) and stored as the object tenant users are served, so what it says cannot depend on where
    it was rendered. (design r9 "The job's folders", Session pointer: "the run page header stops embedding the run
    folder's path")"""
    import shutil

    from defender.presentation import visualize_run
    from defender.tests.support.shared.contracts._spec1077 import fixture_run

    first = tmp_path / "root-alpha-1546"
    run_dir, run, _ = _page_run(first, "page-any-root")
    second = tmp_path / "elsewhere-beta-1546"
    shutil.copytree(first, second, symlinks=True)
    moved = second / run_dir.relative_to(first)
    pages = {first: visualize_run.render_page(run), second: visualize_run.render_page(fixture_run(moved))}
    assert "spec 1471" in pages[first], "premise: a real page, over the planted alert"
    for root, held in ((first, run_dir), (second, moved)):
        for named in (str(held), str(held.resolve()), str(root), str(root.resolve()), root.name):
            assert named not in pages[root], f"the page names {named!r}"
    assert pages[first] == pages[second], "the page's bytes depend on where its run was rendered"
