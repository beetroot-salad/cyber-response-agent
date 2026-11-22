# ruff: noqa: F811, PT018
"""#1471 R13-0: the lifecycle makes a tenant's runs folder (prepare on both paths, the one-time upgrade step), and the
job lane never does. A tenant made by the lifecycle, with no hand-made `runs/`, reaches the worker's first claim."""
from __future__ import annotations

import asyncio
import datetime as _dt
import os
import sys

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from defender.tests.support.jobs._jobs1342 import FIXTURE_ALERT_MAPPING, ScriptedChild, job_store, make_worker, seed_alert_mapping  # noqa: E402
from defender.tests.tenancy.lifecycle_1214._support import LifecycleWorld, lifecycle_config  # noqa: E402

pytestmark = pytest.mark.postgres

LANE_WORDS = "the tenant's runs container cannot be used on this host"


@pytest.fixture
def world(tmp_path, data_root):
    w = LifecycleWorld(tmp_path, data_root)
    yield w
    w.close()


def _runs(world, tenant: str):
    return world.data_root / tenant / "runs"


def _at_prepare(world, *tenants: str) -> None:
    world.drive(stop=lambda: all(world.item(t)["step"] == "prepare" for t in tenants))


# --- prepare makes it ------------------------------------------------------------------------------------------------

def test_a_new_tenant_is_active_with_a_real_empty_runs_folder_and_prepare_made_it_before_the_first_publish(world):
    """A lifecycle-made tenant has `<T>/runs`, a real directory, already there when the first publish runs (R13-0)."""
    seen: list[bool] = []
    first = world.fetch  # #1618: prepare's first read of the knowledge is the fetch (was the first publish)

    def watching(tenant_id, dest, *, data_root, **kw):
        seen.append((data_root / tenant_id / "runs").is_dir())
        return first(tenant_id, dest, data_root=data_root, **kw)

    world.host_actor = world.new_host(world.tenants, fetch=watching)
    tenant = world.active_tenant()
    runs = _runs(world, tenant)
    assert runs.is_dir() and not runs.is_symlink() and list(runs.iterdir()) == []
    assert seen == [True], "the runs folder was not there when the first publish ran"


# 1618 K8: "prepare makes the runs folder beside a kept clone too" is retired with the clone (prepare keeps no clone to skip to;
# `test_resume_and_backfill` retires `_plant_clone` the same way). The new-tenant case above is prepare's one path.


def test_a_link_at_the_runs_folder_fails_prepare_and_nothing_is_followed(world, tmp_path):
    """`<T>/runs` a link: prepare fails like a linked `knowledge/` does, the target gets nothing, no fetch (R13-0)."""
    tenant = world.create()
    _at_prepare(world, tenant)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (world.data_root / tenant).mkdir(exist_ok=True)
    _runs(world, tenant).symlink_to(elsewhere)
    world.drive()
    item = world.item(tenant)
    assert (item["state"], item["step"], item["step_actor"]) == ("creating", "prepare", "host") and item["failure"], item
    assert list(elsewhere.iterdir()) == [] and _runs(world, tenant).is_symlink()
    assert world.fetch.calls == []


# --- the upgrade step ------------------------------------------------------------------------------------------------

def _without_runs(world, *tenants: str) -> None:
    """The state of a tenant made before #1471: no `runs/` (removed where the lifecycle made one)."""
    for tenant in tenants:
        if _runs(world, tenant).exists():
            _runs(world, tenant).rmdir()


def _make(world):
    from defender.lifecycle import make_runs_folders

    return world.call(make_runs_folders, world.tenants, data_root=world.data_root)


def test_the_upgrade_makes_the_runs_folder_of_every_active_tenant_that_lacks_one_and_keeps_the_rest(world):
    """Active tenants without `runs/` get it, one that has it keeps its content, a second run changes nothing (R13-0)."""
    lacking, lacking2, having = world.active_tenant(), world.active_tenant(), world.active_tenant()
    _without_runs(world, lacking, lacking2)
    _runs(world, having).mkdir(exist_ok=True)  # the content to be kept; the lifecycle's own is the other half
    (_runs(world, having) / "run-1.json").write_text("{}")
    made = _make(world)
    assert {lacking, lacking2} <= set(made)
    for tenant in (lacking, lacking2, having):
        assert _runs(world, tenant).is_dir() and not _runs(world, tenant).is_symlink()
    assert [p.name for p in _runs(world, having).iterdir()] == ["run-1.json"]
    before = {t: sorted(p.name for p in _runs(world, t).iterdir()) for t in (lacking, lacking2, having)}
    _make(world)
    assert before == {t: sorted(p.name for p in _runs(world, t).iterdir()) for t in (lacking, lacking2, having)}


def test_the_upgrade_returns_the_made_ids_oldest_first_and_none_for_an_up_to_date_data_root(world):
    """The returned ids are those it made, oldest first; with nothing missing it makes (returns) none (R13-0)."""
    first = world.active_tenant()
    world.clock.advance(_dt.timedelta(seconds=1))  # the world's clock is frozen: without this the two are created at once
    second = world.active_tenant()
    _without_runs(world, second, first)
    assert _make(world) == [first, second]
    assert _make(world) == []


def _link_runs(world, tmp_path, *tenants: str) -> list:
    targets = []
    for n, tenant in enumerate(tenants):
        elsewhere = tmp_path / f"elsewhere{n}"
        elsewhere.mkdir()
        _runs(world, tenant).symlink_to(elsewhere)
        targets.append(elsewhere)
    return targets


def _refusal(world) -> str:
    """The text of the one error `make_runs_folders` raises (its type is not fixed); fails if it returns."""
    try:
        _make(world)
    except ImportError:
        raise  # the function is missing: that is the red, not a refusal
    except Exception as exc:  # noqa: BLE001 — the exception type is not fixed
        return str(exc)
    raise AssertionError("make_runs_folders returned over a refused tenant")


def test_the_upgrade_leaves_non_active_tenants_alone_and_refuses_an_active_tenant_with_no_folder(world):
    """A tenant not `active` is left alone and unnamed; an active one with no `<T>` here is refused, named, and gets no
    folder, after the others are made (R13-0, surface 7b)."""
    import shutil

    gone, control = world.active_tenant(), world.active_tenant()
    shutil.rmtree(world.data_root / gone)
    _without_runs(world, control)
    creating = world.create()
    _at_prepare(world, creating)
    folder = world.data_root / creating
    folder.mkdir(exist_ok=True)
    message = _refusal(world)
    assert gone in message, "an active tenant with no folder on the data root was skipped silently"
    assert control not in message and creating not in message, "a made or non-active tenant is named as refused"
    assert _runs(world, control).is_dir() and not _runs(world, control).is_symlink(), "the others were not made first"
    assert not (folder / "runs").exists(), "a tenant still being created was given a runs folder"
    assert not (world.data_root / gone).exists(), "a tenant folder was made for a tenant that has none here"


def _not_active() -> list[str]:
    from typing import get_args

    from defender.tenancy.models import TenantState

    return [state for state in get_args(TenantState) if state != "active"]


@pytest.mark.parametrize("state", _not_active())
def test_the_upgrade_leaves_a_tenant_in_every_state_but_active_alone_with_or_without_its_folder(world, state):
    """Generated from the tenant states: a tenant not `active`, its folder here without `runs/` or gone (an offboarded
    tenant's teardown removes it), is neither made nor refused, beside an active one that is made. (R13-0, surface 7b;
    repair 5)"""
    import shutil

    from defender.tests.support.jobs._jobs1342 import move_tenant

    left, made = world.active_tenant(), world.active_tenant()
    _without_runs(world, left, made)
    move_tenant(world.dsn, left, state=state)
    assert _make(world) == [made], "a tenant that is not active was made, or refused"
    assert not _runs(world, left).exists(), f"a tenant {state} was given a runs folder"
    shutil.rmtree(world.data_root / left)
    assert _make(world) == [], f"a tenant {state} with no folder here was refused"


def test_links_at_runs_refuse_those_tenants_after_the_others_are_made_and_the_error_names_every_one(world, tmp_path):
    """The sweep finishes, then raises once naming each refused tenant; links are left as found, others made (R13-0)."""
    linked, other, linked2 = world.active_tenant(), world.active_tenant(), world.active_tenant()
    _without_runs(world, linked, other, linked2)
    targets = _link_runs(world, tmp_path, linked, linked2)
    message = _refusal(world)
    assert linked in message and linked2 in message, "a refused tenant was not named"
    assert other not in message, "a tenant that was made is named as refused"
    assert _runs(world, other).is_dir() and not _runs(world, other).is_symlink(), "the sweep stopped at the first refusal"
    for tenant, target in zip((linked, linked2), targets, strict=True):
        assert _runs(world, tenant).is_symlink() and list(target.iterdir()) == []
    assert linked in _refusal(world), "a rerun did not refuse again"


def _lifecycle_env(monkeypatch, world, tmp_path) -> None:
    from defender.lifecycle import config as settings
    from defender.tests.support.tenancy._active1214 import DSN_ENV

    expected = lifecycle_config(tmp_path, world.data_root)
    for name, value in (("forge-token", expected.forge_admin_token), ("bao-login", expected.openbao_login)):
        (tmp_path / name).write_text(value + "\n", encoding="utf-8")
    for name in [k for k in os.environ if k.startswith(("DEFENDER_LIFECYCLE_", "LIFECYCLE_"))]:
        monkeypatch.delenv(name)
    for name, value in ((DSN_ENV, world.dsn), (settings.FORGE_URL_ENV, expected.forge_url),
                        (settings.FORGE_TOKEN_FILE_ENV, str(tmp_path / "forge-token")),
                        (settings.OPENBAO_LOGIN_FILE_ENV, str(tmp_path / "bao-login")),
                        (settings.INTEGRATION_ENV, expected.integration_command),
                        (settings.SECRETS_DIR_ENV, str(expected.secrets_dir)), (settings.DATA_ROOT_ENV, str(world.data_root)),
                        (settings.POLL_ENV, "0.05")):
        monkeypatch.setenv(name, value)


def test_the_lifecycle_command_make_runs_folders_makes_them_and_exits_zero(world, tmp_path, monkeypatch):
    """`python -m defender.lifecycle make-runs-folders` makes the missing runs folders over the configured data root (R13-0)."""
    from defender.lifecycle import __main__ as entry
    from defender.tests.support.tenancy._host1214 import LIFECYCLE_MARK

    monkeypatch.setenv(LIFECYCLE_MARK, "")  # `main` marks the process; monkeypatch removes the mark at teardown
    monkeypatch.delenv(LIFECYCLE_MARK)
    tenant = world.active_tenant()
    _without_runs(world, tenant)
    _lifecycle_env(monkeypatch, world, tmp_path)
    assert entry.main(["make-runs-folders"]) == 0
    assert _runs(world, tenant).is_dir()


def test_the_lifecycle_command_make_runs_folders_exits_non_zero_naming_a_refused_tenant(world, tmp_path, monkeypatch, capsys, caplog):
    """A linked `<T>/runs` makes `make-runs-folders` exit non-zero with text naming that tenant; the other is made (R13-0)."""
    from defender.lifecycle import __main__ as entry
    from defender.tests.support.tenancy._host1214 import LIFECYCLE_MARK

    monkeypatch.setenv(LIFECYCLE_MARK, "")
    monkeypatch.delenv(LIFECYCLE_MARK)
    linked, other = world.active_tenant(), world.active_tenant()
    _without_runs(world, linked, other)
    _link_runs(world, tmp_path, linked)
    _lifecycle_env(monkeypatch, world, tmp_path)
    code: object = 0
    text = ""
    capsys.readouterr()
    caplog.clear()  # setup logs carry the tenant ids; only the command's own output counts
    try:
        code = entry.main(["make-runs-folders"])
    except SystemExit as exc:  # argparse's own "invalid choice" is SystemExit(2) too: the tenant must be named
        code = exc.code
        text = str(exc.code)
    except Exception as exc:  # noqa: BLE001 — an escaping error is a non-zero exit; its text must name the tenant
        code, text = "raised", str(exc)
    captured = capsys.readouterr()
    text += captured.out + captured.err + caplog.text
    assert code not in (0, None), "the command succeeded over a refused tenant"
    assert linked in text, "the non-zero exit does not name the refused tenant"
    assert _runs(world, other).is_dir()


# --- a missing runs folder fails loudly -----------------------------------------------------------------------------

def test_the_job_lane_never_makes_the_runs_folder_and_has_no_make_parameter(world):
    """`JobLane.open` refuses a tenant with no `runs/` and makes nothing; `make=` is a TypeError (R13-0)."""
    from defender.tenancy import data_root_from_path
    from defender.records import job_lane

    tenant = world.active_tenant()
    root = data_root_from_path(world.data_root)
    _runs(world, tenant).mkdir(exist_ok=True)  # this case is about the lane, not the maker
    with job_lane.JobLane.open(root, tenant):
        pass  # control: with the folder there, the lane opens
    _without_runs(world, tenant)
    with pytest.raises(job_lane.JobLaneRefused, match="absent"):
        job_lane.JobLane.open(root, tenant)
    with pytest.raises(TypeError):
        job_lane.JobLane.open(root, tenant, make=True)
    assert not _runs(world, tenant).exists()


# --- the closing test ------------------------------------------------------------------------------------------------

def test_a_lifecycle_made_tenants_first_investigation_is_claimed_without_a_lane_refusal(world, tmp_path):
    """No hand-made `runs/`: the worker's first investigation claim starts its child, not `worker_error` (R13-0)."""
    tenant = world.active_tenant()
    seed_alert_mapping(world.dsn, tenant, FIXTURE_ALERT_MAPPING)  # the claim's other precondition, not the runs folder
    alert = world.add_alert(tenant)
    child = ScriptedChild(tmp_path / "child", _runs(world, tenant))

    async def run() -> str:
        async with job_store(world.dsn) as store:
            inv, _ = await store.create_investigation(tenant, alert, "k1", actor="u-1")
            await make_worker(store, world.data_root, child).drain()
            return inv.investigation_id

    inv = asyncio.run(run())
    from defender.tests.support.jobs._jobs1342 import row

    stored = row(world.dsn, inv)
    assert LANE_WORDS not in (stored["failure_message"] or ""), stored
    assert child.seen() is not None, f"no child was started: {stored}"


def test_a_lifecycle_made_tenants_first_readiness_check_is_claimed_without_a_lane_refusal(world, tmp_path):
    """No hand-made `runs/`: the worker's first readiness claim starts its helper, not `worker_error` (R13-0)."""
    tenant = world.active_tenant()
    marker = tmp_path / "helper-started"

    def readiness_argv(launch) -> list[str]:
        return [sys.executable, "-c", "import pathlib, sys; pathlib.Path(sys.argv[1]).touch()", str(marker)]

    idle = ScriptedChild(tmp_path / "child", _runs(world, tenant))

    async def run():
        async with job_store(world.dsn) as store:
            request, _ = await store.create_readiness(tenant, actor="u-1")
            await make_worker(store, world.data_root, idle, readiness_argv=readiness_argv).drain()
            return await store.get_host_request(tenant, request.request_id, kind="readiness")

    stored = asyncio.run(run())
    assert LANE_WORDS not in (stored.failure_message or ""), stored
    assert marker.exists(), f"no helper was started: {stored}"
